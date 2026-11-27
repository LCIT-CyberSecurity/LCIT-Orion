"""Local task lifecycle for a probe; there is no outbound Orion connection."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from remote_probe.engines import ProbeEngineExecutor
from remote_probe.protocol import (
    TaskValidationError,
    resolve_targets_in_scope,
    restrict_scope,
    validate_task,
)
from remote_probe.spool import ResultSpool

Executor = Callable[[dict[str, Any], threading.Event], dict[str, Any]]


class ProbeAgent:
    """Bounded, durable task queue with local credential verification and result spooling."""

    def __init__(
        self,
        state_dir: Path,
        token_hash: str,
        allowed_networks: list[str],
        executor: Executor | None = None,
        *,
        workers: int = 2,
        capabilities: list[str] | None = None,
        pairing_code_hash: str = "",
        pairing_expires_at: int = 0,
    ) -> None:
        enforce_capabilities = executor is None or capabilities is not None
        if token_hash and (
            len(token_hash) != 64
            or any(c not in "0123456789abcdef" for c in token_hash)
        ):
            raise ValueError("token_hash must be a lowercase SHA-256 digest")
        if pairing_code_hash and (
            len(pairing_code_hash) != 64
            or any(c not in "0123456789abcdef" for c in pairing_code_hash)
        ):
            raise ValueError("pairing_code_hash must be a lowercase SHA-256 digest")
        if not 1 <= workers <= 8:
            raise ValueError("workers must be between 1 and 8")
        self.state_dir = state_dir
        self.tasks_dir = state_dir / "tasks"
        self.tasks_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state_dir, 0o700)
        os.chmod(self.tasks_dir, 0o700)
        self._credential_path = state_dir / "credential.json"
        self._token_hash = token_hash
        self._pairing_code_hash = pairing_code_hash
        self._pairing_expires_at = pairing_expires_at
        self._pairing_failures = 0
        self._load_credential()
        if not self._token_hash and (
            not self._pairing_code_hash or self._pairing_expires_at <= 0
        ):
            raise ValueError("configure a credential or an expiring pairing code")
        self.allowed_networks = tuple(allowed_networks)
        if executor is None:
            executor = ProbeEngineExecutor()
            if capabilities is None:
                capabilities = ProbeEngineExecutor.available_capabilities()
        self.capabilities = tuple(capabilities or [])
        if set(self.capabilities) - {"tls", "ssh", "ipsec", "dns"}:
            raise ValueError("probe capabilities contain an unsupported scan kind")
        self.executor = executor
        self._enforce_capabilities = enforce_capabilities
        self.spool = ResultSpool(state_dir / "spool")
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="orion-probe"
        )
        self._futures: dict[str, Future] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._active = 0
        self.spool_fault = False
        self._restore_queued()

    @staticmethod
    def token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def authenticate(self, token: str) -> bool:
        return bool(self._token_hash) and hmac.compare_digest(
            self.token_digest(token), self._token_hash
        )

    def pair(self, pairing_code: Any) -> str | None:
        """Exchange an expiring, single-use setup code for the installation credential."""
        with self._lock:
            if (
                not isinstance(pairing_code, str)
                or not self._pairing_code_hash
                or datetime.now(UTC).timestamp() > self._pairing_expires_at
                or self._pairing_failures >= 5
            ):
                return None
            if not hmac.compare_digest(
                self.token_digest(pairing_code), self._pairing_code_hash
            ):
                self._pairing_failures += 1
                self._save_credential()
                return None
            token = secrets.token_urlsafe(32)
            self._token_hash = self.token_digest(token)
            self._pairing_code_hash = ""
            self._pairing_expires_at = 0
            self._save_credential()
            return token

    def _load_credential(self) -> None:
        try:
            stored = json.loads(self._credential_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._save_credential()
            return
        except (OSError, ValueError, TypeError):
            raise RuntimeError("probe credential state is corrupt") from None
        token_hash = stored.get("token_hash", "")
        pairing_hash = stored.get("pairing_code_hash", "")
        if (
            not isinstance(token_hash, str)
            or (
                token_hash
                and (
                    len(token_hash) != 64
                    or any(c not in "0123456789abcdef" for c in token_hash)
                )
            )
            or not isinstance(pairing_hash, str)
            or (
                pairing_hash
                and (
                    len(pairing_hash) != 64
                    or any(c not in "0123456789abcdef" for c in pairing_hash)
                )
            )
        ):
            raise RuntimeError("probe credential state is invalid")
        self._token_hash = token_hash
        self._pairing_code_hash = pairing_hash
        self._pairing_expires_at = int(stored.get("pairing_expires_at", 0))
        self._pairing_failures = int(stored.get("pairing_failures", 0))
        if not self._token_hash and not self._pairing_code_hash:
            raise RuntimeError("probe has no usable pairing or API credential")

    def _save_credential(self) -> None:
        temporary = self._credential_path.with_suffix(".json.tmp")
        payload = json.dumps(
            {
                "token_hash": self._token_hash,
                "pairing_code_hash": self._pairing_code_hash,
                "pairing_expires_at": self._pairing_expires_at,
                "pairing_failures": self._pairing_failures,
            },
            separators=(",", ":"),
        )
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self._credential_path)
        directory_fd = os.open(self.state_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _task_path(self, task_id: str) -> Path:
        return self.tasks_dir / f"{task_id}.json"

    def _write_task(self, task: dict[str, Any]) -> None:
        path = self._task_path(task["task_id"])
        tmp = path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(task, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(self.tasks_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read_task(self, task_id: str) -> dict[str, Any] | None:
        try:
            return json.loads(self._task_path(task_id).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None

    def _restore_queued(self) -> None:
        for path in self.tasks_dir.glob("*.json"):
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
                if task.get("status") == "running":
                    task.update(
                        status="interrupted", finished_at=datetime.now(UTC).isoformat()
                    )
                    task["error"] = "The probe restarted while this task was running"
                    self._write_task(task)
                elif task.get("status") == "queued":
                    with self._lock:
                        if self._has_capacity():
                            self._schedule(task)
            except (OSError, ValueError, TypeError, KeyError):
                # Corrupt records are retained for operator recovery and never executed.
                continue

    def submit(self, raw_task: Any) -> dict[str, Any]:
        task = validate_task(raw_task)
        if self._enforce_capabilities and task["kind"] not in self.capabilities:
            raise TaskValidationError("probe does not advertise this scan capability")
        task["scope_networks"] = list(
            restrict_scope(
                task["scope_networks"] or self.allowed_networks, self.allowed_networks
            )
        )
        task["resolved_targets"] = resolve_targets_in_scope(
            task["targets"], task["scope_networks"]
        )
        now = datetime.now(UTC).isoformat()
        task.update(
            status="queued",
            created_at=now,
            started_at=None,
            finished_at=None,
            error="",
            result=None,
        )
        with self._lock:
            existing = self._read_task(task["task_id"])
            if existing is not None:
                stable_existing = {
                    key: existing.get(key)
                    for key in (
                        "task_id",
                        "kind",
                        "targets",
                        "ports",
                        "timeout_seconds",
                        "workers",
                        "policy",
                        "scope_networks",
                    )
                }
                stable_new = {key: task.get(key) for key in stable_existing}
                if stable_existing != stable_new:
                    raise ValueError("task_id was already used with a different task")
                return existing
            if sum(1 for _ in self.tasks_dir.glob("*.json")) >= 2048:
                raise RuntimeError("probe task history capacity reached")
            if not self._has_capacity():
                raise RuntimeError("probe task capacity reached")
            self._write_task(task)
            self._schedule(task)
            return task

    def _schedule(self, task: dict[str, Any]) -> None:
        task_id = task["task_id"]
        cancel = threading.Event()
        self._cancel[task_id] = cancel
        self._active += 1
        self._futures[task_id] = self._pool.submit(self._run, task, cancel)

    def _run(self, task: dict[str, Any], cancel: threading.Event) -> None:
        task_id = task["task_id"]
        task.update(status="running", started_at=datetime.now(UTC).isoformat())
        self._write_task(task)
        try:
            result = self.executor(task, cancel)
            if (
                not isinstance(result, dict)
                or len(json.dumps(result, ensure_ascii=False).encode("utf-8"))
                > 192 * 1024
            ):
                raise ValueError("result is invalid or too large")
            task.update(
                status="cancelled" if cancel.is_set() else "completed", result=result
            )
        except Exception as error:  # noqa: BLE001 - isolate scan executor errors without persisting details
            task.update(status="failed", error=type(error).__name__)
        task["finished_at"] = datetime.now(UTC).isoformat()
        self._write_task(task)
        try:
            self.spool.append(
                {
                    "task_id": task_id,
                    "kind": task["kind"],
                    "status": task["status"],
                    "result": task.get("result"),
                    "error": task.get("error", ""),
                    "started_at": task.get("started_at"),
                    "finished_at": task["finished_at"],
                }
            )
        except (OSError, RuntimeError):
            # Preserve the completed task record and expose a persistent health fault; pending
            # evidence is never evicted to make room.
            self.spool_fault = True
        finally:
            with self._lock:
                self._active -= 1
                self._cancel.pop(task_id, None)
                self._futures.pop(task_id, None)
                self._schedule_next_queued()

    def _schedule_next_queued(self) -> None:
        if not self._has_capacity():
            return
        for path in self.tasks_dir.glob("*.json"):
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            if task.get("status") == "queued":
                self._schedule(task)
                return

    def _has_capacity(self) -> bool:
        if self._active >= 512:
            return False
        pending_bytes = (
            self.spool.path.stat().st_size if self.spool.path.exists() else 0
        )
        return (
            pending_bytes + (self._active + 1) * self.spool.max_event_bytes
            <= self.spool.max_bytes
        )

    def resume_queued(self) -> None:
        with self._lock:
            while self._has_capacity():
                before = self._active
                self._schedule_next_queued()
                if self._active == before:
                    break

    def get(self, task_id: str) -> dict[str, Any] | None:
        return self._read_task(task_id)

    def cancel(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._read_task(task_id)
            if task is None:
                return None
            if task.get("status") == "queued":
                future = self._futures.get(task_id)
                if future and future.cancel():
                    task.update(
                        status="cancelled", finished_at=datetime.now(UTC).isoformat()
                    )
                    self._active -= 1
                    self._futures.pop(task_id, None)
                    self._cancel.pop(task_id, None)
                    self._write_task(task)
                    try:
                        self.spool.append(
                            {
                                "task_id": task_id,
                                "kind": task["kind"],
                                "status": "cancelled",
                            }
                        )
                    except (OSError, RuntimeError):
                        self.spool_fault = True
                    return task
            cancel = self._cancel.get(task_id)
            if cancel:
                cancel.set()
            return task

    def close(self) -> None:
        with self._lock:
            for cancel in self._cancel.values():
                cancel.set()
        self._pool.shutdown(wait=True, cancel_futures=False)
