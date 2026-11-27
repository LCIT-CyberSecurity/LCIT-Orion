"""Bounded, restart-safe result spool without a local database."""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any


class SpoolFullError(RuntimeError):
    """The probe must refuse new results rather than discard unacknowledged evidence."""


class InvalidCursorError(ValueError):
    """An acknowledgement is not a cursor currently present in this spool."""


class ResultSpool:
    """Append-only JSONL spool with fsync, monotonically increasing cursors and explicit ack."""

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = 64 * 1024 * 1024,
        max_event_bytes: int = 256 * 1024,
    ):
        if max_bytes <= 0 or max_event_bytes <= 0 or max_event_bytes > max_bytes:
            raise ValueError("invalid spool limits")
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "results.jsonl"
        self.state_path = self.root / "state.json"
        self.max_bytes, self.max_event_bytes = max_bytes, max_event_bytes
        self._lock = threading.RLock()
        self._sequence = 0
        self._acked = 0
        self._load_state()

    def _load_state(self) -> None:
        if not self.state_path.exists():
            if self.path.exists():
                try:
                    with self.path.open(encoding="utf-8") as stream:
                        for line in stream:
                            event = json.loads(line)
                            cursor = event["cursor"]
                            if (
                                isinstance(cursor, bool)
                                or not isinstance(cursor, int)
                                or cursor <= self._sequence
                            ):
                                raise ValueError
                            self._sequence = cursor
                except (OSError, ValueError, KeyError, TypeError):
                    raise RuntimeError(
                        "probe spool is corrupt; refusing to overwrite pending evidence"
                    ) from None
            self._write_state()
            return
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            sequence, acked = state["sequence"], state["acked"]
            if (
                any(
                    isinstance(value, bool) or not isinstance(value, int) or value < 0
                    for value in (sequence, acked)
                )
                or acked > sequence
            ):
                raise ValueError
            self._sequence, self._acked = sequence, acked
            if self.path.exists():
                with self.path.open(encoding="utf-8") as stream:
                    for line in stream:
                        event = json.loads(line)
                        cursor = event["cursor"]
                        if (
                            isinstance(cursor, bool)
                            or not isinstance(cursor, int)
                            or cursor <= self._acked
                        ):
                            raise ValueError
                        self._sequence = max(self._sequence, cursor)
                if self._sequence != sequence:
                    self._write_state()
        except (OSError, ValueError, KeyError, TypeError):
            raise RuntimeError(
                "probe spool state is corrupt; refusing to overwrite pending evidence"
            ) from None

    def _atomic_write(self, path: Path, data: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
            directory_fd = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    def _write_state(self) -> None:
        data = json.dumps(
            {"sequence": self._sequence, "acked": self._acked}, separators=(",", ":")
        ).encode()
        self._atomic_write(self.state_path, data)

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            event = {
                "cursor": self._sequence + 1,
                "event_id": str(uuid.uuid4()),
                "payload": payload,
            }
            encoded = (
                json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
                + b"\n"
            )
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if (
                len(encoded) > self.max_event_bytes
                or current_size + len(encoded) > self.max_bytes
            ):
                raise SpoolFullError(
                    "result spool capacity reached; pending events were preserved"
                )
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                with os.fdopen(fd, "ab") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                raise RuntimeError("result could not be durably spooled") from None
            self._sequence += 1
            self._write_state()
            return event

    def read_after(self, cursor: int = 0, *, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            events = []
            if self.path.exists():
                with self.path.open(encoding="utf-8") as stream:
                    for line in stream:
                        event = json.loads(line)
                        if event["cursor"] > cursor:
                            events.append(event)
                            if len(events) == limit:
                                break
            return events

    def acknowledge(self, cursor: int) -> None:
        with self._lock:
            if (
                isinstance(cursor, bool)
                or not isinstance(cursor, int)
                or cursor < self._acked
                or cursor > self._sequence
            ):
                raise InvalidCursorError("acknowledgement cursor is invalid")
            if cursor == self._acked:
                return
            kept = []
            if self.path.exists():
                with self.path.open(encoding="utf-8") as stream:
                    kept = [
                        line
                        for line in stream
                        if int(json.loads(line)["cursor"]) > cursor
                    ]
            self._acked = cursor
            self._atomic_write(self.path, "".join(kept).encode("utf-8"))
            self._write_state()
