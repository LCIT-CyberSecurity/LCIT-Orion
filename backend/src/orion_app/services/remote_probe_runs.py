"""Run bounded probe observations for a scan run without falling back to central scanning."""
from __future__ import annotations

import ssl
import time
import uuid
from datetime import UTC, datetime

from cryptography.fernet import InvalidToken
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from orion_app.models import (
    NetworkZone,
    NetworkZoneTarget,
    RemoteProbe,
    RemoteProbeEvent,
    RemoteProbeTask,
    ScanRun,
)
from orion_app.services import audit, greenbone
from orion_app.services.logs import scrub_text
from orion_app.services.notifications import notify_run_finished
from remote_probe.client import ProbeClient, ProbeConnectionError
from remote_probe.protocol import TaskValidationError, validate_task

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def _ports(spec: str, kind: str) -> list[int]:
    if kind == "ipsec":
        return [500, 4500]
    if spec in {"", "fast", "all"}:
        raise ValueError("Remote probes require explicit target ports; fast/all port discovery is not supported")
    values: set[int] = set()
    for part in spec.split(","):
        low_high = part.split("-", 1)
        low, high = int(low_high[0]), int(low_high[-1])
        if high - low > 63:
            raise ValueError("Remote probe port ranges are limited to 64 ports")
        values.update(range(low, high + 1))
    if not values or len(values) > 64:
        raise ValueError("Remote probe tasks require between one and 64 explicit ports")
    return sorted(values)


def _client(probe: RemoteProbe, settings) -> ProbeClient:
    if not probe.encrypted_token:
        raise ValueError("selected probe is not paired")
    try:
        token = greenbone.credential_cipher(settings).decrypt(probe.encrypted_token.encode("ascii")).decode("utf-8")
        return ProbeClient(probe.address, probe.api_port, probe.certificate_pem, probe.certificate_sha256, token)
    except (greenbone.GreenboneError, InvalidToken, ValueError, UnicodeError, ssl.SSLError):
        raise ValueError("probe credentials or TLS identity are unavailable") from None


def _persist_events(db, probe: RemoteProbe, client: ProbeClient) -> int:
    """Persist contiguous probe events before acknowledging their cursor."""
    if probe.pending_ack_cursor is not None:
        client.acknowledge(probe.pending_ack_cursor)
        probe.acknowledged_cursor = probe.pending_ack_cursor
        probe.pending_ack_cursor = None
        db.commit()
    imported_total = 0
    while True:
        page = client.results(after=probe.acknowledged_cursor, limit=20)
        events = page.get("events")
        next_cursor = page.get("next_cursor")
        if not isinstance(events, list) or len(events) > 20 or isinstance(next_cursor, bool) or not isinstance(next_cursor, int):
            raise ValueError("probe returned an invalid results page")
        expected = probe.acknowledged_cursor
        for event in events:
            if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
                raise ValueError("probe returned an invalid result event")
            cursor, event_id = event.get("cursor"), event.get("event_id")
            if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor != expected + 1:
                raise ValueError("probe returned a result cursor gap")
            try:
                uuid.UUID(str(event_id))
            except (ValueError, TypeError, AttributeError):
                raise ValueError("probe returned an invalid result event identifier") from None
            expected = cursor
            exists = db.scalar(select(RemoteProbeEvent.id).where(
                RemoteProbeEvent.probe_id == probe.id, RemoteProbeEvent.event_id == str(event_id)))
            if exists:
                continue
            payload = event["payload"]
            try:
                task_id = uuid.UUID(str(payload.get("task_id")))
            except (ValueError, TypeError, AttributeError):
                task_id = None
            if task_id and db.get(RemoteProbeTask, task_id) is None:
                task_id = None
            with db.begin_nested():
                db.add(RemoteProbeEvent(probe_id=probe.id, event_id=str(event_id), cursor=cursor,
                                        task_id=task_id, payload=payload))
                try:
                    db.flush()
                    imported_total += 1
                except IntegrityError:
                    pass
            if task_id:
                task = db.get(RemoteProbeTask, task_id)
                event_status = payload.get("status")
                if task and event_status in TERMINAL:
                    task.status = event_status
                    task.error = str(payload.get("error", ""))[:80]
                    task.finished_at = datetime.now(UTC)
        if next_cursor != expected:
            raise ValueError("probe returned an invalid result cursor")
        if not events:
            return imported_total
        probe.pending_ack_cursor = next_cursor
        probe.last_seen_at = datetime.now(UTC)
        db.commit()
        client.acknowledge(next_cursor)
        probe.acknowledged_cursor = next_cursor
        probe.pending_ack_cursor = None
        db.commit()


def _task_payload(task_id: uuid.UUID, kind: str, targets: list[str], ports: list[int], zone: NetworkZone) -> dict:
    payload = {"task_id": str(task_id), "kind": kind, "targets": targets, "ports": ports,
               "timeout_seconds": 10, "workers": 4, "scope_networks": [zone.cidr]}
    try:
        return validate_task(payload)
    except TaskValidationError as error:
        raise ValueError(str(error)) from error


def run_remote_probe(settings, session_factory, run_id: uuid.UUID) -> None:
    """Dispatch and supervise a probe-only run; this path never starts the local scan engine."""
    started = time.monotonic()
    clients: dict[uuid.UUID, ProbeClient] = {}
    failed = []
    cancelled = False
    try:
        with session_factory() as db:
            run = db.get(ScanRun, run_id)
            if not run:
                return
            snapshot = run.config_snapshot or {}
            probe_ids = [uuid.UUID(value) for value in snapshot.get("remote_probe_ids", [])]
            probes = db.execute(select(RemoteProbe).where(RemoteProbe.id.in_(probe_ids))).scalars().all()
            if len(probes) != len(probe_ids) or any(probe.status != "active" for probe in probes):
                raise ValueError("a selected probe is missing, revoked, or inactive")
            controls = snapshot.get("enabled_controls") or [snapshot.get("control_type", "tls")]
            definition_id = uuid.UUID(snapshot["definition"]["id"])
            from orion_app.models import ScanDefinition
            from orion_app.services.planner import resolve_targets

            definition = db.get(ScanDefinition, definition_id)
            if not definition:
                raise ValueError("scan definition no longer exists")
            target_rows = resolve_targets(db, definition)
            by_value = {target.value: target for target in target_rows}
            memberships = set(db.execute(select(NetworkZoneTarget.zone_id, NetworkZoneTarget.target_id)
                                         .where(NetworkZoneTarget.target_id.in_([target.id for target in target_rows]))).all())
            task_rows = []
            for probe in probes:
                zone = db.get(NetworkZone, probe.network_zone_id)
                if not zone or not zone.cidr:
                    raise ValueError("a selected probe zone has no network CIDR")
                clients[probe.id] = _client(probe, settings)
                assigned = {target.value: target for target in target_rows
                            if (probe.network_zone_id, target.id) in memberships}
                for kind in controls:
                    if kind not in set(probe.capabilities or []):
                        raise ValueError("a selected probe no longer supports an enabled scan control")
                    for scan_pass in snapshot.get("passes", []):
                        targets = [value for value in scan_pass.get("targets", []) if value in assigned]
                        if not targets:
                            continue
                        if any(by_value[value].kind == "cidr" for value in targets):
                            raise ValueError("remote probe runs currently require explicitly assigned IP or FQDN targets")
                        ports = (((snapshot.get("ssh") or {}).get("settings") or {}).get("ports", [22])
                                 if kind == "ssh" else _ports(str(scan_pass.get("ports") or ""), kind))
                        max_work = 128 if kind == "ipsec" else 32
                        if len(targets) * len(ports) > max_work:
                            raise ValueError(f"remote {kind} work is limited to {max_work} target/port checks per task")
                        task_id = uuid.uuid4()
                        payload = _task_payload(task_id, kind, targets, ports, zone)
                        task = RemoteProbeTask(id=task_id, probe_id=probe.id, run_id=run.id, kind=kind,
                                               request_payload=payload, status="queued", created_by=run.initiated_by)
                        db.add(task)
                        task_rows.append((probe, task, payload))
            if not task_rows:
                raise ValueError("no selected probe owns a target assigned to its zone")
            db.commit()

        for probe, task, payload in task_rows:
            response = clients[probe.id].submit_task(payload)
            if response.get("task_id") != str(task.id):
                raise ValueError("probe returned an unexpected task identifier")
            with session_factory() as db:
                row = db.get(RemoteProbeTask, task.id)
                row.status = "running"
                db.commit()

        deadline = started + settings.max_scan_duration_seconds
        pending = {task.id: (probe, task) for probe, task, _ in task_rows}
        while pending:
            if time.monotonic() >= deadline:
                failed.append("remote probe task timed out")
                for probe, task in list(pending.values()):
                    try:
                        clients[probe.id].cancel_task(str(task.id))
                    except ProbeConnectionError:
                        pass
                    with session_factory() as db:
                        row = db.get(RemoteProbeTask, task.id)
                        row.status = "interrupted"
                        row.error = "worker_timeout"
                        row.finished_at = datetime.now(UTC)
                        db.commit()
                    pending.pop(task.id, None)
                break
            with session_factory() as db:
                run = db.get(ScanRun, run_id)
                if not run or run.cancel_requested:
                    cancelled = True
            if cancelled:
                for probe, task in pending.values():
                    clients[probe.id].cancel_task(str(task.id))
                break
            for task_id, (probe, task) in list(pending.items()):
                remote = clients[probe.id].get_task(str(task_id))
                status = remote.get("status")
                if status not in TERMINAL:
                    continue
                with session_factory() as db:
                    row = db.get(RemoteProbeTask, task_id)
                    row.status = status
                    row.error = str(remote.get("error", ""))[:80]
                    row.finished_at = datetime.now(UTC)
                    db.commit()
                if status != "completed":
                    failed.append(f"{probe.name}: {status}")
                pending.pop(task_id)
            with session_factory() as db:
                run = db.get(ScanRun, run_id)
                run.heartbeat_at = datetime.now(UTC)
                run.phase = "remote_probe"
                run.progress = {"hosts_total": len(task_rows), "hosts_done": len(task_rows) - len(pending),
                                "phase": "remote_probe", "events": []}
                db.commit()
            if pending:
                time.sleep(1)

        for probe in probes:
            if probe.id in clients:
                with session_factory() as db:
                    current_probe = db.get(RemoteProbe, probe.id)
                    _persist_events(db, current_probe, clients[probe.id])

        with session_factory() as db:
            run = db.get(ScanRun, run_id)
            run.status = "cancelled" if cancelled else "partial"
            run.finished_at = datetime.now(UTC)
            run.duration_seconds = round(time.monotonic() - started, 2)
            run.error = "; ".join(failed)
            run.progress = {"hosts_total": len(task_rows), "hosts_done": len(task_rows) - len(pending),
                            "phase": "remote_probe", "events": [{"event": "finished", "status": run.status,
                                                                      "at": run.finished_at.isoformat()}]}
            audit.record(db, "scan.remote_probe_finished", actor_label="worker", resource_type="scan_run",
                         resource_id=run.id, outcome="failure" if failed or cancelled else "success",
                         detail={"task_count": len(task_rows), "failed_count": len(failed), "cancelled": cancelled})
            db.commit()
            notify_run_finished(db, run)
            db.commit()
    except (ProbeConnectionError, ValueError, OSError) as error:
        with session_factory() as db:
            run = db.get(ScanRun, run_id)
            if run and run.status == "running":
                for task in db.execute(select(RemoteProbeTask).where(
                    RemoteProbeTask.run_id == run.id, RemoteProbeTask.status.in_(("queued", "running"))
                )).scalars():
                    task.status = "interrupted"
                    task.error = "dispatch_or_sync_error"
                    task.finished_at = datetime.now(UTC)
                run.status = "partial"
                run.finished_at = datetime.now(UTC)
                run.duration_seconds = round(time.monotonic() - started, 2)
                run.error = "Remote probe dispatch/synchronization failed: " + scrub_text(str(error))[:240]
                db.commit()
                notify_run_finished(db, run)
                db.commit()
    finally:
        for client in clients.values():
            client.close()
