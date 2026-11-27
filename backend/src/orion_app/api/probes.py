"""Administrative inventory and Orion-initiated control of remote probes."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import ssl
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, StrictInt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from orion_app.api.common import get_or_404
from orion_app.deps import get_db, require_role
from orion_app.models import (
    NetworkZone,
    NetworkZoneTarget,
    RemoteProbe,
    RemoteProbeEvent,
    RemoteProbeTask,
    Role,
    Target,
    User,
)
from orion_app.services import audit, greenbone
from orion_app.services.greenbone import GreenboneError
from remote_probe.client import ProbeClient, ProbeConnectionError
from remote_probe.protocol import TaskValidationError, validate_task

router = APIRouter(prefix="/api/remote-probes", tags=["remote-probes"])
reader = require_role(Role.AUDITOR)
operator = require_role(Role.OPERATOR)
administrator = require_role(Role.ADMIN)
DbDependency = Annotated[DbSession, Depends(get_db)]
ReaderDependency = Annotated[User, Depends(reader)]
OperatorDependency = Annotated[User, Depends(operator)]
AdministratorDependency = Annotated[User, Depends(administrator)]


class ProbeCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    address: str = Field(min_length=1, max_length=45)
    api_port: StrictInt = Field(default=9443, ge=1, le=65535)
    network_zone_id: uuid.UUID
    certificate_sha256: str = Field(min_length=64, max_length=95)
    certificate_pem: str = Field(min_length=128, max_length=16384)


class ProbePairBody(BaseModel):
    pairing_code: str = Field(min_length=32, max_length=256)


class ProbeTaskBody(BaseModel):
    kind: Literal["tls", "ssh", "ipsec", "dns"]
    target_ids: list[uuid.UUID] = Field(min_length=1, max_length=256)
    ports: list[StrictInt] | None = Field(default=None, max_length=64)
    timeout_seconds: StrictInt = Field(default=5, ge=1, le=30)
    workers: StrictInt = Field(default=4, ge=1, le=16)
    policy: dict = Field(default_factory=dict)


def _fingerprint(certificate_pem: str) -> tuple[str, str]:
    try:
        der = ssl.PEM_cert_to_DER_cert(certificate_pem)
    except (ssl.SSLError, ValueError):
        raise HTTPException(422, "Invalid probe certificate") from None
    return hashlib.sha256(der).hexdigest(), certificate_pem


def _probe_out(probe: RemoteProbe) -> dict:
    return {
        "id": str(probe.id),
        "name": probe.name,
        "address": probe.address,
        "api_port": probe.api_port,
        "network_zone_id": str(probe.network_zone_id),
        "certificate_sha256": probe.certificate_sha256,
        "status": probe.status,
        "capabilities": probe.capabilities or [],
        "last_seen_at": probe.last_seen_at,
        "created_at": probe.created_at,
    }


def _client(
    probe: RemoteProbe, settings, *, token_required: bool = True
) -> ProbeClient:
    token = ""
    if token_required:
        if not probe.encrypted_token:
            raise HTTPException(409, "Probe is not paired")
        try:
            token = (
                greenbone.credential_cipher(settings)
                .decrypt(probe.encrypted_token.encode("ascii"))
                .decode("utf-8")
            )
        except (GreenboneError, InvalidToken, UnicodeError):
            raise HTTPException(503, "Probe credential is unavailable") from None
    try:
        return ProbeClient(
            probe.address,
            probe.api_port,
            probe.certificate_pem,
            probe.certificate_sha256,
            token,
        )
    except ValueError:
        raise HTTPException(503, "Probe identity configuration is invalid") from None


def _validate_result_page(page: object, acknowledged_cursor: int) -> tuple[list[dict], int]:
    """Reject gaps before advancing the central cursor or acknowledging probe data."""
    if not isinstance(page, dict):
        raise HTTPException(502, "Probe returned an invalid result page")
    events = page.get("events")
    next_cursor = page.get("next_cursor")
    if (
        not isinstance(events, list)
        or len(events) > 20
        or isinstance(next_cursor, bool)
        or not isinstance(next_cursor, int)
        or next_cursor < acknowledged_cursor
    ):
        raise HTTPException(502, "Probe returned an invalid result page")
    expected_cursor = acknowledged_cursor
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
            raise HTTPException(502, "Probe returned an invalid result event")
        cursor = event.get("cursor")
        if isinstance(cursor, bool) or not isinstance(cursor, int):
            raise HTTPException(502, "Probe returned an invalid result cursor")
        expected_cursor += 1
        if cursor != expected_cursor:
            raise HTTPException(502, "Probe returned a result page with a cursor gap")
    if next_cursor != expected_cursor:
        raise HTTPException(502, "Probe returned an invalid result cursor")
    return events, next_cursor


@router.get("")
def list_probes(db: DbDependency, _user: ReaderDependency) -> list[dict]:
    probes = db.execute(select(RemoteProbe).order_by(RemoteProbe.name)).scalars()
    return [_probe_out(probe) for probe in probes]


@router.post("", status_code=201)
def create_probe(
    body: ProbeCreateBody,
    request: Request,
    db: DbDependency,
    user: AdministratorDependency,
) -> dict:
    try:
        address = ipaddress.ip_address(body.address)
    except ValueError:
        raise HTTPException(
            422, "Probe address must be a literal IPv4 address"
        ) from None
    if (
        address.version != 4
        or address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
    ):
        raise HTTPException(
            422, "Probe address must be a reachable unicast IPv4 address"
        )
    fingerprint, pem = _fingerprint(body.certificate_pem)
    expected = body.certificate_sha256.lower().replace(":", "")
    if len(expected) != 64 or any(
        value not in "0123456789abcdef" for value in expected
    ):
        raise HTTPException(422, "Invalid certificate fingerprint")
    if not hmac.compare_digest(fingerprint, expected):
        raise HTTPException(
            422, "Certificate fingerprint does not match the certificate"
        )
    zone = db.get(NetworkZone, body.network_zone_id)
    if zone is None:
        raise HTTPException(422, "Unknown network zone")
    probe = RemoteProbe(
        name=body.name.strip(),
        address=str(address),
        api_port=body.api_port,
        network_zone_id=zone.id,
        certificate_sha256=fingerprint,
        certificate_pem=pem,
        status="pairing",
        created_by=user.id,
    )
    db.add(probe)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            409, "A probe is already registered at this address and port"
        ) from None
    audit.record(
        db,
        "remote_probe.create",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
        detail={"address": probe.address, "zone_id": str(zone.id)},
    )
    db.commit()
    db.refresh(probe)
    return _probe_out(probe)


@router.post("/{probe_id}/pair")
def pair_probe(
    probe_id: uuid.UUID,
    body: ProbePairBody,
    request: Request,
    db: DbDependency,
    user: AdministratorDependency,
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    if probe.status != "pairing":
        raise HTTPException(409, "Probe is not awaiting pairing")
    settings = request.app.state.settings
    try:
        cipher = greenbone.credential_cipher(settings)
    except GreenboneError:
        raise HTTPException(
            503, "Server credential encryption is unavailable"
        ) from None
    client = _client(probe, settings, token_required=False)
    try:
        token = client.pair(body.pairing_code)
        encrypted = cipher.encrypt(token.encode("utf-8")).decode("ascii")
    except ProbeConnectionError:
        raise HTTPException(502, "Probe pairing failed") from None
    finally:
        client.close()
    probe.encrypted_token = encrypted
    probe.status = "active"
    probe.last_seen_at = datetime.now(UTC)
    probe.capabilities = []
    audit.record(
        db,
        "remote_probe.pair",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
    )
    db.commit()
    return _probe_out(probe)


@router.post("/{probe_id}/health")
def probe_health(
    probe_id: uuid.UUID, request: Request, db: DbDependency, user: OperatorDependency
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    if probe.status != "active":
        raise HTTPException(409, "Probe is not active")
    client = _client(probe, request.app.state.settings)
    try:
        health = client.health()
    except ProbeConnectionError:
        raise HTTPException(502, "Probe health check failed") from None
    finally:
        client.close()
    if health.get("status") != "ok":
        raise HTTPException(502, "Probe returned an invalid health response")
    probe.last_seen_at = datetime.now(UTC)
    capabilities = health.get("capabilities", [])
    if not isinstance(capabilities, list) or set(capabilities) - {
        "tls",
        "ssh",
        "ipsec",
        "dns",
    }:
        raise HTTPException(502, "Probe returned invalid capabilities")
    probe.capabilities = capabilities
    audit.record(
        db,
        "remote_probe.health",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
        detail={
            "results_pending": bool(health.get("results_pending")),
            "spool_fault": bool(health.get("spool_fault")),
        },
    )
    db.commit()
    return {"probe": _probe_out(probe), "health": health}


@router.post("/{probe_id}/tasks", status_code=202)
def dispatch_task(
    probe_id: uuid.UUID,
    body: ProbeTaskBody,
    request: Request,
    db: DbDependency,
    user: OperatorDependency,
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    if probe.status != "active":
        raise HTTPException(409, "Probe is not active")
    if body.kind not in set(probe.capabilities or []):
        raise HTTPException(409, "Probe does not advertise this scan capability")
    zone = db.get(NetworkZone, probe.network_zone_id)
    if not zone or not zone.cidr:
        raise HTTPException(409, "The probe network zone has no CIDR scope")
    task_id = uuid.uuid4()
    target_ids = list(dict.fromkeys(body.target_ids))
    if len(target_ids) != len(body.target_ids):
        raise HTTPException(422, "Duplicate target identifiers are not allowed")
    assigned_ids = set(
        db.execute(
            select(NetworkZoneTarget.target_id).where(
                NetworkZoneTarget.zone_id == probe.network_zone_id,
                NetworkZoneTarget.target_id.in_(target_ids),
            )
        ).scalars()
    )
    if assigned_ids != set(target_ids):
        raise HTTPException(
            403, "Every scan target must be explicitly assigned to the probe zone"
        )
    targets = (
        db.execute(select(Target).where(Target.id.in_(target_ids))).scalars().all()
    )
    target_values = [target.value for target in targets]
    payload = {
        "task_id": str(task_id),
        "kind": body.kind,
        "targets": target_values,
        **body.model_dump(exclude={"kind", "target_ids"}, exclude_none=True),
        "scope_networks": [zone.cidr],
    }
    try:
        payload = validate_task(payload)
    except TaskValidationError as error:
        raise HTTPException(422, str(error)) from None
    task = RemoteProbeTask(
        id=task_id,
        probe_id=probe.id,
        kind=body.kind,
        request_payload={**payload, "target_ids": [str(value) for value in target_ids]},
        status="queued",
        created_by=user.id,
    )
    db.add(task)
    db.commit()
    client = _client(probe, request.app.state.settings)
    try:
        remote = client.submit_task(payload)
    except ProbeConnectionError:
        task.status, task.error = "failed", "dispatch_failed"
        task.finished_at = datetime.now(UTC)
        db.commit()
        raise HTTPException(502, "Probe task dispatch failed") from None
    finally:
        client.close()
    if remote.get("task_id") != str(task.id):
        task.status, task.error = "failed", "unexpected_task_id"
        task.finished_at = datetime.now(UTC)
        db.commit()
        raise HTTPException(502, "Probe returned an unexpected task identifier")
    audit.record(
        db,
        "remote_probe.task.dispatch",
        actor=user,
        resource_type="remote_probe_task",
        resource_id=task.id,
        detail={
            "probe_id": str(probe.id),
            "kind": task.kind,
            "target_count": len(payload["targets"]),
        },
    )
    db.commit()
    return {
        "id": str(task.id),
        "probe_id": str(probe.id),
        "status": "queued",
        "kind": task.kind,
        "created_at": task.created_at,
        "remote_status": remote.get("status", "queued"),
    }


@router.post("/{probe_id}/sync")
def sync_probe(
    probe_id: uuid.UUID, request: Request, db: DbDependency, user: OperatorDependency
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    if probe.status != "active":
        raise HTTPException(409, "Probe is not active")
    client = _client(probe, request.app.state.settings)
    try:
        if probe.pending_ack_cursor is not None:
            cursor_to_ack = probe.pending_ack_cursor
            client.acknowledge(cursor_to_ack)
            probe.acknowledged_cursor = cursor_to_ack
            probe.pending_ack_cursor = None
            db.commit()
        page = client.results(after=probe.acknowledged_cursor, limit=20)
    except ProbeConnectionError:
        raise HTTPException(502, "Probe result synchronization failed") from None
    finally:
        client.close()
    events, next_cursor = _validate_result_page(page, probe.acknowledged_cursor)
    imported = 0
    for event in events:
        event_id, cursor = event.get("event_id"), event.get("cursor")
        try:
            uuid.UUID(str(event_id))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                502, "Probe returned an invalid event identifier"
            ) from None
        exists = db.scalar(
            select(RemoteProbeEvent.id).where(
                RemoteProbeEvent.probe_id == probe.id,
                RemoteProbeEvent.event_id == str(event_id),
            )
        )
        if exists:
            continue
        payload = event["payload"]
        task_id = None
        try:
            task_id = uuid.UUID(str(payload.get("task_id")))
        except (ValueError, TypeError, AttributeError):
            pass
        if task_id and db.get(RemoteProbeTask, task_id) is None:
            task_id = None
        record = RemoteProbeEvent(
            probe_id=probe.id,
            event_id=str(event_id),
            cursor=cursor,
            task_id=task_id,
            payload=payload,
        )
        with db.begin_nested():
            db.add(record)
            try:
                db.flush()
                imported += 1
            except IntegrityError:
                pass
        if task_id:
            task = db.get(RemoteProbeTask, task_id)
            if task and payload.get("status") in {
                "completed",
                "failed",
                "cancelled",
                "interrupted",
            }:
                task.status = payload["status"]
                task.error = str(payload.get("error", ""))[:80]
                task.finished_at = datetime.now(UTC)
    if events:
        probe.pending_ack_cursor = next_cursor
    probe.last_seen_at = datetime.now(UTC)
    audit.record(
        db,
        "remote_probe.results.sync",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
        detail={"events_received": len(events), "events_imported": imported},
    )
    db.commit()
    if events:
        client = _client(probe, request.app.state.settings)
        try:
            client.acknowledge(next_cursor)
        except ProbeConnectionError:
            raise HTTPException(
                502, "Results were stored but probe acknowledgement is pending"
            ) from None
        finally:
            client.close()
        probe.acknowledged_cursor = next_cursor
        probe.pending_ack_cursor = None
        db.commit()
    return {
        "events_received": len(events),
        "events_imported": imported,
        "acknowledged_cursor": probe.acknowledged_cursor,
        "acknowledgement_pending": probe.pending_ack_cursor is not None,
    }


@router.post("/{probe_id}/disable")
def disable_probe(
    probe_id: uuid.UUID, db: DbDependency, user: AdministratorDependency
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    if probe.status != "revoked":
        probe.status = "disabled"
    audit.record(
        db,
        "remote_probe.disable",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
    )
    db.commit()
    return _probe_out(probe)


@router.post("/{probe_id}/revoke")
def revoke_probe(
    probe_id: uuid.UUID, db: DbDependency, user: AdministratorDependency
) -> dict:
    probe = get_or_404(db, RemoteProbe, probe_id, "Probe")
    probe.status = "revoked"
    probe.encrypted_token = ""
    audit.record(
        db,
        "remote_probe.revoke",
        actor=user,
        resource_type="remote_probe",
        resource_id=probe.id,
    )
    db.commit()
    return _probe_out(probe)
