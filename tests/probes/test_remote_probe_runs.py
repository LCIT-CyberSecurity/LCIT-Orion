"""Bounds for run-to-probe task construction."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from orion_app.database import Base
from orion_app.models import (
    DefinitionTarget,
    NetworkZone,
    NetworkZoneTarget,
    RemoteProbe,
    ScanDefinition,
    ScanProfile,
    Target,
)
from orion_app.services.planner import PlanError, validate_remote_probe_selection
from orion_app.services.remote_probe_runs import _ports, _task_payload
from orion_app.workers import worker
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def test_remote_tls_ports_are_explicit_and_bounded() -> None:
    assert _ports("443,8443", "tls") == [443, 8443]
    assert _ports("22-24", "ssh") == [22, 23, 24]
    assert _ports("fast", "ipsec") == [500, 4500]
    for spec in ("", "fast", "all", "80-200"):
        with pytest.raises(ValueError):
            _ports(spec, "tls")


def test_remote_task_is_normalized_and_carries_the_zone_scope() -> None:
    zone = NetworkZone(id=uuid.uuid4(), name="lab", cidr="192.0.2.0/24")
    task = _task_payload(uuid.uuid4(), "tls", ["target.example"], [443], zone)
    assert task["targets"] == ["target.example"]
    assert task["ports"] == [443]
    assert task["scope_networks"] == ["192.0.2.0/24"]


def test_remote_task_rejects_invalid_target_before_dispatch() -> None:
    zone = NetworkZone(id=uuid.uuid4(), name="lab", cidr="192.0.2.0/24")
    with pytest.raises(ValueError, match="target"):
        _task_payload(uuid.uuid4(), "tls", ["-oN /tmp/out"], [443], zone)


def test_worker_routes_remote_runs_away_from_the_local_scanner(monkeypatch) -> None:
    run = SimpleNamespace(config_snapshot={"remote_probe_ids": [str(uuid.uuid4())]})

    @contextmanager
    def session():
        yield SimpleNamespace(get=lambda _model, _run_id: run)

    called = []
    monkeypatch.setattr("orion_app.services.remote_probe_runs.run_remote_probe", lambda *_args: called.append(True))
    monkeypatch.setattr(worker.tempfile, "TemporaryDirectory", lambda **_kwargs: pytest.fail("local scan subprocess must not start"))
    worker.run_subprocess(SimpleNamespace(), session, run_id=uuid.uuid4())
    assert called == [True]


def test_probe_selection_requires_capability_and_complete_zone_coverage() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        profile = ScanProfile(name="remote-test")
        db.add(profile)
        db.flush()
        definition = ScanDefinition(name="remote-test", profile_id=profile.id)
        target = Target(value="target.example", kind="fqdn", ports="443")
        zone = NetworkZone(name="remote-test-zone", cidr="192.0.2.0/24")
        db.add_all([definition, target, zone])
        db.flush()
        db.add_all([
            DefinitionTarget(definition_id=definition.id, target_id=target.id),
            NetworkZoneTarget(zone_id=zone.id, target_id=target.id),
        ])
        probe = RemoteProbe(name="remote-test-probe", address="198.51.100.2", network_zone_id=zone.id,
                            certificate_sha256="0" * 64, certificate_pem="fixture", status="active", capabilities=["tls"])
        db.add(probe)
        db.flush()
        snapshot = {"enabled_controls": ["tls"], "passes": [{"targets": [target.value], "ports": "443"}]}
        validate_remote_probe_selection(db, definition, snapshot, [str(probe.id)])
        probe.capabilities = ["ssh"]
        with pytest.raises(PlanError, match="support"):
            validate_remote_probe_selection(db, definition, snapshot, [str(probe.id)])
        probe.capabilities = ["tls"]
        with pytest.raises(PlanError, match="fast/all"):
            validate_remote_probe_selection(db, definition, {**snapshot, "passes": [{"targets": [target.value], "ports": "fast"}]}, [str(probe.id)])
