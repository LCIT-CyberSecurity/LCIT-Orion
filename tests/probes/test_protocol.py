from __future__ import annotations

import uuid

import pytest

from remote_probe.protocol import (
    TaskValidationError,
    resolve_targets_in_scope,
    restrict_scope,
    validate_task,
)


def test_task_is_typed_and_bounded():
    task = validate_task(
        {
            "task_id": str(uuid.uuid4()),
            "kind": "tls",
            "targets": ["192.0.2.10"],
            "ports": [443],
        }
    )
    assert task["targets"] == ["192.0.2.10"]
    with pytest.raises(TaskValidationError, match="unsupported"):
        validate_task(
            {"task_id": str(uuid.uuid4()), "kind": "shell", "targets": ["192.0.2.10"]}
        )
    with pytest.raises(TaskValidationError, match="timeout_seconds"):
        validate_task(
            {
                "task_id": str(uuid.uuid4()),
                "kind": "tls",
                "targets": ["192.0.2.10"],
                "timeout_seconds": 31,
            }
        )
    with pytest.raises(TaskValidationError, match="UDP ports"):
        validate_task(
            {
                "task_id": str(uuid.uuid4()),
                "kind": "ipsec",
                "targets": ["192.0.2.10"],
                "ports": [443],
            }
        )


def test_scope_checks_every_dns_answer_and_returns_pinned_addresses():
    scope = ["192.0.2.0/24"]
    resolver = lambda _hostname: ["192.0.2.10", "192.0.2.11"]
    assert resolve_targets_in_scope(["service.example"], scope, resolver=resolver) == {
        "service.example": ("192.0.2.10", "192.0.2.11")
    }
    with pytest.raises(TaskValidationError, match="outside"):
        resolve_targets_in_scope(
            ["service.example"],
            scope,
            resolver=lambda _: ["192.0.2.10", "198.51.100.8"],
        )


def test_scope_requires_explicit_cidr_and_stops_dns_failures():
    with pytest.raises(TaskValidationError, match="no assigned"):
        resolve_targets_in_scope(["192.0.2.10"], [])
    with pytest.raises(TaskValidationError, match="resolution failed"):
        resolve_targets_in_scope(
            ["service.example"],
            ["192.0.2.0/24"],
            resolver=lambda _: (_ for _ in ()).throw(OSError()),
        )


def test_central_scope_cannot_exceed_the_probe_local_allowlist():
    assert restrict_scope(["192.0.2.0/25"], ["192.0.2.0/24"]) == ("192.0.2.0/25",)
    with pytest.raises(TaskValidationError, match="exceeds"):
        restrict_scope(["192.0.2.0/23"], ["192.0.2.0/24"])
