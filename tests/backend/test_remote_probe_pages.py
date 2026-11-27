"""Cursor validation prevents incomplete probe results from being acknowledged."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from orion_app.api.probes import _validate_probe_task_workload, _validate_result_page


@pytest.mark.parametrize(
    ("kind", "targets", "ports", "expected_limit"),
    [("tls", 16, 2, 32), ("ssh", 32, 1, 32), ("ipsec", 64, 2, 128)],
)
def test_probe_task_workload_accepts_engine_budget(
    kind: str, targets: int, ports: int, expected_limit: int
) -> None:
    assert targets * ports == expected_limit
    _validate_probe_task_workload(kind, targets, ports)


@pytest.mark.parametrize(
    ("kind", "targets", "ports"),
    [("tls", 17, 2), ("ssh", 33, 1), ("ipsec", 65, 2)],
)
def test_probe_task_workload_rejects_over_budget(
    kind: str, targets: int, ports: int
) -> None:
    with pytest.raises(HTTPException) as error:
        _validate_probe_task_workload(kind, targets, ports)

    assert error.value.status_code == 422
    assert error.value.detail == "Task exceeds the probe engine work limit"


def test_result_page_requires_contiguous_cursors() -> None:
    events = [
        {"cursor": 8, "event_id": "event-8", "payload": {}},
        {"cursor": 9, "event_id": "event-9", "payload": {}},
    ]

    assert _validate_result_page({"events": events, "next_cursor": 9}, 7) == (
        events,
        9,
    )

    with pytest.raises(HTTPException) as error:
        _validate_result_page({"events": [events[1]], "next_cursor": 9}, 7)
    assert error.value.status_code == 502
    assert "cursor gap" in error.value.detail


def test_empty_result_page_cannot_advance_the_cursor() -> None:
    with pytest.raises(HTTPException) as error:
        _validate_result_page({"events": [], "next_cursor": 12}, 7)

    assert error.value.status_code == 502
