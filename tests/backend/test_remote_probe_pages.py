"""Cursor validation prevents incomplete probe results from being acknowledged."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from orion_app.api.probes import _validate_result_page


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
