from __future__ import annotations

import pytest

from remote_probe.spool import InvalidCursorError, ResultSpool, SpoolFullError


def test_spool_survives_restart_and_ack_is_idempotent(tmp_path):
    spool = ResultSpool(tmp_path)
    first = spool.append({"status": "timeout"})
    second = spool.append({"status": "observed"})
    assert [e["cursor"] for e in spool.read_after(0, limit=1)] == [1]
    spool = ResultSpool(tmp_path)
    spool.acknowledge(first["cursor"])
    spool.acknowledge(first["cursor"])
    assert spool.read_after(0) == [second]
    with pytest.raises(InvalidCursorError):
        spool.acknowledge(99)


def test_spool_fails_closed_at_capacity(tmp_path):
    spool = ResultSpool(tmp_path, max_bytes=200, max_event_bytes=200)
    spool.append({"value": "x" * 40})
    with pytest.raises(SpoolFullError):
        spool.append({"value": "x" * 100})
    assert len(spool.read_after()) == 1


def test_spool_recovers_durable_event_if_state_write_was_interrupted(tmp_path):
    spool = ResultSpool(tmp_path)
    event = spool.append({"status": "observed"})
    (tmp_path / "state.json").write_text('{"sequence":0,"acked":0}', encoding="utf-8")
    spool = ResultSpool(tmp_path)
    following = spool.append({"status": "timeout"})
    assert (event["cursor"], following["cursor"]) == (1, 2)


def test_spool_recovers_events_when_state_file_is_missing(tmp_path):
    spool = ResultSpool(tmp_path)
    event = spool.append({"status": "observed"})
    (tmp_path / "state.json").unlink()
    recovered = ResultSpool(tmp_path)
    following = recovered.append({"status": "timeout"})
    assert (event["cursor"], following["cursor"]) == (1, 2)
