from datetime import UTC, datetime

from orion_app.workers.worker import apply_activity_event


def test_activity_projection_keeps_real_bounded_and_scrubbed_events():
    progress = {"hosts_total": None, "hosts_done": 0, "events": []}
    state = {"phase": "starting"}
    timestamp = datetime(2026, 11, 23, tzinfo=UTC)

    apply_activity_event(progress, state, {"event": "phase", "phase": "tls_scan", "hosts": ["a", "b"]}, timestamp)
    apply_activity_event(progress, state, {
        "event": "host_done", "target": "https://user:pass@example.test token=secret",
        "hosts_done": 1, "hosts_total": 2,
    }, timestamp)

    assert progress["hosts_done"] == 1 and progress["hosts_total"] == 2
    assert [event["event"] for event in progress["events"]] == ["phase", "target_done"]
    assert progress["events"][1]["target_index"] == 1
    assert all(event["at"] == timestamp.isoformat() for event in progress["events"])
    assert "secret" not in str(progress["events"])


def test_activity_projection_ignores_unknown_events_and_bounds_history():
    progress = {"hosts_total": None, "hosts_done": 0, "events": []}
    state = {"phase": "starting"}
    timestamp = datetime(2026, 11, 23, tzinfo=UTC)

    apply_activity_event(progress, state, {"event": "raw_log", "text": "must not be shown"}, timestamp)
    for index in range(40):
        apply_activity_event(progress, state, {"event": "phase", "phase": f"phase-{index}"}, timestamp)

    assert len(progress["events"]) == 30
    assert all(set(event) <= {"event", "phase", "target_index", "hosts_done", "hosts_total", "at"} for event in progress["events"])
