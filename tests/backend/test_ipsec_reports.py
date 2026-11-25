import csv
import io
import json
import signal
from pathlib import Path

import pytest
from orion_app.workers import child
from orion_app.workers.child import write_ipsec_reports


def test_ipsec_report_includes_only_observed_replies_and_keeps_scan_limits(tmp_path: Path):
    observations = [
        {
            "target": "ike.example.test", "port": 500, "status": "observed", "ike_version": "IKEv2",
            "exchange": "IKE_SA_INIT", "verdict": "indeterminate",
            "proposal": {"encryption": "AES_GCM_16", "key_length_bits": 256},
            "evidence": {"policy_verdicts": {}},
        },
        {
            "target": "silent.example.test", "port": 4500, "status": "timeout", "ike_version": "",
            "exchange": "", "verdict": "indeterminate", "proposal": {}, "evidence": {},
        },
    ]

    paths = write_ipsec_reports(observations, tmp_path, "run-1", ["html", "md", "csv"])
    html_report, markdown_report, csv_report = [Path(path).read_text(encoding="utf-8") for path in paths]
    rows = list(csv.DictReader(io.StringIO(csv_report)))

    assert len(rows) == 1
    assert rows[0]["target"] == "ike.example.test"
    assert "silent.example.test" not in html_report + markdown_report + csv_report
    assert "ESP/Child SA" in html_report and "authentication" in markdown_report and "PFS" in html_report
    assert "Observed IKE proposals" in html_report


def test_ipsec_report_empty_state_and_csv_header_for_silent_probes(tmp_path: Path):
    observations = [
        {"target": "silent.example.test", "port": 500, "status": "timeout", "proposal": {}},
        {"target": "silent.example.test", "port": 4500, "status": "indeterminate", "proposal": {}},
    ]

    paths = write_ipsec_reports(observations, tmp_path, "run-2", ["html", "md", "csv"])
    html_report, markdown_report, csv_report = [Path(path).read_text(encoding="utf-8") for path in paths]

    assert "No IKE response was observed" in html_report
    assert "UDP silence and timeouts are inconclusive" in html_report
    assert "No IKE response was observed" in markdown_report
    assert "silent.example.test" not in html_report + markdown_report + csv_report
    assert len(list(csv.reader(io.StringIO(csv_report)))) == 1


@pytest.mark.parametrize("control_type", ["ipsec", "multi"])
def test_standalone_and_multi_ipsec_paths_share_empty_report_format(tmp_path: Path, monkeypatch, control_type: str):
    ike = {"versions": ["IKEv2"], "ports": [500], "timeout_ms": 100, "retries": 0}
    scan_settings = {"ike": ike, "policies": []}
    snapshot = {
        "control_type": control_type,
        "passes": [{"targets": ["silent.example.test"]}],
        "export_formats": ["html", "md", "csv"],
    }
    if control_type == "ipsec":
        snapshot.update(scan_settings)
    else:
        snapshot.update({"enabled_controls": ["ipsec", "ssh"], "ipsec": scan_settings})
    snapshot_path = tmp_path / f"{control_type}-snapshot.json"
    outcome_path = tmp_path / f"{control_type}-outcome.json"
    snapshot_path.write_text(json.dumps({
        "snapshot": snapshot, "export_dir": str(tmp_path / "reports"),
        "run_id": control_type, "max_workers": 1,
    }), encoding="utf-8")
    monkeypatch.setattr(child, "probe_targets", lambda *args, **kwargs: [
        {"target": "silent.example.test", "port": 500, "status": "timeout", "ike_version": "",
         "exchange": "", "proposal": {}, "evidence": {}}
    ])

    previous_handler = signal.getsignal(signal.SIGTERM)
    try:
        assert child.main(["orion-child", str(snapshot_path), str(outcome_path)]) == 0
    finally:
        signal.signal(signal.SIGTERM, previous_handler)

    outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    files = {Path(path).suffix: Path(path).read_text(encoding="utf-8") for path in outcome["written_files"]}
    assert outcome["status"] == "completed"
    assert "No IKE response was observed" in files[".html"]
    assert "No IKE response was observed" in files[".md"]
    assert len(list(csv.reader(io.StringIO(files[".csv"])))) == 1

