from types import SimpleNamespace
from pathlib import Path

from orion_app.services.multiprotocol_report import build_sections, finalize_multiprotocol_reports
from orion_app.services.runs import _format_of


def test_combined_sections_keep_ipsec_ssh_and_mail_evidence_separate_and_truthful(tmp_path):
    snapshot = {
        "control_type": "multi",
        "enabled_controls": ["ipsec", "ssh"],
        "ipsec": {"targets": ["192.0.2.1"], "ike": {"ports": [500, 4500], "versions": ["IKEv2"]}},
        "ssh": {"targets": ["192.0.2.1", "192.0.2.2", "192.0.2.3"], "settings": {"max_targets": 2, "ports": [22, 2222], "preset": "quick"}},
        "mail_security": {"enabled": True, "domains": ["example.test"]},
        "export_formats": ["html", "md"],
    }
    outcome = {
        "status": "completed",
        "ipsec_observations": [{"target": "192.0.2.1", "port": 500, "status": "timeout"}],
        "ssh_observations": [],
        "mail_security_results": [],
    }

    links, sections, markdown = build_sections(snapshot, outcome)

    assert [(anchor, label) for anchor, label in links] == [
        ("control-ipsec", "IPsec / IKE"), ("control-ssh", "SSH"), ("control-mail", "DNS / Mail")
    ]
    assert "No IKE response was observed" in sections
    assert "do not establish that no VPN is present" in sections
    assert "2 target(s) selected" in sections
    assert "Selected targets: 2 / 3" in markdown
    assert "TCP 22" in sections
    assert "No SSH handshake observation was recorded" in sections
    assert "No mail security result was recorded" in sections
    assert "No IKE response was observed" in markdown
    assert "No SSH handshake observation" in markdown
    assert "<script>" not in sections


def test_tls_primary_report_is_augmented_without_creating_a_second_html_report(tmp_path):
    main_report = tmp_path / "tls-report.html"
    main_report.write_text('<html><header><nav aria-label="Report sections"></nav><div class="header-actions"></div></header><main><section id="endpoints"></section></main></html>', encoding="utf-8")
    snapshot = {"enabled_controls": ["tls", "ssh"], "export_formats": ["html"], "ssh": {"targets": ["192.0.2.1"], "settings": {"max_targets": 1, "ports": [22]}}}
    outcome = {"status": "completed", "written_files": [str(main_report)], "ssh_observations": []}

    created = finalize_multiprotocol_reports(snapshot, outcome, tmp_path, "run-1")

    updated = main_report.read_text(encoding="utf-8")
    assert created == []
    assert updated.count("control-ssh") >= 2
    assert "href=\"#endpoints\"" in updated
    assert "No SSH handshake observation was recorded" in updated
    assert list(tmp_path.glob("*.html")) == [main_report]


def test_non_tls_multi_scan_creates_a_single_primary_report_in_the_export_directory(tmp_path):
    snapshot = {"control_type": "multi", "enabled_controls": ["ipsec", "ssh"], "ipsec": {"targets": [], "ike": {}}, "ssh": {"targets": [], "settings": {}}, "export_formats": ["html"]}
    outcome = {"status": "partial", "written_files": [], "ipsec_observations": [], "ssh_observations": []}

    created = finalize_multiprotocol_reports(snapshot, outcome, tmp_path, "run-2")

    report = tmp_path / "run-2" / "multiprotocol-report.html"
    assert created == [str(report)]
    assert report.is_file()
    html = report.read_text(encoding="utf-8")
    assert "IPsec / IKE" in html
    assert "SSH audit" in html
    assert "No IKE response was observed" in html


def test_observed_protocol_results_have_distinct_evidence_and_partial_coverage():
    snapshot = {
        "enabled_controls": ["ipsec", "ssh"],
        "ipsec": {"targets": ["192.0.2.10"], "ike": {"ports": [500], "versions": ["IKEv2"]}},
        "ssh": {"targets": ["192.0.2.10", "192.0.2.11"], "settings": {"max_targets": 1, "ports": [22, 2222], "preset": "deep"}},
    }
    outcome = {
        "status": "partial",
        "ipsec_observations": [{"target": "192.0.2.10", "port": 500, "status": "observed", "ike_version": "IKEv2",
                                "proposal": {"encryption": "AES_GCM_16", "dh_group": "MODP_2048"}, "verdict": "compliant"}],
        "ssh_observations": [{"target": "192.0.2.10", "port": 2222, "status": "observed", "banner": "SSH-2.0-test",
                              "algorithms": {"encryption": ["aes256-ctr"]}, "evidence": {"security_grade": "B"}}],
    }

    links, sections, markdown = build_sections(snapshot, outcome)

    assert [anchor for anchor, _ in links] == ["control-ipsec", "control-ssh"]
    assert sections.count("Partial; scan stopped before configured coverage was complete.") == 2
    assert "AES_GCM_16" in sections and "SSH-2.0-test" in sections
    assert "Grade" in sections and "B" in sections
    assert "ESP/Child SA" in sections
    assert "Selected targets: 1 / 2" in markdown
    assert "TCP ports [22, 2222]" in markdown


def test_html_navigation_stays_inside_report_navigation_and_escapes_observation_data(tmp_path):
    main_report = tmp_path / "tls-report.html"
    main_report.write_text('<html><header><nav aria-label="Report sections"><a href="#endpoints">Endpoints</a></nav><div class="header-actions"></div></header><main></main></html>', encoding="utf-8")
    snapshot = {"enabled_controls": ["tls", "ssh"], "export_formats": ["html"], "ssh": {"targets": ["192.0.2.1"], "settings": {"max_targets": 1, "ports": [22]}}}
    outcome = {"status": "completed", "written_files": [str(main_report)], "ssh_observations": [
        {"target": "192.0.2.1", "port": 22, "status": "observed", "banner": "<script>alert(1)</script>", "algorithms": {}, "evidence": {}}]}

    finalize_multiprotocol_reports(snapshot, outcome, tmp_path, "run-3")

    updated = main_report.read_text(encoding="utf-8")
    assert '<a href="#control-ssh">SSH</a></nav>' in updated
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in updated
    assert "<script>alert(1)</script>" not in updated


def test_ipsec_detail_export_keeps_its_schema_in_a_non_tls_multiprotocol_run():
    run = SimpleNamespace(control_type="multi", config_snapshot={"enabled_controls": ["ipsec", "ssh"]})

    assert _format_of(Path("ipsec-results.html"), run) == "ipsec_html"
