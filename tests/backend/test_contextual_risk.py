from __future__ import annotations

import ipaddress
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from orion_app.api.catalog import ExposureBody, _validate_exposure
from orion_app.models import Role
from orion_app.services.contextual_risk import (
    MATRIX_VERSION,
    append_html,
    append_markdown,
    assess,
    exposure_for_endpoint,
    report_rows,
)


def test_unknown_or_unvalidated_exposure_is_not_weighted() -> None:
    public_ip_hint_only = {"state": "internet_confirmed", "validated": False, "source": "public IP"}
    result = assess("high", public_ip_hint_only)
    assert result["assessed"] is False
    assert result["contextual_severity"] is None
    assert result["exposure_state"] == "unknown"


def test_same_intrinsic_finding_gets_different_contextual_risk_without_changing_grade() -> None:
    intrinsic = "high"
    internet = assess(intrinsic, {"state": "internet_confirmed", "validated": True, "source": "external check"})
    isolated = assess(intrinsic, {"state": "not_internet_confirmed", "validated": True, "zone_context": "segmented"})
    assert internet["contextual_severity"] == "critical"
    assert isolated["contextual_severity"] == "medium"
    assert internet["intrinsic_severity"] == isolated["intrinsic_severity"] == intrinsic
    assert internet["matrix_version"] == isolated["matrix_version"] == MATRIX_VERSION


def test_risk_boundaries_and_non_severity_findings_are_stable() -> None:
    external = {"state": "internet_confirmed", "validated": True}
    internal = {"state": "not_internet_confirmed", "validated": True}
    assert assess("low", external)["contextual_severity"] == "medium"
    assert assess("critical", external)["contextual_severity"] == "critical"
    assert assess("low", internal)["contextual_severity"] == "low"
    assert assess("critical", internal)["contextual_severity"] == "high"
    assert assess("informational", external)["assessed"] is False


def test_report_rows_snapshot_per_endpoint_and_never_infer_exposure() -> None:
    model = {"endpoints": [{"endpoint_id": "203.0.113.4:443/tcp", "hostname": "service.example", "ip_address": "203.0.113.4", "port": 443, "overall_grade": "D"}],
             "findings": [{"finding_id": "CERTIFICATE_CHAIN_UNTRUSTED", "title": "Untrusted", "severity": "high", "affected_endpoint_ids": ["203.0.113.4:443/tcp"]}]}
    rows = report_rows(model, {"exposure_snapshot": []})
    assert rows[0]["contextual_severity"] == "not_evaluated"
    assert rows[0]["exposure"] == "unknown"
    assert rows[0]["intrinsic_severity"] == "high"
    assert model["endpoints"][0]["overall_grade"] == "D"


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_globally_routable_endpoint_ip_gets_assumed_untrust_context(address: str) -> None:
    assert ipaddress.ip_address(address).is_global
    endpoint = {"hostname": "service.example", "ip_address": address, "port": 443}
    exposure = exposure_for_endpoint(endpoint, {"exposure_snapshot": []})
    assert exposure["state"] == "internet_assumed_public_ip"
    assert exposure["classification"] == "UNTRUST"
    assert exposure["validated"] is False
    risk = assess("high", exposure)
    assert risk["assessed"] is True
    assert risk["contextual_severity"] == "critical"
    assert risk["exposure_state"] == "UNTRUST"
    assert "reachability is not verified" in risk["reason"]


@pytest.mark.parametrize("address", ["192.168.1.7", "10.0.0.1", "127.0.0.1", "203.0.113.4", "not-an-ip"])
def test_non_global_or_unparseable_endpoint_ip_remains_unknown(address: str) -> None:
    endpoint = {"hostname": "service.example", "ip_address": address, "port": 443}
    assert exposure_for_endpoint(endpoint, {"exposure_snapshot": []}) is None


def test_validated_non_internet_exposure_overrides_public_ip_default() -> None:
    endpoint = {"hostname": "service.example", "ip_address": "8.8.8.8", "port": 443}
    evidence = {"protocol": "tls", "port": 443, "target_value": "service.example", "sni": "",
                "state": "not_internet_confirmed", "validated": True, "source": "firewall review"}
    exposure = exposure_for_endpoint(endpoint, {"exposure_snapshot": [evidence]})
    assert exposure is evidence
    assert assess("high", exposure)["contextual_severity"] == "medium"


def test_only_admin_can_validate_and_confirmed_evidence_needs_provenance() -> None:
    body = ExposureBody(protocol="tls", port=443, state="internet_confirmed", validated=True,
                        evidence_method="external_probe", source="approved external monitor", justification="TCP/TLS handshake completed")
    operator = SimpleNamespace(id="operator-id", role=Role.OPERATOR)
    admin = SimpleNamespace(id="admin-id", role=Role.ADMIN)
    with pytest.raises(HTTPException, match="Only an administrator"):
        _validate_exposure(body, operator)
    saved = _validate_exposure(body, admin)
    assert saved["validated"] is True and saved["validated_by"] == "admin-id"
    with pytest.raises(HTTPException, match="method, source and justification"):
        _validate_exposure(ExposureBody(protocol="tls", port=443, state="not_internet_confirmed"), admin)


def test_report_formats_escape_html_and_preserve_markdown_table(tmp_path) -> None:
    rows = [{"endpoint": "host.example:443", "finding": "<script>alert(1)</script>", "intrinsic_severity": "high",
             "contextual_severity": "critical", "exposure": "internet_confirmed", "source": "monitor",
             "method": "probe", "justification": "line 1 | line 2", "confidence": "high"}]
    html_path = tmp_path / "report.html"
    html_path.write_text("<html><body><h1>Report</h1></body></html>", encoding="utf-8")
    append_html(html_path, rows)
    html = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html
    assert "<script>" not in html
    assert html.index("Contextual exposure risk") < html.index("</body>")

    markdown_path = tmp_path / "report.md"
    markdown_path.write_text("# Report\n", encoding="utf-8")
    append_markdown(markdown_path, rows)
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "line 1 \\| line 2" in markdown
    assert f"`{MATRIX_VERSION}`" in markdown
