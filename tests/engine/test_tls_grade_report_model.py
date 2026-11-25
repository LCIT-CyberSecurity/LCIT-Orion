from tls_scanner.checks.contracts import CheckResult
from tls_scanner.exports.report_model import build_report_model
from tls_scanner.models import ScanJob


def report_row(grade="M", trust="PUBLIC_TRUSTED"):
    return [
        "203.0.113.10", "service.example", 443, grade, "TLSv1.3", "TLS_AES_128_GCM_SHA256",
        "RSA 2048 bits", "2099-01-01", "RSA 2048", "no", 26000, "Example CA", "CN=service.example",
        "service.example", "RSA", 2048, "sha256WithRSAEncryption", trust, "Example trust store",
        "Example Root", "Passed", "Not Tested", "Not Tested", "Not Tested", "OK", "",
    ]


def test_report_model_keeps_display_crypto_and_pki_axes_and_fails_mismatch_closed():
    endpoint_id = "203.0.113.10:443/tcp"
    job = ScanJob(targets="service.example", ports="443", crypto="standard", ip=False)
    job.grade_assessments[endpoint_id] = {
        "display_grade": "M", "crypto_grade": "A+", "pki_status": "NAME_MISMATCH",
        "pki_issues": ["NAME_MISMATCH"], "grade_version": "tls-grade-v2",
    }
    job.tls_check_results[endpoint_id] = (
        CheckResult("hostname_san", "FAIL", evidence=("service.example does not match SAN wrong.example",)),
    )

    report = build_report_model([report_row()], job, "2026-11-24T00:00:00Z")

    endpoint = report.endpoints[0]
    assert (endpoint.overall_grade, endpoint.crypto_grade, endpoint.pki_status) == ("M", "A+", "NAME_MISMATCH")
    assert endpoint.grade_version == "tls-grade-v2"
    assert endpoint.compliance_status == "non_compliant"
    assert "CERTIFICATE_NAME_MISMATCH" in endpoint.finding_ids
    assert report.statistics.grade_distribution["M"] == 1


def test_simultaneous_trust_and_name_failures_remain_visible_in_report():
    endpoint_id = "203.0.113.10:443/tcp"
    job = ScanJob(targets="service.example", ports="443", crypto="standard", ip=False)
    job.grade_assessments[endpoint_id] = {
        "display_grade": "T", "crypto_grade": "A+", "pki_status": "UNTRUSTED",
        "pki_issues": ["NAME_MISMATCH", "UNTRUSTED"], "grade_version": "tls-grade-v2",
    }
    job.tls_check_results[endpoint_id] = (
        CheckResult("hostname_san", "FAIL", evidence=("service.example does not match SAN wrong.example",)),
    )

    report = build_report_model([report_row("T", "UNTRUSTED")], job, "2026-11-24T00:00:00Z")

    endpoint = report.endpoints[0]
    assert endpoint.overall_grade == "T"
    assert endpoint.crypto_grade == "A+"
    assert endpoint.pki_issues == ("NAME_MISMATCH", "UNTRUSTED")
    assert {"CERTIFICATE_CHAIN_UNTRUSTED", "CERTIFICATE_NAME_MISMATCH"}.issubset(endpoint.finding_ids)
