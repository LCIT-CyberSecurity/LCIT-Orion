from tls_scanner.crypto_policy import assess_endpoint_grade, calculate_host_grade, grade_finding


def finding(version="TLSv1.3", suite="TLS_AES_128_GCM_SHA256", **overrides):
    value = {
        "tls_version": version,
        "cipher_suite": suite,
        "public_key_type": "RSA",
        "public_key_bits": 2048,
        "cert_validity": "2099-01-01",
        "trust_classification": "PUBLIC_TRUSTED",
        "revocation_status": "Not Tested",
    }
    value.update(overrides)
    return value


def test_modern_tls_and_rsa_2048_are_not_penalized_for_certificate_signature():
    item = finding(certificate_output="Signature Algorithm: sha1WithRSAEncryption")
    assert grade_finding(item) == "A+"
    assert assess_endpoint_grade([item])["display_grade"] == "A+"


def test_untrusted_certificate_keeps_crypto_grade_and_displays_trust_grade():
    result = assess_endpoint_grade([finding(trust_classification="UNTRUSTED")])
    assert result["crypto_grade"] == "A+"
    assert result["display_grade"] == "T"
    assert result["pki_status"] == "UNTRUSTED"


def test_trusted_private_certificate_does_not_receive_trust_grade():
    result = assess_endpoint_grade([finding(trust_classification="PRIVATE_TRUSTED")])
    assert result["display_grade"] == "A+"
    assert result["pki_status"] == "TRUSTED_PRIVATE"


def test_name_mismatch_requires_an_effective_failed_identity_check():
    item = finding()
    assert assess_endpoint_grade([item])["display_grade"] == "A+"
    result = assess_endpoint_grade([item], identity_status="FAIL")
    assert result["display_grade"] == "M"
    assert result["pki_issues"] == ["NAME_MISMATCH"]


def test_trust_failure_has_display_priority_but_retains_both_pki_issues():
    result = assess_endpoint_grade([finding(trust_classification="UNTRUSTED")], identity_status="FAIL")
    assert result["display_grade"] == "T"
    assert result["pki_issues"] == ["NAME_MISMATCH", "UNTRUSTED"]


def test_unknown_and_silent_results_are_not_fabricated_as_f():
    assert grade_finding(finding(version="unknown")) == "NOT_EVALUATED"
    assert calculate_host_grade([]) == "NOT_EVALUATED"


def test_grade_ladder_has_distinct_e_and_f_evidence():
    assert grade_finding(finding("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")) == "C"
    assert grade_finding(finding("TLSv1.1", "TLS_RSA_WITH_AES_128_GCM_SHA256")) == "D"
    assert grade_finding(finding("TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA")) == "E"
    assert grade_finding(finding("TLSv1.2", "TLS_RSA_WITH_NULL_SHA")) == "F"


def test_certificate_expiry_is_a_pki_issue_not_a_crypto_grade():
    item = finding(cert_validity="2000-01-01")
    result = assess_endpoint_grade([item])
    assert result["crypto_grade"] == "A+"
    assert result["display_grade"] == "T"
    assert result["pki_status"] == "EXPIRED"
