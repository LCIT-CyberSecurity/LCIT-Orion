"""
Standard TLS cryptographic analysis and compliance grading.

Called by:
- `tls_scanner.scanner`, to evaluate each observed cipher suite;
- `tls_scanner.cli`, to apply endpoint grades after collection;
- TLS compliance and grading tests.

Produces:
- OK/KO compliance statuses with reasons;
- endpoint grades;
- certificate and cipher details extracted from Nmap script output.
"""

import re
from datetime import datetime

from .models import EncryptionPolicy

DEFAULT_TLS_POLICY = EncryptionPolicy(
    name="anssi_encryption_policy",
    version="1.0",
    description="ANSSI TLS encryption policy template.",
    allowed_versions=("TLSv1.2", "TLSv1.3"),
    allowed_cipher_algorithms=("AES-GCM", "AES-CCM", "CHACHA20-POLY1305"),
    allowed_signature_hashes=("SHA-256", "SHA-384", "SHA-512"),
    minimum_rsa_bits=2048,
)


def extract_public_key(certificate_output):
    key_type_match = re.search(
        r"Public Key type:\s*([^\s]+)",
        certificate_output,
        re.IGNORECASE,
    )
    key_bits_match = re.search(
        r"Public Key bits:\s*(\d+)",
        certificate_output,
        re.IGNORECASE,
    )

    if not key_type_match:
        return "Unknown", None

    key_type = key_type_match.group(1).upper()
    key_bits = int(key_bits_match.group(1)) if key_bits_match else None
    return key_type, key_bits


def extract_signature_algorithm(certificate_output):
    signature_match = re.search(
        r"Signature Algorithm:\s*([^\s]+)",
        certificate_output,
        re.IGNORECASE,
    )
    return signature_match.group(1) if signature_match else ""


def normalize_algorithm_name(value):
    return value.upper().replace("-", "_")


def normalize_signature_name(value):
    return value.upper().replace("-", "").replace("_", "")


def selected_policies(policies=None):
    return tuple(policies or (DEFAULT_TLS_POLICY,))


def cipher_matches_algorithm(cipher_suite, algorithm):
    normalized_cipher = normalize_algorithm_name(cipher_suite)
    normalized_algorithm = normalize_algorithm_name(algorithm)
    if normalized_algorithm == "AES_GCM":
        return "AES" in normalized_cipher and "GCM" in normalized_cipher
    if normalized_algorithm == "AES_CCM":
        return "AES" in normalized_cipher and "CCM" in normalized_cipher
    if normalized_algorithm == "CHACHA20_POLY1305":
        return "CHACHA20_POLY1305" in normalized_cipher
    return normalized_algorithm in normalized_cipher


def signature_matches_hash(signature_algorithm, allowed_hash):
    normalized_signature = normalize_signature_name(signature_algorithm)
    normalized_hash = normalize_signature_name(allowed_hash)
    return normalized_hash in normalized_signature

def cipher_suite_hashes(cipher_suite):
    hashes = []
    for token in normalize_algorithm_name(cipher_suite).split("_"):
        if token in {"MD5", "SHA", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}:
            hashes.append("SHA1" if token == "SHA" else token)
    return tuple(hashes)


def cipher_suite_hash_allowed(cipher_suite, policy):
    hashes = cipher_suite_hashes(cipher_suite)
    if not hashes:
        return True
    return all(
        any(normalize_signature_name(cipher_hash) == normalize_signature_name(allowed_hash)
            for allowed_hash in policy.allowed_signature_hashes)
        for cipher_hash in hashes
    )


def policy_allows_cipher_suite(tls_version, cipher_suite, policy):
    if tls_version not in policy.allowed_versions:
        return False, "TLS version"
    if not cipher_suite_hash_allowed(cipher_suite, policy):
        if any(cipher_hash in {"SHA1", "MD5"} for cipher_hash in cipher_suite_hashes(cipher_suite)):
            return False, "SHA-1"
        return False, "Signature hash"
    if not any(
        cipher_matches_algorithm(cipher_suite, algorithm)
        for algorithm in policy.allowed_cipher_algorithms
    ):
        return False, "Cipher suite"
    return True, ""


def policy_allows_signature(signature_algorithm, policy):
    if not signature_algorithm:
        return True
    return any(
        signature_matches_hash(signature_algorithm, allowed_hash)
        for allowed_hash in policy.allowed_signature_hashes
    )


def is_cipher_suite_compliant(tls_version, cipher_suite, policies=None):
    return all(
        policy_allows_cipher_suite(tls_version, cipher_suite, policy)[0]
        for policy in selected_policies(policies)
    )


def extract_cipher_suites(cipher_output):
    cipher_suites = []
    tls_version = "N/A"

    for line in cipher_output.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith("TLSv"):
            tls_version = stripped_line.split(":")[0]
        elif stripped_line.startswith("TLS_"):
            cipher_suites.append((tls_version, stripped_line.split()[0]))

    return cipher_suites


def check_compliance(
    tls_version,
    cipher_suite,
    cert_validity,
    certificate_output,
    public_key_type,
    public_key_bits,
    policies=None,
):
    compliance, _ = evaluate_compliance(
        tls_version,
        cipher_suite,
        cert_validity,
        certificate_output,
        public_key_type,
        public_key_bits,
        policies,
    )
    return compliance


# Return the first failing compliance reason; this keeps remediation messages actionable.
def evaluate_compliance(
    tls_version,
    cipher_suite,
    cert_validity,
    certificate_output,
    public_key_type,
    public_key_bits,
    policies=None,
):
    signature_algorithm = extract_signature_algorithm(certificate_output)
    policies = selected_policies(policies)

    for policy in policies:
        cipher_allowed, reason = policy_allows_cipher_suite(
            tls_version,
            cipher_suite,
            policy,
        )
        if not cipher_allowed:
            return "KO", reason
        if not policy_allows_signature(signature_algorithm, policy):
            return "KO", "Signature hash"
        if public_key_type == "RSA" and (
            public_key_bits is None or public_key_bits < policy.minimum_rsa_bits
        ):
            return "KO", "RSA key size"

    try:
        cert_expiry_date = datetime.strptime(cert_validity, "%Y-%m-%d")
    except ValueError:
        return "KO", "Certificate date"

    if cert_expiry_date < datetime.now():
        return "KO", "Certificate expired"

    return "OK", ""


# Grades describe negotiated TLS cryptography only. PKI trust, identity, expiry and
# revocation are separate dimensions applied by assess_endpoint_grade().
GRADE_ORDER = {"A+": 0, "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
GRADE_VERSION = "tls-grade-v2"


def grade_finding(finding):
    tls_version = finding.get("tls_version", "")
    cipher_suite = finding["cipher_suite"].upper()
    cipher_tokens = cipher_suite.split("_")
    public_key_type = finding["public_key_type"]
    public_key_bits = finding["public_key_bits"]

    if any(token in cipher_tokens for token in ["NULL", "EXPORT"]) or tls_version in {"SSLv2", "SSLv2.0"}:
        return "F"

    if tls_version not in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        return "NOT_EVALUATED"

    if public_key_type == "RSA" and public_key_bits is not None and public_key_bits < 2048:
        return "D"

    if "MD5" in cipher_tokens:
        return "D"

    if tls_version == "TLSv1.0" or any(token in cipher_tokens for token in ["DES", "3DES", "IDEA", "RC4"]):
        return "E"

    if tls_version == "TLSv1.1":
        return "D"

    # A certificate signature is PKI hygiene and must not be counted as a
    # negotiated cipher property. SHA-1 in a TLS CBC suite remains a crypto issue.
    if "SHA1" in cipher_tokens or cipher_suite.endswith("_SHA"):
        return "C"

    if tls_version == "TLSv1.2" and cipher_suite.startswith("TLS_RSA_"):
        return "B"

    if "_CBC_" in cipher_suite:
        return "A"

    return "A+"


def calculate_host_grade(findings):
    grades = [grade_finding(finding) for finding in findings]
    grades = [grade for grade in grades if grade in GRADE_ORDER]
    if not grades:
        return "NOT_EVALUATED"

    worst_grade = max(grades, key=GRADE_ORDER.get)
    has_tls_1_3 = any(
        finding["tls_version"] == "TLSv1.3" for finding in findings
    )
    if worst_grade == "A+" and not has_tls_1_3:
        return "A"
    return worst_grade


def assess_endpoint_grade(findings, identity_status="NOT_TESTED"):
    """Return display, crypto and PKI grades without conflating their meanings."""
    crypto_grade = calculate_host_grade(findings)
    issues = []
    for finding in findings:
        trust = finding.get("trust_classification")
        revoked = finding.get("revocation_status") == "REVOKED"
        try:
            expired = datetime.strptime(finding.get("cert_validity", ""), "%Y-%m-%d") < datetime.now()
        except (TypeError, ValueError):
            expired = False
        if revoked:
            issues.append("REVOKED")
        if trust == "ERROR":
            issues.append("ERROR")
        if expired:
            issues.append("EXPIRED")
        if trust == "UNTRUSTED":
            issues.append("UNTRUSTED")
    if identity_status == "FAIL":
        issues.append("NAME_MISMATCH")
    if issues:
        priority = ("REVOKED", "EXPIRED", "UNTRUSTED", "NAME_MISMATCH", "ERROR")
        pki_status = next((status for status in priority if status in issues), "INCONCLUSIVE")
    elif any(f.get("trust_classification") == "PUBLIC_TRUSTED" for f in findings):
        pki_status = "TRUSTED_PUBLIC"
    elif any(f.get("trust_classification") == "PRIVATE_TRUSTED" for f in findings):
        pki_status = "TRUSTED_PRIVATE"
    elif identity_status in {"ERROR", "INCONCLUSIVE"}:
        pki_status = "INCONCLUSIVE"
    else:
        pki_status = "NOT_TESTED"
    display_grade = "T" if any(status in issues for status in ("UNTRUSTED", "EXPIRED", "REVOKED")) else "M" if "NAME_MISMATCH" in issues else crypto_grade
    return {"crypto_grade": crypto_grade, "display_grade": display_grade, "pki_status": pki_status, "pki_issues": sorted(set(issues)), "grade_version": GRADE_VERSION}


def apply_endpoint_grades(results, findings, grade_assessments=None, tls_check_results=None):
    grade_assessments = grade_assessments if grade_assessments is not None else {}
    tls_check_results = tls_check_results or {}
    for endpoint, endpoint_findings in findings.items():
        endpoint_id = f"{endpoint[0]}:{endpoint[1]}/tcp"
        identity_status = next((item.status for item in tls_check_results.get(endpoint_id, ()) if item.check_id == "hostname_san"), "NOT_TESTED")
        grade_assessments[endpoint_id] = assess_endpoint_grade(endpoint_findings, identity_status)
    endpoint_grades = {endpoint: grade_assessments[f"{endpoint[0]}:{endpoint[1]}/tcp"]["display_grade"] for endpoint in findings}
    for row in results:
        # A grade belongs to one IP and port, not to the whole host.
        row.insert(3, endpoint_grades[(row[0], row[2])])
