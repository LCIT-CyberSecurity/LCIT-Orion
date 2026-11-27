"""Remote probe inventory, TLS identity and role boundaries."""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

from conftest import Api
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _certificate() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe-fixture")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("192.0.2.10"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    der = certificate.public_bytes(serialization.Encoding.DER)
    return pem, hashlib.sha256(der).hexdigest()


def test_probe_registry_requires_admin_and_does_not_expose_credentials(
    admin: Api, operator: Api, auditor: Api
) -> None:
    suffix = uuid.uuid4().hex[:8]
    zone = operator.post(
        "/api/map/zones",
        json={
            "name": f"probe-zone-{suffix}",
            "zone_type": "dmz",
            "cidr": "192.0.2.0/24",
        },
    )
    assert zone.status_code == 201, zone.text
    certificate, fingerprint = _certificate()
    body = {
        "name": f"probe-{suffix}",
        "address": "192.0.2.10",
        "api_port": 9443,
        "network_zone_id": zone.json()["id"],
        "certificate_sha256": fingerprint,
        "certificate_pem": certificate,
    }
    assert operator.post("/api/remote-probes", json=body).status_code == 403
    mismatch = admin.post(
        "/api/remote-probes", json={**body, "certificate_sha256": "0" * 64}
    )
    assert mismatch.status_code == 422, mismatch.text
    invalid_address = admin.post(
        "/api/remote-probes", json={**body, "address": "probe.example.test"}
    )
    assert invalid_address.status_code == 422, invalid_address.text

    created = admin.post("/api/remote-probes", json=body)
    assert created.status_code == 201, created.text
    probe = created.json()
    assert probe["status"] == "pairing"
    assert probe["certificate_sha256"] == fingerprint
    assert "certificate_pem" not in probe and "encrypted_token" not in probe
    assert any(
        item["id"] == probe["id"] for item in auditor.get("/api/remote-probes").json()
    )
    assert operator.post(f"/api/remote-probes/{probe['id']}/health").status_code == 409
    assert operator.post(f"/api/remote-probes/{probe['id']}/revoke").status_code == 403
    revoked = admin.post(f"/api/remote-probes/{probe['id']}/revoke")
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
