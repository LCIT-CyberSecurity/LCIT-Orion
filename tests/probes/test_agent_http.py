from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from remote_probe.agent import ProbeAgent
from remote_probe.client import ProbeClient
from remote_probe.http_api import create_https_server


def _certificate(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe-test")])
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
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_https_api_authenticates_tasks_and_acknowledges_results(tmp_path):
    token = "probe-test-token-with-sufficient-entropy"
    agent = ProbeAgent(
        tmp_path / "state",
        ProbeAgent.token_digest(token),
        ["127.0.0.0/8"],
        lambda task, _cancel: {"target": task["targets"][0], "status": "observed"},
    )
    certificate, key = _certificate(tmp_path)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = create_https_server("127.0.0.1", port, str(certificate), str(key), agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"https://127.0.0.1:{server.server_port}"
        with httpx.Client(verify=False, timeout=2) as client:
            assert client.get(f"{base_url}/v1/health").status_code == 401
            headers = {"Authorization": f"Bearer {token}"}
            task = {
                "task_id": str(uuid.uuid4()),
                "kind": "tls",
                "targets": ["127.0.0.1"],
                "ports": [443],
            }
            response = client.post(f"{base_url}/v1/tasks", headers=headers, json=task)
            assert response.status_code == 202
            deadline = time.monotonic() + 2
            while (
                agent.get(task["task_id"])["status"] in {"queued", "running"}
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            assert agent.get(task["task_id"])["status"] == "completed"
            events = client.get(
                f"{base_url}/v1/results?after=0", headers=headers
            ).json()["events"]
            assert len(events) == 1 and events[0]["payload"]["status"] == "completed"
            ack = client.post(
                f"{base_url}/v1/results/ack",
                headers=headers,
                json={"cursor": events[0]["cursor"]},
            )
            assert ack.status_code == 200
            assert (
                client.get(f"{base_url}/v1/results?after=0", headers=headers).json()[
                    "events"
                ]
                == []
            )
    finally:
        server.shutdown()
        server.server_close()
        agent.close()


def test_task_submission_is_idempotent_and_rejects_reused_id(tmp_path):
    token = "probe-test-token-with-sufficient-entropy"
    agent = ProbeAgent(
        tmp_path / "state",
        ProbeAgent.token_digest(token),
        ["127.0.0.0/8"],
        lambda _task, _cancel: {},
    )
    task_id = str(uuid.uuid4())
    task = {"task_id": task_id, "kind": "tls", "targets": ["127.0.0.1"], "ports": [443]}
    try:
        first = agent.submit(task)
        duplicate = agent.submit(task)
        assert first["task_id"] == duplicate["task_id"]
        try:
            agent.submit({**task, "ports": [8443]})
        except ValueError as error:
            assert "different task" in str(error)
        else:
            raise AssertionError("reused task ID was accepted with a different payload")
    finally:
        agent.close()


def test_pairing_code_is_single_use_and_credential_survives_restart(tmp_path):
    pairing_code = "high-entropy-pairing-code-for-test"
    agent = ProbeAgent(
        tmp_path / "state",
        "",
        ["127.0.0.0/8"],
        lambda _task, _cancel: {},
        pairing_code_hash=ProbeAgent.token_digest(pairing_code),
        pairing_expires_at=int(time.time()) + 120,
    )
    certificate, key = _certificate(tmp_path)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = create_https_server("127.0.0.1", port, str(certificate), str(key), agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(verify=False, timeout=2) as client:
            response = client.post(
                f"https://127.0.0.1:{port}/v1/pair", json={"pairing_code": pairing_code}
            )
            assert response.status_code == 200
            token = response.json()["token"]
            assert agent.authenticate(token)
            duplicate = client.post(
                f"https://127.0.0.1:{port}/v1/pair", json={"pairing_code": pairing_code}
            )
            assert duplicate.status_code == 401
    finally:
        server.shutdown()
        server.server_close()
        agent.close()
    restored = ProbeAgent(
        tmp_path / "state", "", ["127.0.0.0/8"], lambda _task, _cancel: {}
    )
    try:
        assert restored.authenticate(token)
        assert not restored.authenticate(pairing_code)
    finally:
        restored.close()


def test_central_client_pins_certificate_and_initiates_requests(tmp_path):
    token = "probe-test-token-with-sufficient-entropy"
    agent = ProbeAgent(
        tmp_path / "state",
        ProbeAgent.token_digest(token),
        ["127.0.0.0/8"],
        lambda _task, _cancel: {},
    )
    certificate, key = _certificate(tmp_path)
    certificate_pem = certificate.read_text(encoding="ascii")
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate_pem)).hexdigest()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = create_https_server("127.0.0.1", port, str(certificate), str(key), agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = ProbeClient("127.0.0.1", port, certificate_pem, fingerprint, token)
    try:
        assert client.health()["status"] == "ok"
        with pytest.raises(ValueError, match="fingerprint"):
            ProbeClient("127.0.0.1", port, certificate_pem, "0" * 64, token)
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        agent.close()
