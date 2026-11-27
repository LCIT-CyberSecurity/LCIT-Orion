from __future__ import annotations

import socket
import ssl
import sys
import threading
import types
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from remote_probe.agent import ProbeAgent
from remote_probe.engines import ProbeEngineExecutor


def test_ssh_engine_scans_only_validated_pinned_addresses(monkeypatch):
    seen = []
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/ssh-audit")

    def audit(target, port, timeout_seconds):
        seen.append((target, port, timeout_seconds))
        return {"target": target, "port": port, "status": "observed"}

    monkeypatch.setattr("orion_app.services.ssh_audit.audit_target", audit)
    task = {
        "kind": "ssh",
        "targets": ["service.example"],
        "resolved_targets": {"service.example": ("192.0.2.10",)},
        "ports": [22, 2222],
        "timeout_seconds": 20,
    }

    result = ProbeEngineExecutor()(task, threading.Event())

    assert seen == [("192.0.2.10", 22, 5), ("192.0.2.10", 2222, 5)]
    assert [item["target"] for item in result["observations"]] == [
        "192.0.2.10",
        "192.0.2.10",
    ]


def test_ssh_engine_stops_before_next_target_when_cancelled(monkeypatch):
    calls = []
    cancel = threading.Event()
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/ssh-audit")

    def audit(target, port, timeout_seconds):
        calls.append((target, port))
        cancel.set()
        return {"target": target, "port": port, "status": "observed"}

    monkeypatch.setattr("orion_app.services.ssh_audit.audit_target", audit)
    task = {
        "kind": "ssh",
        "targets": ["192.0.2.10", "192.0.2.11"],
        "resolved_targets": {
            "192.0.2.10": ("192.0.2.10",),
            "192.0.2.11": ("192.0.2.11",),
        },
        "ports": [22],
        "timeout_seconds": 5,
    }

    result = ProbeEngineExecutor()(task, cancel)

    assert calls == [("192.0.2.10", 22)]
    assert result["cancelled"] is True


def test_ipsec_engine_uses_orion_engine_with_bounded_parameters(monkeypatch):
    calls = []
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/ike-scan")

    def probe_targets(targets, versions, ports, **kwargs):
        calls.append((targets, versions, ports, kwargs))
        return [{"target": targets[0], "status": "timeout"}]

    monkeypatch.setattr("orion_app.services.ipsec.probe_targets", probe_targets)
    task = {
        "kind": "ipsec",
        "targets": ["router.example"],
        "resolved_targets": {"router.example": ("192.0.2.20",)},
        "ports": [500, 4500],
        "timeout_seconds": 30,
        "workers": 16,
    }

    result = ProbeEngineExecutor()(task, threading.Event())

    targets, versions, ports, kwargs = calls[0]
    assert targets == ["192.0.2.20"]
    assert versions == ["IKEv1", "IKEv2"]
    assert ports == [500, 4500]
    assert kwargs["timeout_ms"] == 5000
    assert kwargs["retries"] == 0
    assert kwargs["max_parallelism"] == 8
    assert result["observations"][0]["status"] == "timeout"


def test_tls_engine_pins_destination_sets_sni_and_keeps_silent_unknown(monkeypatch):
    calls = []

    class PortScanner:
        def scan(self, *, hosts, ports, arguments):
            calls.append((hosts, ports, arguments))

    monkeypatch.setitem(
        sys.modules, "nmap", types.SimpleNamespace(PortScanner=PortScanner)
    )

    def collect(_scanner, _job, rows, _findings, _fqdn_cache):
        # The scanner has no open-port/script evidence in this test.
        return None

    monkeypatch.setattr("tls_scanner.scanner.collect_scan_results", collect)
    task = {
        "kind": "tls",
        "targets": ["service.example"],
        "resolved_targets": {"service.example": ("192.0.2.30",)},
        "ports": [443],
        "timeout_seconds": 7,
    }

    result = ProbeEngineExecutor()(task, threading.Event())

    assert calls[0][0:2] == ("192.0.2.30", "443")
    assert "tls.servername=service.example" in calls[0][2]
    assert "--host-timeout 7s" in calls[0][2]
    assert result["observations"][0]["resolved_target"] == "192.0.2.30"
    assert result["observations"][0]["status"] == "indeterminate"


def test_tls_engine_observes_only_its_loopback_test_service(tmp_path):
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("service.example")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    certificate_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate_path), str(key_path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stop = threading.Event()
    port = listener.getsockname()[1]

    def serve_loopback():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with context.wrap_socket(connection, server_side=True) as stream:
                    stream.settimeout(0.2)
                    try:
                        stream.recv(1024)
                    except (TimeoutError, OSError):
                        pass
            except (ssl.SSLError, OSError):
                connection.close()

    server_thread = threading.Thread(target=serve_loopback, daemon=True)
    server_thread.start()
    task = {
        "kind": "tls",
        "targets": ["service.example"],
        "resolved_targets": {"service.example": ("127.0.0.1",)},
        "ports": [port],
        "timeout_seconds": 20,
    }
    try:
        result = ProbeEngineExecutor()(task, threading.Event())
    finally:
        stop.set()
        listener.close()
        server_thread.join(timeout=2)

    observation = result["observations"][0]
    assert observation["resolved_target"] == "127.0.0.1"
    assert observation["status"] == "observed"
    assert observation["rows"]


def test_executor_does_not_offer_unimplemented_engines(monkeypatch):
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/usr/bin/ssh-audit" if name == "ssh-audit" else None,
    )

    assert ProbeEngineExecutor.available_capabilities() == ["ssh"]


def test_probe_agent_selects_local_engines_and_rejects_unavailable_capabilities(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/usr/bin/ssh-audit" if name == "ssh-audit" else None,
    )
    agent = ProbeAgent(
        tmp_path / "state",
        ProbeAgent.token_digest("probe-test-token-with-sufficient-entropy"),
        ["192.0.2.0/24"],
    )
    try:
        assert agent.capabilities == ("ssh",)
        try:
            agent.submit(
                {
                    "task_id": "1c263d90-0b4b-4f2a-838b-60fe12557d91",
                    "kind": "tls",
                    "targets": ["192.0.2.10"],
                    "ports": [443],
                }
            )
        except ValueError as error:
            assert "does not advertise" in str(error)
        else:
            raise AssertionError("unavailable scan engine was accepted")
    finally:
        agent.close()
