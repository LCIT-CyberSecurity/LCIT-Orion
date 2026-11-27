"""Adapters from the bounded probe protocol to Orion's local scan engines."""

from __future__ import annotations

import importlib.util
import shutil
import threading
from typing import Any


class ProbeEngineExecutor:
    """Execute only installed Orion engines against the probe's pinned addresses."""

    def __call__(self, task: dict[str, Any], cancel: threading.Event) -> dict[str, Any]:
        kind = task["kind"]
        if kind == "tls":
            return self._tls(task, cancel)
        if kind == "ssh":
            return self._ssh(task, cancel)
        if kind == "ipsec":
            return self._ipsec(task, cancel)
        raise ValueError(
            "this probe installation does not support the requested engine"
        )

    @staticmethod
    def available_capabilities() -> list[str]:
        capabilities = []
        if shutil.which("nmap") and importlib.util.find_spec("nmap"):
            capabilities.append("tls")
        if shutil.which("ssh-audit"):
            capabilities.append("ssh")
        if shutil.which("ike-scan"):
            capabilities.append("ipsec")
        return capabilities

    def _tls(self, task: dict[str, Any], cancel: threading.Event) -> dict[str, Any]:
        import nmap

        from tls_scanner.models import ScanJob
        from tls_scanner.scanner import collect_scan_results

        destinations = [
            (address, name)
            for name, addresses in task["resolved_targets"].items()
            for address in addresses
        ]
        work = len(destinations) * len(task["ports"])
        if not 1 <= work <= 32:
            raise ValueError("TLS task exceeds the probe work limit")

        observations = []
        timeout = min(task["timeout_seconds"], 30)
        for address, name in destinations:
            for port in task["ports"]:
                if cancel.is_set():
                    return {"observations": observations, "cancelled": True}
                args = (
                    "-sV --version-light --script ssl-cert,ssl-enum-ciphers "
                    f"--host-timeout {timeout}s --script-timeout {timeout}s "
                    "--max-retries 1"
                )
                if name != address:
                    # `name` passed the protocol's strict hostname parser.
                    args += f" --script-args tls.servername={name}"
                scanner = nmap.PortScanner()
                scanner.scan(hosts=address, ports=str(port), arguments=args)
                rows: list[list[Any]] = []
                findings: dict[str, Any] = {}
                job = ScanJob(
                    targets=address,
                    ports=str(port),
                    crypto="standard",
                    ip=True,
                    log_file=None,
                    workers=1,
                )
                collect_scan_results(
                    scanner,
                    job,
                    rows,
                    findings,
                    {address: name} if name != address else {},
                )
                observations.append(
                    {
                        "target": name,
                        "resolved_target": address,
                        "port": port,
                        "status": "observed" if rows else "indeterminate",
                        "rows": rows,
                        "findings": findings,
                    }
                )
        return {"observations": observations, "cancelled": cancel.is_set()}

    @staticmethod
    def _pinned_targets(task: dict[str, Any]) -> list[str]:
        resolved = task.get("resolved_targets")
        if not isinstance(resolved, dict):
            raise TypeError("task has no validated pinned destinations")
        targets = []
        for name in task["targets"]:
            addresses = resolved.get(name)
            if not isinstance(addresses, (list, tuple)) or not addresses:
                raise TypeError("task has no validated pinned destinations")
            targets.extend(addresses)
        return list(dict.fromkeys(targets))

    def _ssh(self, task: dict[str, Any], cancel: threading.Event) -> dict[str, Any]:
        if not shutil.which("ssh-audit"):
            raise RuntimeError("ssh-audit is not installed")
        from orion_app.services.ssh_audit import audit_target

        targets = self._pinned_targets(task)
        if len(targets) * len(task["ports"]) > 32:
            raise ValueError("SSH task exceeds the probe work limit")
        observations = []
        for target in targets:
            for port in task["ports"]:
                if cancel.is_set():
                    return {"observations": observations, "cancelled": True}
                observation = audit_target(
                    target, port, timeout_seconds=min(task["timeout_seconds"], 5)
                )
                observations.append(observation)
        return {"observations": observations, "cancelled": cancel.is_set()}

    def _ipsec(self, task: dict[str, Any], cancel: threading.Event) -> dict[str, Any]:
        if not shutil.which("ike-scan"):
            raise RuntimeError("ike-scan is not installed")
        if cancel.is_set():
            return {"observations": [], "cancelled": True}
        from orion_app.services.ipsec import probe_targets

        targets = self._pinned_targets(task)
        if len(targets) * len(task["ports"]) * 2 > 256:
            raise ValueError("IPsec task exceeds the probe work limit")
        observations = probe_targets(
            targets,
            ["IKEv1", "IKEv2"],
            task["ports"],
            timeout_ms=min(task["timeout_seconds"] * 1000, 5000),
            retries=0,
            max_parallelism=min(task["workers"], 8),
            cancel=cancel,
        )
        return {"observations": observations, "cancelled": cancel.is_set()}
