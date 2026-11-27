"""Typed task validation shared by the remote probe API and its executor."""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from collections.abc import Callable, Iterable
from typing import Any

HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$"
)
ALLOWED_KINDS = {"tls", "ssh", "ipsec", "dns"}
MAX_TARGETS = 256
MAX_PORTS = 64
MAX_TIMEOUT_SECONDS = 30
MAX_WORKERS = 16
MAX_TASK_BYTES = 128 * 1024


class TaskValidationError(ValueError):
    """A task is outside the supported, bounded protocol."""


def _bounded_int(value: Any, *, minimum: int, maximum: int, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise TaskValidationError(f"{name} must be between {minimum} and {maximum}")
    return value


def validate_task(task: Any) -> dict[str, Any]:
    """Validate and normalize a task; no shell text or arbitrary executable options are accepted."""
    if not isinstance(task, dict):
        raise TaskValidationError("task must be an object")
    if len(str(task).encode("utf-8")) > MAX_TASK_BYTES:
        raise TaskValidationError("task is too large")
    try:
        task_id = str(uuid.UUID(str(task.get("task_id", ""))))
    except (ValueError, AttributeError):
        raise TaskValidationError("task_id must be a UUID") from None
    kind = task.get("kind")
    if kind not in ALLOWED_KINDS:
        raise TaskValidationError("unsupported task kind")
    targets = task.get("targets")
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        raise TaskValidationError(
            f"targets must contain between 1 and {MAX_TARGETS} entries"
        )
    normalized_targets = []
    for target in targets:
        if not isinstance(target, str) or target != target.strip() or not target:
            raise TaskValidationError("each target must be a non-empty string")
        try:
            normalized_targets.append(str(ipaddress.ip_address(target)))
        except ValueError:
            if not HOSTNAME.fullmatch(target) or target.startswith("-"):
                raise TaskValidationError(
                    "target must be an IP address or DNS name"
                ) from None
            normalized_targets.append(target.rstrip(".").lower())
    default_ports = {"tls": [443], "ssh": [22], "ipsec": [500, 4500], "dns": []}
    ports = task.get("ports", default_ports[kind])
    if not isinstance(ports, list) or len(ports) > MAX_PORTS:
        raise TaskValidationError(f"ports must contain at most {MAX_PORTS} entries")
    normalized_ports = sorted(
        {_bounded_int(p, minimum=1, maximum=65535, name="port") for p in ports}
    )
    if kind in {"tls", "ssh"} and not normalized_ports:
        raise TaskValidationError(f"{kind} tasks require at least one TCP port")
    if kind == "ipsec" and set(normalized_ports) - {500, 4500}:
        raise TaskValidationError("IPsec tasks support only UDP ports 500 and 4500")
    if kind == "dns" and normalized_ports:
        raise TaskValidationError("DNS tasks do not accept port overrides")
    timeout = _bounded_int(
        task.get("timeout_seconds", 5),
        minimum=1,
        maximum=MAX_TIMEOUT_SECONDS,
        name="timeout_seconds",
    )
    workers = _bounded_int(
        task.get("workers", 4), minimum=1, maximum=MAX_WORKERS, name="workers"
    )
    # Only versioned, JSON policy data is accepted. Command fragments and unknown task fields are discarded.
    policy = task.get("policy", {})
    if not isinstance(policy, dict) or len(str(policy).encode("utf-8")) > 32 * 1024:
        raise TaskValidationError("policy must be a bounded object")
    scope_networks = task.get("scope_networks", [])
    if not isinstance(scope_networks, list) or len(scope_networks) > 64:
        raise TaskValidationError("scope_networks must contain at most 64 CIDRs")
    try:
        scope_networks = sorted(
            {str(ipaddress.ip_network(value, strict=False)) for value in scope_networks}
        )
    except (ValueError, TypeError):
        raise TaskValidationError("scope_networks must contain valid CIDRs") from None
    return {
        "task_id": task_id,
        "kind": kind,
        "targets": normalized_targets,
        "ports": normalized_ports,
        "timeout_seconds": timeout,
        "workers": workers,
        "policy": policy,
        "scope_networks": scope_networks,
    }


def resolve_targets_in_scope(
    targets: Iterable[str],
    allowed_networks: Iterable[str],
    *,
    resolver: Callable[[str], list[str]] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Resolve targets and fail closed unless every address is inside an assigned CIDR.

    The returned addresses must be passed as pinned scan destinations; resolving the hostname
    again at connect time would reintroduce DNS rebinding. Callers retain the hostname separately
    for TLS SNI and certificate identity validation.
    """
    networks = tuple(
        ipaddress.ip_network(value, strict=False) for value in allowed_networks
    )
    if not networks:
        raise TaskValidationError("probe has no assigned target scope")
    resolve = resolver or _resolve
    result: dict[str, tuple[str, ...]] = {}
    for target in targets:
        try:
            address = ipaddress.ip_address(target)
            addresses = [str(address)]
        except ValueError:
            if not HOSTNAME.fullmatch(target):
                raise TaskValidationError("invalid DNS target") from None
            try:
                addresses = resolve(target)
            except OSError:
                raise TaskValidationError("target DNS resolution failed") from None
            if not addresses:
                raise TaskValidationError("target DNS resolution returned no addresses")
        normalized = tuple(
            sorted({str(ipaddress.ip_address(value)) for value in addresses})
        )
        if any(
            not any(ipaddress.ip_address(value) in network for network in networks)
            for value in normalized
        ):
            raise TaskValidationError(
                "target resolves outside the assigned probe scope"
            )
        result[target] = normalized
    return result


def restrict_scope(requested: Iterable[str], allowed: Iterable[str]) -> tuple[str, ...]:
    """Ensure every centrally declared target CIDR is contained in local probe policy."""
    local_networks = tuple(
        ipaddress.ip_network(value, strict=False) for value in allowed
    )
    requested_networks = tuple(
        ipaddress.ip_network(value, strict=False) for value in requested
    )
    if not local_networks or not requested_networks:
        raise TaskValidationError("both local and central target scope are required")
    for network in requested_networks:
        if not any(
            network.version == permitted.version and network.subnet_of(permitted)
            for permitted in local_networks
        ):
            raise TaskValidationError(
                "central task scope exceeds the probe's local scope"
            )
    return tuple(str(network) for network in requested_networks)


def _resolve(hostname: str) -> list[str]:
    return sorted(
        {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    )
