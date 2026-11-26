"""Bounded, transient PTR enrichment for network map nodes."""
from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait

import dns.exception
import dns.resolver

_MAX_ACTIVE = 8
_MAX_LOOKUPS_PER_GRAPH = 64
_WAIT_SECONDS = 0.35
_LOOKUP_SECONDS = 0.25
_executor = ThreadPoolExecutor(max_workers=_MAX_ACTIVE, thread_name_prefix="map-ptr")
_slots = threading.BoundedSemaphore(_MAX_ACTIVE)
_cache_lock = threading.Lock()
_positive_cache: dict[str, tuple[float, str]] = {}


def _lookup_ptr(address: str) -> str | None:
    now = time.monotonic()
    with _cache_lock:
        cached = _positive_cache.get(address)
        if cached and cached[0] > now:
            return cached[1]
    try:
        resolver = dns.resolver.Resolver(configure=True)
        answers = resolver.resolve_address(address, lifetime=_LOOKUP_SECONDS, search=False)
        name = answers[0].to_text().rstrip(".")
        if not name or len(name) > 253:
            return None
        with _cache_lock:
            if len(_positive_cache) >= 512:
                _positive_cache.pop(next(iter(_positive_cache)))
            _positive_cache[address] = (now + 300, name)
        return name
    except (dns.exception.DNSException, OSError, ValueError):
        return None


def _release_slot(_future: Future[str | None]) -> None:
    _slots.release()


def enrich_map_nodes(nodes: list[dict]) -> list[dict]:
    """Add a current PTR name to IP nodes without unbounded map latency."""
    addresses: dict[str, list[dict]] = {}
    for node in nodes:
        candidate = node.get("value") if node.get("kind") == "host" else (
            node.get("ip_address") if node.get("kind") == "device" else None
        )
        if not isinstance(candidate, str):
            continue
        try:
            address = str(ipaddress.ip_address(candidate.strip()))
        except ValueError:
            continue
        addresses.setdefault(address, []).append(node)

    futures: dict[str, Future[str | None]] = {}
    for address in list(addresses)[:_MAX_LOOKUPS_PER_GRAPH]:
        if not _slots.acquire(blocking=False):
            break
        future = _executor.submit(_lookup_ptr, address)
        future.add_done_callback(_release_slot)
        futures[address] = future
    if futures:
        done, _ = wait(futures.values(), timeout=_WAIT_SECONDS)
        for address, future in futures.items():
            if future not in done:
                continue
            try:
                name = future.result()
            except Exception:  # Resolver worker errors must not break map rendering.
                name = None
            if name:
                for node in addresses[address]:
                    node["dns_name"] = name
    return nodes
