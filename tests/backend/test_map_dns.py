from __future__ import annotations

from orion_app.services import map_dns


def test_map_ptr_enrichment_adds_names_only_for_literal_ip_nodes(monkeypatch) -> None:
    calls: list[str] = []

    def lookup(address: str) -> str | None:
        calls.append(address)
        return "edge.example.test"

    monkeypatch.setattr(map_dns, "_lookup_ptr", lookup)
    nodes = [
        {"kind": "host", "value": "192.0.2.10"},
        {"kind": "host", "value": "192.0.2.10"},
        {"kind": "host", "value": "host.example.test"},
        {"kind": "host", "value": "192.0.2.0/24"},
        {"kind": "device", "ip_address": "2001:db8::1"},
    ]

    result = map_dns.enrich_map_nodes(nodes)

    assert result is nodes
    assert calls == ["192.0.2.10", "2001:db8::1"]
    assert nodes[0]["dns_name"] == nodes[1]["dns_name"] == "edge.example.test"
    assert nodes[2].get("dns_name") is None
    assert nodes[3].get("dns_name") is None
    assert nodes[4]["dns_name"] == "edge.example.test"


def test_map_ptr_timeout_or_missing_record_keeps_ip_without_dns_label(monkeypatch) -> None:
    monkeypatch.setattr(map_dns, "_lookup_ptr", lambda _address: None)
    nodes = [{"kind": "host", "value": "192.0.2.11"}]

    map_dns.enrich_map_nodes(nodes)

    assert nodes == [{"kind": "host", "value": "192.0.2.11"}]
