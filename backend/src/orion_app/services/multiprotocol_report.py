"""Add protocol sections to the primary scan report without mixing observation types."""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value not in (None, "") else "—"), quote=True)


def _table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> str:
    head = "".join(f"<th scope=\"col\">{_esc(label)}</th>" for label in headers)
    body = "".join("<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in row) + "</tr>" for row in rows)
    if not rows:
        body = f"<tr><td colspan=\"{len(headers)}\">No responding observation was recorded. Silence or timeout does not prove that a service is absent.</td></tr>"
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _section(section_id: str, title: str, summary: str, content: str) -> str:
    return (f'<section class="panel report-chapter" id="{_esc(section_id)}"><div class="section-heading">'
            f'<div><p class="eyebrow">Control results</p><h2>{_esc(title)}</h2>'
            f'<p class="section-subtitle">{_esc(summary)}</p></div></div>{content}</section>')


def _result_state(observations: list[dict], status: str, *, response_status: str | None = "observed") -> str:
    if status in {"partial", "cancelled", "canceled"}:
        return "Partial; scan stopped before configured coverage was complete."
    if observations and (response_status is None or any(item.get("status") == response_status for item in observations)):
        return "Results observed."
    if observations:
        return "Probes completed; no response was observed. Results are inconclusive."
    return "No result was recorded for this control."


def _ipsec_section(snapshot: dict, observations: list[dict], status: str) -> str:
    config = snapshot.get("ipsec") or {}
    ike = config.get("ike") or {}
    targets = config.get("targets") or []
    ports = ike.get("ports") or []
    versions = ike.get("versions") or []
    observed = [item for item in observations if item.get("status") == "observed"]
    counts: dict[str, int] = {}
    for item in observations:
        key = str(item.get("status") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    coverage = (f"{_result_state(observations, status)} {len(observations)} probe(s) recorded across {len(targets)} target(s); "
                f"UDP {', '.join(map(str, ports)) or 'not recorded'}; IKE {', '.join(map(str, versions)) or 'not recorded'}. "
                f"State: {status}. " + ", ".join(f"{key}: {value}" for key, value in sorted(counts.items())))
    rows = []
    for item in observed:
        proposal = item.get("proposal") or {}
        policies = (item.get("evidence") or {}).get("policy_verdicts") or {}
        rows.append((item.get("target"), item.get("port"), item.get("ike_version"), item.get("exchange"),
                     item.get("verdict"), proposal.get("encryption"), proposal.get("key_length_bits"),
                     proposal.get("integrity"), proposal.get("prf"), proposal.get("dh_group"),
                     ", ".join(f"{name}: {value}" for name, value in sorted(policies.items())) or "—"))
    content = ('<p>Unauthenticated IKE discovery only. ESP/Child SA, authentication, PFS, and tunnel operation are not evaluated. '
               'An observed proposal is not an exhaustive proposal list.</p>' +
               _table(("Target", "UDP", "IKE", "Exchange", "Policy", "Encryption", "Key bits", "Integrity", "PRF", "DH group", "Policy checks"), rows))
    if not observed:
        content = '<p role="status" class="empty-state">No IKE response was observed. UDP silence and timeouts are inconclusive and do not establish that no VPN is present.</p>' + content
    return _section("control-ipsec", "IPsec / IKE", coverage, content)


def _ssh_section(snapshot: dict, observations: list[dict], status: str) -> str:
    config = snapshot.get("ssh") or {}
    settings = config.get("settings") or {}
    targets = config.get("targets") or []
    max_targets = int(settings.get("max_targets", 256))
    selected_targets = targets[:max_targets]
    ports = settings.get("ports") or [22]
    if settings.get("preset", "quick") == "quick":
        ports = ports[:1]
    observations = observations or []
    cap_note = f"Target cap: {max_targets}. " if len(targets) > max_targets else ""
    coverage = (f"{_result_state(observations, status)} {len(selected_targets)} target(s) selected; TCP {', '.join(map(str, ports))}; "
                f"{len(observations)} SSH handshake observation(s) stored. State: {status}. {cap_note}"
                "The audit is unauthenticated; it does not test credentials or prove service absence.")
    rows = []
    for item in observations:
        algorithms = item.get("algorithms") or {}
        evidence = item.get("evidence") or {}
        rows.append((item.get("target"), item.get("port"), item.get("status"), evidence.get("security_grade"),
                     item.get("banner"), "; ".join(f"{key}: {', '.join(values)}" for key, values in sorted(algorithms.items()) if values)))
    content = _table(("Target", "TCP", "Probe", "Grade", "Banner", "Observed algorithms"), rows)
    if not observations:
        content = '<p role="status" class="empty-state">No SSH handshake observation was recorded within this scan’s configured coverage. This does not prove that SSH is absent outside that coverage.</p>' + content
    return _section("control-ssh", "SSH audit", coverage, content)


def _mail_section(config: dict, results: list[dict], status: str) -> str:
    domains = config.get("domains") or []
    checks = []
    smtp = []
    for domain in results:
        for item in domain.get("checks") or []:
            checks.append((domain.get("domain"), item.get("check"), item.get("status"), item.get("message"), "; ".join(item.get("records") or [])))
        for item in domain.get("smtp_starttls") or []:
            smtp.append((domain.get("domain"), item.get("host"), item.get("port"), item.get("status"), item.get("message"), ", ".join(item.get("tls_versions") or [])))
    summary = (f"{_result_state(results, status, response_status=None)} {len(domains)} configured domain(s); "
               f"{len(checks) + len(smtp)} observation(s); DNS and mail checks are limited to the configured domains and checks.")
    content = _table(("Domain", "Check", "Status", "Observation", "Evidence"), checks)
    if smtp:
        content += '<h3>SMTP STARTTLS observations</h3>' + _table(("Domain", "Host", "Port", "Probe", "Observation", "TLS versions"), smtp)
    if not checks and not smtp:
        content = '<p role="status" class="empty-state">No mail security result was recorded for the configured domains.</p>' + content
    return _section("control-mail", "DNS and mail security", summary, content)


def _service_section(observations: list[dict], enabled: bool, status: str) -> str | None:
    if not enabled:
        return None
    rows = [(item.get("target"), item.get("port"), item.get("service"), item.get("product"), item.get("version"), item.get("status"), item.get("confidence"))
            for item in observations]
    content = '<p>Bounded service identification. No service is inferred from a silent or filtered probe.</p>' + _table(("Target", "TCP", "Service", "Product", "Version", "Status", "Confidence"), rows)
    if not observations:
        content = '<p role="status" class="empty-state">No service identification observation was recorded.</p>' + content
    return _section("control-services", "Service identification",
                    f"{_result_state(observations, status, response_status=None)} {len(observations)} observation(s) stored.", content)


def _quic_section(observations: list[dict], config: dict | None, status: str) -> str | None:
    if not config:
        return None
    rows = [(item.get("target"), item.get("port"), item.get("status"), item.get("quic_version"), item.get("tls_version"), item.get("alpn"), item.get("cipher_suite"))
            for item in observations]
    content = _table(("Target", "UDP", "Probe", "QUIC", "TLS", "ALPN", "Cipher"), rows)
    if not observations:
        content = '<p role="status" class="empty-state">No QUIC handshake observation was recorded. UDP silence is inconclusive.</p>' + content
    return _section("control-quic", "QUIC / HTTP/3",
                    f"{_result_state(observations, status)} UDP {', '.join(map(str, config.get('ports') or []))}.", content)


def _navigation(links: list[tuple[str, str]]) -> str:
    return "".join(f'<a href="#{_esc(anchor)}">{_esc(label)}</a>' for anchor, label in links)


def _md_table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> str:
    def cell(value: Any) -> str:
        return html.escape(str(value if value not in (None, "") else "—"), quote=False).replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _markdown_sections(snapshot: dict, outcome: dict, status: str) -> str:
    controls = set(snapshot.get("enabled_controls") or [snapshot.get("control_type", "tls")])
    parts: list[str] = []
    if "ipsec" in controls:
        config = snapshot.get("ipsec") or {}
        ike = config.get("ike") or {}
        observations = outcome.get("ipsec_observations") or []
        observed = [item for item in observations if item.get("status") == "observed"]
        parts += ["## IPsec / IKE", "", f"{_result_state(observations, status)} {len(observations)} probes recorded across {len(config.get('targets') or [])} targets; UDP ports {ike.get('ports') or 'not recorded'}; scan state: {status}.", "",
                  "Unauthenticated IKE discovery only. Silence and timeouts do not establish that no VPN is present. ESP/Child SA, authentication, PFS, and tunnel operation are not evaluated.", ""]
        rows = [(item.get("target"), item.get("port"), item.get("status"), item.get("ike_version"), item.get("exchange"), item.get("verdict"), (item.get("proposal") or {}).get("encryption"), (item.get("proposal") or {}).get("integrity"), (item.get("proposal") or {}).get("dh_group")) for item in observed]
        parts += (["No IKE response was observed; the probes are inconclusive.", ""] if not rows else [])
        parts += [_md_table(("Target", "UDP", "Probe", "IKE", "Exchange", "Policy", "Encryption", "Integrity", "DH group"), rows), ""]
    if "ssh" in controls:
        config = snapshot.get("ssh") or {}
        settings = config.get("settings") or {}
        observations = outcome.get("ssh_observations") or []
        targets = config.get("targets") or []
        cap = int(settings.get("max_targets", 256))
        ports = settings.get("ports") or [22]
        if settings.get("preset", "quick") == "quick":
            ports = ports[:1]
        coverage = f"Selected targets: {min(len(targets), cap)} / {len(targets)}; TCP ports {ports}; {len(observations)} handshake observation(s); status: {status}."
        if len(targets) > cap:
            coverage += f" The configured target cap is {cap}; coverage is partial."
        no_observations = " No SSH handshake observation was recorded." if not observations else ""
        parts += ["## SSH", "", f"{_result_state(observations, status)} {coverage}{no_observations}",
                  "SSH probing is unauthenticated and bounded by the configured target cap and timeout. No observation does not prove SSH is absent.", "",
                  _md_table(("Target", "TCP", "Probe", "Grade", "Banner"), [(item.get("target"), item.get("port"), item.get("status"), (item.get("evidence") or {}).get("security_grade"), item.get("banner")) for item in observations]), ""]
    mail = snapshot.get("mail_security") or {}
    if mail.get("enabled"):
        results = outcome.get("mail_security_results") or []
        rows = [(domain.get("domain"), item.get("check"), item.get("status"), item.get("message"), "; ".join(item.get("records") or [])) for domain in results for item in domain.get("checks") or []]
        parts += ["## DNS and mail security", "", f"{_result_state(results, status, response_status=None)} Configured domains: {', '.join(mail.get('domains') or []) or 'none'}; scan state: {status}.", "",
                  _md_table(("Domain", "Check", "Status", "Observation", "Evidence"), rows), ""]
    services = snapshot.get("service_identification") or {}
    if services.get("enabled"):
        observations = outcome.get("service_observations") or []
        parts += ["## Service identification", "", f"{_result_state(observations, status, response_status=None)} {len(observations)} observation(s) recorded; scan state: {status}.", "",
                  _md_table(("Target", "TCP", "Service", "Product", "Version", "Status"), [(item.get("target"), item.get("port"), item.get("service"), item.get("product"), item.get("version"), item.get("status")) for item in observations]), ""]
    quic_config = snapshot.get("quic")
    if quic_config:
        observations = outcome.get("quic_observations") or []
        parts += ["## QUIC / HTTP/3", "", f"{_result_state(observations, status)} UDP ports: {quic_config.get('ports') or 'not recorded'}; scan state: {status}.", "",
                  _md_table(("Target", "UDP", "Probe", "QUIC", "TLS", "ALPN", "Cipher"), [(item.get("target"), item.get("port"), item.get("status"), item.get("quic_version"), item.get("tls_version"), item.get("alpn"), item.get("cipher_suite")) for item in observations]), ""]
    return "\n".join(parts).rstrip()


def _inject_html(path: Path, links: list[tuple[str, str]], sections: str) -> None:
    text = path.read_text(encoding="utf-8")
    if "</nav>" in text:
        text = text.replace("</nav>", _navigation(links) + "</nav>", 1)
    if "</main>" not in text:
        raise ValueError(f"Cannot append multiprotocol sections to {path.name}: report main element is missing")
    path.write_text(text.replace("</main>", sections + "</main>", 1), encoding="utf-8")


def _generic_html(title: str, links: list[tuple[str, str]], sections: str) -> str:
    nav = _navigation(links)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="referrer" content="no-referrer"><title>{_esc(title)}</title><style>'
            ':root{font-family:system-ui,sans-serif;color:#17212f;background:#f3f6fa}*{box-sizing:border-box}body{margin:0}header,main{max-width:1180px;margin:auto;padding:24px}header{background:#fff;border-bottom:1px solid #dce3ed}nav{display:flex;gap:10px;flex-wrap:wrap}nav a{padding:8px 12px;border:1px solid #dce3ed;border-radius:8px;color:#334; text-decoration:none}.panel{margin:18px 0;padding:22px;background:#fff;border:1px solid #dce3ed;border-radius:12px}.section-heading{margin-bottom:16px}.section-subtitle{color:#53657a;line-height:1.5}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:9px;border-bottom:1px solid #e6ebf1}th{background:#f7f9fc}.empty-state{padding:14px;background:#f8fafc;border:1px dashed #bac8d8;border-radius:8px}'
            '</style></head><body><header><p>Orion · LCIT Cybersecurity</p><h1>Multiprotocol security report</h1><nav aria-label="Control navigation">'
            f'{nav}</nav></header><main>{sections}</main></body></html>')


def build_sections(snapshot: dict, outcome: dict) -> tuple[list[tuple[str, str]], str, str]:
    controls = set(snapshot.get("enabled_controls") or [snapshot.get("control_type", "tls")])
    status = outcome.get("status", "unknown")
    sections: list[str] = []
    links: list[tuple[str, str]] = []
    if "tls" in controls:
        links.append(("endpoints", "TLS / PKI"))
    if "ipsec" in controls:
        links.append(("control-ipsec", "IPsec / IKE"))
        sections.append(_ipsec_section(snapshot, outcome.get("ipsec_observations") or [], status))
    if "ssh" in controls:
        links.append(("control-ssh", "SSH"))
        sections.append(_ssh_section(snapshot, outcome.get("ssh_observations") or [], status))
    mail_config = snapshot.get("mail_security") or {}
    if mail_config.get("enabled"):
        links.append(("control-mail", "DNS / Mail"))
        sections.append(_mail_section(mail_config, outcome.get("mail_security_results") or [], status))
    service_config = snapshot.get("service_identification") or {}
    service = _service_section(outcome.get("service_observations") or [], bool(service_config.get("enabled")), status)
    if service:
        links.append(("control-services", "Services"))
        sections.append(service)
    quic = _quic_section(outcome.get("quic_observations") or [], snapshot.get("quic"), status)
    if quic:
        links.append(("control-quic", "QUIC"))
        sections.append(quic)
    markdown = _markdown_sections(snapshot, outcome, status)
    return links, "".join(sections), markdown


def finalize_multiprotocol_reports(snapshot: dict, outcome: dict, export_dir: Path, run_id: str) -> list[str]:
    controls = set(snapshot.get("enabled_controls") or [snapshot.get("control_type", "tls")])
    mail_enabled = bool((snapshot.get("mail_security") or {}).get("enabled"))
    service_enabled = bool((snapshot.get("service_identification") or {}).get("enabled"))
    quic_enabled = bool(snapshot.get("quic"))
    if len(controls) < 2 and not mail_enabled and not service_enabled and not quic_enabled:
        return []
    links, sections, markdown_sections = build_sections(snapshot, outcome)
    formats = set(snapshot.get("export_formats") or [])
    files = list(outcome.get("written_files") or [])
    html_path = next((Path(item) for item in files if Path(item).suffix == ".html" and not Path(item).name.startswith(("ipsec-results.", "ssh-results."))), None)
    md_path = next((Path(item) for item in files if Path(item).suffix == ".md" and not Path(item).name.startswith(("ipsec-results.", "ssh-results."))), None)
    if "html" in formats:
        if html_path:
            _inject_html(html_path, links, sections)
        else:
            html_path = export_dir / run_id / "multiprotocol-report.html"
            html_path.parent.mkdir(parents=True, exist_ok=True)
            html_path.write_text(_generic_html((snapshot.get("definition") or {}).get("name", "Scan"), links, sections), encoding="utf-8")
            files.append(str(html_path))
    if "md" in formats:
        if md_path:
            md_path.write_text(md_path.read_text(encoding="utf-8").rstrip() + "\n\n" + markdown_sections + "\n", encoding="utf-8")
        else:
            md_path = export_dir / run_id / "multiprotocol-report.md"
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text("# Multiprotocol security report\n\n" + markdown_sections + "\n", encoding="utf-8")
            files.append(str(md_path))
    return files[len(outcome.get("written_files") or []):]
