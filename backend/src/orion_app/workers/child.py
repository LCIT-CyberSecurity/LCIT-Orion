"""Scan subprocess: runs the engine for one snapshot, with no database access.

Usage: python -m orion_app.workers.child <snapshot.json> <outcome.json>
Emits one JSON event per line on stdout. SIGTERM requests a cooperative cancellation: hosts not yet
started are skipped and the partial results are still written.
"""
from __future__ import annotations

import csv
import html
import io
import json
import signal
import sys
import threading
from pathlib import Path

from orion_app.services.ipsec import evaluate_policy, probe_targets
from orion_app.services.planner import job_from_snapshot
from orion_app.services.quic_scan import scan as scan_quic, write_csv as write_quic_report
from orion_app.services.service_identification import identify_services
from orion_app.services.service_identification import write_report as write_service_report
from orion_app.services.ssh_audit import audit_target, evaluate_ssh_policy, ssh_security_grade
from tls_scanner.runner import execute_scan


def emit(name: str, data: dict) -> None:
    print(json.dumps({"event": name, **data}), flush=True)


def scan_ssh(config: dict, cancel, emit):
    """Bounded unauthenticated ssh-audit probes. No credentials or rate tests are used."""
    settings, policies = config["settings"], config.get("policies", [])
    observations = []
    targets = config.get("targets", [])[:int(settings.get("max_targets", 256))]
    ports = settings.get("ports", [22])
    if settings.get("preset", "quick") == "quick":
        ports = ports[:1]
    total, done = len(targets) * len(ports), 0
    for target in targets:
        for port in ports:
            if cancel.is_set():
                break
            emit("phase", {"phase": "ssh_audit", "hosts": targets})
            observation = audit_target(target, int(port), int(settings.get("timeout_seconds", 2)))
            retries = int(settings.get("retries", 0))
            for _ in range(retries):
                if observation.get("status") not in {"timeout", "no_service"} or cancel.is_set():
                    break
                observation = audit_target(target, int(port), int(settings.get("timeout_seconds", 2)))
            done += 1
            if observation.get("status") == "no_service":
                # no SSH server answered: nothing to audit, so nothing is reported for this port
                emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
                continue
            verdicts = {p["name"]: evaluate_ssh_policy(observation, p["content"]) for p in policies}
            values = set(verdicts.values())
            observation.update({"target": target, "port": int(port), "verdict": (
                "non_compliant" if "non_compliant" in values else "compliant" if values == {"compliant"} else "indeterminate")})
            evidence = observation.setdefault("evidence", {})
            evidence["policy_verdicts"] = verdicts
            evidence["security_grade"] = ssh_security_grade(observation, policies)
            observations.append(observation)
            emit("host_done", {"target": target, "hosts_done": done, "hosts_total": total})
        if cancel.is_set():
            break
    return observations, targets


def write_ssh_reports(observations: list[dict], export_dir: Path, run_id: str, formats: list[str]):
    root = export_dir / run_id
    root.mkdir(parents=True, exist_ok=True)
    files = []
    fields = ("target", "port", "status", "security_grade", "banner", "protocol_versions", "key_exchange", "encryption", "mac", "host_key", "fingerprints")
    for fmt in formats:
        path = root / f"ssh-results.{fmt}"
        rows = [{"target": x["target"], "port": x["port"], "status": x["status"], "security_grade": (x.get("evidence") or {}).get("security_grade") or "—", "banner": x.get("banner", ""),
                 **{k: ", ".join((x.get("algorithms") or {}).get(src, [])) for k, src in (("protocol_versions", "protocol_versions"), ("key_exchange", "key_exchange"), ("encryption", "encryption"), ("mac", "mac"), ("host_key", "host_key"))},
                 "fingerprints": json.dumps(x.get("fingerprints") or {}, sort_keys=True)}
                for x in observations]
        if fmt == "csv":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(rows)
            path.write_text(stream.getvalue(), encoding="utf-8")
        elif fmt == "md":
            lines = ["# SSH audit results", "", "> Note is relative to the selected SSH policy and existing finding severity. Audit is unauthenticated; no password, key or rate-limit tests were performed.", "",
                     "| Target | Port | Status | Grade | Banner | Algorithms |", "|---|---:|---|---:|---|---|"]
            lines.extend(f"| {r['target']} | {r['port']} | {r['status']} | {r['security_grade']} | {r['banner']} | {', '.join(r['key_exchange'] + r['encryption'] + r['mac'] + r['host_key'])} |" for r in rows)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        elif fmt == "html":
            import html
            head = "".join(f"<th>{html.escape(k.replace('_', ' ').title())}</th>" for k in fields)
            body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(k, '')))}</td>" for k in fields) + "</tr>" for r in rows)
            path.write_text("<!doctype html><meta charset='utf-8'><title>SSH audit</title><h1>SSH audit results</h1><p>Grade is relative to the selected SSH policy and existing finding severity. Unauthenticated protocol audit; no credentials or rate tests were used.</p><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>", encoding="utf-8")
        else:
            continue
        files.append(str(path))
    return files


IPSEC_REPORT_FIELDS = (
    "target", "port", "status", "ike_version", "exchange", "verdict", "policy_verdicts",
    "encryption", "key_length_bits", "integrity", "prf", "dh_group",
)
IPSEC_REPORT_HEADERS = (
    "Target", "UDP port", "Response", "IKE", "Exchange", "Policy", "Encryption",
    "Key length", "Integrity", "PRF", "DH group",
)
IPSEC_REPORT_LIMITS = (
    "Unauthenticated IKE discovery only. Silence or a timeout does not prove that a VPN is absent. "
    "ESP/Child SA, authentication, PFS, and tunnel operation are not evaluated."
)


def write_ipsec_reports(observations: list[dict], export_dir: Path, run_id: str, formats: list[str]) -> list[str]:
    """Write responding IKE proposals while leaving silent probes in stored scan data only."""
    root = export_dir / run_id
    root.mkdir(parents=True, exist_ok=True)
    observed = [item for item in observations if item.get("status") == "observed"]
    targets = {str(item.get("target", "")) for item in observations if item.get("target")}
    files: list[str] = []

    def display_policies(item: dict) -> str:
        policies = item.get("evidence", {}).get("policy_verdicts", {})
        return ", ".join(f"{name}: {verdict}" for name, verdict in sorted(policies.items())) or "—"

    def proposal_value(item: dict, key: str) -> object:
        return (item.get("proposal") or {}).get(key, "")

    for fmt in formats:
        path = root / f"ipsec-results.{fmt}"
        if fmt == "csv":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=IPSEC_REPORT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for item in observed:
                writer.writerow({
                    "target": item.get("target", ""), "port": item.get("port", ""), "status": item.get("status", ""),
                    "ike_version": item.get("ike_version", ""), "exchange": item.get("exchange", ""),
                    "verdict": item.get("verdict", ""),
                    "policy_verdicts": json.dumps(item.get("evidence", {}).get("policy_verdicts", {}), sort_keys=True),
                    **(item.get("proposal") or {}),
                })
            path.write_text(stream.getvalue(), encoding="utf-8")
        elif fmt == "md":
            lines = [
                "# IPsec / IKE Security Assessment", "", f"> {IPSEC_REPORT_LIMITS}", "",
                "## Scan summary", "", f"- Targets probed: {len(targets)}", f"- IKE responses observed: {len(observed)}", "",
                "## Observed IKE proposals", "",
            ]
            if observed:
                lines.extend([
                    "| " + " | ".join(IPSEC_REPORT_HEADERS) + " |",
                    "|" + "|".join(["---"] * len(IPSEC_REPORT_HEADERS)) + "|",
                ])
                for item in observed:
                    values = (
                        item.get("target", ""), item.get("port", ""), "Observed", item.get("ike_version", ""),
                        item.get("exchange", ""), display_policies(item),
                        *(proposal_value(item, key) or "—" for key in ("encryption", "key_length_bits", "integrity", "prf", "dh_group")),
                    )
                    lines.append("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ") for value in values) + " |")
            else:
                lines.append("> **No IKE response was observed.** No responding IKE service or proposal can be reported. UDP silence and timeouts are inconclusive; they do not establish that no VPN is present.")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        elif fmt == "html":
            def cell(value: object) -> str:
                return html.escape(str(value)) if value not in (None, "") else "—"

            rows = []
            for item in observed:
                values = (
                    item.get("target", ""), item.get("port", ""), "Observed", item.get("ike_version", ""),
                    item.get("exchange", ""), display_policies(item),
                    *(proposal_value(item, key) for key in ("encryption", "key_length_bits", "integrity", "prf", "dh_group")),
                )
                rows.append("<tr>" + "".join(f"<td>{cell(value)}</td>" for value in values) + "</tr>")
            if observed:
                content = (
                    '<div class="table-wrap"><table><thead><tr>'
                    + "".join(f"<th>{html.escape(label)}</th>" for label in IPSEC_REPORT_HEADERS)
                    + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
                )
            else:
                content = (
                    '<div class="empty-state" role="status"><h2>No IKE response was observed</h2>'
                    '<p>No responding IKE service or proposal can be reported. UDP silence and timeouts are inconclusive; '
                    "they do not establish that no VPN is present.</p></div>"
                )
            document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>IPsec / IKE Security Assessment</title>
<style>
:root {{ color-scheme: light; font-family: Inter, system-ui, sans-serif; color: #17212f; background: #f3f6fa; }}
* {{ box-sizing: border-box; }} body {{ margin: 0; }} main {{ max-width: 1180px; margin: 0 auto; padding: 40px 24px 56px; }}
.masthead {{ border-bottom: 1px solid #dce3ed; padding-bottom: 22px; }} .brand {{ color: #53657a; font-size: .78rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }}
h1 {{ margin: 12px 0 8px; font-size: clamp(1.8rem, 4vw, 2.7rem); letter-spacing: -.035em; }} .lead {{ max-width: 780px; margin: 0; color: #53657a; line-height: 1.6; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin: 24px 0 32px; }}
.metric, .panel {{ background: #fff; border: 1px solid #dce3ed; border-radius: 12px; box-shadow: 0 3px 12px #24364a0b; }} .metric {{ padding: 17px 19px; }}
.metric span {{ display: block; color: #53657a; font-size: .82rem; }} .metric strong {{ display: block; margin-top: 5px; font-size: 1.65rem; }}
.panel {{ padding: clamp(18px, 3vw, 28px); }} h2 {{ margin: 0 0 16px; font-size: 1.25rem; }} .empty-state {{ border: 1px dashed #bac8d8; border-radius: 10px; padding: 24px; background: #f8fafc; }}
.empty-state h2 {{ margin-bottom: 8px; }} .empty-state p {{ max-width: 760px; margin: 0; color: #53657a; line-height: 1.6; }} .table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }} th, td {{ padding: 12px 11px; border-bottom: 1px solid #e6ebf1; text-align: left; vertical-align: top; }}
th {{ background: #f7f9fc; color: #43556b; font-size: .77rem; letter-spacing: .035em; }} tbody tr:last-child td {{ border-bottom: 0; }} footer {{ margin-top: 24px; color: #66788d; font-size: .8rem; }}
@media (max-width: 640px) {{ main {{ padding: 24px 14px 36px; }} .panel {{ padding: 16px; }} }}
@media print {{ :root {{ background: #fff; }} main {{ max-width: none; padding: 0; }} .metric, .panel {{ box-shadow: none; break-inside: avoid; }} body {{ print-color-adjust: exact; }} }}
</style></head><body><main>
<header class="masthead"><div class="brand">Orion · LCIT Cybersecurity</div><h1>IPsec / IKE Security Assessment</h1><p class="lead">{html.escape(IPSEC_REPORT_LIMITS)}</p></header>
<section class="summary" aria-label="Scan summary"><div class="metric"><span>Targets probed</span><strong>{len(targets)}</strong></div><div class="metric"><span>IKE responses observed</span><strong>{len(observed)}</strong></div></section>
<section class="panel"><h2>Observed IKE proposals</h2>{content}</section>
<footer>Discovery only. An observed IKE proposal does not demonstrate successful tunnel establishment or prove this is the complete proposal set.</footer>
</main></body></html>
"""
            path.write_text(document, encoding="utf-8")
        else:
            continue
        files.append(str(path))
    return files


def scan_ipsec(config: dict, targets: list[str], export_dir: Path, run_id: str, formats: list[str], cancel, emit):
    """Run bounded IKE probes and keep the observations separate from TLS grades."""
    ike = config["ike"]
    policies = config.get("policies", [])
    total = len(targets) * len(ike["versions"]) * len(ike["ports"])
    emit("phase", {"phase": "ipsec_probe", "hosts": targets})
    observations = probe_targets(
        targets, ike["versions"], ike["ports"], timeout_ms=ike.get("timeout_ms", 1000),
        retries=ike.get("retries", 0), nat_t=ike.get("nat_t", True),
        ikev1_transforms=ike.get("ikev1_transforms", []), max_parallelism=ike.get("max_parallelism", 4),
        cancel=cancel, on_complete=lambda target, done, _total: emit(
            "host_done", {"target": target, "hosts_done": done, "hosts_total": total}),
    )
    for observation in observations:
        verdicts = {p["name"]: evaluate_policy(observation, p["content"]) for p in policies}
        values = set(verdicts.values())
        observation["verdict"] = ("non_compliant" if "non_compliant" in values else
                                   "compliant" if values == {"compliant"} else "indeterminate")
        observation.setdefault("evidence", {})["policy_verdicts"] = verdicts

    written = write_ipsec_reports(observations, export_dir, run_id, formats)
    return observations, written


def main(argv: list[str]) -> int:
    snapshot_path, outcome_path = Path(argv[1]), Path(argv[2])
    payload = json.loads(snapshot_path.read_text())
    cancel = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: cancel.set())
    def scan_services(snapshot: dict, passes: list[dict], open_ports: dict[str, list[int]] | None = None,
                      scope_names_by_ip: dict[str, list[str]] | None = None):
        config = snapshot.get("service_identification")
        if not config or not config.get("enabled") or cancel.is_set():
            return [], []
        emit("phase", {"phase": "service_identification", "hosts": sorted({t for p in passes for t in p["targets"]})})
        observations, _metadata = identify_services(passes, config, open_ports=open_ports,
                                                     scope_names_by_ip=scope_names_by_ip, cancel=cancel)
        files = write_service_report(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        return observations, files
    def scan_quic_for_snapshot(snapshot: dict):
        config = snapshot.get("quic")
        if not config or not config.get("enabled") or cancel.is_set():
            return [], []
        emit("phase", {"phase": "quic_probe", "hosts": sorted({t for p in snapshot["passes"] for t in p["targets"]})})
        observations = scan_quic(config, snapshot["passes"], snapshot.get("tls_policies") or snapshot.get("policies") or [], cancel)
        files = write_quic_report(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        return observations, files
    if payload["snapshot"].get("control_type") == "ssh":
        snapshot = payload["snapshot"]
        observations, targets = scan_ssh(snapshot["ssh"], cancel, emit)
        written = write_ssh_reports(observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ssh_observations": len(observations), "service_observations": len(service_observations)}}, "ssh_observations": observations,
            "service_observations": service_observations,
            "written_files": [*written, *service_files], "scanned_hosts": targets, "skipped_hosts": [], "duration_seconds": 0}, default=str))
        return 0
    if payload["snapshot"].get("control_type") == "ipsec":
        snapshot = payload["snapshot"]
        targets = sorted({target for p in snapshot["passes"] for target in p["targets"]})
        observations, written = scan_ipsec(
            {"ike": snapshot["ike"], "policies": snapshot["policies"]}, targets,
            Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"], cancel, emit,
        )
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ipsec_observations": len(observations), "service_observations": len(service_observations)}}, "ipsec_observations": observations,
            "service_observations": service_observations,
            "written_files": [*written, *service_files], "scanned_hosts": targets, "skipped_hosts": [],
            "duration_seconds": 0}, default=str))
        return 0
    if "tls" not in payload["snapshot"].get("enabled_controls", []) and "ipsec" in payload["snapshot"].get("enabled_controls", []):
        snapshot = payload["snapshot"]
        ike_config = snapshot["ipsec"]
        ike_targets = ike_config.get("targets") or sorted({t for p in snapshot["passes"] for t in p["targets"]})
        ike_observations, ike_files = scan_ipsec(ike_config, ike_targets, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"], cancel, emit)
        ssh_observations, ssh_files, ssh_targets = [], [], []
        if snapshot.get("ssh") and "ssh" in snapshot["enabled_controls"] and not cancel.is_set():
            ssh_observations, ssh_targets = scan_ssh(snapshot["ssh"], cancel, emit)
            ssh_files = write_ssh_reports(ssh_observations, Path(payload["export_dir"]), payload["run_id"], snapshot["export_formats"])
        service_observations, service_files = scan_services(snapshot, snapshot["passes"])
        outcome_path.write_text(json.dumps({"status": "partial" if cancel.is_set() else "completed",
            "report_model": {"statistics": {"ipsec_observations": len(ike_observations), "ssh_observations": len(ssh_observations), "service_observations": len(service_observations)}},
            "ipsec_observations": ike_observations, "ssh_observations": ssh_observations,
            "service_observations": service_observations,
            "written_files": [*ike_files, *ssh_files, *service_files], "scanned_hosts": sorted(set(ike_targets + ssh_targets)),
            "skipped_hosts": [], "duration_seconds": 0}, default=str))
        return 0
    job, passes = job_from_snapshot(
        payload["snapshot"], payload["run_id"], payload["export_dir"], payload.get("log_file"), payload["max_workers"]
    )
    service_config = payload["snapshot"].get("service_identification") or {}
    outcome = execute_scan(job, cancel_event=cancel, on_event=emit, passes=passes,
                           collect_open_ports=bool(service_config.get("enabled")))
    service_observations, service_files = scan_services(payload["snapshot"], payload["snapshot"]["passes"],
                                                        open_ports=getattr(outcome, "open_ports", {}) if service_config.get("enabled") else None,
                                                        scope_names_by_ip=getattr(outcome, "scope_names_by_ip", {}))
    if service_observations:
        outcome.report_model["statistics"]["service_observations"] = len(service_observations)
        outcome.written_files.extend(service_files)
        outcome.service_observations = service_observations
    quic_observations, quic_files = scan_quic_for_snapshot(payload["snapshot"])
    if quic_observations:
        outcome.written_files.extend(quic_files)
        outcome.quic_observations = quic_observations
    ipsec_config = payload["snapshot"].get("ipsec")
    if ipsec_config and "ipsec" in payload["snapshot"].get("enabled_controls", []):
        targets = ipsec_config.get("targets") or sorted({target for item in payload["snapshot"]["passes"] for target in item["targets"]})
        observations, ipsec_files = scan_ipsec(ipsec_config, targets, Path(payload["export_dir"]), payload["run_id"],
                                               payload["snapshot"]["export_formats"], cancel, emit)
        outcome.report_model["statistics"]["ipsec_observations"] = len(observations)
        outcome.written_files.extend(ipsec_files)
        outcome.ipsec_observations = observations
    ssh_config = payload["snapshot"].get("ssh")
    if ssh_config and "ssh" in payload["snapshot"].get("enabled_controls", []) and not cancel.is_set():
        observations, _ = scan_ssh(ssh_config, cancel, emit)
        outcome.report_model["statistics"]["ssh_observations"] = len(observations)
        outcome.written_files.extend(write_ssh_reports(observations, Path(payload["export_dir"]), payload["run_id"],
                                                       payload["snapshot"]["export_formats"]))
        outcome.ssh_observations = observations
    mail_security_results = []
    mail_cfg = payload["snapshot"].get("mail_security") or {}
    if mail_cfg.get("enabled") and not cancel.is_set():
        emit("phase", {"phase": "mail_security", "hosts": mail_cfg.get("domains", [])})
        from orion_app.services.mail_security import inspect_domains
        mail_security_results = inspect_domains(mail_cfg.get("domains", []), mail_cfg, cancel)
    outcome_path.write_text(json.dumps({
        "status": outcome.status,
        "report_model": outcome.report_model,
        "written_files": outcome.written_files,
        "scanned_hosts": outcome.scanned_hosts,
        "skipped_hosts": outcome.skipped_hosts,
        "duration_seconds": outcome.duration_seconds,
        "mail_security_results": mail_security_results,
        "ipsec_observations": getattr(outcome, "ipsec_observations", []),
        "ssh_observations": getattr(outcome, "ssh_observations", []),
        "service_observations": getattr(outcome, "service_observations", service_observations),
        "quic_observations": getattr(outcome, "quic_observations", quic_observations),
    }, default=str))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as error:  # noqa: BLE001 - reported to the parent through stderr
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
