# Endpoint exposure and contextual risk architecture

## Data and flow

`endpoint_exposures` stores evidence per target, protocol, port and optional SNI. State defaults to `unknown`; proposals have `validated=false`. `POST/PUT /api/targets/{id}/exposures` requires OPERATOR and the validation flag requires ADMIN. Read access follows the existing AUDITOR role. Changes are audit logged; the evidence table is separate from SI, network zones and scan policies.

At scan planning, `planner.exposure_snapshot` copies the matching target evidence into the immutable run config snapshot. Unvalidated proposals are represented as effective `unknown`, with their proposed state retained separately. At result persistence, the observed endpoint IP is evaluated locally; a globally routable address without a validated endpoint-specific override receives the `UNTRUST` assumption. The resulting snapshot is stored on `RunEndpoint`. `RunFinding.contextual_risk_by_endpoint` stores a per-endpoint calculation. Existing `RunEndpoint.grade`, compliance status and `RunFinding.severity` stay unchanged.

## Matrix `exposure-risk-v2`

| Exposure evidence | Contextual severity |
|---|---|
| Unknown, pending or unvalidated | Not evaluated; no weighting |
| Globally routable IP observed for endpoint (default `UNTRUST`, reachability unverified) | Intrinsic severity raised one level; marked as assumed, low-confidence context |
| Confirmed Internet | Intrinsic severity raised one level |
| Confirmed not Internet-exposed | Intrinsic severity lowered one level |

The bounded order is low → medium → high → critical. The matrix leaves informational/unknown intrinsic severities unweighted. It does not alter policy compliance or cryptographic grade. Every calculation records the matrix version, original severity, evidence state, provenance, confidence and justification. History is immutable because the resulting endpoint context is stored with the run.

## Safety constraints

- A globally routable IP address observed on the scanned endpoint is classified `UNTRUST` by the owner-approved default and raises contextual severity one level. This is explicitly an assumption, not proof that the service is reachable. A validated endpoint-specific assessment takes precedence. IP literals that are private, reserved, loopback, documentation-only or otherwise not globally routable remain unknown without evidence.
- DNS names, reverse DNS, DMZ, NAT, proxy and scan location are not used as exposure evidence. No DNS-only inference or live lookup is performed.
- No automatic external probes or third-party service calls exist; a configured external measurement can only be recorded and administrator-validated.
- Validated exposure records and the explicit public-IP default affect contextual severity; pending manual proposals do not. A missing record remains unknown unless the endpoint IP observed during the scan is globally routable.
- No risk-based changes are applied to scans, profiles or encryption policies.
- The exposure evidence foreign key cascades with target deletion; migration defaults historical runs to empty snapshots and historical findings to empty risk maps.

## Migration and operations

Migration `0023_endpoint_exposure_context` follows `0022_dns_lookalike_monitoring` and adds the evidence table and nullable-history-compatible JSON snapshots with empty defaults. Apply it using the normal Docker upgrade procedure in [installation](../admin/install.md). Rollback removes only these new fields/table and discards their saved context; back up before downgrading after recording evidence.

No external probing is enabled. To validate a deployment, run backend/frontend suites, build the image, apply migrations, create a target, add a pending record, confirm it as ADMIN, queue a scan and inspect its immutable endpoint snapshot and per-finding risk. Confirm historical runs are unchanged after editing the current exposure. Docker Sandbox validation is still required before rollout.
