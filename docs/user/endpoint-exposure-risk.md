# Endpoint exposure and contextual risk

Orion keeps the cryptographic grade separate from exposure context. A weak cipher, untrusted chain or other finding keeps the same technical grade and intrinsic severity even when the endpoint is internal. A contextual severity is shown only when an administrator has validated endpoint-specific exposure evidence.

## Record evidence

Open **Targets**, edit a target and use **Endpoint exposure context**. Add a record for the protocol and port (TLS, IPsec/IKE or SSH), optionally with FQDN/SNI. Enter the current state, supporting source, method, justification and confidence. Operators can record a proposal; only an administrator can validate it. Each record is scoped to that target, protocol, port and SNI.

Choose **Unknown / unverified** when there is no sufficient evidence. By the approved default, an endpoint with an observed globally routable IP is classified **UNTRUST (assumed Internet exposure)** and its contextual severity is raised one level. This is a conservative risk assumption, not proof that the service is reachable; the report says that reachability is unverified. A validated endpoint-specific assessment overrides the default. Private, reserved and documentation addresses remain unknown unless separately assessed. Public DNS alone does not trigger the default. No external connectivity probe runs automatically.

## Read the scan result

The scan detail and Network Map show the exposure snapshot used for the run. Findings retain their intrinsic severity and add a contextual severity per endpoint. The current versioned matrix moves assumed or confirmed Internet-exposed findings up one level and confirmed non-Internet findings down one level (bounded between low and critical). Unknown, pending and informational evidence is not weighted and is shown as not evaluated. The cryptographic A–F grade, PKI status and compliance verdict do not change.

HTML and Markdown reports include the per-endpoint exposure evidence and the intrinsic/contextual severities. When CSV export is configured, a separate **CONTEXTUAL RISK CSV** is available. Reports preserve the run-time snapshot; changing evidence later does not rewrite an old run.

## Validation and limitations

An administrator's validation confirms the supplied evidence and provenance. The app does not prove network reachability itself. An external measurement can only be entered when performed by an authorized external vantage point and documented by the operator. This version does not initiate any outbound probe, port scan, SaaS request or broad discovery. Evidence freshness must be reviewed by the organization; the app does not automatically expire or refresh it.
