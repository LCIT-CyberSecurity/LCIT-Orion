# Orion TLS grading v2

Orion records three independent outputs for each TLS endpoint:

* **Display grade**: `T` for a proven trust, expiry or revocation failure; `M` when an enabled identity check proves that the requested DNS name or IP does not match; otherwise the cryptographic grade. If trust/validity and identity both fail, `T` is displayed and both reasons remain in `pki_issues` and the certificate/identity evidence.
* **Cryptographic grade**: the worst negotiated TLS configuration observed. It is not changed by certificate trust, name, expiry, revocation, or exposure. No handshake or unsupported evidence is `NOT_EVALUATED`, never `F`.
* **PKI status**: `TRUSTED_PUBLIC`, `TRUSTED_PRIVATE`, `UNTRUSTED`, `NAME_MISMATCH`, `EXPIRED`, `REVOKED`, `NOT_TESTED`, `INCONCLUSIVE`, or `ERROR`. `NOT_TESTED` is not trusted. An explicitly configured trust anchor can validate a self-signed certificate or private CA.

The deterministic `tls-grade-v2` ladder is:

| Grade | Evidence rule |
| --- | --- |
| A+ | Strong observed configuration including TLS 1.3; a 2048-bit RSA certificate is not demoted. |
| A | Strong TLS 1.2 configuration, or strong configuration without observed TLS 1.3. |
| B | TLS 1.2 static RSA key exchange. |
| C | SHA-1 MAC suites or TLS 1.2 CBC suites that meet that rule. |
| D | TLS 1.1, an observed MD5 suite, or an RSA public key below 2048 bits. |
| E | TLS 1.0, 3DES, IDEA, or RC4 while encryption remains present. |
| F | A NULL/EXPORT suite or SSLv2 is explicitly observed. |
| NOT_EVALUATED | No negotiated TLS evidence or an observation that cannot be classified. |

The certificate signature hash is reported as PKI evidence and does not lower the cryptographic grade. The policy compliance result and findings remain independent, so an A/A+ can still be non-compliant. Contextual exposure risk continues to use its own `exposure-risk-v1` matrix and does not change either grade. Existing run snapshots are immutable; new results record `grade_version` in the existing contextual-risk JSON field, so no historical rows are rewritten and no relational migration is needed.

This is Orion's deterministic rubric, inspired by but not a reproduction of SSL Labs. SSL Labs describes trust and name mismatch as separate T/M grades and uses its own scoring and additional override rules; its numeric configuration scoring does not map directly to this ladder. Orion only emits M after an enabled identity comparison returns a mismatch and does not treat an untested check as a mismatch. The T/M labels and known differences are documented in the [SSL Labs rating guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide) and [Qualys T/M announcement](https://blog.qualys.com/product-tech/2014/06/17/ssl-labs-new-grades-for-trust-t-and-mismatch-m-issues).
