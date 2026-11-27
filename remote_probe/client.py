"""Central-side HTTPS client for a registered probe with certificate pinning."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import ssl
import uuid
from typing import Any

import httpx


class ProbeConnectionError(RuntimeError):
    """Safe error for an unavailable or rejected remote probe."""


MAX_RESPONSE_BYTES = 6 * 1024 * 1024


class ProbeClient:
    """Orion-initiated HTTPS requests to one IPv4 probe; redirects and environment proxies are disabled."""

    def __init__(
        self,
        address: str,
        port: int,
        certificate_pem: str,
        certificate_sha256: str,
        token: str = "",
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("probe must use a literal IPv4 address and valid port")
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("probe timeout must be between 0.1 and 30 seconds")
        try:
            der = ssl.PEM_cert_to_DER_cert(certificate_pem)
        except (ssl.SSLError, ValueError):
            raise ValueError("registered probe certificate is invalid") from None
        actual_fingerprint = hashlib.sha256(der).hexdigest()
        expected = certificate_sha256.lower().replace(":", "")
        if len(expected) != 64 or not hmac.compare_digest(actual_fingerprint, expected):
            raise ValueError("registered probe certificate fingerprint does not match")
        context = ssl.create_default_context(cadata=certificate_pem)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.base_url = f"https://{ip}:{port}"
        self.token = token
        self._client = httpx.Client(
            verify=context,
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )

    def pair(self, pairing_code: str) -> str:
        response = self._request(
            "POST", "/v1/pair", payload={"pairing_code": pairing_code}
        )
        token = response.get("token")
        if not isinstance(token, str) or not token:
            raise ProbeConnectionError("probe pairing response is invalid")
        self.token = token
        return token

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health", authenticated=True)

    def submit_task(self, task: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/tasks", payload=task, authenticated=True)

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._request(
            "GET", f"/v1/tasks/{uuid.UUID(task_id)}", authenticated=True
        )

    def cancel_task(self, task_id: str) -> dict[str, Any]:
        return self._request(
            "DELETE", f"/v1/tasks/{uuid.UUID(task_id)}", authenticated=True
        )

    def results(self, after: int = 0, limit: int = 20) -> dict[str, Any]:
        if isinstance(after, bool) or not isinstance(after, int) or after < 0:
            raise ValueError("result cursor must be a non-negative integer")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 20
        ):
            raise ValueError("result page size must be between 1 and 20")
        return self._request(
            "GET", f"/v1/results?after={after}&limit={limit}", authenticated=True
        )

    def acknowledge(self, cursor: int) -> dict[str, Any]:
        return self._request(
            "POST", "/v1/results/ack", payload={"cursor": cursor}, authenticated=True
        )

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = False,
        payload: dict | None = None,
    ) -> dict[str, Any]:
        headers = {}
        if authenticated:
            if not self.token:
                raise ProbeConnectionError("probe credential is not configured")
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            with self._client.stream(
                method, self.base_url + path, headers=headers, json=payload
            ) as response:
                if response.is_redirect:
                    raise ProbeConnectionError("probe returned an unexpected redirect")
                if response.status_code >= 400:
                    raise ProbeConnectionError(
                        f"probe rejected the request (HTTP {response.status_code})"
                    )
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ProbeConnectionError(
                            "probe response exceeded the size limit"
                        )
                    chunks.append(chunk)
                body = b"".join(chunks)
        except httpx.HTTPError:
            raise ProbeConnectionError("probe HTTPS request failed") from None
        try:
            data = json.loads(body)
        except ValueError:
            raise ProbeConnectionError("probe returned invalid JSON") from None
        if not isinstance(data, dict):
            raise ProbeConnectionError("probe returned an invalid response")
        return data
