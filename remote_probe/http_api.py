"""Small HTTPS API for Orion-initiated probe management requests."""

from __future__ import annotations

import ipaddress
import json
import ssl
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from remote_probe.agent import ProbeAgent
from remote_probe.protocol import TaskValidationError
from remote_probe.spool import InvalidCursorError, SpoolFullError

MAX_BODY_BYTES = 128 * 1024


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, agent: ProbeAgent):
        self.agent = agent
        super().__init__(address, handler)


class ProbeRequestHandler(BaseHTTPRequestHandler):
    server: _Server

    def log_message(self, _format: str, *args: object) -> None:
        # The standard logger includes request paths and may include credentials accidentally.
        return

    def _reply(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        scheme, separator, token = value.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or len(token) > 256:
            self._reply(401, {"error": "unauthorized"})
            return False
        if not self.server.agent.authenticate(token):
            self._reply(401, {"error": "unauthorized"})
            return False
        return True

    def _body(self) -> dict:
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > MAX_BODY_BYTES:
            raise ValueError("invalid request body size")
        raw = self.rfile.read(int(length))
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise TypeError("JSON body must be an object")
        return value

    def do_GET(self) -> None:
        if not self._authorized():
            return
        route = urlsplit(self.path)
        if route.path == "/v1/health":
            self._reply(
                200,
                {
                    "status": "ok",
                    "version": "1",
                    "capabilities": list(self.server.agent.capabilities),
                    "results_pending": bool(
                        self.server.agent.spool.read_after(0, limit=1)
                    ),
                    "spool_fault": self.server.agent.spool_fault,
                },
            )
            return
        if route.path == "/v1/results":
            try:
                query = parse_qs(route.query, strict_parsing=True)
                cursor = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", ["100"])[0])
                events = self.server.agent.spool.read_after(cursor, limit=limit)
            except (ValueError, TypeError):
                self._reply(400, {"error": "invalid_cursor_or_limit"})
                return
            next_cursor = events[-1]["cursor"] if events else cursor
            self._reply(200, {"events": events, "next_cursor": next_cursor})
            return
        prefix = "/v1/tasks/"
        if route.path.startswith(prefix):
            task_id = route.path.removeprefix(prefix)
            try:
                task_id = str(uuid.UUID(task_id))
            except ValueError:
                self._reply(404, {"error": "not_found"})
                return
            task = self.server.agent.get(task_id)
            if task is None:
                self._reply(404, {"error": "not_found"})
                return
            self._reply(200, task)
            return
        self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route == "/v1/pair":
            try:
                body = self._body()
            except (ValueError, TypeError, json.JSONDecodeError):
                self._reply(400, {"error": "invalid_request"})
                return
            token = self.server.agent.pair(body.get("pairing_code"))
            if token is None:
                self._reply(401, {"error": "pairing_rejected"})
                return
            self._reply(200, {"token": token})
            return
        if not self._authorized():
            return
        try:
            body = self._body()
            if route == "/v1/tasks":
                task = self.server.agent.submit(body)
                self._reply(202, task)
                return
            if route == "/v1/results/ack":
                cursor = body.get("cursor")
                self.server.agent.spool.acknowledge(cursor)
                self.server.agent.resume_queued()
                self._reply(200, {"acknowledged": cursor})
                return
        except TaskValidationError as error:
            self._reply(422, {"error": str(error)})
            return
        except InvalidCursorError:
            self._reply(409, {"error": "invalid_cursor"})
            return
        except SpoolFullError:
            self._reply(503, {"error": "result_capacity_reached"})
            return
        except (ValueError, json.JSONDecodeError):
            self._reply(400, {"error": "invalid_request"})
            return
        except RuntimeError:
            self._reply(503, {"error": "probe_capacity_reached"})
            return
        self._reply(404, {"error": "not_found"})

    def do_DELETE(self) -> None:
        if not self._authorized():
            return
        prefix = "/v1/tasks/"
        path = urlsplit(self.path).path
        if not path.startswith(prefix):
            self._reply(404, {"error": "not_found"})
            return
        try:
            task_id = str(uuid.UUID(path.removeprefix(prefix)))
        except ValueError:
            self._reply(404, {"error": "not_found"})
            return
        task = self.server.agent.cancel(task_id)
        if task is None:
            self._reply(404, {"error": "not_found"})
            return
        self._reply(202, task)


def create_https_server(
    host: str, port: int, certificate: str, private_key: str, agent: ProbeAgent
) -> ThreadingHTTPServer:
    """Create an IPv4-only TLS 1.2+ server; TLS identity provisioning stays local to Debian setup."""
    address = ipaddress.ip_address(host)
    if address.version != 4 or not 1 <= port <= 65535:
        raise ValueError("probe listener must use an IPv4 address and valid TCP port")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    server = _Server((str(address), port), ProbeRequestHandler, agent)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server
