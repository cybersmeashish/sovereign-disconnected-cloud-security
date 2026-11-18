"""Ephemeral HTTP demonstration bound only to IPv4 loopback.

No TLS, production rate limiter, durable state, or remotely exposed admin API.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import unquote, urlsplit

from .identity import Denied

MAX_BODY = 4096


def handler_for(authority):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SyntheticOfflineLab/1"

        def log_message(self, *args):
            pass

        def reply(self, status, body):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def payload(self):
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("chunked request unsupported")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("bounded JSON body required")
            self.connection.settimeout(2)
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            return payload

        def bearer(self):
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer ") or len(header) > 200:
                raise Denied("bearer required")
            return header[7:]

        def do_POST(self):
            try:
                path = urlsplit(self.path).path
                if path == "/login":
                    payload = self.payload()
                    if set(payload) != {"principal_id", "password"}:
                        raise ValueError("only principal_id and password accepted")
                    token = authority.login(payload["principal_id"], payload["password"])
                    self.reply(200, {"token": token})
                elif path.startswith("/alerts/") and path.endswith("/ack"):
                    resource_id = unquote(path[len("/alerts/"):-len("/ack")])
                    authority.authorize(self.bearer(), "acknowledge_alert", resource_id)
                    self.reply(200, {"synthetic": True, "acknowledged": resource_id})
                else:
                    self.reply(404, {"error": "unknown endpoint"})
            except Denied:
                self.reply(403, {"error": "denied"})
            except (ValueError, TypeError, UnicodeError, OSError):
                self.reply(400, {"error": "invalid request"})

        def do_GET(self):
            try:
                path = urlsplit(self.path).path
                if not path.startswith("/records/"):
                    self.reply(404, {"error": "unknown endpoint"})
                    return
                resource = authority.authorize(
                    self.bearer(), "read_record", unquote(path[len("/records/"):]),
                )
                self.reply(200, {"id": resource.id, "record": resource.body})
            except Denied:
                self.reply(403, {"error": "denied"})
            except (ValueError, TypeError):
                self.reply(400, {"error": "invalid request"})

    return Handler


@contextmanager
def running_service(authority):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(authority))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
