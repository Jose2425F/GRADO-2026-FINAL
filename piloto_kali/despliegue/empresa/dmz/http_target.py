"""Portal legado sintético de NovaFlow: consola /manager/html con HTTP Basic.

Objetivo de laboratorio para el perfil hydra_http_get_single_v1 y su corroboración
urllib. No ejecuta comandos ni sirve archivos del anfitrión; solo valida credenciales
sintéticas en memoria y responde 401 Basic cuando faltan.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERNAME = os.environ.get("LAB_HTTP_USER", "console")
PASSWORD = os.environ["LAB_HTTP_PASSWORD"]
EXPECTED = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
REALM = os.environ.get("LAB_HTTP_REALM", "NovaFlow Legacy Console")
LOCK = threading.Lock()
EVENTS: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    server_version = "NovaFlowConsole/1.0"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def _record(self, status: str) -> None:
        with LOCK:
            EVENTS.append({"path": self.path, "status": status})
            del EVENTS[:-64]

    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"ready": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path not in ("/manager/html", "/manager/status"):
            self._record("404")
            self.send_error(404)
            return
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            self._record("401")
            self.send_response(401)
            self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if header.split(" ", 1)[1].strip() != EXPECTED:
            self._record("403")
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._record("200")
        body = json.dumps({"kind": "manager_console", "user": USERNAME}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET


if __name__ == "__main__":
    Server(("0.0.0.0", 8080), Handler).serve_forever()
