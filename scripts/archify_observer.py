#!/usr/bin/env python3
"""Visor opcional de arquitectura; solo consulta el panel local existente."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

REPOSITORY = Path(__file__).resolve().parents[1]
ASSETS = REPOSITORY / "scripts" / "archify_viewer"
DEFAULT_DIAGRAM = REPOSITORY / ".archify" / "architecture-auditoria-dualstack-20261012-204850" / "auditoria-dualstack.html"
if not DEFAULT_DIAGRAM.is_file():
    DEFAULT_DIAGRAM = REPOSITORY / "docs" / "diagramas-finales" / "arquitectura-v2-historica.html"


def make_server(diagram: Path, port: int = 8766, panel_port: int = 8765) -> ThreadingHTTPServer:
    # Ignora proxies del entorno: la única fuente autorizada es loopback.
    opener = build_opener(ProxyHandler({}))
    diagram = diagram.resolve(strict=True)
    routes = {
        "/": (ASSETS / "index.html", "text/html; charset=utf-8"),
        "/viewer.js": (ASSETS / "viewer.js", "text/javascript; charset=utf-8"),
        "/viewer.css": (ASSETS / "viewer.css", "text/css; charset=utf-8"),
        "/diagram": (diagram, "text/html; charset=utf-8"),
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, body: bytes, content_type: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'")
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionError:
                pass

        def do_GET(self):
            if self.headers.get("Host") not in {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }:
                self.send(b"Host no permitido", "text/plain; charset=utf-8", 403)
                return
            path = urlsplit(self.path).path
            if path == "/api/state":
                try:
                    with opener.open(f"http://127.0.0.1:{panel_port}/api/state", timeout=3) as response:
                        state = json.load(response)
                    if not isinstance(state, dict) or not isinstance(state.get("runs"), list):
                        raise ValueError("estado invalido")
                    self.send(json.dumps(state, ensure_ascii=False, allow_nan=False).encode(), "application/json; charset=utf-8")
                except (OSError, URLError, ValueError):
                    self.send(b'{"error":"Panel local no disponible"}', "application/json; charset=utf-8", 503)
            elif path in routes:
                file, content_type = routes[path]
                try:
                    self.send(file.read_bytes(), content_type)
                except OSError:
                    self.send(b"Archivo no disponible", "text/plain; charset=utf-8", 404)
            else:
                self.send(b"No encontrado", "text/plain; charset=utf-8", 404)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--panel-port", type=int, default=8765)
    parser.add_argument("--diagram", type=Path, default=DEFAULT_DIAGRAM)
    args = parser.parse_args()
    for port in (args.port, args.panel_port):
        if not 1024 <= port <= 65535:
            parser.error("los puertos deben estar entre 1024 y 65535")
    if args.port == args.panel_port:
        parser.error("el visor y el panel necesitan puertos distintos")
    try:
        server = make_server(args.diagram, args.port, args.panel_port)
    except OSError as exc:
        parser.error(str(exc))
    print(f"Visor de arquitectura: http://127.0.0.1:{server.server_port} · Ctrl+C para cerrar", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
