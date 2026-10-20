"""API de solo lectura para el receptor VM; escuchar solo en gestión con TLS."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def ip_json(*args: str) -> list[dict]:
    result = subprocess.run(["ip", "-j", *args], capture_output=True, text=True,
                            timeout=5, check=True)
    return json.loads(result.stdout)


def kernel_counters() -> dict[str, int]:
    wanted = {"Ip6ReasmReqds", "Ip6ReasmOKs", "Ip6ReasmFails", "Ip6InHdrErrors",
              "Udp6InDatagrams", "Icmp6InErrors"}
    counters = {}
    with open("/proc/net/snmp6", encoding="ascii") as stream:
        for line in stream:
            parts = line.split()
            if len(parts) == 2 and parts[0] in wanted:
                counters[parts[0]] = int(parts[1])
    return counters


def forwarding_state() -> dict[str, bool]:
    values = {}
    for name, path in (("ipv4", "/proc/sys/net/ipv4/ip_forward"),
                       ("ipv6", "/proc/sys/net/ipv6/conf/all/forwarding")):
        with open(path, encoding="ascii") as stream:
            values[name] = stream.read().strip() == "1"
    return values


def serve(bind: str, port: int, asset_id: str, audit_interface: str,
          certificate: str, key: str, token_env: str, udp_port: int) -> None:
    token = os.environ.get(token_env, "")
    if not token:
        raise RuntimeError("token del observador no configurado")
    deliveries: list[dict] = []
    lock = threading.Lock()

    def udp_listener() -> None:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind(("::", udp_port))
        while True:
            payload, source = sock.recvfrom(4096)
            with lock:
                deliveries.append({"nonce": payload.split(b":", 1)[0].decode("ascii", "replace")[:64],
                                   "source": source[0], "length": len(payload)})
                del deliveries[:-32]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            actual = self.headers.get("Authorization", "")
            if not hmac.compare_digest(actual, f"Bearer {token}"):
                self.send_error(401)
                return
            if self.path != "/snapshot":
                self.send_error(404)
                return
            with lock:
                recent_deliveries = list(deliveries)
            state = {"addresses": ip_json("-6", "addr", "show", "dev", audit_interface),
                     "routes": ip_json("-6", "route", "show"),
                     "neighbors": ip_json("-6", "neigh", "show", "dev", audit_interface),
                     "link": ip_json("link", "show", "dev", audit_interface),
                     "kernel_counters": kernel_counters(),
                     "forwarding": forwarding_state(),
                     "udp_deliveries": recent_deliveries}
            body = json.dumps({"asset_id": asset_id, "state": state}, sort_keys=True).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format_string: str, *args) -> None:
            pass

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

    threading.Thread(target=udp_listener, daemon=True).start()
    server = Server((bind, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--audit-interface", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--token-env", default="LAB_OBSERVER_TOKEN")
    parser.add_argument("--udp-port", type=int, default=53000)
    args = parser.parse_args()
    serve(args.bind, args.port, args.asset_id, args.audit_interface,
          args.cert, args.key, args.token_env, args.udp_port)


if __name__ == "__main__":
    main()
