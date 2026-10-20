"""Observador local del piloto IPv6: captura recepción y entrega UDP."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scapy.all import (IPv6, IPv6ExtHdrFragment, ICMPv6ND_NA,
                       ICMPv6ND_NS, ICMPv6ND_RA, sniff)

LOCK = threading.Lock()
STATE = {"fragments": [], "router_advertisements": [],
         "neighbor_advertisements": [], "neighbor_solicitations": [],
         "udp_deliveries": []}


def observe(packet) -> None:
    if IPv6 not in packet:
        return
    entry = {"source": packet[IPv6].src, "destination": packet[IPv6].dst}
    with LOCK:
        if IPv6ExtHdrFragment in packet:
            fragment = packet[IPv6ExtHdrFragment]
            STATE["fragments"].append({**entry, "id": fragment.id,
                                       "offset": fragment.offset, "more": fragment.m})
            STATE["fragments"] = STATE["fragments"][-32:]
        if ICMPv6ND_RA in packet:
            ra = packet[ICMPv6ND_RA]
            STATE["router_advertisements"].append({**entry, "hop_limit": packet[IPv6].hlim,
                                                     "router_lifetime": ra.routerlifetime})
            STATE["router_advertisements"] = STATE["router_advertisements"][-16:]
        if ICMPv6ND_NA in packet:
            STATE["neighbor_advertisements"].append({**entry, "target": packet[ICMPv6ND_NA].tgt,
                                                       "hop_limit": packet[IPv6].hlim})
            STATE["neighbor_advertisements"] = STATE["neighbor_advertisements"][-16:]
        if ICMPv6ND_NS in packet:
            STATE["neighbor_solicitations"].append({**entry, "target": packet[ICMPv6ND_NS].tgt,
                                                      "hop_limit": packet[IPv6].hlim})
            STATE["neighbor_solicitations"] = STATE["neighbor_solicitations"][-16:]


def capture() -> None:
    sniff(iface="eth0", prn=observe, store=False)


def receive_udp() -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", 53000))
    while True:
        data, address = sock.recvfrom(4096)
        nonce = data.split(b":", 1)[0].decode("ascii", errors="replace")[:64]
        with LOCK:
            STATE["udp_deliveries"].append({"nonce": nonce, "source": address[0], "length": len(data)})
            STATE["udp_deliveries"] = STATE["udp_deliveries"][-16:]


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/state":
            self.send_error(404)
            return
        with LOCK:
            body = json.dumps(STATE, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args) -> None:
        pass


threading.Thread(target=capture, daemon=True).start()
threading.Thread(target=receive_udp, daemon=True).start()
Server(("::", 8000), Handler).serve_forever()
