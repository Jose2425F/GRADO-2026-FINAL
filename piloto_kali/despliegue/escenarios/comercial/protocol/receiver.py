"""Receptor Linux instrumentado del datacenter NovaFlow (segmento fd57:2026:121::/64).

Idéntico en lógica al receptor v2 revisado; solo cambia el direccionamiento del
segmento. Configuración protegida y datos observables separados.
"""

import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scapy.all import (
    ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptMTU,
    IPv6, IPv6ExtHdrFragment, sniff,
)

if os.environ.get("LAB_GUARDED") == "1":
    # Control del host para estos casos; no se presenta como SEND ni como un switch RA Guard.
    subprocess.run(["nft", "-f", "-"], input="""
table ip6 lab_guard {
 chain input {
  type filter hook input priority -300; policy accept;
  iifname "eth0" icmpv6 type nd-router-advert ip6 saddr != fe80::57:20ff:fe26:a2fe counter drop
  iifname "eth0" icmpv6 type nd-neighbor-advert ip6 saddr { fe80::57:20ff:fe26:a210, fd57:2026:121::10 } counter drop
 }
}
""", text=True, check=True)
    subprocess.run([
        "ip", "-6", "neigh", "replace", "fd57:2026:121::10", "lladdr",
        "02:57:20:26:a2:10", "nud", "permanent", "dev", "eth0",
    ], check=True)

LOCK = threading.Lock()
STATE = {key: [] for key in [
    "fragments", "router_advertisements", "neighbor_advertisements",
    "neighbor_solicitations", "udp_deliveries", "mtu_changes",
]}


def observe(packet):
    if IPv6 not in packet:
        return
    entry = {"source": packet[IPv6].src, "destination": packet[IPv6].dst}
    with LOCK:
        if IPv6ExtHdrFragment in packet:
            frag = packet[IPv6ExtHdrFragment]
            STATE["fragments"].append({**entry, "id": frag.id, "offset": frag.offset, "more": frag.m})
        if ICMPv6ND_RA in packet:
            prefix = packet.getlayer(ICMPv6NDOptPrefixInfo)
            mtu_option = packet.getlayer(ICMPv6NDOptMTU)
            STATE["router_advertisements"].append({
                **entry, "hop_limit": packet[IPv6].hlim,
                "router_lifetime": packet[ICMPv6ND_RA].routerlifetime,
                "prefix": prefix.prefix if prefix else None,
                "prefix_length": prefix.prefixlen if prefix else None,
                "autonomous": bool(prefix.A) if prefix else None,
                "advertised_mtu": mtu_option.mtu if mtu_option else None,
            })
        for layer, key in [(ICMPv6ND_NA, "neighbor_advertisements"),
                           (ICMPv6ND_NS, "neighbor_solicitations")]:
            if layer in packet:
                STATE[key].append({**entry, "target": packet[layer].tgt})
        for key in STATE:
            STATE[key] = STATE[key][-64:]


def monitor_kernel_mtu():
    previous = None
    while True:
        mtu = int(Path("/proc/sys/net/ipv6/conf/eth0/mtu").read_text())
        if mtu != previous:
            with LOCK:
                STATE["mtu_changes"].append({"mtu": mtu, "observed_at": time.monotonic()})
                STATE["mtu_changes"] = STATE["mtu_changes"][-64:]
            previous = mtu
        time.sleep(0.02)


def receive_udp():
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(("::", 53000))
        while True:
            data, address = sock.recvfrom(4096)
            with LOCK:
                STATE["udp_deliveries"].append({
                    "nonce": data.split(b":", 1)[0].decode("ascii", errors="replace")[:64],
                    "source": address[0], "length": len(data),
                })
                STATE["udp_deliveries"] = STATE["udp_deliveries"][-64:]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
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


class Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


threading.Thread(target=lambda: sniff(iface="eth0", prn=observe, store=False), daemon=True).start()
threading.Thread(target=receive_udp, daemon=True).start()
threading.Thread(target=monitor_kernel_mtu, daemon=True).start()
Server(("::", 8000), Handler).serve_forever()
