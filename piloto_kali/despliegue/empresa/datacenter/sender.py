"""Emisor de protocolo del datacenter NovaFlow.

Reutiliza la biblioteca de perfiles finitos ipv6_sender.py (idéntica a la revisada
en v2) y la acota a los dos receptores del segmento fd57:2026:70::/64. No toca los
scripts congelados de v2; solo cambia el direccionamiento del segmento NovaFlow.
"""

import argparse
import base64
import json
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/app")
import ipv6_sender as profiles
from scapy.all import ICMPv6ND_NS, sendp, sniff, wrpcap

parser = argparse.ArgumentParser()
parser.add_argument("profile", choices=[
    "ra_mtu", "ra_route", "na_neighbor", "dad_na", "control", "overlap",
    "control_middle", "overlap_middle", "plain", "atomic", "incomplete_chain",
])
parser.add_argument("receiver", choices=["fd57:2026:70::20", "fd57:2026:70::21"])
parser.add_argument("nonce")
args = parser.parse_args()
if re.fullmatch(r"[0-9a-f]{16}", args.nonce) is None:
    raise ValueError("nonce inválido")
profiles.SOURCE = "fd57:2026:70::10"
profiles.TARGET = args.receiver
profiles.DAD_TARGET = "fd57:2026:70::30" if args.receiver.endswith("::20") else "fd57:2026:70::31"
mac = "02:57:20:26:70:20" if args.receiver.endswith("::20") else "02:57:20:26:70:21"
packets, fragment_id = profiles.packets_for(args.profile, mac, args.nonce)
# Acotar incluso los perfiles ND al receptor elegido; no alterar el otro receptor ni el puente del host.
if args.profile in {"ra_mtu", "ra_route", "dad_na"}:
    packets[0][profiles.Ether].dst = mac
    if args.profile != "dad_na":
        packets[0][profiles.IPv6].dst = args.receiver
solicitation_seen = None
if args.profile == "dad_na":
    observed = sniff(
        iface="eth0", timeout=4, count=1,
        lfilter=lambda p: ICMPv6ND_NS in p and p[ICMPv6ND_NS].tgt == profiles.DAD_TARGET,
        started_callback=lambda: print("READY", flush=True), store=True,
    )
    solicitation_seen = bool(observed)
    if not solicitation_seen:
        packets = []
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "probe.pcap"
    if packets:
        wrpcap(str(path), packets)
        raw = path.read_bytes()
    else:
        raw = b""
if packets:
    sendp(packets, iface="eth0", inter=0.05, verbose=False)
print(json.dumps({
    "profile": args.profile, "packet_count": len(packets), "fragment_id": fragment_id,
    "solicitation_seen": solicitation_seen, "pcap_b64": base64.b64encode(raw).decode(),
}))
