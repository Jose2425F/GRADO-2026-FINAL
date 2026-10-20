"""Perfiles Scapy finitos del emisor, ejecutables solo en la red Docker del piloto."""

from __future__ import annotations

import argparse
import base64
import json
import random
import subprocess
import tempfile
from pathlib import Path

from scapy.all import (Ether, ICMPv6NDOptDstLLAddr, ICMPv6NDOptMTU,
                       ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, IPv6,
                       IPv6ExtHdrFragment, Raw, UDP, fragment6,
                       sendp, sniff, wrpcap)

SOURCE = "fd57:2026:9:28::10"
TARGET = "fd57:2026:9:28::20"
DAD_TARGET = "fd57:2026:9:28::30"
SPOOF_MAC = "02:57:20:26:09:10"


def link_local() -> str:
    addresses = json.loads(subprocess.check_output(["ip", "-j", "-6", "addr", "show", "dev", "eth0"]))
    source = next((entry["local"] for address in addresses
                   for entry in address.get("addr_info", []) if entry.get("scope") == "link"), None)
    if not source:
        raise RuntimeError("el emisor no tiene dirección link-local")
    return source


def packets_for(profile: str, mac: str, nonce: str):
    if profile in {"ra_mtu", "ra_route"}:
        packet = (Ether(dst="33:33:00:00:00:01") /
                  IPv6(src=link_local(), dst="ff02::1", hlim=255) /
                  ICMPv6ND_RA(routerlifetime=20 if profile == "ra_route" else 0))
        if profile == "ra_mtu":
            packet /= ICMPv6NDOptMTU(mtu=1280)
        return [packet], None

    if profile == "na_neighbor":
        packet = (Ether(dst=mac) / IPv6(src=SOURCE, dst=TARGET, hlim=255) /
                  ICMPv6ND_NA(R=0, S=0, O=1, tgt=SOURCE) /
                  ICMPv6NDOptDstLLAddr(lladdr=SPOOF_MAC))
        return [packet], None

    if profile == "dad_na":
        packet = (Ether(dst="33:33:00:00:00:01") /
                  IPv6(src=link_local(), dst="ff02::1", hlim=255) /
                  ICMPv6ND_NA(R=0, S=0, O=0, tgt=DAD_TARGET) /
                  ICMPv6NDOptDstLLAddr(lladdr=SPOOF_MAC))
        return [packet], None

    if profile == "plain":
        return [Ether(dst=mac) / IPv6(src=SOURCE, dst=TARGET) /
                UDP(sport=53001, dport=53000) / Raw((nonce + ":plain").encode())], None

    if profile == "atomic":
        packet = (Ether(dst=mac) / IPv6(src=SOURCE, dst=TARGET) /
                  IPv6ExtHdrFragment(nh=17, id=random.getrandbits(32), offset=0, m=0) /
                  UDP(sport=53001, dport=53000) / Raw((nonce + ":atomic").encode()))
        return [packet], packet[IPv6ExtHdrFragment].id

    if profile == "incomplete_chain":
        udp = bytes(IPv6(src=SOURCE, dst=TARGET) / UDP(sport=53001, dport=53000) /
                    Raw((nonce + ":chain").encode()))[40:]
        # Destination Options anuncia 16 octetos; el primer fragmento lleva solo 8.
        first = bytes([17, 1, 1, 12, 0, 0, 0, 0])
        remainder = b"\x00" * 8 + udp
        fragment_id = random.getrandbits(32)
        fragments = [
            IPv6(src=SOURCE, dst=TARGET) /
            IPv6ExtHdrFragment(nh=60, id=fragment_id, offset=0, m=1) / Raw(first),
            IPv6(src=SOURCE, dst=TARGET) /
            IPv6ExtHdrFragment(nh=60, id=fragment_id, offset=1, m=0) / Raw(remainder),
        ]
        return [Ether(dst=mac) / fragment for fragment in fragments], fragment_id

    packet = IPv6(src=SOURCE, dst=TARGET) / UDP(sport=53001, dport=53000) / Raw(
        (nonce + ":" + "X" * (2600 if profile in {"control_middle", "overlap_middle"} else 1400)).encode("ascii"))
    fragments = fragment6(packet, 1280)
    expected = 3 if profile in {"control_middle", "overlap_middle"} else 2
    if len(fragments) != expected:
        raise RuntimeError(f"el perfil requiere exactamente {expected} fragmentos")
    if profile == "overlap":
        fragments[1][IPv6ExtHdrFragment].offset -= 1
    elif profile == "overlap_middle":
        fragments[1][IPv6ExtHdrFragment].offset -= 1
    elif profile not in {"control", "control_middle"}:
        raise ValueError("perfil no admitido")
    return [Ether(dst=mac) / fragment for fragment in fragments], fragments[0][IPv6ExtHdrFragment].id


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=["ra_mtu", "ra_route", "na_neighbor", "dad_na",
                                            "control", "overlap", "control_middle",
                                            "overlap_middle", "plain", "atomic",
                                            "incomplete_chain"])
    parser.add_argument("target_mac")
    parser.add_argument("nonce")
    args = parser.parse_args()
    packets, fragment_id = packets_for(args.profile, args.target_mac, args.nonce)
    solicitation_seen = None
    if args.profile == "dad_na":
        observed = sniff(iface="eth0", timeout=4, count=1,
                         lfilter=lambda p: ICMPv6ND_NS in p and p[ICMPv6ND_NS].tgt == DAD_TARGET,
                         started_callback=lambda: print("READY", flush=True),
                         store=True)
        solicitation_seen = bool(observed)
        if not solicitation_seen:
            packets = []
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "probe.pcap"
        if packets:
            wrpcap(str(path), packets)
        else:
            path.write_bytes(b"")
        pcap = base64.b64encode(path.read_bytes()).decode("ascii")
    if packets:
        sendp(packets, iface="eth0", inter=0.05, verbose=False)
    print(json.dumps({"profile": args.profile, "packet_count": len(packets),
                      "fragment_id": fragment_id, "solicitation_seen": solicitation_seen,
                      "pcap_b64": pcap}))


if __name__ == "__main__":
    main()
