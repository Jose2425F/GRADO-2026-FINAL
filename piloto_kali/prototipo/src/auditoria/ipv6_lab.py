"""Preflight y observador del banco Docker IPv6, separado de eth0 de Kali."""

from __future__ import annotations

import base64
import json
import re
import select
import subprocess
import time
import urllib.request

from .red import RouteDenied, check_route

NETWORK = "lab_auditoria_ipv6"
INTERFACE = "br-lab-ipv6"
SUBNET = "fd57:2026:9:28::/64"
IPV4_SUBNET = "192.168.58.0/24"
TARGET = "fd57:2026:9:28::20"
SENDER = "fd57:2026:9:28::10"
TARGET_CONTAINER = "obj-ipv6"
SENDER_CONTAINER = "emisor-ipv6"
UDP_PORT = 53000
DAD_TARGET = "fd57:2026:9:28::30"


class IPv6LabError(RuntimeError):
    pass


def _docker(*args: str, timeout: int = 10) -> str:
    try:
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise IPv6LabError(f"falló docker {args[0]}") from exc


def _inspect(kind: str, name: str) -> dict:
    try:
        items = json.loads(_docker(kind, "inspect", name))
        if len(items) != 1 or not isinstance(items[0], dict):
            raise ValueError("respuesta inesperada")
        return items[0]
    except (ValueError, KeyError) as exc:
        raise IPv6LabError(f"inspección inválida de {name}") from exc


def _network_attachment(container: dict, expected: str) -> dict:
    if container.get("State", {}).get("Running") is not True:
        raise IPv6LabError("contenedor IPv6 detenido")
    attachments = container.get("NetworkSettings", {}).get("Networks", {})
    if set(attachments) != {NETWORK}:
        raise IPv6LabError("contenedor conectado fuera de la red IPv6 aislada")
    if any(container.get("NetworkSettings", {}).get("Ports", {}).values()):
        raise IPv6LabError("contenedor IPv6 con puertos publicados")
    attachment = attachments[NETWORK]
    if attachment.get("GlobalIPv6Address") != expected:
        raise IPv6LabError("dirección IPv6 del contenedor inesperada")
    return attachment


def _container_routes(container: str) -> list[dict]:
    try:
        return json.loads(_docker("exec", container, "ip", "-j", "-6", "route", "show"))
    except ValueError as exc:
        raise IPv6LabError("rutas IPv6 inválidas") from exc


def _container_ipv4_routes(container: str) -> list[dict]:
    try:
        return json.loads(_docker("exec", container, "ip", "-j", "-4", "route", "show"))
    except ValueError as exc:
        raise IPv6LabError("rutas IPv4 inválidas") from exc


def _observer_state() -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://[{TARGET}]:8000/state", timeout=3) as response:
            return json.load(response)
    except (OSError, ValueError) as exc:
        raise IPv6LabError("observador IPv6 inaccesible") from exc


def verify_ipv6_lab() -> dict:
    network = _inspect("network", NETWORK)
    if network.get("Driver") != "bridge" or network.get("Internal") is not True:
        raise IPv6LabError("la red IPv6 no es un puente interno")
    if network.get("EnableIPv6") is not True:
        raise IPv6LabError("la red de laboratorio no tiene IPv6 habilitado")
    if network.get("Options", {}).get("com.docker.network.bridge.name") != INTERFACE:
        raise IPv6LabError("interfaz de puente inesperada")
    subnets = {item.get("Subnet") for item in network.get("IPAM", {}).get("Config", [])}
    if subnets != {SUBNET, IPV4_SUBNET}:
        raise IPv6LabError("subredes del laboratorio IPv6 inesperadas")
    target = _inspect("container", TARGET_CONTAINER)
    sender = _inspect("container", SENDER_CONTAINER)
    target_attachment = _network_attachment(target, TARGET)
    _network_attachment(sender, SENDER)
    for name in (TARGET_CONTAINER, SENDER_CONTAINER):
        if any(route.get("dst") == "default" for route in _container_routes(name)):
            raise IPv6LabError(f"{name} tiene ruta IPv6 predeterminada")
        if any(route.get("dst") == "default" for route in _container_ipv4_routes(name)):
            raise IPv6LabError(f"{name} tiene ruta IPv4 predeterminada")
    try:
        check_route(TARGET, INTERFACE)
    except RouteDenied as exc:
        raise IPv6LabError(str(exc)) from exc
    _observer_state()
    return {
        "network": NETWORK,
        "network_id": network.get("Id"),
        "internal": True,
        "interface": INTERFACE,
        "subnet": SUBNET,
        "target": TARGET_CONTAINER,
        "target_id": target.get("Id"),
        "target_address": TARGET,
        "target_mac": target_attachment.get("MacAddress"),
        "target_image_id": target.get("Image"),
        "sender": SENDER_CONTAINER,
        "sender_id": sender.get("Id"),
        "sender_address": SENDER,
        "sender_image_id": sender.get("Image"),
    }


def target_snapshot() -> dict:
    try:
        address = json.loads(
            _docker("exec", TARGET_CONTAINER, "ip", "-j", "-6", "addr", "show", "dev", "eth0")
        )
        routes = _container_routes(TARGET_CONTAINER)
        neighbors = json.loads(_docker("exec", TARGET_CONTAINER, "ip", "-j", "-6", "neigh", "show"))
        link = json.loads(
            _docker("exec", TARGET_CONTAINER, "ip", "-j", "link", "show", "dev", "eth0")
        )
        mtu = int(
            _docker("exec", TARGET_CONTAINER, "cat", "/proc/sys/net/ipv6/conf/eth0/mtu").strip()
        )
        counters = {}
        for line in _docker("exec", TARGET_CONTAINER, "cat", "/proc/net/snmp6").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in {
                "Ip6ReasmReqds",
                "Ip6ReasmOKs",
                "Ip6ReasmFails",
                "Ip6InHdrErrors",
                "Udp6InDatagrams",
                "Icmp6InErrors",
            }:
                counters[parts[0]] = int(parts[1])
        return {
            "addresses": address,
            "routes": routes,
            "neighbors": neighbors,
            "link": link,
            "ipv6_mtu": mtu,
            "kernel_counters": counters,
            "observer": _observer_state(),
        }
    except (ValueError, KeyError) as exc:
        raise IPv6LabError("estado del objetivo IPv6 inválido") from exc


def send_probe(profile: str, mac: str, nonce: str) -> tuple[bytes, dict]:
    if profile not in {
        "ra_mtu",
        "ra_route",
        "na_neighbor",
        "plain",
        "atomic",
        "control",
        "overlap",
        "control_middle",
        "overlap_middle",
        "incomplete_chain",
    }:
        raise IPv6LabError("perfil Scapy no autorizado")
    if not re.fullmatch(r"[0-9a-f]{16}", nonce):
        raise IPv6LabError("nonce inválido")
    if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        raise IPv6LabError("MAC inválida")
    try:
        output = _docker(
            "exec",
            SENDER_CONTAINER,
            "python",
            "/app/ipv6_sender.py",
            profile,
            mac,
            nonce,
            timeout=12,
        )
        return _parse_probe(output, allowed_counts={1, 2, 3})
    except (ValueError, KeyError) as exc:
        raise IPv6LabError("respuesta del emisor inválida") from exc


def _parse_probe(output: str, *, allowed_counts: set[int]) -> tuple[bytes, dict]:
    response = json.loads(output)
    raw = base64.b64decode(response.pop("pcap_b64"), validate=True)
    if response.get("packet_count") not in allowed_counts:
        raise ValueError("número de paquetes fuera del perfil")
    if raw and not 24 <= len(raw) <= 10000:
        raise ValueError("captura fuera de límites")
    return raw, response


def prime_neighbor() -> None:
    script = (
        "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
        f"s.sendto(b'neighbor-prime',('{SENDER}',53000))"
    )
    _docker("exec", TARGET_CONTAINER, "python", "-c", script)


def send_dad_probe(mac: str, nonce: str) -> tuple[bytes, dict]:
    if not re.fullmatch(r"[0-9a-f]{16}", nonce):
        raise IPv6LabError("nonce inválido")
    command = [
        "docker",
        "exec",
        SENDER_CONTAINER,
        "python",
        "/app/ipv6_sender.py",
        "dad_na",
        mac,
        nonce,
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([process.stdout], [], [], 20)[0]:
            raise IPv6LabError("agotado el tiempo al iniciar la captura DAD")
        ready = process.stdout.readline().strip()
        if ready != "READY":
            raise IPv6LabError("el emisor DAD no inició la captura")
        _docker(
            "exec",
            TARGET_CONTAINER,
            "ip",
            "-6",
            "addr",
            "add",
            f"{DAD_TARGET}/64",
            "dev",
            "eth0",
            timeout=5,
        )
        output, _ = process.communicate(timeout=7)
        if process.returncode != 0:
            raise IPv6LabError("falló el emisor de DAD")
        return _parse_probe(output, allowed_counts={0, 1})
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise IPv6LabError("no se completó el perfil de DAD") from exc
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def _configuration(snapshot: dict) -> tuple:
    global_addresses = sorted(
        entry["local"]
        for interface in snapshot["addresses"]
        for entry in interface.get("addr_info", [])
        if entry.get("scope") == "global"
    )
    routes = sorted((entry.get("dst"), entry.get("gateway")) for entry in snapshot["routes"])
    return snapshot["ipv6_mtu"], tuple(global_addresses), tuple(routes)


def restore_target(before: dict) -> dict:
    expected_neighbor = next(
        (entry.get("lladdr") for entry in before["neighbors"] if entry.get("dst") == SENDER), None
    )
    _docker("restart", "-t", "1", TARGET_CONTAINER, timeout=12)
    if expected_neighbor:
        prime_neighbor()
    for _ in range(20):
        try:
            snapshot = target_snapshot()
            neighbor = next(
                (
                    entry.get("lladdr")
                    for entry in snapshot["neighbors"]
                    if entry.get("dst") == SENDER
                ),
                None,
            )
            if _configuration(snapshot) == _configuration(before) and (
                expected_neighbor is None or neighbor == expected_neighbor
            ):
                return snapshot
        except IPv6LabError:
            pass
        time.sleep(0.25)
    raise IPv6LabError("no se pudo verificar la restauración del objetivo IPv6")
