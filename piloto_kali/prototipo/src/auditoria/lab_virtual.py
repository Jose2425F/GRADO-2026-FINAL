"""Preflight configurable para la futura red de auditoría y gestión de VM."""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import urllib.request
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, model_validator

from .contracts import StrictModel
from .red import RouteDenied, check_route


class VirtualLabError(RuntimeError):
    pass


class VirtualLabConfig(StrictModel):
    asset_id: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    audit_interface: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$")
    audit_network: str
    kali_address: str
    sender_address: str
    target_address: str
    management_interface: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$")
    observer_url: str
    observer_ca_path: str
    observer_token_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")

    @model_validator(mode="after")
    def validate_topology(self) -> VirtualLabConfig:
        network = ip_network(self.audit_network, strict=True)
        if network.version != 6:
            raise ValueError("audit_network debe ser IPv6")
        addresses = [ip_address(value) for value in
                     (self.kali_address, self.sender_address, self.target_address)]
        if any(address not in network for address in addresses) or len(set(addresses)) != 3:
            raise ValueError("direcciones IPv6 fuera del segmento o repetidas")
        if self.audit_interface == self.management_interface:
            raise ValueError("auditoría y gestión deben usar interfaces distintas")
        parsed = urlparse(self.observer_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"}:
            raise ValueError("observer_url debe ser la raíz HTTPS del observador")
        if ip_address(parsed.hostname).version != 4:
            raise ValueError("el observador debe usar la red IPv4 de gestión")
        return self


def load_config(path: Path) -> VirtualLabConfig:
    return VirtualLabConfig.model_validate_json(path.read_text(encoding="utf-8"))


def _ip_json(*args: str) -> list[dict]:
    try:
        result = subprocess.run(["ip", "-j", *args], capture_output=True, text=True,
                                timeout=5, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise VirtualLabError("no se pudo consultar el estado de red de Kali") from exc


def observer_snapshot(config: VirtualLabConfig) -> dict:
    token = os.environ.get(config.observer_token_env, "")
    if not token:
        raise VirtualLabError("falta el token del observador en el entorno")
    ca_path = Path(config.observer_ca_path)
    if not ca_path.is_file():
        raise VirtualLabError("falta el certificado CA del observador")
    context = ssl.create_default_context(cafile=str(ca_path))
    request = urllib.request.Request(
        config.observer_url.rstrip("/") + "/snapshot",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            snapshot = json.load(response)
    except (OSError, ValueError) as exc:
        raise VirtualLabError("observador de gestión inaccesible o respuesta inválida") from exc
    if snapshot.get("asset_id") != config.asset_id or not isinstance(snapshot.get("state"), dict):
        raise VirtualLabError("identidad o estructura del observador inesperada")
    return snapshot


def preflight_virtual_lab(config: VirtualLabConfig) -> dict:
    links = _ip_json("link", "show", "dev", config.audit_interface)
    if len(links) != 1 or "UP" not in links[0].get("flags", []):
        raise VirtualLabError("interfaz de auditoría ausente o inactiva")
    addresses = _ip_json("-6", "addr", "show", "dev", config.audit_interface)
    locals_ = {entry.get("local") for interface in addresses
               for entry in interface.get("addr_info", [])}
    if config.kali_address not in locals_:
        raise VirtualLabError("la IPv6 de Kali no está en la interfaz de auditoría")
    try:
        check_route(config.sender_address, config.audit_interface)
        check_route(config.target_address, config.audit_interface)
    except RouteDenied as exc:
        raise VirtualLabError(str(exc)) from exc
    management = _ip_json("route", "get", urlparse(config.observer_url).hostname)
    if not management or management[0].get("dev") != config.management_interface:
        raise VirtualLabError("la ruta de gestión no usa la interfaz autorizada")
    snapshot = observer_snapshot(config)
    state = snapshot["state"]
    if state.get("forwarding") != {"ipv4": False, "ipv6": False}:
        raise VirtualLabError("el receptor VM reenvía paquetes o no informó su estado")
    target_addresses = {entry.get("local") for interface in state.get("addresses", [])
                        for entry in interface.get("addr_info", [])}
    if config.target_address not in target_addresses:
        raise VirtualLabError("la IPv6 objetivo no aparece en el receptor")
    return {"asset_id": config.asset_id, "audit_interface": config.audit_interface,
            "audit_network": config.audit_network, "sender_address": config.sender_address,
            "target_address": config.target_address,
            "management_interface": config.management_interface,
            "observer_url": config.observer_url,
            "observer_state_keys": sorted(state), "forwarding": state["forwarding"]}
