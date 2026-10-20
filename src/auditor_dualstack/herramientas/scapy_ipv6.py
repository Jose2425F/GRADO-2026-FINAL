"""Adaptadores de Scapy para los agentes IPv6 (NDP/SLAAC y Fragmentación).

Estas rutinas forjan y envían paquetes ICMPv6/IPv6 crudos. Requieren root y
una interfaz L2 real: **solo funcionan en Kali**, no en Windows. Por eso la
importación de scapy es diferida (dentro de cada función), de modo que el
paquete se pueda importar y testear en Windows sin cargar el backend de red.

Stubs del incremento 0. Implementación real en los incrementos 3 y 4.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResultadoIPv6:
    vector: str          # p. ej. "ra_spoofing", "ndp_poisoning", "overlap_frag"
    exito: bool
    evidencia: str = ""


# ── NDP / SLAAC (incremento 3) ────────────────────────────────────────
def suplantar_router_advertisement(interfaz: str, prefijo: str) -> ResultadoIPv6:
    raise NotImplementedError("scapy_ipv6: RA spoofing se implementa en el incremento 3 (Kali, root)")


def envenenar_cache_ndp(interfaz: str, objetivo_ipv6: str) -> ResultadoIPv6:
    raise NotImplementedError("scapy_ipv6: NDP poisoning se implementa en el incremento 3 (Kali, root)")


# ── Fragmentación (incremento 4) ──────────────────────────────────────
def enviar_fragmentos_solapados(interfaz: str, objetivo_ipv6: str) -> ResultadoIPv6:
    raise NotImplementedError("scapy_ipv6: fragmentos solapados (RFC 5722) — incremento 4 (Kali, root)")
