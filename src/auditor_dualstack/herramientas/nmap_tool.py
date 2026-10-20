"""Adaptador de Nmap para el Agente IPv4-Servicios (y descubrimiento IPv6 -6).

Stub del incremento 0: define la interfaz. La ejecución (subprocess a `nmap`
con salida XML parseable) se implementa en el incremento 1 y corre en Kali.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ServicioDetectado:
    puerto: int
    protocolo: str        # tcp | udp
    servicio: str         # ssh, ftp, http…
    producto: str = ""    # software
    version: str = ""
    cpe: str = ""         # p. ej. cpe:/a:vsftpd:vsftpd:2.3.4


def escanear_servicios(objetivo: str, ipv6: bool = False) -> list[ServicioDetectado]:
    """Escanea puertos y versiones. Implementación real en el incremento 1."""
    raise NotImplementedError("nmap_tool.escanear_servicios se implementa en el incremento 1 (Kali)")
