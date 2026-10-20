"""Agente IPv6-NDP/SLAAC (RF-05).

Detecta configuraciones susceptibles a suplantación de Router Advertisement y
envenenamiento de caché NDP mediante paquetes ICMPv6 generados con Scapy.
Detecta el bloque GT-09..GT-12.

Requiere root y una interfaz L2 real → solo corre en Kali. Estado: stub del
incremento 0. Implementación real en el incremento 3.
"""
from __future__ import annotations

from ..estado import AuditState
from ..modelos import Categoria, Hallazgo
from .base import AgenteEspecializado


class AgenteIPv6NdpSlaac(AgenteEspecializado):
    id_agente = "ipv6_ndp_slaac"
    categoria = Categoria.IPV6_NDP_SLAAC
    herramientas = ("scapy_ndp",)

    def ejecutar(self, state: AuditState) -> list[Hallazgo]:
        # TODO(inc-3): ciclo ReAct sobre Scapy/ICMPv6 —
        #   1. RA spoofing: anunciar prefijo/gateway y observar cambio en víctima
        #   2. NDP poisoning: NA no solicitado → caché de la víctima
        #   3. DAD DoS / rogue router con MTU baja
        #   4. emitir un Hallazgo por vector confirmado (GT-09..12)
        return []
