"""Agente IPv4-Servicios (RF-03).

Audita servicios TCP/UDP expuestos con Nmap y correlaciona las versiones
detectadas contra la base de CVE. Detecta el bloque GT-01..GT-04 del ground
truth.

Estado: stub del incremento 0. La implementación real (ciclo ReAct sobre la
herramienta Nmap + consulta NVD) corresponde al incremento 1.
"""
from __future__ import annotations

from ..estado import AuditState
from ..modelos import Categoria, Hallazgo
from .base import AgenteEspecializado


class AgenteIPv4Servicios(AgenteEspecializado):
    id_agente = "ipv4_servicios"
    categoria = Categoria.IPV4_SERVICIOS
    herramientas = ("nmap", "nvd_api")

    def ejecutar(self, state: AuditState) -> list[Hallazgo]:
        # TODO(inc-1): ciclo ReAct —
        #   1. nmap -sV -6? sobre el objetivo IPv4
        #   2. parsear puertos/versiones
        #   3. correlacionar versión→CVE contra NVD
        #   4. emitir un Hallazgo por servicio vulnerable (GT-01..04)
        return []
