"""Agente IPv4-Credenciales (RF-04).

Evalúa autenticación débil con Hydra sobre los servicios identificados (SSH,
FTP, HTTP Basic, SMB, PostgreSQL, Tomcat…). Detecta el bloque GT-05..GT-08.

Estado: stub del incremento 0. Implementación real en el incremento 2.
"""
from __future__ import annotations

from ..estado import AuditState
from ..modelos import Categoria, Hallazgo
from .base import AgenteEspecializado


class AgenteIPv4Credenciales(AgenteEspecializado):
    id_agente = "ipv4_credenciales"
    categoria = Categoria.IPV4_CREDENCIALES
    herramientas = ("hydra",)

    def ejecutar(self, state: AuditState) -> list[Hallazgo]:
        # TODO(inc-2): ciclo ReAct —
        #   1. seleccionar servicios autenticables del estado
        #   2. hydra con listas de credenciales configurables
        #   3. emitir un Hallazgo por credencial débil/por defecto (GT-05..08)
        return []
