"""Agente IPv6-Fragmentación (RF-06).

Prueba la conformidad con RFC 5722 (fragmentos solapados) y RFC 8200 §4.5
(cadenas de extension headers, fragmentos atómicos y tiny-fragment evasion)
según el modelo de Di Paolo et al. [20]. Detecta el bloque GT-13..GT-16.

Requiere root y una interfaz L2 real → solo corre en Kali. Estado: stub del
incremento 0. Implementación real en el incremento 4.
"""
from __future__ import annotations

from ..estado import AuditState
from ..modelos import Categoria, Hallazgo
from .base import AgenteEspecializado


class AgenteIPv6Fragmentacion(AgenteEspecializado):
    id_agente = "ipv6_fragmentacion"
    categoria = Categoria.IPV6_FRAGMENTACION
    herramientas = ("scapy_frag",)

    def ejecutar(self, state: AuditState) -> list[Hallazgo]:
        # TODO(inc-4): ciclo ReAct sobre Scapy —
        #   1. fragmentos solapados (sobre-escritura inicial/intermedia) → RFC 5722
        #   2. extension headers + fragmento atómico → evasión IDS (RFC 8200)
        #   3. tiny fragment evasion
        #   4. emitir un Hallazgo por caso no conforme (GT-13..16)
        return []
