"""Agente Administrador (RF-02, RF-08): orquestador + validación cruzada.

Cumple dos funciones dentro del grafo, sin añadir un nodo extra por función:

  * `planificar`  — nodo de entrada. Fija el objetivo y despacha (en paralelo)
    a los cuatro agentes especializados.
  * `consolidar`  — nodo de convergencia. Aplica el protocolo de validación
    cruzada a los hallazgos y separa los verificados de los no verificados
    (bitácora) antes de que lleguen al módulo de reportes.

Protocolo de validación cruzada (numeral 1.6.3). Un hallazgo se acepta solo si
cumple las tres condiciones:
  1. La salida de la herramienta es reproducible y contrastable con un patrón
     documentado.
  2. El CVE-ID o RFC asociado existe en la NVD consultada por API.
  3. El agente especializado reproduce el hallazgo con un prompt de
     verificación distinto del original.

Estado: stub del incremento 0. La validación real (consultas NVD + re-prompting)
corresponde al incremento 5; aquí `consolidar` deja pasar todos los hallazgos
como verificados para que el grafo compile y fluya de punta a punta.
"""
from __future__ import annotations

from ..estado import AuditState
from ..modelos import EstadoValidacion, Hallazgo


class AgenteAdministrador:
    id_agente = "administrador"

    # ── Nodo de entrada ───────────────────────────────────────────────
    def planificar(self, state: AuditState) -> dict:
        """Prepara la corrida. En el incremento 5 decidirá dinámicamente qué
        agentes activar según el objetivo; por ahora inicializa la telemetría."""
        metricas = state.get("metricas", {})
        return {"metricas": {**metricas, "abortada_por_disyuntor": False}}

    # ── Nodo de convergencia ──────────────────────────────────────────
    def consolidar(self, state: AuditState) -> dict:
        """Aplica la validación cruzada y reparte hallazgos verificados vs. no."""
        verificados: list[Hallazgo] = []
        no_verificados: list[Hallazgo] = []

        for hallazgo in state.get("hallazgos", []):
            hallazgo = hallazgo.con_severidad_derivada()
            if self._validar(hallazgo, state):
                verificados.append(hallazgo.model_copy(update={"validacion": EstadoValidacion.VERIFICADO}))
            else:
                no_verificados.append(hallazgo.model_copy(update={"validacion": EstadoValidacion.NO_VERIFICADO}))

        return {
            "hallazgos_validados": verificados,
            "bitacora_no_verificados": no_verificados,
        }

    def _validar(self, hallazgo: Hallazgo, state: AuditState) -> bool:
        # TODO(inc-5): protocolo de validación cruzada de tres condiciones —
        #   1. reproducibilidad de la evidencia de la herramienta
        #   2. existencia del CVE/RFC en NVD (tools.nvd_api)
        #   3. reproducción por re-prompting del agente especializado
        # En el incremento 0 se acepta todo para permitir el flujo end-to-end.
        return True
