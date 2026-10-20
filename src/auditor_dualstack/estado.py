"""Estado compartido del grafo LangGraph (`AuditState`).

El estado es el único canal de coordinación entre nodos. Los cuatro agentes
especializados corren en paralelo, por lo que las listas que ellos escriben
usan el reductor `operator.add`: LangGraph fusiona sus aportes sin que un
brazo pise el del otro. Los campos de un solo escritor no llevan reductor.
"""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from .modelos import Hallazgo, ObjetivoAuditoria


class MetricasCorrida(TypedDict, total=False):
    """Datos crudos que alimentan los KPIs (TRTO, IDE, ETV). El cálculo de los
    KPIs se hace en el arnés de evaluación (incremento 6), no aquí."""

    tokens_por_agente: dict[str, int]
    tokens_total: int
    segundos_por_agente: dict[str, float]
    segundos_total: float
    abortada_por_disyuntor: bool


class AuditState(TypedDict, total=False):
    """Estado que fluye por el grafo de una corrida de auditoría."""

    # Entrada
    objetivo: ObjetivoAuditoria

    # Escrito por los agentes especializados (en paralelo) → reductor add
    hallazgos: Annotated[list[Hallazgo], operator.add]

    # Bitácora de hallazgos descartados por la validación cruzada (RF-08)
    bitacora_no_verificados: Annotated[list[Hallazgo], operator.add]

    # Escrito solo por el administrador tras validar
    hallazgos_validados: list[Hallazgo]

    # Escrito solo por el módulo de reportes
    ruta_informe: str

    # Telemetría de la corrida
    metricas: MetricasCorrida
