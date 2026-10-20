"""Capa de observabilidad y trazabilidad de los agentes (RF-09).

Registra las cadenas Thought–Action–Observation del patrón ReAct, las llamadas
a herramientas, los tokens por nodo y los tiempos, alimentando un dashboard
(Arize Phoenix; alternativa LangSmith). Cumple la trazabilidad exigida por el
control NIST SP 800-53 AU-2.

Stub del incremento 0: la instrumentación real se activa en el incremento 5
(depende del extra `obs` de pyproject).
"""
from __future__ import annotations

from .config import get_config


def iniciar_observabilidad() -> bool:
    """Activa el tracing si PHOENIX_ENABLED=true. Devuelve si quedó activo."""
    if not get_config().phoenix_habilitado:
        return False
    # TODO(inc-5): arrancar Phoenix e instrumentar LangChain/LangGraph
    #   from phoenix.otel import register
    #   register(project_name="auditor-dualstack")
    return False
