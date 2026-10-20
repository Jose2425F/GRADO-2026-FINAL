"""Construcción del grafo de estado LangGraph (arquitectura de 6 componentes).

Topología (el paralelismo de los cuatro especialistas es la propiedad que
sustenta el KPI TRTO):

    START
      │
      ▼
   planificar (administrador)
      ├──────────────┬──────────────┬──────────────┐
      ▼              ▼              ▼              ▼
 ipv4_servicios ipv4_credenciales ipv6_ndp_slaac ipv6_fragmentacion   (en paralelo)
      └──────────────┴──────────────┴──────────────┘
      ▼
   consolidar (administrador · validación cruzada)
      ▼
   reportes
      ▼
     END

Los cuatro especialistas escriben en `hallazgos` (reductor add); LangGraph
espera a que los cuatro terminen antes de entrar a `consolidar` (fan-in).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .agentes.administrador import AgenteAdministrador
from .agentes.ipv4_credenciales import AgenteIPv4Credenciales
from .agentes.ipv4_servicios import AgenteIPv4Servicios
from .agentes.ipv6_fragmentacion import AgenteIPv6Fragmentacion
from .agentes.ipv6_ndp_slaac import AgenteIPv6NdpSlaac
from .estado import AuditState
from .reportes import nodo_reportes

if TYPE_CHECKING:  # pragma: no cover
    from langgraph.graph.state import CompiledStateGraph

# Instancias de los agentes especializados (paralelizables).
AGENTES_ESPECIALIZADOS = (
    AgenteIPv4Servicios(),
    AgenteIPv4Credenciales(),
    AgenteIPv6NdpSlaac(),
    AgenteIPv6Fragmentacion(),
)


def construir_grafo() -> "CompiledStateGraph":
    """Arma y compila el grafo del prototipo multi-agente."""
    from langgraph.graph import END, START, StateGraph

    admin = AgenteAdministrador()
    grafo = StateGraph(AuditState)

    # Nodos del administrador (entrada y convergencia)
    grafo.add_node("planificar", admin.planificar)
    grafo.add_node("consolidar", admin.consolidar)

    # Nodos de los agentes especializados
    for agente in AGENTES_ESPECIALIZADOS:
        grafo.add_node(agente.id_agente, agente.como_nodo())

    # Nodo del módulo de reportes
    grafo.add_node("reportes", nodo_reportes)

    # Aristas: entrada → especialistas (en paralelo) → convergencia
    grafo.add_edge(START, "planificar")
    for agente in AGENTES_ESPECIALIZADOS:
        grafo.add_edge("planificar", agente.id_agente)
        grafo.add_edge(agente.id_agente, "consolidar")

    grafo.add_edge("consolidar", "reportes")
    grafo.add_edge("reportes", END)

    return grafo.compile()
