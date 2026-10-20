"""Base común de los agentes especializados (patrón ReAct).

Cada agente especializado razona sobre el estado, selecciona una herramienta de
su dominio, ejecuta la acción y observa el resultado (ciclo
Thought–Action–Observation, Yao et al. [26]). Esta clase concentra lo que
comparten los cuatro: identidad, dominio de herramientas y la firma del nodo
que LangGraph invoca.

En el incremento 0 los agentes son *stubs*: declaran su interfaz y devuelven
una lista de hallazgos vacía. Cada `ejecutar` se implementa en su incremento
correspondiente (1–4).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..estado import AuditState
from ..modelos import Categoria, Hallazgo


class AgenteEspecializado(ABC):
    """Contrato de un agente especializado del prototipo."""

    id_agente: str
    categoria: Categoria
    herramientas: tuple[str, ...]  # dominio de herramientas (privilegio mínimo)

    @abstractmethod
    def ejecutar(self, state: AuditState) -> list[Hallazgo]:
        """Audita el objetivo dentro de su dominio y devuelve los hallazgos.

        No modifica el estado directamente: devuelve la lista que el nodo
        volcará en `state["hallazgos"]` (reductor add).
        """
        raise NotImplementedError

    def como_nodo(self):
        """Adapta el agente a un nodo de LangGraph.

        El nodo devuelve solo el fragmento de estado que le corresponde; el
        reductor de `hallazgos` fusiona los aportes de los agentes paralelos.
        """

        def nodo(state: AuditState) -> dict:
            hallazgos = self.ejecutar(state)
            return {"hallazgos": hallazgos}

        nodo.__name__ = self.id_agente
        return nodo
