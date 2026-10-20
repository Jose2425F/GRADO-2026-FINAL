"""Test de integración del grafo end-to-end (requiere langgraph instalado).

Con agentes stub, el grafo debe compilar, correr de punta a punta, consolidar
sin hallazgos y generar un informe. Valida la orquestación, no la red.
"""
import importlib.util
from pathlib import Path

import pytest

from auditor_dualstack.modelos import ObjetivoAuditoria

# El grafo depende de langgraph; si no está instalado, se omite el test.
_TIENE_LANGGRAPH = importlib.util.find_spec("langgraph") is not None
pytestmark = pytest.mark.skipif(not _TIENE_LANGGRAPH, reason="langgraph no instalado")


def test_grafo_corre_end_to_end(tmp_path, monkeypatch):
    # Aísla los reportes generados en un directorio temporal.
    monkeypatch.chdir(tmp_path)

    from auditor_dualstack.grafo import construir_grafo

    grafo = construir_grafo()
    objetivo = ObjetivoAuditoria(host_ipv4="192.168.56.101", prefijo_ipv6="fd00::/64")
    resultado = grafo.invoke({"objetivo": objetivo})

    # Agentes stub → cero hallazgos, pero el flujo completa y genera informe.
    assert resultado.get("hallazgos_validados") == []
    ruta = resultado.get("ruta_informe")
    assert ruta and Path(ruta).exists()


def test_grafo_tiene_los_seis_componentes():
    from auditor_dualstack.grafo import construir_grafo

    grafo = construir_grafo()
    nodos = set(grafo.get_graph().nodes)
    esperados = {
        "planificar",
        "consolidar",
        "ipv4_servicios",
        "ipv4_credenciales",
        "ipv6_ndp_slaac",
        "ipv6_fragmentacion",
        "reportes",
    }
    assert esperados <= nodos
