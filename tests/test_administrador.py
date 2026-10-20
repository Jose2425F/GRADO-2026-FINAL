"""Tests del nodo de consolidación / validación cruzada (sin langgraph)."""
from auditor_dualstack.agentes.administrador import AgenteAdministrador
from auditor_dualstack.modelos import Categoria, EstadoValidacion, Hallazgo


def test_consolidar_marca_verificados_y_deriva_severidad():
    admin = AgenteAdministrador()
    state = {
        "hallazgos": [
            Hallazgo(
                id_agente="ipv4_credenciales",
                categoria=Categoria.IPV4_CREDENCIALES,
                titulo="msfadmin:msfadmin en SSH",
                cvss=9.8,
            )
        ]
    }
    salida = admin.consolidar(state)
    validados = salida["hallazgos_validados"]
    assert len(validados) == 1
    assert validados[0].validacion is EstadoValidacion.VERIFICADO
    assert validados[0].severidad.value == "critical"
    assert salida["bitacora_no_verificados"] == []


def test_planificar_inicializa_metricas():
    admin = AgenteAdministrador()
    salida = admin.planificar({})
    assert salida["metricas"]["abortada_por_disyuntor"] is False
