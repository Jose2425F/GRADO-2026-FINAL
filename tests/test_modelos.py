"""Tests de los modelos de dominio (no requieren langgraph ni red)."""
from auditor_dualstack.modelos import (
    Categoria,
    EstadoValidacion,
    Hallazgo,
    Severidad,
)


def test_severidad_desde_cvss():
    assert Severidad.desde_cvss(10.0) is Severidad.CRITICA
    assert Severidad.desde_cvss(9.0) is Severidad.CRITICA
    assert Severidad.desde_cvss(7.5) is Severidad.ALTA
    assert Severidad.desde_cvss(5.3) is Severidad.MEDIA
    assert Severidad.desde_cvss(1.0) is Severidad.BAJA
    assert Severidad.desde_cvss(0.0) is Severidad.INFO


def test_hallazgo_deriva_severidad():
    h = Hallazgo(
        id_agente="ipv4_servicios",
        categoria=Categoria.IPV4_SERVICIOS,
        identificador="CVE-2011-2523",
        titulo="Backdoor vsftpd 2.3.4",
        cvss=10.0,
    )
    assert h.severidad is Severidad.INFO  # sin derivar
    derivado = h.con_severidad_derivada()
    assert derivado.severidad is Severidad.CRITICA
    assert derivado.validacion is EstadoValidacion.PENDIENTE
