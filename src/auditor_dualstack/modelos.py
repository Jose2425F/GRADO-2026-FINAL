"""Modelos de datos del dominio: objetivo de auditoría, hallazgos y severidad.

Estos tipos son el contrato entre los agentes especializados, el agente
administrador y el módulo de reportes. Un `Hallazgo` solo entra al informe
final si supera el protocolo de validación cruzada (RF-08).
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severidad(str, Enum):
    """Severidad CVSS v3.1 cualitativa."""

    CRITICA = "critical"
    ALTA = "high"
    MEDIA = "medium"
    BAJA = "low"
    INFO = "info"

    @classmethod
    def desde_cvss(cls, score: float) -> "Severidad":
        if score >= 9.0:
            return cls.CRITICA
        if score >= 7.0:
            return cls.ALTA
        if score >= 4.0:
            return cls.MEDIA
        if score > 0.0:
            return cls.BAJA
        return cls.INFO


class Categoria(str, Enum):
    """Las cuatro categorías del ground truth, una por agente especializado."""

    IPV4_SERVICIOS = "ipv4_servicios"
    IPV4_CREDENCIALES = "ipv4_credenciales"
    IPV6_NDP_SLAAC = "ipv6_ndp_slaac"
    IPV6_FRAGMENTACION = "ipv6_fragmentacion"


class EstadoValidacion(str, Enum):
    """Resultado del protocolo de validación cruzada del administrador."""

    PENDIENTE = "pendiente"
    VERIFICADO = "verificado"
    NO_VERIFICADO = "no_verificado"


class ObjetivoAuditoria(BaseModel):
    """Alcance técnico de una corrida de auditoría sobre el entorno dual-stack."""

    host_ipv4: str | None = None
    subred_ipv4: str | None = None  # p. ej. "192.168.56.0/24"
    host_ipv6: str | None = None
    prefijo_ipv6: str | None = None  # p. ej. "fd00::/64"
    interfaz: str = "eth0"           # interfaz de red en Kali
    descripcion: str = ""


class Hallazgo(BaseModel):
    """Una vulnerabilidad detectada por un agente especializado."""

    id_agente: str                       # qué agente lo produjo
    categoria: Categoria
    identificador: str = ""              # CVE-ID o RFC asociado
    titulo: str
    descripcion: str = ""
    cvss: float = 0.0
    severidad: Severidad = Severidad.INFO
    evidencia: str = ""                  # salida cruda de la herramienta (reproducible)
    herramienta: str = ""               # nmap | hydra | scapy
    validacion: EstadoValidacion = EstadoValidacion.PENDIENTE
    motivo_no_verificado: str = ""      # por qué se descartó, si aplica
    gt_id: str | None = None            # traza al ground truth (GT-01..16), si se conoce

    def con_severidad_derivada(self) -> "Hallazgo":
        """Devuelve una copia con la severidad calculada desde el CVSS."""
        return self.model_copy(update={"severidad": Severidad.desde_cvss(self.cvss)})
