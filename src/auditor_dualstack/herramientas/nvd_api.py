"""Cliente de la NVD (National Vulnerability Database) para la validación
cruzada del agente administrador (RF-08, condición 2).

Verifica que un CVE-ID exista y recupera su score CVSS base. Stub del
incremento 0; la consulta HTTP real (con o sin NVD_API_KEY) se implementa en el
incremento 5.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RegistroCVE:
    cve_id: str
    existe: bool
    cvss_v31: float = 0.0
    descripcion: str = ""


def consultar_cve(cve_id: str, api_key: str | None = None) -> RegistroCVE:
    """Consulta un CVE en la NVD. Implementación real en el incremento 5."""
    raise NotImplementedError("nvd_api.consultar_cve se implementa en el incremento 5")
