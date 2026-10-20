"""Adaptador de Hydra para el Agente IPv4-Credenciales.

Stub del incremento 0. La ejecución (subprocess a `hydra` con listas de
credenciales configurables) se implementa en el incremento 2 y corre en Kali.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CredencialDebil:
    servicio: str
    puerto: int
    usuario: str
    clave: str


def probar_credenciales(
    objetivo: str,
    servicio: str,
    puerto: int,
    lista_usuarios: str,
    lista_claves: str,
) -> list[CredencialDebil]:
    """Prueba autenticación débil. Implementación real en el incremento 2."""
    raise NotImplementedError("hydra_tool.probar_credenciales se implementa en el incremento 2 (Kali)")
