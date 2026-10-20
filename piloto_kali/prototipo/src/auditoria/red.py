"""Comprobaciones de ruta compartidas por los agentes y el laboratorio."""

from __future__ import annotations

import json
import subprocess


class RouteDenied(RuntimeError):
    pass


def check_route(address: str, interface: str) -> None:
    """Rechaza rutas que el sistema enviaría por otra interfaz o gateway."""
    try:
        result = subprocess.run(
            ["ip", "-j", "route", "get", address], capture_output=True,
            text=True, timeout=5, check=True,
        )
        routes = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as exc:
        raise RouteDenied(f"no se pudo comprobar la ruta hacia {address}") from exc
    if not routes or routes[0].get("dev") != interface or routes[0].get("gateway"):
        actual = routes[0].get("dev") if routes else None
        raise RouteDenied(f"ruta por {actual!r} o con gateway; se esperaba {interface!r} directa")
