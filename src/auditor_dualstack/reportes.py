"""Módulo de Reportes (RF-07).

Consolida los hallazgos validados y genera el informe de remediación priorizado
por severidad CVSS. En el incremento 5 producirá JSON estructurado + PDF; en el
incremento 0 emite un resumen JSON en disco para cerrar el flujo del grafo.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .estado import AuditState
from .modelos import Hallazgo, Severidad

# Orden de prioridad para el informe (crítico primero).
_ORDEN_SEVERIDAD = {
    Severidad.CRITICA: 0,
    Severidad.ALTA: 1,
    Severidad.MEDIA: 2,
    Severidad.BAJA: 3,
    Severidad.INFO: 4,
}

DIR_REPORTES = Path("reportes_generados")


def _priorizar(hallazgos: list[Hallazgo]) -> list[Hallazgo]:
    return sorted(hallazgos, key=lambda h: (_ORDEN_SEVERIDAD[h.severidad], -h.cvss))


def generar_informe(state: AuditState, dir_salida: Path = DIR_REPORTES) -> str:
    """Escribe el informe de remediación y devuelve su ruta."""
    dir_salida.mkdir(parents=True, exist_ok=True)
    validados = _priorizar(state.get("hallazgos_validados", []))
    no_verificados = state.get("bitacora_no_verificados", [])
    objetivo = state.get("objetivo")

    marca = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ruta = dir_salida / f"informe_{marca}.json"

    informe = {
        "generado_utc": marca,
        "objetivo": objetivo.model_dump() if objetivo else None,
        "resumen": {
            "total_validados": len(validados),
            "total_no_verificados": len(no_verificados),
            "por_severidad": {
                sev.value: sum(1 for h in validados if h.severidad is sev) for sev in Severidad
            },
        },
        "hallazgos": [h.model_dump(mode="json") for h in validados],
        "bitacora_no_verificados": [h.model_dump(mode="json") for h in no_verificados],
    }
    ruta.write_text(json.dumps(informe, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(ruta)


def nodo_reportes(state: AuditState) -> dict:
    """Nodo LangGraph del módulo de reportes."""
    return {"ruta_informe": generar_informe(state)}
