"""Protocolo reproducible de 25 parejas manuales; no ejecuta auditorías.

``schedule()`` devuelve las 50 posiciones en orden. ``protocol()`` añade la
configuración y su huella. ``next_slot(recorded)`` consume primeros intentos,
incluidos fallos, y ``validate_next(options, recorded)`` comprueba la siguiente
selección del panel. La autorización y prueba de una
restauración nueva deben verificarse en el servidor antes de ejecutar.

No importa evaluacion_manual, motores, proveedores ni bibliotecas de red.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
from random import Random

STUDY_ID = "langgraph_manual_20261018"
PROTOCOL_VERSION = "3"
PROTOCOL_ID = "novaflow-langgraph-manual-3"
SEED = 20261018
SCENARIOS = ("integrado", "sucursal", "comercial", "mixto", "reforzado")
ARCHITECTURES = ("single", "multiagent")
PAIRS_PER_SCENARIO = 5
MODEL = "gpt-6.1-sol"
TOKENS = 60_000
MAX_COST_USD = 2.0
CATALOG_TASK_COUNTS = {"integrado": 32, "sucursal": 25, "comercial": 28, "mixto": 32, "reforzado": 37}
PROPOSED_TASK_LIMITS = {name: total * 3 // 5 for name, total in CATALOG_TASK_COUNTS.items()}
# Cálculo exacto offline del cierre de dependencias, proporcionado por el análisis
# de referencia. No procede de llamadas LLM ni modifica los planes del auditor.
MINIMUM_PRESENT_COVER = {"integrado": 12, "sucursal": 9, "comercial": 10, "mixto": 10, "reforzado": 3}
# empresa_agent.request fija 2400; AuditRequest admite como máximo 3600.
# Registrar el techo del contrato no cambia el plazo operativo seleccionado.
MAX_RUNTIME_SECONDS = 2400
CONTRACT_RUNTIME_CEILING_SECONDS = 3600


def schedule():
    """Lista nueva de 50 posiciones, con parejas consecutivas y orden fijo.

    Se sortean tres laboratorios con mayoría de agente único primero. Cada uno
    contiene tres parejas U→M y dos M→U; los otros dos invierten esa proporción.
    El orden de los cinco primeros de cada laboratorio se baraja con la misma
    semilla. Resultado: 13 parejas U→M y 12 M→U, sin aleatoriedad en ejecución.
    """
    rng = Random(SEED)
    majority = list(SCENARIOS)
    rng.shuffle(majority)
    single_majority = set(majority[:3])
    rows = []
    for scenario in SCENARIOS:
        firsts = ["single"] * (3 if scenario in single_majority else 2)
        firsts += ["multiagent"] * (PAIRS_PER_SCENARIO - len(firsts))
        rng.shuffle(firsts)
        for pair, first in enumerate(firsts, 1):
            second = "multiagent" if first == "single" else "single"
            for pair_position, architecture in enumerate((first, second), 1):
                sequence = len(rows) + 1
                rows.append({"slot": sequence, "sequence": sequence,
                    "study_id": STUDY_ID, "protocol_version": PROTOCOL_VERSION,
                    "scenario": scenario, "pair": pair, "architecture": architecture,
                    "first_architecture": first, "pair_position": pair_position,
                    "restore_required": True, "preflight_required": True})
    return rows


def protocol():
    """Protocolo JSON determinista; ambas huellas excluyen los campos de huella.

    No incluye fechas de generación, rutas absolutas ni resultados. Una revisión
    del diseño requiere otra versión, no reemplazar silenciosamente la propuesta.
    El 60 % con redondeo hacia abajo fue autorizado por el usuario. No cumple la
    condición de excluir todas las rutas positivas: sus mínimos caben en el tope.
    """
    value = {"schema_version": 1, "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION, "study_id": STUDY_ID,
        "status": "frozen", "state": "confirmed",
        "seed": SEED, "model": MODEL, "tokens": TOKENS,
        "max_cost_usd": MAX_COST_USD, "max_runtime_seconds": MAX_RUNTIME_SECONDS,
        "task_limit_status": "confirmed", "task_limit": None,
        "proposed_task_limit": None, "proposed_task_fraction": 0.6,
        "proposed_task_limits": dict(PROPOSED_TASK_LIMITS), "task_limits": dict(PROPOSED_TASK_LIMITS),
        "catalog_task_counts": dict(CATALOG_TASK_COUNTS),
        "task_fraction": 0.6,
        "task_limit_rounding": "floor(catalogue_tasks * 3 / 5)", "task_limit_applied": True,
        "task_limit_policy": "proportional_catalogue_60_percent",
        "structural_validation": {"satisfied": False, "method": "exact_offline_dependency_closure_no_llm",
            "minimum_tasks_for_all_present_conditions": dict(MINIMUM_PRESENT_COVER),
            "required_condition": "El límite debe ser menor que el mínimo necesario para cubrir todas las condiciones presentes y sus dependencias.",
            "note": "Los mínimos de los cinco laboratorios caben dentro de los límites autorizados. Se limita la cobertura de tareas al 60 %, pero no se garantiza impedir todos los positivos; IDE puede ser 0 %. No se usa la referencia reservada para planificar."},
        "alternative_strict_task_limits": {name: minimum - 1 for name, minimum in MINIMUM_PRESENT_COVER.items()},
        "task_limit_record_required_per_run": True,
        "execution_enabled": True,
        "planned_laboratories": len(SCENARIOS), "pairs_per_laboratory": PAIRS_PER_SCENARIO,
        "planned_pairs": 25, "planned_runs": 50,
        "scenarios": list(SCENARIOS),
        "randomization": {"algorithm": "python-random-shuffle-stratified-v1",
            "seed": SEED, "laboratory_order": "fixed",
            "first_architecture_balance_per_laboratory": [3, 2],
            "first_architecture_balance_global": {"single": 13, "multiagent": 12},
            "randomize_at_execution": False},
        "restoration": {"required_before_every_slot": True,
            "preflight_after_restore_required": True, "reuse_between_slots": False,
            "receipt_required_for_exact_slot": True},
        "limits": {"model": MODEL, "tokens_per_run": TOKENS,
            "max_cost_usd_per_run": MAX_COST_USD,
            "max_runtime_seconds_per_run": MAX_RUNTIME_SECONDS,
            "audit_request_contract_ceiling_seconds": CONTRACT_RUNTIME_CEILING_SECONDS,
            "runtime_source": "piloto_kali/prototipo/src/auditoria/empresa_agent.py:request",
            "contract_source": "piloto_kali/prototipo/src/auditoria/contracts.py:AuditRequest",
            "runtime_limit_applied_by_this_module": False,
            "cost_limit_applied_by_this_module": False,
            "cost_note": "El tope de USD 2 corresponde a cada corrida; no es un consumo previsto ni autorización para gastar USD 100."},
        "attempt_policy": {"first_attempt_only": True,
            "failed_attempt_consumes_slot": True, "replace_failed_attempt": False,
            "out_of_order_attempts": "reject_before_execution",
            "order_gaps": "require_review_before_continuing"},
        "configuration_status": "Límite del 60 % confirmado. La aceptación funcional sin IA conserva el catálogo completo y no ocupa posiciones del estudio. La cobertura positiva completa sigue siendo posible.",
        "schedule": schedule()}
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return {**value, "protocol_sha256": digest, "sha256": digest}


def _recorded_positions(recorded):
    """Acepta números de posición o filas/contextos de primeros intentos.

    Filas directas: scenario/pair/architecture; también se aceptan corridas con
    manual_context anidado. Filas de otro study_id se omiten. El llamador debe
    filtrar prácticas sin etiqueta antes de pasar filas directas sin study_id.
    El estado del resultado no interviene: una falla también ocupa la posición.
    """
    rows = schedule()
    by_key = {(row["scenario"], row["pair"], row["architecture"]): row["slot"] for row in rows}
    positions = set()
    for item in recorded or ():
        if type(item) is int:
            if not 1 <= item <= len(rows):
                raise ValueError("Posición registrada fuera del protocolo.")
            positions.add(item)
            continue
        if not isinstance(item, dict):
            raise ValueError("Registro de posición inválido.")
        context = item.get("manual_context", item)
        if not isinstance(context, dict):
            continue
        study_id = context.get("study_id", item.get("study_id", STUDY_ID))
        if study_id != STUDY_ID:
            continue
        scenario = context.get("scenario", item.get("scenario")) or "integrado"
        pair = context.get("pair", item.get("pair"))
        architecture = context.get("architecture", item.get("architecture"))
        if type(pair) is not int or not isinstance(scenario, str) or not isinstance(architecture, str):
            raise ValueError("La posición registrada no identifica laboratorio, pareja y arquitectura.")
        position = by_key.get((scenario, pair, architecture))
        if position is None:
            raise ValueError("La posición registrada pertenece a otro catálogo.")
        declared = item.get("sequence", item.get("slot"))
        if declared is not None and (type(declared) is not int or declared != position):
            raise ValueError("El número de posición no coincide con el orden del protocolo.")
        positions.add(position)
    return positions


def next_slot(recorded=()):
    """Primera posición sin intento; ``None`` cuando las 50 ya tienen intento.

    Rechaza huecos: si alguien registró una posición futura no se salta a ella ni
    se oculta la ruptura del orden. Duplicados de una misma posición no avanzan.
    """
    positions = _recorded_positions(recorded)
    if positions and positions != set(range(1, max(positions) + 1)):
        raise ValueError("Hay intentos fuera de orden; revisa el registro antes de continuar.")
    rows = schedule()
    return rows[len(positions)] if len(positions) < len(rows) else None


def validate_next(options, recorded=()):
    """Comprueba sólo selección/orden; la confirmación y restauración son externas.

    ``options`` sigue el panel: scenario (vacío para integrado), architecture y
    manual_context con study_id/pair. No ejecuta ni valida límites del motor.
    """
    if not isinstance(options, dict) or not isinstance(options.get("manual_context"), dict):
        raise ValueError("Falta el contexto de la evaluación manual.")
    context = options["manual_context"]
    if context.get("study_id") != STUDY_ID or type(context.get("pair")) is not int:
        raise ValueError("El contexto no corresponde al protocolo manual.")
    expected = next_slot(recorded)
    if expected is None:
        raise ValueError("Las 50 posiciones del protocolo ya tienen un intento.")
    selected = (options.get("scenario") or "integrado", context["pair"], options.get("architecture"))
    required = (expected["scenario"], expected["pair"], expected["architecture"])
    if selected != required:
        raise ValueError(f"La siguiente posición es {expected['sequence']}: {expected['scenario']}, pareja {expected['pair']}, {expected['architecture']}.")
    return expected


def write_protocol(directory):
    """Persiste la propuesta JSON y sus 50 filas CSV; no reemplaza otro diseño."""
    directory = Path(directory)
    value = protocol()
    json_data = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    buffer = io.StringIO(newline="")
    fields = ["sequence", "slot", "study_id", "protocol_version", "protocol_sha256", "scenario", "pair",
              "architecture", "first_architecture", "pair_position", "restore_required", "preflight_required",
              "model", "tokens", "max_cost_usd", "max_runtime_seconds", "status", "task_limit_status",
              "proposed_task_limit", "task_limit", "catalog_task_count", "task_limit_applied"]
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in value["schedule"]:
        writer.writerow({**row, "protocol_sha256": value["protocol_sha256"], "model": MODEL,
            "tokens": TOKENS, "max_cost_usd": MAX_COST_USD, "max_runtime_seconds": MAX_RUNTIME_SECONDS,
            "status": value["status"], "task_limit_status": value["task_limit_status"],
            "proposed_task_limit": PROPOSED_TASK_LIMITS[row["scenario"]],
            "task_limit": PROPOSED_TASK_LIMITS[row["scenario"]],
            "catalog_task_count": CATALOG_TASK_COUNTS[row["scenario"]], "task_limit_applied": True})
    csv_data = buffer.getvalue().encode("utf-8")
    outputs = {directory/"PROTOCOLO_MANUAL_LANGGRAPH.json": json_data,
               directory/"PROTOCOLO_MANUAL_LANGGRAPH.csv": csv_data}
    for path, data in outputs.items():
        if path.is_symlink() or (path.exists() and path.read_bytes() != data):
            raise FileExistsError("Ya existe una propuesta diferente; publica otra versión sin reemplazarla.")
    directory.mkdir(parents=True, exist_ok=True)
    for path, data in outputs.items():
        if not path.exists():
            path.write_bytes(data)
    return {"protocol_sha256": value["protocol_sha256"], "sha256": value["sha256"],
            "json": str(next(iter(outputs))), "csv": str(list(outputs)[1]), "rows": len(value["schedule"]),
            "status": value["status"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", type=Path, metavar="DIRECTORY", help="Guardar la propuesta JSON/CSV sin ejecutar auditorías.")
    args = parser.parse_args()
    print(json.dumps(write_protocol(args.write) if args.write else protocol(), ensure_ascii=False, indent=2))
