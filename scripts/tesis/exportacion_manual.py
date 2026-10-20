"""Exportación pública y verificación offline de la evaluación manual.

Sólo admite columnas declaradas; no importa el panel, motores ni proveedores.
output_tokens representa salida facturable (incluye razonamiento); éste se
conserva como desglose y nunca vuelve a sumarse al total.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import re
import statistics
import zipfile

from .protocolo_manual import protocol as current_protocol

FIELDS = (
    "sequence", "scenario", "laboratory", "pair", "architecture", "status", "recorded", "run_id", "audit_id", "started_at", "seconds", "execution_seconds", "review_seconds",
    "input_tokens", "output_tokens", "text_output_tokens", "provider_output_tokens", "reasoning_tokens", "total_tokens",
    "known_tokens", "usage_complete", "token_usage_complete", "cost_estimate_usd", "known_cost_estimate_usd",
    "cost_limit_usd", "token_budget", "max_runtime_seconds", "TP", "FP", "FN", "TN", "unknown_negative_controls", "negative_conditions_total",
    "eligible_pair", "exclusion_reasons", "model", "reported_models", "protocol_sha256", "source_sha256",
    "graph_sha256", "ground_truth_sha256", "restoration_id", "recorded_protocol_sha256", "scope_sha256", "scenario_source_sha256",
    "images_sha256", "fixture_sha256", "adapter_sha256", "extensions_sha256", "graph_version", "langgraph_version",
    "api_generations", "fallbacks", "specialist_reviews_accepted", "specialist_reviews_expected", "evidence_valid", "task_limit", "catalogue_size", "executed_tasks", "task_limit_applied")
INTS = {"sequence", "pair", "input_tokens", "output_tokens", "text_output_tokens", "provider_output_tokens",
    "reasoning_tokens", "total_tokens", "known_tokens", "token_budget", "max_runtime_seconds", "TP", "FP", "FN", "TN",
    "unknown_negative_controls", "negative_conditions_total", "api_generations", "fallbacks", "specialist_reviews_accepted", "specialist_reviews_expected", "task_limit", "catalogue_size", "executed_tasks"}
NUMBERS = {"seconds", "execution_seconds", "review_seconds", "cost_estimate_usd", "known_cost_estimate_usd", "cost_limit_usd"}
BOOLS = {"recorded", "usage_complete", "token_usage_complete", "eligible_pair", "evidence_valid", "task_limit_applied"}
HASHES = {name for name in FIELDS if name.endswith("_sha256")} - {"extensions_sha256"}
MEASUREMENTS = (INTS | NUMBERS | BOOLS | HASHES | {"run_id", "audit_id", "started_at", "model", "reported_models", "restoration_id",
    "extensions_sha256", "graph_version", "langgraph_version"}) - {"sequence", "pair", "recorded", "protocol_sha256"}
METRICS = ("TRTO_percent", "IDE_percent", "ETV_ratio", "token_reduction_percent")
FILES = {"protocol.json", "runs.csv", "runs.json", "pairs.json", "summary.json", "matrix.json", "attempts_extra.json"}
STATES = {"complete", "partial", "failed", "interrupted", "running", "pending", "queued", "not_started", "not_initiated"}
_UNSAFE = re.compile(r"(?:https?|ftp|file)://|www\.|\bBearer\s+\S+|\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}|(?:api[_ -]?key|password|cookie|authorization)\s*[:=]", re.I)


def _text(value, maximum=500):
    if not isinstance(value, str) or len(value) > maximum or any(ord(char) < 32 for char in value) or _UNSAFE.search(value):
        raise ValueError("Texto fuera del esquema público de exportación.")
    return value


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Huella inválida en la exportación.")
    return value


def _number(value, integer=False):
    if type(value) not in ({int} if integer else {int, float}) or not math.isfinite(value) or value < 0:
        raise ValueError("Valor numérico inválido en la exportación.")
    return value


def _json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _public_protocol(value):
    """Allowlist estructural del protocolo puro, conservando su huella original."""
    template = current_protocol()

    def copy(item, schema):
        if isinstance(schema, dict):
            if not isinstance(item, dict):
                raise ValueError("Estructura de protocolo inválida.")
            return {key: copy(item[key], child) for key, child in schema.items() if key in item}
        if isinstance(schema, list):
            if not isinstance(item, list):
                raise ValueError("Lista de protocolo inválida.")
            return [copy(child, schema[0]) for child in item] if schema else []
        if isinstance(item, str):
            return _text(item, 1500)
        if item is None or type(item) is bool:
            return item
        return _number(item)

    result = copy(value, template)
    supplied = result.pop("protocol_sha256", None)
    alias = result.pop("sha256", supplied)
    digest = hashlib.sha256(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if supplied != digest or alias != digest:
        raise ValueError("La huella del protocolo no corresponde a su contenido público.")
    return {**result, "protocol_sha256": digest, "sha256": digest}


def _row(raw):
    if not isinstance(raw, dict):
        raise ValueError("Fila de corrida inválida.")
    result = {name: raw.get(name) for name in FIELDS}
    if type(result["recorded"]) is not bool:
        raise ValueError("Cada posición debe indicar si tiene intento registrado.")
    for key in MEASUREMENTS:
        if not result["recorded"]:
            result[key] = None
    result["exclusion_reasons"] = raw.get("exclusion_reasons") or []
    for name, value in result.items():
        if value is None:
            continue
        if name in INTS:
            _number(value, True)
        elif name in NUMBERS:
            _number(value)
        elif name in BOOLS:
            if type(value) is not bool:
                raise ValueError("Indicador booleano inválido.")
        elif name in HASHES:
            _hash(value)
        elif name == "extensions_sha256":
            if not isinstance(value, dict):
                raise ValueError("Inventario de extensiones inválido.")
            for path, digest in value.items():
                _text(path, 150)
                if path.startswith('/') or '..' in path.split('/') or ':' in path:
                    raise ValueError("Ruta de extensión no pública.")
                _hash(digest)
        elif name in {"reported_models", "exclusion_reasons"}:
            if not isinstance(value, list) or len(value) > 50:
                raise ValueError("Lista pública inválida.")
            for text in value:
                _text(text, 100 if name == "reported_models" else 700)
        else:
            _text(value, 250)
    if result["scenario"] not in current_protocol()["scenarios"] or result["architecture"] not in {"single", "multiagent"}:
        raise ValueError("Laboratorio o arquitectura fuera del protocolo.")
    if result["status"] not in STATES:
        raise ValueError("Estado de corrida no público.")
    if result["laboratory"] and result["laboratory"][0] in "=+@-":
        raise ValueError("Nombre no apto para CSV.")
    if result["run_id"] and (result["run_id"].startswith('/') or '..' in result["run_id"].split('/') or ':' in result["run_id"]):
        raise ValueError("Identificador de corrida no público.")
    return result


def _rows(summary, proposal):
    source = summary.get("records")
    if not isinstance(source, list) or len(source) != 50:
        raise ValueError("La exportación requiere las 50 posiciones, incluidas las no iniciadas.")
    rows = [_row(raw) for raw in source]
    if len({row["sequence"] for row in rows}) != 50:
        raise ValueError("Hay posiciones duplicadas en el registro principal.")
    rows.sort(key=lambda row: row["sequence"])
    for row, slot in zip(rows, proposal["schedule"]):
        if any(row[name] != slot[name] for name in ("sequence", "scenario", "pair", "architecture")):
            raise ValueError("Una posición no corresponde al orden del protocolo.")
    extras = summary.get("records_extra", [])
    if not isinstance(extras, list):
        raise ValueError("Registro de intentos adicionales inválido.")
    return rows, [_row(raw) for raw in extras]


def _csv(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: "" if row[name] is None else json.dumps(row[name], ensure_ascii=False, sort_keys=True)
            if isinstance(row[name], (list, dict)) else row[name] for name in FIELDS})
    return output.getvalue().encode("utf-8")


def export_csv(summary):
    """CSV de 50 posiciones. Los valores no medidos quedan como celda vacía."""
    rows, _ = _rows(summary, _public_protocol(summary.get("protocol") or current_protocol()))
    return _csv(rows)


def _stats(values):
    return {"n": len(values), "mean": statistics.fmean(values) if values else None,
        "stddev": statistics.stdev(values) if len(values) > 1 else None,
        "min": min(values) if values else None, "max": max(values) if values else None}


def _pair(single, multi, proposal):
    reasons = list(dict.fromkeys(single["exclusion_reasons"] + multi["exclusion_reasons"]))
    for row in (single, multi):
        if not row["recorded"] or row["status"] != "complete":
            reasons.append("Falta un primer intento completo en ambas arquitecturas.")
            continue
        if row["eligible_pair"] is not True:
            reasons.append("La evaluación registrada no declara apta esta pareja.")
        if row["usage_complete"] is not True or row["token_usage_complete"] is not True:
            reasons.append("El consumo de tokens está incompleto.")
        if row["evidence_valid"] is not True:
            reasons.append("La evidencia ejecutada no está validada.")
        if (type(row['negative_conditions_total']) is not int or type(row['unknown_negative_controls']) is not int
            or type(row['TN']) is not int or row['TN']+row['unknown_negative_controls']>row['negative_conditions_total']):
            reasons.append('Falta distinguir controles negativos comprobados y no examinados.')
        if row["model"] != proposal["model"] or not row["reported_models"] or len(set(row["reported_models"])) != 1:
            reasons.append("El modelo solicitado o el modelo real no están acreditados.")
        if row["fallbacks"] != 0 or not row["api_generations"]:
            reasons.append("No se acredita participación por API sin decisiones de respaldo.")
        expected = row['specialist_reviews_expected']
        if (type(expected) is not int or not 1<=expected<=(1 if row['architecture']=='single' else 5)
            or row["specialist_reviews_accepted"] != expected):
            reasons.append("Faltan revisiones aceptadas para los roles previstos.")
        if row["token_budget"] != proposal["tokens"] or row["cost_limit_usd"] != proposal["max_cost_usd"] or row["max_runtime_seconds"] != proposal["max_runtime_seconds"]:
            reasons.append("Los límites registrados no corresponden al protocolo.")
        task_limits = proposal.get("task_limits")
        expected_limit = task_limits.get(row["scenario"]) if isinstance(task_limits, dict) else proposal.get("task_limit")
        if expected_limit is not None and row["task_limit"] != expected_limit:
            reasons.append("El límite de tareas capturado no corresponde al laboratorio.")
        if (row['task_limit_applied'] is not True or row['catalogue_size']!=proposal['catalog_task_counts'][row['scenario']]
            or type(row['executed_tasks']) is not int or not 0<row['executed_tasks']<=expected_limit):
            reasons.append('El presupuesto de tareas aplicado no concilia con el protocolo.')
        if row["recorded_protocol_sha256"] != proposal["protocol_sha256"]:
            reasons.append("La corrida no acredita la huella del protocolo efectivamente capturada.")
        total = row["total_tokens"]
        if (type(total) is not int or total <= 0 or total != row["known_tokens"] or total > proposal["tokens"]
            or type(row["input_tokens"]) is not int or type(row["provider_output_tokens"]) is not int
            or total != row["input_tokens"] + row["provider_output_tokens"]
            or row["output_tokens"] != row["provider_output_tokens"]):
            reasons.append("El desglose de tokens no concilia con el total facturable.")
        if (row["text_output_tokens"] is not None and row["reasoning_tokens"] is not None
            and row["text_output_tokens"] + row["reasoning_tokens"] != row["provider_output_tokens"]):
            reasons.append("El desglose de texto y razonamiento no concilia con la salida facturable.")
        if row["cost_estimate_usd"] is None or row["cost_estimate_usd"] > proposal["max_cost_usd"]:
            reasons.append("El costo no está completo o excede el límite por corrida.")
        if row["seconds"] is None or row["seconds"] <= 0 or row["seconds"] > proposal["max_runtime_seconds"]:
            reasons.append("El tiempo no está medido o excede el límite.")
        if any(row[name] is None for name in ("TP", "FP", "FN", "TN", "restoration_id")):
            reasons.append("Faltan conteos de referencia o identidad de restauración.")
    identities = ("protocol_sha256", "source_sha256", "graph_sha256", "ground_truth_sha256", "scope_sha256",
        "scenario_source_sha256", "images_sha256", "fixture_sha256", "adapter_sha256", "extensions_sha256",
        "graph_version", "langgraph_version")
    if any(not single[name] or single[name] != multi[name] for name in identities):
        reasons.append("Las identidades de código, grafo, catálogo, imágenes o referencia no coinciden.")
    if single["protocol_sha256"] != proposal["protocol_sha256"] or multi["protocol_sha256"] != proposal["protocol_sha256"]:
        reasons.append("La huella del protocolo no corresponde a la propuesta exportada.")
    if single["reported_models"] != multi["reported_models"]:
        reasons.append("Los modelos reales son diferentes.")
    if single["task_limit"] != multi["task_limit"]:
        reasons.append("Los límites de tareas son diferentes entre arquitecturas.")
    if single["restoration_id"] and single["restoration_id"] == multi["restoration_id"]:
        reasons.append("Una restauración se reutilizó entre posiciones.")
    counts = all(type(row[name]) is int for row in (single, multi) for name in ("TP", "FP", "FN", "TN"))
    if counts and (single["TP"] + single["FN"] != multi["TP"] + multi["FN"] or single['negative_conditions_total']!=multi['negative_conditions_total']):
        reasons.append("Las condiciones positivas o negativas de referencia son distintas.")
    eligible = not reasons
    metrics = dict.fromkeys(METRICS)
    if eligible:
        metrics["TRTO_percent"] = (single["seconds"] - multi["seconds"]) / single["seconds"] * 100
        metrics["token_reduction_percent"] = (single["total_tokens"] - multi["total_tokens"]) / single["total_tokens"] * 100
        if single["TP"] > 0:
            metrics["IDE_percent"] = (multi["TP"] - single["TP"]) / single["TP"] * 100
        if single["TP"] > 0 and multi["TP"] > 0:
            metrics["ETV_ratio"] = (single["total_tokens"] / single["TP"]) / (multi["total_tokens"] / multi["TP"])
    return {"pair": single["pair"], "eligible": eligible, "complete": eligible,
        "reasons": list(dict.fromkeys(reasons)), "metrics": metrics,
        "single": {name: single[name] for name in ("run_id", "status", "sequence", "recorded")},
        "multiagent": {name: multi[name] for name in ("run_id", "status", "sequence", "recorded")}}


def _analysis(rows, extras, proposal):
    groups = []
    all_metrics = {key: [] for key in METRICS}
    by_key = {(row["scenario"], row["pair"], row["architecture"]): row for row in rows}
    for scenario in proposal["scenarios"]:
        group_rows = [row for row in rows if row["scenario"] == scenario]
        pairs = [_pair(by_key[(scenario, pair, "single")], by_key[(scenario, pair, "multiagent")], proposal) for pair in range(1, 6)]
        values = {key: [pair["metrics"][key] for pair in pairs if pair["metrics"][key] is not None] for key in METRICS}
        for key in METRICS:
            all_metrics[key].extend(values[key])
        groups.append({"id": scenario, "laboratory": group_rows[0]["laboratory"], "pairs": pairs,
            "planned_runs": 10, "recorded_runs": sum(row["recorded"] for row in group_rows),
            "completed_runs": sum(row["recorded"] and row["status"] == "complete" for row in group_rows),
            "failed_runs": sum(row["recorded"] and row["status"] not in {"complete", "running", "pending", "queued"} for row in group_rows),
            "eligible_pairs": sum(pair["eligible"] for pair in pairs),
            "analysis": {key: _stats(numbers) for key, numbers in values.items()}})
    matrix = [{key: group[key] for key in ("id", "laboratory", "planned_runs", "recorded_runs", "completed_runs", "failed_runs", "eligible_pairs")} for group in groups]
    result = {"schema_version": 1, "protocol_sha256": proposal["protocol_sha256"],
        "planned_runs": 50, "planned_pairs": 25, "recorded_runs": sum(row["recorded"] for row in rows),
        "not_started_runs": sum(not row["recorded"] for row in rows), "extra_attempts": len(extras),
        "eligible_pairs": sum(group["eligible_pairs"] for group in groups),
        "analysis": {key: _stats(values) for key, values in all_metrics.items()},
        "note": "Resultados descriptivos por laboratorio; el agregado no demuestra causalidad. IDE o ETV son indefinidos cuando su denominador es cero.",
        "verification_scope": "Integridad y recálculo de datos públicos; no reproduce herramientas ni vuelve a adjudicar evidencia o texto del proveedor."}
    return result, groups, matrix


def export_zip(summary, protocol):
    """ZIP determinista con datos públicos, recálculo y manifiesto de hashes."""
    proposal = _public_protocol(protocol)
    rows, extras = _rows(summary, proposal)
    aggregate, groups, matrix = _analysis(rows, extras, proposal)
    payloads = {"protocol.json": _json(proposal), "runs.csv": _csv(rows), "runs.json": _json(rows),
        "pairs.json": _json(groups), "summary.json": _json(aggregate), "matrix.json": _json(matrix),
        "attempts_extra.json": _json(extras)}
    manifest = {"schema_version": 1, "format": "novaflow-manual-public-export-1",
        "protocol_sha256": proposal["protocol_sha256"], "planned_rows": 50,
        "manifest_not_self_hashed": True,
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in payloads.items()}}
    payloads["manifest.json"] = _json(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(payloads):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, payloads[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def verify_export(data):
    """Valida ZIP/schema/huellas y recalcula métricas desde runs.json sin panel/API."""
    errors = []
    result = {"valid": False, "errors": errors, "warnings": [], "counts": {}, "analysis": {}, "scenarios": []}
    try:
        if not isinstance(data, bytes) or len(data) > 10_000_000:
            raise ValueError("Tamaño o formato de archivo inválido.")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or set(names) != FILES | {"manifest.json"}:
                raise ValueError("Faltan archivos o hay nombres duplicados/no permitidos.")
            if sum(item.file_size for item in archive.infolist()) > 10_000_000:
                raise ValueError("Contenido descomprimido demasiado grande.")
            payloads = {name: archive.read(name) for name in names}
        manifest = json.loads(payloads["manifest.json"])
        if manifest.get("schema_version") != 1 or set(manifest.get("files", {})) != FILES:
            raise ValueError("Manifiesto incompatible.")
        for name in FILES:
            expected = manifest["files"][name]
            if expected != {"sha256": hashlib.sha256(payloads[name]).hexdigest(), "bytes": len(payloads[name])}:
                errors.append("No coincide la huella o tamaño de " + name + ".")
        if errors:
            return result
        raw_protocol = json.loads(payloads["protocol.json"])
        proposal = _public_protocol(raw_protocol)
        if proposal != raw_protocol or manifest.get("protocol_sha256") != proposal["protocol_sha256"]:
            raise ValueError("Protocolo o identidad del manifiesto incompatible.")
        raw_rows = json.loads(payloads["runs.json"])
        raw_extras = json.loads(payloads["attempts_extra.json"])
        rows, extras = _rows({"records": raw_rows, "records_extra": raw_extras}, proposal)
        if rows != raw_rows or extras != raw_extras or payloads["runs.csv"] != _csv(rows):
            raise ValueError("JSON/CSV incompatibles o columnas fuera del esquema público.")
        aggregate, groups, matrix = _analysis(rows, extras, proposal)
        for name, expected in (("summary.json", aggregate), ("pairs.json", groups), ("matrix.json", matrix)):
            if json.loads(payloads[name]) != expected:
                errors.append("El recálculo no coincide con " + name + ".")
        run_ids = [row["run_id"] for row in rows if row["recorded"] and row["run_id"]]
        if len(run_ids) != len(set(run_ids)):
            errors.append("Una corrida ocupa varias posiciones del registro principal.")
        for group in groups:
            for pair in group["pairs"]:
                claimed = [row for row in rows if row["scenario"] == group["id"] and row["pair"] == pair["pair"]]
                if any(row["eligible_pair"] is True for row in claimed) and not pair["eligible"]:
                    errors.append(f"La pareja {group['id']}/{pair['pair']} se declara apta pero sus datos no son compatibles.")
        result.update(valid=not errors, counts={key: aggregate[key] for key in ("planned_runs", "planned_pairs", "recorded_runs", "not_started_runs", "extra_attempts", "eligible_pairs")},
                      analysis=aggregate["analysis"], scenarios=groups)
        if any(pair["eligible"] and any(value is None for value in pair["metrics"].values()) for group in groups for pair in group["pairs"]):
            result["warnings"].append("Hay métricas indefinidas por denominadores nulos; no se sustituyeron por cero.")
    except (ValueError, TypeError, KeyError, AttributeError, OSError, zipfile.BadZipFile, RuntimeError):
        errors.append("El archivo no supera la validación del esquema público de exportación.")
    return result
