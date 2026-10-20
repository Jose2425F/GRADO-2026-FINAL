#!/usr/bin/env python3
"""Cotejo RO-11 posterior: lee 50 originales y Word, sin ejecutar auditorías/API.

Sólo escribe un recibo nuevo en docs/verificacion-postevaluacion. No modifica
criterios, corridas, exportación ni documento. Usa únicamente biblioteca estándar.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def aggregate(rows):
    """Denominador descriptivo: todos los intentos iniciados, también parciales."""
    result = {}
    for arm in ("single", "multiagent"):
        selected = [r for r in rows if r["architecture"] == arm and r["recorded"]]
        tp, fn = (sum(r[key] for r in selected) for key in ("TP", "FN"))
        result[arm] = {
            "attempts": len(selected),
            "complete": sum(r["status"] == "complete" for r in selected),
            "partial": sum(r["status"] == "partial" for r in selected),
            "TP": tp, "FN": fn,
            "recall_percent": 100 * tp / (tp + fn) if tp + fn else None,
            "mean_seconds": statistics.fmean(r["seconds"] for r in selected),
            "included_sequences": [r["sequence"] for r in selected],
        }
    return result


def numeric(text):
    return float(text.strip().replace("%", "").replace(",", "."))


def document_tables(document):
    with zipfile.ZipFile(document) as archive:
        root = ET.fromstring(archive.read("word/document.xml"))
    tables = [
        [["".join(t.text or "" for t in cell.findall(".//w:t", NS))
          for cell in row.findall("w:tc", NS)] for row in table.findall("w:tr", NS)]
        for table in root.findall(".//w:tbl", NS)
    ]
    paragraphs = ["".join(t.text or "" for t in p.findall(".//w:t", NS))
                  for p in root.findall(".//w:p", NS)]
    return tables, paragraphs


def compare_table(table, summary):
    expected_names = {"Agente único": "single", "Multiagente": "multiagent"}
    checked = []
    for row in table[1:]:
        if not row or row[0] not in expected_names or len(row) != 6:
            return False, checked
        arm = expected_names[row[0]]
        observed = summary[arm]
        complete, attempts = (int(x.strip()) for x in row[1].split("/"))
        ok = (complete == observed["complete"] and attempts == observed["attempts"]
              and int(row[2]) == observed["TP"] and int(row[3]) == observed["FN"]
              and abs(numeric(row[4]) - observed["recall_percent"]) <= .051
              and abs(numeric(row[5]) - observed["mean_seconds"]) <= .0051)
        checked.append({"architecture": arm, "matches": ok, "cells": row})
    return len(checked) == 2 and all(r["matches"] for r in checked), checked


def read_json(path):
    return json.loads(path.read_bytes())


def verify(root, document):
    public = root / "docs/evaluacion-langgraph"
    tracked = [public / n for n in ("runs.json", "pairs.json", "summary.json", "protocol.json")]
    tracked.append(document)
    before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
    rows, pairs, summary, protocol = (read_json(p) for p in tracked[:4])
    schedule = protocol["schedule"]
    checks = []
    def check(name, ok, detail):
        checks.append({"name": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    check("RO11_50_POSICIONES_PRIMER_INTENTO", len(rows) == 50
          and Counter(r["sequence"] for r in rows) == Counter(range(1, 51))
          and all(r["recorded"] for r in rows)
          and all(all(r[k] == s[k] for k in ("sequence", "scenario", "pair", "architecture"))
                  for r, s in zip(sorted(rows, key=lambda x: x["sequence"]), schedule)),
          {"positions": len(rows), "recorded": sum(r["recorded"] for r in rows)})
    original_checks = []
    for row in rows:
        run = (root / "piloto_kali/prototipo/corridas" / row["run_id"]).resolve()
        run.relative_to((root / "piloto_kali/prototipo/corridas").resolve())
        evaluation, report, runtime = (read_json(run / n) for n in ("evaluation.json", "report.json", "runtime.json"))
        metrics = report["metrics"]
        runtime_seconds = (datetime.fromisoformat(runtime["ended_at"]) - datetime.fromisoformat(runtime["started_at"])).total_seconds()
        ok = (all(evaluation[k] == row[k] for k in ("TP", "FN", "FP", "TN"))
              and report["status"] == row["status"]
              and math.isclose(metrics["elapsed_seconds"], row["seconds"], abs_tol=1e-8)
              and math.isclose(metrics["execution_seconds"], row["execution_seconds"], abs_tol=1e-8)
              and math.isclose(metrics["expert_review_seconds"], row["review_seconds"], abs_tol=1e-8)
              and 0 <= runtime_seconds - row["seconds"] < 1)
        original_checks.append({"sequence": row["sequence"], "result": "PASS" if ok else "FAIL",
            "run_id": row["run_id"], "TP": evaluation["TP"], "FN": evaluation["FN"],
            "seconds": metrics["elapsed_seconds"], "status": report["status"],
            "runtime_seconds": runtime_seconds})
    check("RO11_50_ORIGINALES_TP_FN_TIEMPOS", all(r["result"] == "PASS" for r in original_checks),
          {"checked": len(original_checks), "failed": sum(r["result"] != "PASS" for r in original_checks)})
    descriptive = aggregate(rows)
    partials = [r for r in rows if r["status"] != "complete"]
    check("RO11_PARCIALES_CONSERVADOS_EN_DENOMINADOR", len(partials) == 2
          and {r["sequence"] for r in partials} == {1, 42}
          and all(r["sequence"] in descriptive[r["architecture"]]["included_sequences"] for r in partials),
          [{"sequence": r["sequence"], "TP": r["TP"], "FN": r["FN"], "seconds": r["seconds"]} for r in partials])
    eligible = [(lab["id"], p["pair"]) for lab in pairs for p in lab["pairs"] if p["eligible"]]
    excluded = [(lab["id"], p["pair"]) for lab in pairs for p in lab["pairs"] if not p["eligible"]]
    check("RO11_KPI_23_PAREJAS_DISTINTAS_DEL_DESCRIPTIVO_50", len(eligible) == summary["eligible_pairs"] == 23
          and len(excluded) == 2 and sum(r["eligible_pair"] for r in rows) == 46,
          {"eligible_pairs": len(eligible), "excluded_pairs": excluded,
           "descriptive_attempts": sum(r["attempts"] for r in descriptive.values()),
           "criterion": "Se conserva elegibilidad registrada, sin cambiar o re-adjudicar criterios."})
    tables, paragraphs = document_tables(document)
    candidates = [(i + 1, table) for i, table in enumerate(tables)
                  if table and table[0] == ["Arquitectura", "Completas / intentos", "TP", "FN", "Recall (%)", "Tiempo medio (s)"]]
    matches, cells = compare_table(candidates[0][1], descriptive) if len(candidates) == 1 else (False, [])
    check("RO11_TABLA11_WORD_TODOS_50_INTENTOS", len(candidates) == 1 and candidates[0][0] == 11 and matches,
          {"document": str(document.relative_to(root)), "table_number": candidates[0][0] if candidates else None,
           "rows": cells})
    kpi_header = ["Indicador", "Media", "Mediana", "IC 95 % exploratorio", "Meta", "Lectura descriptiva"]
    kpi_tables = [table for table in tables if table and table[0] == kpi_header]
    kpi_map = {"TRTO": "TRTO_percent", "IDE": "IDE_percent", "ETV": "ETV_ratio"}
    kpi_match = len(kpi_tables) == 1 and all(
        any(row[0] == label and abs(numeric(row[1]) - summary["analysis"][field]["mean"]) <= .0051
            for row in kpi_tables[0][1:]) for label, field in kpi_map.items())
    check("RO11_TABLA12_KPI_CORRESPONDE_23_PAREJAS", kpi_match,
          {"means": {label: summary["analysis"][field]["mean"] for label, field in kpi_map.items()}, "n": 23})
    after = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
    check("RO11_FUENTES_PUBLICAS_Y_WORD_SIN_MODIFICAR", before == after, {"sha256": after})
    return {"schema_version": 1, "verification": "RO11_DESCRIPTIVO_50_Y_KPI_23",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": "PASS" if all(c["result"] == "PASS" for c in checks) else "FAIL",
        "proposed_status": "VALIDADO" if all(c["result"] == "PASS" for c in checks) else "PARCIAL",
        "scope": "Cotejo read-only posterior; sin API, herramientas de auditoría, cambios de criterio o Word.",
        "descriptive": descriptive, "checks": checks, "original_runs": original_checks,
        "document_context": [p for p in paragraphs if "23 parejas" in p or "50 intentos" in p or "50 corridas" in p][:15],
        "limitations": ["El cotejo conserva la adjudicación original; no vuelve a validar experimentalmente los hallazgos.",
                         "El tiempo descriptivo incluye parciales; sólo las parejas aptas integran TRTO/IDE/ETV."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--document", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document, output = args.document.resolve(), args.output.resolve()
    document.relative_to(ROOT)
    if output.parent != (ROOT / "docs/verificacion-postevaluacion").resolve() or output.suffix != ".json":
        parser.error("El recibo debe ser un JSON nuevo en docs/verificacion-postevaluacion.")
    receipt = verify(ROOT, document)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"result": receipt["result"], "proposed_status": receipt["proposed_status"],
                      "output": str(output), "checks": len(receipt["checks"])}, ensure_ascii=False))
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
