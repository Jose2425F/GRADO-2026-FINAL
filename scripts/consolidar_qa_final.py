#!/usr/bin/env python3
"""Consolida recibos QA locales; no ejecuta pruebas, Docker ni APIs.

Escribe qa.json y QA.md en docs/cierre-final-2026-10-17. Si qa-nucleo.json
ya existe lo respeta byte por byte; solo lo crea desde JUnit si hace falta.
No copia trazas, cuerpos de error, variables ni configuraciones privadas.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / "piloto_kali/prototipo/.verificacion/cierre-final-20261017"
PUBLIC = ROOT / "docs/cierre-final-2026-10-17"


def read(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference(path):
    if not path.is_file():
        return None
    return {"path": str(path.relative_to(ROOT)), "sha256": digest(path),
            "modified_at_utc": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}


def log_result(path):
    if not path.is_file():
        return {"status": "NO EJECUTADA", "source": None}
    text = path.read_text(encoding="utf-8", errors="replace")
    runs = list(re.finditer(r"Ran (\d+) tests? in ([\d.]+)s", text))
    if runs:
        last = runs[-1]
        tail = text[last.end():]
        status = "APROBADA" if re.search(r"^OK(?:\s|$)", tail, re.M) else "FALLIDA" if "FAILED" in tail else "PARCIAL"
        failures = re.search(r"failures=(\d+)", tail)
        errors = re.search(r"errors=(\d+)", tail)
        return {"status": status, "tests": int(last[1]), "duration_seconds": float(last[2]),
                "failures": int(failures[1]) if failures else 0,
                "errors": int(errors[1]) if errors else 0, "source": reference(path)}
    pytest_lines = [line for line in text.splitlines() if re.search(r"\d+ passed.* in [\d.]+s", line)]
    if pytest_lines:
        summary = pytest_lines[-1]
        counts = {key: int(match[1]) if (match := re.search(r"(\d+) " + key, summary)) else 0 for key in ("passed", "failed", "error", "warning", "skipped")}
        duration = re.search(r"in ([\d.]+)s", summary)
        return {"status": "FALLIDA" if counts["failed"] or counts["error"] else "APROBADA",
                "tests": counts["passed"] + counts["failed"] + counts["error"] + counts["skipped"],
                "failures": counts["failed"], "errors": counts["error"], "warnings": counts["warning"],
                "duration_seconds": float(duration[1]), "source": reference(path)}
    if "AssertionError" in text or "FAILED" in text:
        return {"status": "FALLIDA", "source": reference(path)}
    if re.search(r"^PASS:", text, re.M):
        return {"status": "APROBADA", "source": reference(path)}
    return {"status": "PARCIAL", "source": reference(path)}


def core_receipt():
    path = PUBLIC / "qa-nucleo.json"
    raw = PRIVATE / "qa-nucleo-junit.xml"
    if not path.exists() and raw.exists():
        tree = ET.fromstring(raw.read_bytes())
        cases = []
        for case in tree.iter("testcase"):
            state = "FALLIDA" if case.find("failure") is not None or case.find("error") is not None else "NO EJECUTADA" if case.find("skipped") is not None else "APROBADA"
            cases.append({"id": case.get("classname", "") + "." + case.get("name", ""),
                          "component": case.get("classname"), "elapsed_seconds": float(case.get("time", 0)),
                          "status": state, "expected": "Cumplir las aserciones del contrato identificado.",
                          "procedure": "pytest tests --junitxml; fixtures y contratos locales.",
                          "evidence": "JUnit privado; SHA-256 conservado, sin publicar payloads."})
        suites = list(tree.iter("testsuite"))
        payload = {"at": datetime.now(timezone.utc).isoformat(), "source": "pytest-junit",
                   "tests": len(cases), "failures": sum(int(s.get("failures", 0)) for s in suites),
                   "errors": sum(int(s.get("errors", 0)) for s in suites),
                   "skipped": sum(int(s.get("skipped", 0)) for s in suites),
                   "duration_seconds": sum(float(s.get("time", 0)) for s in suites),
                   "raw_sha256": digest(raw), "cases": cases}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    data = read(path)
    if not data:
        return {"status": "NO EJECUTADA", "source": reference(path)}
    result = {k: data.get(k) for k in ["at", "tests", "failures", "errors", "skipped", "duration_seconds", "raw_sha256"]}
    result.update(status="APROBADA" if data.get("tests", 0) > 0 and data.get("failures") == 0 and data.get("errors") == 0 else "FALLIDA",
                  passed=data.get("tests", 0) - data.get("failures", 0) - data.get("errors", 0) - data.get("skipped", 0),
                  source=reference(path), raw_source=reference(raw),
                  junit_hash_matches=raw.exists() and data.get("raw_sha256") == digest(raw),
                  limitations="Pruebas del núcleo con fixtures. No equivalen a corridas API ni a aceptación universal.")
    if raw.exists() and not result["junit_hash_matches"]:
        result["status"] = "PARCIAL"
    warning = log_result(PRIVATE / "qa-nucleo-final.log")
    result["warnings"] = warning.get("warnings", 0)
    result["warning_note"] = "Deprecación de FFDH en dependencia Scapy/cryptography; no se interpreta como vulnerabilidad demostrada." if result["warnings"] else None
    return result


def panel_receipt():
    path = PUBLIC / "qa-panel.json"
    data = read(path)
    if not data:
        return {"status": "NO EJECUTADA", "source": reference(path)}
    changed = [name for name, expected in data.get("source_sha256", {}).items()
               if not (ROOT / name).is_file() or digest(ROOT / name) != expected]
    result = {k: data.get(k) for k in ["at", "executed", "failures", "errors", "skipped", "passed", "kernel_tainted_after", "private_log_sha256"]}
    case_durations = [r.get("elapsed_seconds", 0) for r in data.get("tests", [])]
    result.update(status="APROBADA" if data.get("passed") is True else "FALLIDA", source=reference(path),
                  test_sources_changed_since_execution=changed, case_duration_sum_seconds=round(sum(case_durations), 6),
                  unique_case_ids=len({r.get("id") for r in data.get("tests", [])}),
                  limitations="Suite completa registrada en ese recibo. La focalización posterior se informa separada; no se suman baterías superpuestas.")
    log = log_result(PRIVATE / "qa-panel-final.log")
    if (log.get("source") or {}).get("sha256") == data.get("private_log_sha256"):
        result["duration_seconds"] = log.get("duration_seconds")
    else:
        old = log_result(PRIVATE / "qa-panel.log")
        result["duration_seconds"] = old.get("duration_seconds") if (old.get("source") or {}).get("sha256") == data.get("private_log_sha256") else None
    return result


def suite_receipt():
    path = ROOT / "piloto_kali/prototipo/.lab-suite/acceptance.json"
    data = read(path)
    safe = []
    for row in data.get("scenarios", []):
        ev = row.get("evaluation") or {}
        safe.append({"id": row.get("id"), "status": row.get("status"), "expected_tasks": row.get("expected_tasks"),
                     "evaluation": {k: ev.get(k) for k in ["tasks_checked", "tasks_valid", "TP", "FP", "FN", "TN", "acceptance_passed", "evidence_valid"]},
                     "mode": "acceptance_without_ia"})
    complete = len(safe) == 4 and {r["id"] for r in safe} == {"sucursal", "comercial", "mixto", "reforzado"}
    passed = data.get("status") == "accepted" and complete and all(r["status"] == "accepted" and r["evaluation"]["acceptance_passed"] is True and r["evaluation"]["evidence_valid"] is True and r["evaluation"]["tasks_valid"] == r["expected_tasks"] for r in safe)
    return {"status": "APROBADA" if passed else "PARCIAL" if data else "NO EJECUTADA",
            "source_status": data.get("status"), "version": data.get("version"), "scenarios": safe,
            "new_api_generations": data.get("new_api_generations"), "source": reference(path),
            "limitations": "Aceptación funcional del banco instrumentado, sin IA; TP/TN describen condiciones sintéticas, no réplicas estadísticas ni cobertura universal."}


def source_integrity():
    path = PRIVATE / "fuentes-iniciales.json"
    source = read(path)
    changed, missing = [], []
    for name, expected in source.items():
        current = ROOT / name
        if not current.is_file():
            missing.append(name)
        elif digest(current) != expected:
            changed.append(name)
    return {"status": "APROBADA" if source and not changed and not missing else "PARCIAL",
            "files_in_manifest": len(source), "changed": changed, "missing": missing, "source": reference(path),
            "scope_note": "El manifiesto cubre los archivos enumerados del núcleo y despliegue. No demuestra identidad de todo el repositorio; pyproject y módulos externos se registran aparte."}


def collect_attempts():
    rows = []
    for path in sorted(PRIVATE.glob("qa-*.log")):
        result = log_result(path)
        note = "Repetición de QA; no sumar al tamaño de muestra experimental."
        if path.name == "qa-browser-tesis.log" and result["status"] == "FALLIDA":
            note = "La fixture esperaba una etapa nueva y recibió el estado histórico detenido. Se corrigió la fixture y la repetición quedó conservada; no se interpreta como caída de una API."
        elif "panel-anterior" in path.name:
            note = "Dos errores de importación: faltaba el directorio raíz en sys.path del ejecutor QA. El intento se conserva; la corrección del ejecutor se verificó después."
        elif path.name == "qa-gate-contexto-final.log" and result["status"] == "FALLIDA":
            note = "KeyError por elapsed_seconds ausente en fixture mínima. El análisis se corrigió para admitir métricas faltantes y se repitió la focal."
        rows.append({"id": f"QA-ATT-{len(rows)+1:03}", "component": path.stem, **result,
                     "audit_api_calls": False, "interpretation": note})
    for path in sorted(PRIVATE.glob("qa-panel-anterior-*.json")):
        data = read(path)
        rows.append({"id": f"QA-ATT-{len(rows)+1:03}", "component": "panel_previous_receipt", "status": "APROBADA" if data.get("passed") else "FALLIDA",
                     "tests": data.get("executed"), "failures": data.get("failures"), "errors": data.get("errors"),
                     "source": reference(path), "audit_api_calls": False,
                     "interpretation": "Recibo del mismo intento anterior cuyo log se conserva; no se cuenta como otra ejecución independiente."})
    return rows


def frozen_closure_receipts():
    inventory_path = PUBLIC / "evidencias/inventario.json"
    statistics_path = PUBLIC / "evidencias/metricas-por-cohorte.json"
    inventory = read(inventory_path)
    try:
        statistics = json.loads(statistics_path.read_text())
    except (OSError, ValueError):
        statistics = []
    completed = []
    for cohort in inventory.get("summary", {}).get("novaflow_studies", []):
        planned = cohort.get("planned_formal_pairs")
        if cohort.get("study_status") != "complete" or type(planned) is not int or planned < 1 or cohort.get("formal_attempts") != 2 * planned:
            continue
        usable = [row for row in statistics if row.get("phase") == "formal" and row.get("cohort_or_evaluator_source") == cohort["id"] and row.get("eligible_pairs", 0) > 0]
        if usable:
            completed.append({"id": cohort["id"], "formal_attempts": cohort["formal_attempts"], "planned_pairs": planned,
                              "eligible_pairs": sum(row["eligible_pairs"] for row in usable)})
    latest = sorted(completed, key=lambda row: row["id"])[-1] if completed else None
    scored = [row for row in inventory.get("runs", []) if latest and row.get("cohort") == latest["id"] and row.get("phase") == "formal"]
    findings_valid = bool(scored) and all(row.get("scoring_status") == "reserved_reference_and_evaluator_preserved" and not row.get("copy_hash_conflict") and not row.get("score_copy_conflict") for row in scored)
    document_path = PUBLIC / "verificacion-documental.json"
    document = read(document_path)
    document_sources_match = bool(document.get("archivos")) and all((ROOT / name).is_file() and digest(ROOT / name) == metadata.get("sha256") for name, metadata in document.get("archivos", {}).items())
    provenance_path = PUBLIC / "evidencias/procedencia-documental.json"
    provenance = read(provenance_path)
    provenance_current = provenance.get("status") == "APROBADA" and bool(provenance.get("checks")) and all((ROOT / row["path"]).is_file() and row.get("matches") and digest(ROOT / row["path"]) == row.get("expected_sha256") for row in provenance.get("checks", []))
    return {"terminal_comparison": latest, "formal_findings_preserved_and_adjudicated": findings_valid,
            "document_structural_checks_passed": document.get("estado") == "APROBADA" and document_sources_match,
            "document_inputs_still_match": provenance_current,
            "sources": [reference(path) for path in (inventory_path, statistics_path, document_path, provenance_path) if path.is_file()]}


def checklist(core, panel, driver, browsers, suite, integrity, installation, reports, closure):
    approved = "APROBADA"
    partial = "PARCIAL"
    basic_qa = all(x.get("status") == approved for x in [core, panel, driver])
    terminal = bool(closure["terminal_comparison"])
    current_sources = not panel.get("test_sources_changed_since_execution") and integrity.get("status") == approved
    documents_verified = closure["document_structural_checks_passed"] and closure["document_inputs_still_match"]
    items = [
        ("El código corresponde a la última versión validada", approved if terminal and basic_qa and current_sources else partial, "qa-nucleo.json;qa-panel.json;evidencias/inventario.json", "Código del corte experimental y fuentes de tests cotejados. La publicación del commit remoto se verifica aparte; no se suman baterías solapadas."),
        ("Los módulos principales están integrados", approved if terminal and basic_qa and suite.get("status") == approved and reports.get("status") == approved else partial, "qa-panel.json;qa-browser-*.log;informes-piloto-api.json", "Flujo del banco de tesis comprobado con agentes y artefactos reales; la afirmación queda limitada a las configuraciones verificadas."),
        ("El laboratorio funciona dentro del alcance comprobado", suite["status"], "suite_acceptance", "La aceptación de los cuatro escenarios verifica perfiles sintéticos sin IA; no acredita cobertura de otras redes."),
        ("Las pruebas ejecutadas tienen resultados documentados", approved if basic_qa else partial, "qa-nucleo.json;qa-panel.json;qa-gate-definitivo.log", "Los fallos y repeticiones se conservan y se distinguen del estudio con API."),
        ("Agentes y orquestación descritos correctamente", approved if documents_verified else partial, "scripts/laboratorio_empresa.py;scripts/llm_especialistas.py;verificacion-documental.json", "Controlador actual Python y núcleo histórico LangGraph diferenciados y revisados; la comprobación no certifica toda propiedad de calidad de la arquitectura."),
        ("Los hallazgos tienen evidencia suficiente", approved if terminal and closure["formal_findings_preserved_and_adjudicated"] else partial, "evidencias/inventario.json", "Validez adjudicada por corrida y referencia reservada en el banco declarado, con candidatos CVE separados; no prueba vulnerabilidades universales."),
        ("Informes consistentes con resultados estructurados", approved if reports.get("status") == approved else partial, "informes-piloto-api.json;qa-panel.json", "Comprobación concreta de cuatro informes de una pareja piloto real: HTTP200, final y tarjetas coincidentes con TP. No certifica cada recomendación LLM ni sustituye revisar toda la muestra formal." if reports.get("status") == approved else "Hay contratos automatizados de informes; verificar también los artefactos de las corridas finales."),
        ("KPI calculados o declarados no calculables", approved if terminal else partial, "evidencias/metricas-por-cohorte.json", "Comparación exploratoria con denominadores y exclusiones por cohorte/fase. Cumplir el objetivo de evaluar no exige alcanzar metas favorables de TRTO/IDE/ETV."),
        ("El trabajo de grado refleja el prototipo real", approved if documents_verified else partial, "TrabajoDeGrado_II_Completo.docx;verificacion-documental.json", "Construcción, insumos y artefactos académicos cotejados; aprobación institucional y publicación son criterios separados."),
        ("Los anexos conservan la trazabilidad", approved if documents_verified else partial, "evidencias/trazabilidad.csv;TrabajoDeGrado_II_Anexos.docx", "Matriz e insumos conservados con referencias por anexo; no adjudica automáticamente el cumplimiento de los 79 requisitos."),
        ("El repositorio está organizado", partial, "verificacion-exportador.json", "Preparación y exportación no equivalen a publicación validada en el remoto."),
        ("No se publican secretos ni datos sensibles", partial, "verificacion-exportador.json", "La selección saneada se verifica aparte; la publicación requiere autorización explícita y comparación remota."),
        ("El README permite reproducir el despliegue", partial if installation.get("source") else "NO EJECUTADA", "instalacion-venv-limpio.json;README.md", "Verificación parcial en un venv nuevo del mismo Kali: dependencias, CLI, once GET y pruebas públicas. No es una máquina ni sistema operativo nuevo; las exclusiones de fixtures se conservan." if installation.get("source") else "No hay recibo disponible de instalación limpia; no se infiere a partir de tests del entorno existente."),
        ("Documentación académica coherente y con formato", partial, "Word/PDF finales y recibo de render", "Verificar páginas, índices, IEEE y plantilla institucional disponible; no certificar normas no aportadas."),
        ("Limitaciones y pendientes identificados", approved, "QA.md;evidencias/LEEME.md;evidencias/TRAZABILIDAD.md", "Se conservan intentos fallidos, uso desconocido, alcance acotado y evaluación incompleta.")]
    return [{"id": f"CF-{n:02}", "criterion": criterion, "status": status, "evidence": evidence, "limitation": limitation}
            for n, (criterion, status, evidence, limitation) in enumerate(items, 1)]


def publish():
    PUBLIC.mkdir(parents=True, exist_ok=True)
    core = core_receipt()
    panel = panel_receipt()
    focal_logs = [PRIVATE / name for name in ("qa-gate-definitivo.log", "qa-contexto-entorno.log", "qa-protocolo-15-pares.log") if (PRIVATE / name).exists()]
    driver = log_result(max(focal_logs, key=lambda path: path.stat().st_mtime) if focal_logs else PRIVATE / "qa-gate-definitivo.log")
    driver["limitations"] = "Batería focal del conductor; se solapa con el panel. No se suma como treinta casos adicionales."
    browser_rows = [{"id": name, **log_result(PRIVATE / filename), "real_audit_controls": "intercepted", "real_api_calls": 0}
                    for name, filename in [("tesis", "qa-browser-tesis-repeticion.log"), ("suite", "qa-browser-suite.log"), ("navegacion", "qa-browser-navegacion.log")]]
    browsers = {"passed": sum(r["status"] == "APROBADA" for r in browser_rows), "scenarios": browser_rows,
                "limitations": "Pruebas de interfaz con controles interceptados; cero API real. No reemplazan auditoría end-to-end."}
    raw_env = read(PRIVATE / "entorno-inicial.json")
    environment = {k: raw_env.get(k) for k in ["at", "kernel", "tainted", "cpu", "docker_version", "panel_initial"]}
    environment.update(new_faults_count=len(raw_env.get("new_faults", [])), source=reference(PRIVATE / "entorno-inicial.json"),
                       status="APROBADA" if raw_env and raw_env.get("tainted") == 0 and not raw_env.get("new_faults") else "PARCIAL",
                       limitations="Estado al inicio posterior al reinicio; no implica que todos los servicios ya estuvieran levantados ni vigencia indefinida.")
    suite, integrity = suite_receipt(), source_integrity()
    installation_path = PUBLIC / "instalacion-venv-limpio.json"
    raw_installation = read(installation_path)
    installed_results = raw_installation.get("results") or {}
    http = installed_results.get("http_get_smoke") or {}
    public_tests = installed_results.get("core_tests_public") or {}
    try:
        public_test_counts = {key: int(public_tests.get(key, 0)) for key in ("tests", "failures", "errors", "skipped")}
        public_test_counts["passed"] = public_test_counts["tests"] - public_test_counts["failures"] - public_test_counts["errors"] - public_test_counts["skipped"]
    except (TypeError, ValueError):
        public_test_counts = {}
    installation = {"source": reference(installation_path), "source_status": raw_installation.get("status"),
                    "status": "PARCIAL" if raw_installation else "NO EJECUTADA",
                    "environment": raw_installation.get("environment"), "python": raw_installation.get("python"),
                    "installation": installed_results.get("installation"), "cli_help": installed_results.get("cli_help"),
                    "http_get_route_count": len(http.get("routes", [])),
                    "core_tests_public": public_test_counts,
                    "limitations": "Venv nuevo en el mismo Kali; no acredita una instalación en otra máquina. Las pruebas omitidas por ausencia de fixtures privadas no se convierten en aprobadas."}
    reports_path = PUBLIC / "informes-piloto-api.json"
    reports_raw = read(reports_path)
    reports_rows = []
    for row in reports_raw.get("checks", []):
        safe = {key: row.get(key) for key in ("architecture", "audience", "http_status", "final", "finding_cards", "expected_TP", "html_sha256", "report_json_sha256")}
        private_path = ROOT / str(row.get("private_html", ""))
        safe["html_hash_matches"] = private_path.is_file() and private_path.resolve().is_relative_to(ROOT.resolve()) and digest(private_path) == row.get("html_sha256")
        reports_rows.append(safe)
    reports_complete = {(row["architecture"], row["audience"]) for row in reports_rows} == {(a, b) for a in ("single", "multiagent") for b in ("technical", "executive")}
    reports_valid = len(reports_rows) == 4 and reports_complete and all(r["http_status"] == 200 and r["final"] is True and r["finding_cards"] == r["expected_TP"] and r["html_hash_matches"] for r in reports_rows)
    reports = {"source": reference(reports_path), "status": "APROBADA" if reports_valid else "PARCIAL" if reports_raw else "NO EJECUTADA",
               "cohort": reports_raw.get("cohort"), "phase": reports_raw.get("phase"), "block": reports_raw.get("block"),
               "checks": reports_rows, "limitations": "GET de informes sobre una pareja piloto real; no certifica exactitud semántica de toda recomendación ni añade corridas a la muestra formal."}
    closure = frozen_closure_receipts()
    attempts = collect_attempts()
    receipt = {"schema_version": "1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "status": "PARCIAL", "core": core, "panel": panel, "driver_final": driver,
               "browsers": browsers, "environment": environment, "suite_acceptance": suite,
               "installation": installation,
               "reports_smoke": reports,
               "closure_receipts": closure,
               "source_integrity": integrity, "attempts": attempts,
               "checklist": checklist(core, panel, driver, browsers, suite, integrity, installation, reports, closure),
               "counting_rule": "Baterías independientes en la presentación; no sumar núcleo, panel, focal y navegador ni repetir intentos como réplicas de auditoría.",
               "limitations": ["QA de software no es evaluación experimental de auditorías con API.",
                               "Los estados PARCIAL y NO EJECUTADA impiden afirmar cumplimiento global del 100 %.",
                               "La suite puede estar en curso al generar el snapshot; refrescar tras finalizar.",
                               "No se publican cuerpos de error, logs completos, configuraciones, direcciones ni credenciales.",
                               "El informe no ejecuta pruebas ni realiza llamadas API o Docker."]}
    (PUBLIC / "qa.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Cierre QA de NovaFlow", "", f"Estado del cierre: **{receipt['status']}**. Corte UTC: {receipt['generated_at_utc']}.", "",
             "Los recibos originales se conservan. Este resumen no ejecuta pruebas ni APIs y no suma baterías superpuestas.", "",
             "| Batería | Resultado | Número registrado | Duración |", "|---|---|---:|---:|",
             f"| Núcleo | {core['status']} | {core.get('tests', '—')} | {core.get('duration_seconds', '—')} s |",
             f"| Panel y módulos externos | {panel['status']} | {panel.get('executed', '—')} | {panel.get('duration_seconds', '—')} s |",
             f"| Conductor, focal definitiva | {driver['status']} | {driver.get('tests', '—')} | {driver.get('duration_seconds', '—')} s |",
             f"| Navegador, escenarios interceptados | {browsers['passed']}/3 aprobados | 3 escenarios | No agregada |", "",
             "La focal del conductor se solapa con la batería del panel. Un nuevo caso o una repetición no permite actualizar el total de la batería completa sin ejecutar y conservar su recibo.", "",
             f"Fuentes de tests del panel que cambiaron desde su recibo: {len(panel.get('test_sources_changed_since_execution', []))}. Esto se distingue de los archivos históricos: {integrity['files_in_manifest']} en el manifiesto inicial, {len(integrity['changed'])} modificados y {len(integrity['missing'])} ausentes.", "",
             f"Entorno inicial: kernel `{environment.get('kernel')}`, tainted `{environment.get('tainted')}`, Docker `{environment.get('docker_version')}`, nuevos fallos relevantes `{environment['new_faults_count']}`. Estado inicial del panel: `{environment.get('panel_initial')}`. Es un corte inicial, no una garantía permanente.", "",
             "## Verificación de instalación", "", f"Estado del alcance de instalación: **{installation['status']}**. Recibo fuente: `{installation.get('source_status')}`. Se comprobaron {installation['http_get_route_count']} rutas GET y las pruebas públicas registran {public_test_counts.get('passed', '—')} aprobadas y {public_test_counts.get('skipped', '—')} omitidas. Es un venv nuevo dentro del mismo Kali, sin configuración privada; no una máquina ni sistema operativo nuevo. No se suman esas repeticiones a las baterías anteriores.", "",
             "## Comprobación de informes reales", "", f"Estado: **{reports['status']}**. Se conservan {len(reports['checks'])} comprobaciones HTTP de informes de una pareja piloto real, con hashes de HTML y JSON, estado final y concordancia de tarjetas con TP. Solo se consultaron artefactos existentes; no se inició una auditoría. La concordancia estructural no certifica la exactitud semántica de cada recomendación LLM ni añade muestra formal.", "",
             "## Aceptación de escenarios sin IA", "", f"Estado: **{suite['status']}** (origen: {suite.get('source_status')}).", "",
             "| Escenario | Estado | Tareas válidas / previstas | TP/FP/FN/TN |", "|---|---|---:|---|"]
    for r in suite["scenarios"]:
        ev = r["evaluation"]
        lines.append(f"| {r['id']} | {r['status']} | {ev.get('tasks_valid')}/{r['expected_tasks']} | {'/'.join(str(ev.get(k)) for k in ['TP','FP','FN','TN'])} |")
    lines += ["", "Estos resultados son condiciones sintéticas adjudicadas dentro del banco instrumentado. No son réplicas estadísticas ni demuestran cobertura de toda una empresa o todas las vulnerabilidades IPv4/IPv6.", "",
              "## Intentos fallidos conservados", ""]
    for attempt in attempts:
        if attempt["status"] == "FALLIDA":
            lines.append(f"- {attempt['id']} · `{attempt['component']}`: {attempt['interpretation']}")
    lines += ["", "Una deprecación de FFDH en Scapy/cryptography quedó registrada en las pruebas del núcleo. No se interpreta como fallo del prototipo ni como vulnerabilidad confirmada.", "",
              "## Criterios de cierre", "", "| ID | Criterio | Estado | Límite de la comprobación |", "|---|---|---|---|"]
    lines.extend(f"| {c['id']} | {c['criterion']} | {c['status']} | {c['limitation']} |" for c in receipt["checklist"])
    lines += ["", "`qa.json` conserva los hashes y localizadores de los recibos privados; `qa-nucleo.json` y `qa-panel.json` conservan los casos individuales. Los históricos fallidos permanecen separados. Publicar solo el resumen saneado; las fuentes privadas no se vuelven públicas por estar referenciadas."]
    (PUBLIC / "QA.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "core": core.get("tests"), "panel": panel.get("executed"),
                      "driver": driver.get("tests"), "browsers_passed": browsers["passed"],
                      "suite_status": suite["status"], "sources_unchanged": integrity["status"]}, ensure_ascii=False))
    return receipt


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    publish()
