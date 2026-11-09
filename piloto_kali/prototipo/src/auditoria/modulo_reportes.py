"""Módulo de Reportes: JSON estructurado y vista HTML sin secretos."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .agentes import AGENT_NAMES
from .contracts import AuditRequest, Task, TaskResult, TaskStatus
from .store import write_json


def finding_identifier(finding: dict) -> str:
    """Identidad del hallazgo en el banco, con la misma clave de deduplicación."""
    existing = finding.get("finding_id")
    if isinstance(existing, str) and existing.strip():
        return existing
    return f"{finding.get('asset_id', '')}:{finding.get('defect_key') or finding.get('condition', '')}"


def report_scope(request: AuditRequest | dict) -> dict:
    """Proyecta el alcance declarado sin referencias a credenciales ni sesiones."""
    data = request.model_dump(mode="json") if isinstance(request, AuditRequest) else request
    personal = data.get("personal", {})
    return {
        "bank": data.get("bank", "personal" if personal else None),
        "authorization_ref": data.get("authorization_ref"),
        "ipv4": list(data.get("scope_ipv4", [])) if not personal else [v for v in personal.get("ipv4", "").split(",") if v],
        "ipv6": list(data.get("scope_ipv6", [])) if not personal else [v for v in personal.get("ipv6", "").split(",") if v],
        "targets": [
            {key: target[key] for key in ("asset_id", "address", "interface", "ports") if key in target}
            for target in data.get("targets", [])
        ],
        **({key: personal[key] for key in ("interface", "ports", "port_mode") if key in personal} if personal else {}),
    }


def prepare_report(report: dict, request: AuditRequest | dict | None = None) -> dict:
    """Añade trazabilidad a una copia; conserva los IDs y registros existentes."""
    projected = dict(report)
    projected["findings"] = [dict(finding, finding_id=finding_identifier(finding)) for finding in report.get("findings", [])]
    if request is not None:
        projected["scope"] = report_scope(request)
        data = request.model_dump(mode="json") if isinstance(request, AuditRequest) else request
        for key in ("operator", "authorization_ref"):
            if key in data:
                projected.setdefault(key, data[key])
    if "limitations" not in projected:
        projected["limitations"] = [report["note"]] if report.get("note") else []
    return projected


def make_report(
    request: AuditRequest, tasks: list[Task], results: list[TaskResult], *, live: bool
) -> dict:
    agent_by_task = {
        task.task_id: (
            "Agente único"
            if request.architecture == "single"
            else AGENT_NAMES.get(task.agent_type, task.agent_type)
        )
        for task in tasks
    }
    successful = {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
    target_by_task = {task.task_id: task.target for task in tasks}
    status = (
        "dry_run"
        if not live
        else (
            "complete"
            if all(
                result.status in successful
                or (result.status == TaskStatus.SKIPPED and result.reason_code == "no_applicable")
                for result in results
            )
            else "partial"
        )
    )
    return {
        "schema_version": "1",
        "audit_id": request.audit_id,
        "operator": request.operator,
        "authorization_ref": request.authorization_ref,
        "scope": report_scope(request),
        "mode": "live" if live else "dry_run",
        "status": status,
        "inventory": [
            {"task_id": result.task_id,
             "asset_id": target_by_task[result.task_id].asset_id,
             "address": target_by_task[result.task_id].address,
             "discovery_tasks": [{"task_id": result.task_id, "attempt_id": result.attempt_id,
                                  "evidence_ref": result.evidence_ref, "evidence_sha256": result.evidence_sha256}],
             "services": [s.model_dump() for s in result.services]}
            for result in results
            if result.services
        ],
        "authentication": [
            {"task_id": result.task_id, **result.authentication.model_dump()}
            for result in results
            if result.authentication is not None
        ],
        "findings": [],
        "tasks": [
            {**result.model_dump(mode="json"), "agent_name": agent_by_task.get(result.task_id)}
            for result in results
        ],
        "note": "Solo la sección de hallazgos verificados reúne evidencia íntegra, criterio público y corroboración independiente. El inventario y los efectos IPv6 son observaciones; la evaluación contra ground truth se realiza por separado.",
    }


def save_report(root: Path, report: dict) -> None:
    report = prepare_report(report)
    write_json(root / "report.json", report)
    template_text = (
        files("auditoria").joinpath("templates/report.html.j2").read_text(encoding="utf-8")
    )
    environment = Environment(autoescape=select_autoescape(["html", "xml"]))
    html = environment.from_string(template_text).render(report=report)
    (root / "report.html").write_text(html, encoding="utf-8")
    save_pdf(root, report)


def save_pdf(root: Path, report: dict) -> None:
    report = prepare_report(report)
    from html import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()

    def paragraph(text, style="BodyText"):
        return Paragraph(escape(str(text)), styles[style])

    content = [
        paragraph("Auditoría dual-stack", "Title"),
        paragraph(report["audit_id"]),
        Spacer(1, 12),
        paragraph(
            f"Estado: {report.get('status', 'unknown')} · Modo: {report.get('mode', 'unknown')}"
        ),
        paragraph(f"Operador: {report.get('operator', 'unknown')}"),
        paragraph(f"Autorización: {report.get('authorization_ref', 'unknown')}"),
        paragraph(f"Arquitectura: {report.get('architecture', 'multiagent')}"),
        paragraph(
            f"IA: {report.get('llm', {}).get('status', 'disabled')} · Modelo: {report.get('llm', {}).get('model') or '-'}"
        ),
        Spacer(1, 12),
        paragraph("Hallazgos verificados", "Heading2"),
    ]
    control = report.get("execution_control", {})
    if report.get("error"):
        content.insert(-1, paragraph("Incidencia registrada: " + str(report["error"])))
    scope = report.get("scope", {})
    if scope:
        content[-1:-1] = [
            paragraph("Alcance declarado", "Heading2"),
            paragraph("IPv4: " + (", ".join(scope.get("ipv4", [])) or "No declarado")),
            paragraph("IPv6: " + (", ".join(scope.get("ipv6", [])) or "No declarado")),
        ]
        for target in scope.get("targets", []):
            content.insert(-1, paragraph(f"{target.get('asset_id', '')}: {target.get('address', '')} · {target.get('interface', '')} · puertos {', '.join(map(str, target.get('ports', [])))}"))
    if control.get("stopped"):
        content.insert(-1, paragraph(
            "Pruebas detenidas tras acceso corroborado en "
            f"{control['trigger_task_id']}; {control['cancelled_tasks']} tareas canceladas. "
            "Cobertura parcial de demostración."
        ))
    for finding in report.get("findings", []):
        content += [
            paragraph(f"{finding.get('asset_id', 'Activo no consignado')} - {finding.get('title') or 'Título no consignado'}", "Heading3"),
            paragraph(f"ID: {finding['finding_id']}"),
            paragraph(f"Condición: {finding.get('defect_key') or finding.get('condition') or 'No consignada'}"),
            paragraph(f"Tarea: {finding.get('task_id') or 'No consignada'}"),
            paragraph(f"Evidencia: {finding.get('evidence_ref') or 'No consignada'}"),
            paragraph(f"Corroboración: {finding.get('confirmation_ref') or 'No consignada'}"),
            paragraph(f"Referencia: {finding.get('reference') or 'No consignada'}"),
            paragraph(finding.get("remediation") or "Recomendación no consignada."),
            Spacer(1, 2),
        ]
    if not report.get("findings", []):
        content.append(
            paragraph(
                "No hay hallazgos verificados. Esto no demuestra ausencia de vulnerabilidades."
            )
        )
    content.append(paragraph("Resultados de tareas", "Heading2"))
    rows = [[paragraph(x) for x in ["Tarea", "Intento", "Estado / motivo", "Evidencia"]]]
    rows += [
        [
            paragraph(t["task_id"]),
            paragraph(t.get("attempt_id") or "No ejecutada / no consignado"),
            paragraph(
                {
                    "completed": "Completada",
                    "completed_no_findings": "Sin hallazgos",
                    "skipped": "Omitida",
                    "blocked": "Bloqueada",
                    "failed": "Fallida",
                    "cancelled": "Cancelada",
                }.get(t["status"], t["status"]) + (" · " + str(t["reason_code"]) if t.get("reason_code") else "")
            ),
            paragraph((t.get("evidence_ref") or "—") + (" · Diagnóstico: " + t["diagnostic_ref"] if t.get("diagnostic_ref") else "")),
        ]
        for t in report.get("tasks", [])
    ]
    table = Table(rows, colWidths=[150, 110, 100, 140], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f7")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    content += [table, Spacer(1, 12)]
    if report.get("inventory"):
        content.append(paragraph("Inventario y origen del descubrimiento", "Heading2"))
        for item in report["inventory"]:
            content.append(paragraph(f"{item.get('asset_id') or item.get('task_id') or 'Activo'} · {item.get('address') or 'Dirección no consignada'}", "Heading3"))
            for service in item.get("services", []):
                content.append(paragraph(f"{service.get('port')}/{service.get('protocol')}: {service.get('state', 'open')} · {service.get('name') or 'Sin identificar'}"))
            if not item.get("services"):
                content.append(paragraph("Sin servicios observados en este registro; no acredita ausencia de vulnerabilidades."))
            discoveries = item.get("discovery_tasks", [])
            if not discoveries and item.get("task_id"):
                discoveries = [{"task_id": item["task_id"]}]
            for discovery in discoveries:
                content.append(paragraph(f"Tarea: {discovery.get('task_id')} · Intento: {discovery.get('attempt_id') or 'No consignado'} · Evidencia: {discovery.get('evidence_ref') or 'No generada'}"))
    observations = [v for v in report.get("validation", []) if v.get("case_id")]
    if observations:
        content.append(paragraph("Observaciones IPv6", "Heading2"))
        rows = [[paragraph(x) for x in ["Caso", "Clasificación", "Resultado"]]]
        rows += [
            [paragraph(v["case_id"]), paragraph(v["state"]), paragraph(v["reason"])]
            for v in observations
        ]
        ipv6_table = Table(rows, colWidths=[60, 150, 290], repeatRows=1)
        ipv6_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f7")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        content += [ipv6_table, Spacer(1, 12)]
    content.append(paragraph(report.get("note", "")))
    for limitation in report.get("limitations", []):
        if limitation != report.get("note"):
            content.append(paragraph(limitation))

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(550, 25, f"Página {doc.page}")

    SimpleDocTemplate(
        str(root / "report.pdf"),
        pagesize=A4,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45,
    ).build(content, onFirstPage=footer, onLaterPages=footer)
