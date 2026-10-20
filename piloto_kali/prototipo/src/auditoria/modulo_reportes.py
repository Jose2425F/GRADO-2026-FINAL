"""Módulo de Reportes: JSON estructurado y vista HTML sin secretos."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .agentes import AGENT_NAMES
from .contracts import AuditRequest, Task, TaskResult, TaskStatus
from .store import write_json


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
        "mode": "live" if live else "dry_run",
        "status": status,
        "inventory": [
            {"task_id": result.task_id, "services": [s.model_dump() for s in result.services]}
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
    write_json(root / "report.json", report)
    template_text = (
        files("auditoria").joinpath("templates/report.html.j2").read_text(encoding="utf-8")
    )
    environment = Environment(autoescape=select_autoescape(["html", "xml"]))
    html = environment.from_string(template_text).render(report=report)
    (root / "report.html").write_text(html, encoding="utf-8")
    save_pdf(root, report)


def save_pdf(root: Path, report: dict) -> None:
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
    if control.get("stopped"):
        content.insert(-1, paragraph(
            "Pruebas detenidas tras acceso corroborado en "
            f"{control['trigger_task_id']}; {control['cancelled_tasks']} tareas canceladas. "
            "Cobertura parcial de demostración."
        ))
    for finding in report.get("findings", []):
        content += [
            paragraph(f"{finding['asset_id']} - {finding['title']}", "Heading3"),
            paragraph(f"Condición: {finding['defect_key']}"),
            paragraph(f"Evidencia: {finding['evidence_ref']}"),
            paragraph(f"Corroboración: {finding['confirmation_ref']}"),
            paragraph(f"Referencia: {finding['reference']}"),
            paragraph(finding["remediation"]),
            Spacer(1, 2),
        ]
    if not report.get("findings", []):
        content.append(
            paragraph(
                "No hay hallazgos verificados. Esto no demuestra ausencia de vulnerabilidades."
            )
        )
    content.append(paragraph("Resultados de tareas", "Heading2"))
    rows = [[paragraph(x) for x in ["Tarea", "Estado", "Motivo"]]]
    rows += [
        [
            paragraph(t["task_id"].removeprefix(report["audit_id"] + "_")),
            paragraph(
                {
                    "completed": "Completada",
                    "completed_no_findings": "Sin hallazgos",
                    "skipped": "Omitida",
                    "blocked": "Bloqueada",
                    "failed": "Fallida",
                    "cancelled": "Cancelada",
                }.get(t["status"], t["status"])
            ),
            paragraph(t["reason_code"] or "—"),
        ]
        for t in report.get("tasks", [])
    ]
    table = Table(rows, colWidths=[280, 120, 100], repeatRows=1)
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
    observations = [v for v in report.get("validation", []) if v["case_id"]]
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
