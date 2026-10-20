import json
from pathlib import Path

from typer.testing import CliRunner

from auditoria.cli import app
from auditoria.contracts import Service, TaskResult, TaskStatus


BASE = Path(__file__).resolve().parents[1]


def test_pilot_writes_live_report_and_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr("auditoria.cli.verify_pilot_lab", lambda: {
        "internal": True, "image_id": "sha256:example", "address": "192.168.57.13",
    })

    def fake_nmap(task, store, *, timeout_seconds):
        ref, digest = store.evidence(task.task_id, "xml", b"<nmaprun/>")
        return TaskResult(task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS,
                          services=[Service(port=8080, protocol="tcp", state="open", name="http")],
                          evidence_ref=ref, evidence_sha256=digest)

    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_nmap", fake_nmap)
    result = CliRunner().invoke(app, [
        "piloto-docker", "--autorizacion", "acta-piloto",
        "--politica", str(BASE / "config/lab_policy.example.json"),
        "--salida", str(tmp_path),
    ])
    assert result.exit_code == 0, result.output
    reports = list(tmp_path.glob("*/report.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
    assert report["mode"] == "live"
    assert report["inventory"][0]["services"][0]["port"] == 8080
    assert report["tasks"][0]["agent_name"] == "Agente IPv4 de Servicios"
    assert "Agente IPv4 de Servicios" in result.output
    assert (reports[0].parent / report["tasks"][0]["evidence_ref"]).exists()
