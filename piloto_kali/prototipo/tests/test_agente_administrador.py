from pathlib import Path

from auditoria.contracts import AuditRequest, LabPolicy
from auditoria.store import RunStore
from auditoria.agentes.agente_administrador import build_graph


BASE = Path(__file__).resolve().parents[1]


def test_dry_run_does_not_invoke_nmap(tmp_path, monkeypatch):
    request = AuditRequest.model_validate_json((BASE / "examples/solicitud.example.json").read_text())
    policy = LabPolicy.model_validate_json((BASE / "config/lab_policy.example.json").read_text())

    def unexpected(*args, **kwargs):
        raise AssertionError("Nmap no debe ejecutarse en dry_run")

    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_nmap", unexpected)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=False).invoke({
            "request": request, "policy": policy, "tasks": [], "results": [], "report": {},
        })
    finally:
        store.close()
    assert state["report"]["status"] == "dry_run"
    assert state["report"]["findings"] == []
    assert (tmp_path / "run" / "report.json").exists()
