import hashlib
from pathlib import Path

from auditoria.agentes.agente_administrador import build_graph
from auditoria.contracts import AuditRequest, LabPolicy, Task, TaskResult, TaskStatus
from auditoria.store import RunStore
from auditoria.validation import validate_results


BASE = Path(__file__).resolve().parents[1]


def test_validation_rejects_changed_evidence(tmp_path):
    root = tmp_path / "run"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    packet = evidence / "packet.pcap"
    diagnostic = evidence / "state.json"
    packet.write_bytes(b"packet")
    diagnostic.write_bytes(b"state")
    target = AuditRequest.model_validate_json((BASE / "examples/solicitud.example.json").read_text()).targets[0]
    task = Task(task_id="case_gt09", case_id="GT-09", agent_type="ipv6_ndp",
                target=target, protocol="icmpv6", action_profile="ipv6_ra_route_v1",
                timeout_seconds=30)
    result = TaskResult(
        task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS,
        observations={"packet_observed": True, "route_changed": True, "restored": True},
        evidence_ref="evidence/packet.pcap", evidence_sha256=hashlib.sha256(b"packet").hexdigest(),
        diagnostic_ref="evidence/state.json", diagnostic_sha256=hashlib.sha256(b"state").hexdigest())
    assert validate_results(root, [task], [result])[0]["state"] == "candidate"
    packet.write_bytes(b"tampered")
    record = validate_results(root, [task], [result])[0]
    assert record["state"] == "indeterminate"
    assert record["reason"] == "evidence_incomplete_or_changed"


def test_scheduler_dry_run_never_initializes_openai(tmp_path, monkeypatch):
    request = AuditRequest.model_validate_json((BASE / "examples/solicitud.example.json").read_text())
    policy = LabPolicy.model_validate_json((BASE / "config/ipv6_pilot.policy.json").read_text())
    request = request.model_copy(update={"token_budget":512,"llm_mode":"scheduler","llm_provider":"openai"})
    def denied(*args, **kwargs):
        raise AssertionError("una simulación no debe abrir el proveedor")
    monkeypatch.setattr("auditoria.openai_provider.OpenAIScheduler.__init__", denied)
    store = RunStore(tmp_path / "dry-run", request.audit_id)
    try:
        state = build_graph(store, live=False).invoke({"request":request,"policy":policy,"tasks":[],"results":[],"report":{}})
    finally:
        store.close()
    assert state["report"]["llm"]["status"] == "disabled"
    assert state["report"]["llm"].get("known_tokens",0) == 0
