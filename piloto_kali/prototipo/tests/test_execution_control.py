"""Verifica límites del planificador y parada sin tráfico ni proveedores reales."""

import json
from contextlib import nullcontext

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from auditoria.agentes.agente_administrador import build_graph
from auditoria.cli import app
from auditoria.contracts import Authentication, LabPolicy, Service, Task, TaskResult, TaskStatus
from auditoria.decisions import decision_prompt, parse_choice
from auditoria.laboratorio import prepare, request_for_lab
from auditoria.store import RunStore


def inputs(tmp_path, architecture="multiagent", stop=True):
    config = tmp_path / "config"
    prepare(config)
    policy = LabPolicy.model_validate_json((config / "policy.json").read_text())
    request = request_for_lab("test-control", architecture=architecture, ipv6=False)
    request = request.model_copy(update={
        "targets": request.targets[:2], "stop_on_verified_access": stop,
    })
    return config, policy, request


def mock_adapters(monkeypatch, *, confirmation="valid"):
    executed = []

    def scan(task, store, **kwargs):
        executed.append(task.task_id)
        ref, digest = store.evidence(task.task_id, "xml", b"<nmaprun/>")
        return TaskResult(
            task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS,
            services=[Service(port=p, protocol="tcp", state="open") for p in task.target.ports],
            evidence_ref=ref, evidence_sha256=digest,
        )

    def authenticate(task, profile, store, **kwargs):
        executed.append(task.task_id)
        data = {
            "target": task.target.address, "port": profile.port, "service": profile.service,
            "credential_ref": profile.ref, "outcome": "accepted",
        }
        ref, digest = store.evidence(
            task.task_id, "json", json.dumps({**data, "tool": "hydra"}).encode(),
        )
        tool = {
            "ssh": "paramiko", "ftp": "ftplib", "postgres": "psycopg",
            "http-get": "urllib-basic-auth",
        }[profile.service]
        corroboration = {**data, "tool": tool}
        if confirmation == "rejected":
            corroboration["outcome"] = "rejected"
        elif confirmation == "wrong_target":
            corroboration["target"] = "192.0.2.1"
        diag, diag_hash = store.evidence(
            task.task_id + "_confirmation", "json", json.dumps(corroboration).encode(),
        )
        if confirmation == "tampered":
            (store.root / diag).write_text("changed")
        elif confirmation == "missing":
            diag = diag_hash = None
        return TaskResult(
            task_id=task.task_id, status=TaskStatus.COMPLETED,
            authentication=Authentication(
                credential_ref=profile.ref, service=profile.service, port=profile.port,
                outcome="accepted",
            ),
            evidence_ref=ref, evidence_sha256=digest,
            diagnostic_ref=diag, diagnostic_sha256=diag_hash,
        )

    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_nmap", scan)
    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_hydra", authenticate)
    return executed


@pytest.mark.parametrize("architecture", ["single", "multiagent"])
def test_verified_access_stops_before_next_adapter_and_persists_cancellations(
    tmp_path, monkeypatch, architecture,
):
    _, policy, request = inputs(tmp_path, architecture)
    executed = mock_adapters(monkeypatch)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({"request": request, "policy": policy})
        control = state["report"]["execution_control"]
        assert control["stopped"] is True
        assert control["execution_concurrency"] == 1
        assert executed == [state["tasks"][0].task_id, state["tasks"][1].task_id]
        assert control["trigger_task_id"] == executed[-1]
        assert control["cancelled_tasks"] == len(state["tasks"]) - 2
        assert len(state["results"]) == len(state["tasks"])
        assert all(
            r.status == TaskStatus.CANCELLED and r.reason_code == "access_objective_reached"
            for r in state["results"][2:]
        )
        assert state["report"]["status"] == "partial"
        assert len(state["report"]["findings"]) == 1
        saved = json.loads((store.root / "report.json").read_text())
        assert saved["execution_control"] == control
        assert "Pruebas detenidas" in (store.root / "report.html").read_text()
        assert (store.root / "report.pdf").read_bytes().startswith(b"%PDF-")
        assert store.connection.execute(
            "SELECT count(*) FROM events WHERE kind='access_objective_reached'"
        ).fetchone()[0] == 1
    finally:
        store.close()


@pytest.mark.parametrize("confirmation", ["rejected", "wrong_target", "tampered", "missing"])
def test_unsubstantiated_access_never_activates_stop(tmp_path, monkeypatch, confirmation):
    _, policy, request = inputs(tmp_path)
    executed = mock_adapters(monkeypatch, confirmation=confirmation)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({"request": request, "policy": policy})
        assert state["report"]["execution_control"]["stopped"] is False
        assert len(executed) == len(state["tasks"])
        assert state["report"]["findings"] == []
    finally:
        store.close()


def test_stop_verifies_access_without_requiring_a_vulnerability_label(tmp_path, monkeypatch):
    _, policy, request = inputs(tmp_path)
    policy = policy.model_copy(update={"credential_profiles": [
        p.model_copy(update={"condition": None}) for p in policy.credential_profiles
    ]})
    mock_adapters(monkeypatch)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({"request": request, "policy": policy})
        assert state["report"]["execution_control"]["stopped"] is True
        assert state["report"]["findings"] == []
    finally:
        store.close()


def test_full_evaluation_keeps_running_after_verified_access(tmp_path, monkeypatch):
    _, policy, request = inputs(tmp_path, architecture="single", stop=False)
    executed = mock_adapters(monkeypatch)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({"request": request, "policy": policy})
        assert state["report"]["execution_control"]["stopped"] is False
        assert len(executed) == len(state["tasks"])
        assert state["report"]["status"] == "complete"
    finally:
        store.close()


@pytest.mark.parametrize("extra", [{"script": "print('x')"}, {"command": ["sh"]}])
def test_contracts_reject_executable_fields_and_unknown_profiles(tmp_path, extra):
    _, _, request = inputs(tmp_path)
    with pytest.raises(ValidationError):
        type(request).model_validate({**request.model_dump(), **extra})
    with pytest.raises(ValidationError):
        type(request).model_validate({**request.model_dump(), "execution_policy": "generated_scripts"})
    task = dict(
        task_id="approved", agent_type="ipv4_services", target=request.targets[0],
        protocol="tcp", action_profile="nmap_tcp_services_v1", timeout_seconds=10,
    )
    with pytest.raises(ValidationError):
        Task.model_validate({**task, **extra})
    with pytest.raises(ValidationError):
        Task.model_validate({**task, "action_profile": "generated_script_v1"})


@pytest.mark.parametrize("output", [
    '{"choice":"a","script":"print(1)"}', '{"choice":"a","command":["sh"]}',
    '{"choice":["a"]}', '{"choice":"outside"}', 'print(1)',
])
def test_llm_response_cannot_supply_code_even_with_an_authorized_choice(output):
    with pytest.raises(ValueError):
        parse_choice(output, ["a", "b"])


def test_prompt_cannot_accept_commands_in_place_of_ids():
    with pytest.raises(ValueError):
        decision_prompt(["a; sh"], {}, "single")
    with pytest.raises(ValueError):
        decision_prompt(["a", "a"], {}, "single")


def test_controller_discards_fabricated_scheduler_tasks(tmp_path, monkeypatch):
    _, policy, request = inputs(tmp_path, architecture="single", stop=False)
    request = request.model_copy(update={"llm_mode": "scheduler", "token_budget": 40000})
    executed = mock_adapters(monkeypatch)

    class ForgedScheduler:
        config = type("Config", (), {"model": "fake"})()

        def __init__(self, *args, **kwargs):
            pass

        def select(self, ready, previous, tasks):
            return ready[0].model_copy(update={"action_profile": "generated_script_v1"})

        def close(self):
            pass

        def summary(self):
            return {"status": "fallback", "model": "fake", "calls": []}

    monkeypatch.setattr("auditoria.openai_provider.OpenAIScheduler", ForgedScheduler)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({"request": request, "policy": policy})
        assert len(executed) == len(state["tasks"])
        assert store.connection.execute(
            "SELECT count(*) FROM events WHERE kind='task_selection_rejected'"
        ).fetchone()[0] > 0
        assert state["report"]["status"] == "complete"
    finally:
        store.close()


def test_demo_stop_option_records_policy_without_network_or_provider(tmp_path, monkeypatch):
    config, _, _ = inputs(tmp_path)
    monkeypatch.setattr("auditoria.cli.operation_lock", nullcontext)
    monkeypatch.setattr(
        "auditoria.laboratorio.preflight", lambda **kwargs: pytest.fail("no Docker in dry-run")
    )
    executed = mock_adapters(monkeypatch)
    result = CliRunner().invoke(app, [
        "demo", "--config", str(config), "--salida", str(tmp_path / "runs"),
        "--autorizacion", "test-control", "--parar-al-confirmar-acceso", "--sin-ipv6",
    ])
    assert result.exit_code == 0, result.output
    assert not executed
    manifest = json.loads(next((tmp_path / "runs").glob("*/manifest.json")).read_text())
    assert manifest["execution_policy"] == "predefined_profiles"
    assert manifest["stop_on_verified_access"] is True
    assert manifest["execution_concurrency"] == 1


def test_even_a_complete_access_demo_is_excluded_from_formal_kpis(tmp_path, monkeypatch):
    from auditoria import metrics

    config, _, request = inputs(tmp_path)
    roots = [tmp_path / name for name in ["single", "multiagent"]]
    for architecture, root in zip(["single", "multiagent"], roots):
        root.mkdir()
        demo_request = request.model_copy(update={
            "architecture": architecture, "audit_id": architecture,
            "llm_mode": "scheduler", "token_budget": 40000,
        })
        (root / "request.json").write_text(demo_request.model_dump_json())
        (root / "report.json").write_text(json.dumps({"llm": {
            "status": "accepted", "usage_complete": True, "calls": [{}], "model": "fake",
        }}))

    def score(root, truth):
        return {
            "architecture": root.name, "audit_id": root.name, "status": "complete",
            "mode": "live", "evidence_valid": True, "elapsed_seconds": 1,
            "TP": 1, "tokens": 100,
        }

    monkeypatch.setattr(metrics, "score_run", score)
    monkeypatch.setattr(metrics, "comparison_context", lambda root: {})
    pair = metrics.compare_pair(*roots, config / "ground_truth.json")
    assert pair["eligible"] is False
    assert pair["formal_kpis"] is None
    assert pair["ineligibility_reasons"] == [
        "single_access_demo_not_full_evaluation", "multiagent_access_demo_not_full_evaluation",
    ]
