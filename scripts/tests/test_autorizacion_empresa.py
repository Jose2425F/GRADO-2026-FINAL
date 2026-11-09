"""Autorización del flujo LangGraph real con herramientas simuladas: cero tráfico."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime")

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "piloto_kali/prototipo/src")]

import laboratorio_empresa as company
from auditoria import empresa_agent as agent
from auditoria.contracts import TaskResult
from auditoria.policy import PolicyError
from tesis.laboratorios import Context


def _changed_request(req, case):
    now = datetime.now(timezone.utc)
    if case == "expired":
        return req.model_copy(update={"not_before": now - timedelta(hours=2),
                                      "not_after": now - timedelta(hours=1)})
    if case == "future":
        return req.model_copy(update={"not_before": now + timedelta(hours=1),
                                      "not_after": now + timedelta(hours=2)})
    if case == "ipv4_target_outside_scope":
        return req.model_copy(update={"scope_ipv4": []})
    if case == "ipv6_target_outside_scope":
        return req.model_copy(update={"scope_ipv6": []})
    if case == "public_scope":
        return req.model_copy(update={"scope_ipv4": ["8.8.8.0/24"]})
    if case == "wrong_scope_family":
        return req.model_copy(update={"scope_ipv4": ["2001:db8::/64"]})
    if case == "interface":
        target = req.targets[0].model_copy(update={"interface": "eth-unapproved"})
        return req.model_copy(update={"targets": [target, *req.targets[1:]]})
    if case == "category":
        return req.model_copy(update={"categories": req.categories[:-1]})
    if case == "ports":
        target = req.targets[0].model_copy(update={"ports": [65535]})
        return req.model_copy(update={"targets": [target, *req.targets[1:]]})
    if case == "profile_policy":
        return req.model_copy(update={"execution_policy": "unapproved"})
    raise AssertionError(case)


CASES = [
    ("expired", "outside_window"),
    ("future", "outside_window"),
    ("ipv4_target_outside_scope", "target_out_of_scope"),
    ("ipv6_target_outside_scope", "target_out_of_scope"),
    ("public_scope", "scope_denied"),
    ("wrong_scope_family", "scope_version"),
    ("interface", "interface_denied"),
    ("category", "category_denied"),
    ("ports", "port_denied"),
    ("profile_policy", "empresa_scope_denied"),
]


@pytest.mark.parametrize("scenario", ["original", "sucursal", "comercial", "mixto", "reforzado"])
def test_canonical_requests_and_each_task_authorized_for_all_five_labs(tmp_path, scenario):
    engine = agent if scenario == "original" else Context(scenario, state_root=tmp_path).agent
    req = engine.request("LAB-PROPIO", llm=False)
    engine.authorize_empresa(req, engine.policy())
    for task in engine.build_plan(req):
        engine.authorize_empresa(req, engine.policy(), task=task)


@pytest.mark.parametrize("scenario", ["original", "sucursal", "comercial", "mixto", "reforzado"])
@pytest.mark.parametrize("case,reason", CASES)
def test_request_rejects_window_scope_interface_categories_and_profiles(tmp_path, scenario, case, reason):
    engine = agent if scenario == "original" else Context(scenario, state_root=tmp_path).agent
    req = _changed_request(engine.request("LAB-PROPIO", llm=False), case)
    with pytest.raises(PolicyError) as rejected:
        engine.authorize_empresa(req, engine.policy())
    assert rejected.value.reason_code == reason


@pytest.mark.parametrize("field,value,reason", [
    ("action_profile", "ipv6_ra_route_v2", "empresa_profile_denied"),
    ("task_id", "task_not_approved", "empresa_profile_denied"),
    ("agent_type", "category_not_approved", "category_denied"),
])
def test_concrete_task_must_match_authorized_catalogue(field, value, reason):
    req = agent.request("LAB-PROPIO", llm=False)
    task = agent.build_plan(req)[0].model_copy(update={field: value})
    with pytest.raises(PolicyError) as rejected:
        agent.authorize_empresa(req, agent.policy(), task=task)
    assert rejected.value.reason_code == reason


def test_concrete_task_cannot_change_target_or_interface():
    req = agent.request("LAB-PROPIO", llm=False)
    task = agent.build_plan(req)[0]
    changed = task.model_copy(update={"target": task.target.model_copy(update={"interface": "eth-unapproved"})})
    with pytest.raises(PolicyError) as rejected:
        agent.authorize_empresa(req, agent.policy(), task=changed)
    assert rejected.value.reason_code == "target_out_of_scope"


def _events(directory):
    with sqlite3.connect(directory / "events.sqlite3") as con:
        return [(kind, task_id, json.loads(payload)) for kind, task_id, payload in
                con.execute("SELECT kind,task_id,payload_json FROM events ORDER BY rowid")]


def _simulate_panel(tmp_path, req, *, preflight=None, guard=None, worker=None):
    options = {"authorization": "LAB-PROPIO", "architecture": req.architecture,
               "tokens": req.token_budget, "ia": "openai" if req.token_budget else "none"}
    with patch.object(agent, "request", return_value=req), \
         patch.object(agent, "authorize_empresa", side_effect=guard or agent.authorize_empresa), \
         patch.object(company.lab, "load_auditor_environment") as load_environment, \
         patch.object(company.lab, "preflight", side_effect=preflight or (lambda state: {})) as check_lab, \
         patch.object(agent, "run_task", side_effect=worker or (
             lambda task, store: TaskResult(task_id=task.task_id, status="completed_no_findings"))) as execute, \
         patch.object(company, "validation_for", return_value=({"state": "observed"}, [])), \
         patch("tesis.evaluacion.score", return_value={"evidence_valid": False, "simulation_only": True}), \
         patch("auditoria.openai_provider.load_openai_config") as load_provider:
        code = company.run_panel(options, tmp_path)
    directory = next(tmp_path.glob("*/report.json")).parent
    return code, directory, json.loads((directory / "report.json").read_text()), \
        _events(directory), load_environment, check_lab, execute, load_provider


@pytest.mark.parametrize("case,reason", CASES)
def test_initial_rejection_persists_reason_before_any_network_or_api(tmp_path, case, reason):
    req = _changed_request(agent.request("LAB-PROPIO", architecture="single", llm=True), case)
    code, directory, report, events, load_environment, preflight, execute, provider = _simulate_panel(tmp_path, req)
    assert code == 3
    assert report["status"] == "rejected" and report["reason_code"] == report["error"] == reason
    assert report["llm"]["known_tokens"] == 0 and report["llm"]["calls"] == []
    assert report["tasks"] == report["findings"] == []
    assert json.loads((directory / "request.json").read_text())["audit_id"] == req.audit_id
    assert json.loads((directory / "runtime.json").read_text())["status"] == "finished"
    assert any(kind == "request_rejected" and payload["reason_code"] == reason
               for kind, _, payload in events)
    load_environment.assert_not_called()
    preflight.assert_not_called()
    execute.assert_not_called()
    provider.assert_not_called()


@pytest.mark.usefixtures("healthy_kernel")
def test_expired_after_initial_check_is_rejected_before_preflight_network(tmp_path):
    req = agent.request("LAB-PROPIO", architecture="single", llm=False)
    real_guard = agent.authorize_empresa
    checked = []

    def expire_after_initial(request, policy, *, task=None):
        real_guard(request, policy, task=task)
        checked.append(task)
        if len(checked) == 1:
            request.not_after = datetime.now(timezone.utc) - timedelta(seconds=1)

    code, _, report, events, environment, preflight, execute, provider = _simulate_panel(
        tmp_path, req, guard=expire_after_initial)
    assert code == 3 and report["status"] == "partial"
    assert report["reason_code"] == "outside_window"
    assert any(kind == "authorization_rejected" and payload["stage"] == "preflight"
               for kind, _, payload in events)
    environment.assert_not_called()
    preflight.assert_not_called()
    execute.assert_not_called()
    provider.assert_not_called()


@pytest.mark.usefixtures("healthy_kernel")
def test_changed_task_profile_after_preflight_is_rejected_before_network(tmp_path):
    req = agent.request("LAB-PROPIO", architecture="single", llm=False)
    real_build_plan = agent.build_plan
    plans = []

    def remember_plan(request):
        tasks = real_build_plan(request)
        plans.append(tasks)
        return tasks

    def change_task(state):
        plans[0][0].action_profile = "hydra_ssh_single_v1"
        return {}

    with patch.object(agent, "build_plan", side_effect=remember_plan):
        code, _, report, events, _, _, execute, provider = _simulate_panel(tmp_path, req, preflight=change_task)
    assert code == 3 and report["status"] == "partial"
    assert report["reason_code"] == "empresa_profile_denied"
    assert any(kind == "authorization_rejected" and payload["stage"] == "admission"
               for kind, _, payload in events)
    execute.assert_not_called()
    provider.assert_not_called()


@pytest.mark.usefixtures("healthy_kernel")
def test_expired_after_preflight_is_rejected_before_first_dispatch_and_persisted(tmp_path):
    req = agent.request("LAB-PROPIO", architecture="single", llm=False)

    def expire(state):
        req.not_after = datetime.now(timezone.utc) - timedelta(seconds=1)
        return {}

    code, _, report, events, _, preflight, execute, provider = _simulate_panel(tmp_path, req, preflight=expire)
    assert code == 3 and report["status"] == "partial"
    assert report["reason_code"] == "outside_window"
    assert report["authorization_rejection"]["stage"] == "admission"
    assert any(kind == "authorization_rejected" and payload["reason_code"] == "outside_window"
               for kind, _, payload in events)
    preflight.assert_called_once()
    execute.assert_not_called()
    provider.assert_not_called()


@pytest.mark.usefixtures("healthy_kernel")
def test_expired_after_admission_is_rechecked_in_executor_before_network(tmp_path):
    req = agent.request("LAB-PROPIO", architecture="single", llm=False)
    real_guard = agent.authorize_empresa
    concrete_checks = []

    def expire_after_admission(request, policy, *, task=None):
        real_guard(request, policy, task=task)
        if task is not None:
            concrete_checks.append(task.task_id)
            if len(concrete_checks) == 1:
                request.not_after = datetime.now(timezone.utc) - timedelta(seconds=1)

    code, _, report, events, _, _, execute, provider = _simulate_panel(tmp_path, req, guard=expire_after_admission)
    assert code == 3 and report["status"] == "partial"
    assert report["reason_code"] == "outside_window"
    assert any(kind == "authorization_rejected" and payload["stage"] == "execution"
               and payload["reason_code"] == "outside_window" for kind, _, payload in events)
    execute.assert_not_called()
    provider.assert_not_called()


@pytest.mark.usefixtures("healthy_kernel")
def test_scope_is_rechecked_for_next_task_after_first_worker_changes_request(tmp_path):
    req = agent.request("LAB-PROPIO", architecture="single", llm=False)

    def change_scope(task, store):
        req.scope_ipv4 = []
        return TaskResult(task_id=task.task_id, status="completed_no_findings")

    code, _, report, events, _, _, execute, provider = _simulate_panel(tmp_path, req, worker=change_scope)
    assert code == 3 and report["status"] == "partial"
    assert report["reason_code"] == "target_out_of_scope"
    assert any(kind == "authorization_rejected" and payload["stage"] == "admission"
               and payload["reason_code"] == "target_out_of_scope" for kind, _, payload in events)
    execute.assert_called_once()
    provider.assert_not_called()


@pytest.mark.parametrize("scenario", ["sucursal", "comercial", "mixto", "reforzado"])
@pytest.mark.parametrize("stage", ["initial", "preflight"])
def test_suite_authorization_rejection_returns_without_docker_or_manifest_postprocessing(tmp_path, scenario, stage):
    import laboratorio_suite as suite

    ctx = Context(scenario, state_root=tmp_path / "states")
    # Solo archivos ficticios para la cápsula del wrapper: no se prepara ni
    # arranca un laboratorio y ningún dato operativo del usuario se consulta.
    ctx.state.mkdir(parents=True)
    for name in ["ground_truth.json", "policy.json", "lab.env", "compose.json", "http_target.py", "prepared.json"]:
        (ctx.state / name).write_text("{}\n")
    (ctx.state / "protocol").mkdir()
    req = ctx.agent.request("LAB-PROPIO", architecture="single", llm=True)
    real_guard = ctx.agent.authorize_empresa
    checked = []

    def expire_before_preflight(request, policy, *, task=None):
        real_guard(request, policy, task=task)
        checked.append(task)
        if len(checked) == 1:
            request.not_after = datetime.now(timezone.utc) - timedelta(seconds=1)

    if stage == "initial":
        req = _changed_request(req, "expired")
    options = {"authorization": "LAB-PROPIO", "architecture": "single", "tokens": req.token_budget,
               "ia": "openai"}
    output = tmp_path / "output"
    with patch.object(suite, "STATE", tmp_path / "suite"), \
         patch.object(ctx.agent, "request", return_value=req), \
         patch.object(ctx.agent, "authorize_empresa", side_effect=(
             real_guard if stage == "initial" else expire_before_preflight)), \
         patch.object(ctx.agent, "run_task") as execute, \
         patch.object(ctx, "validation", return_value=({"state": "observed"}, [])), \
         patch.object(ctx.lab, "load_auditor_environment") as environment, \
         patch.object(suite, "ready", side_effect=AssertionError("readiness forbidden after rejection")) as ready, \
         patch.object(suite, "images", side_effect=AssertionError("Docker forbidden after rejection")) as images, \
         patch.object(suite.subprocess, "run", side_effect=AssertionError("subprocess forbidden")) as process, \
         patch("auditoria.openai_provider.load_openai_config") as provider:
        code = suite.audit(ctx, options, output)
    assert code == 3
    directory = next(output.glob("*/report.json")).parent
    report = json.loads((directory / "report.json").read_text())
    assert report["status"] == ("rejected" if stage == "initial" else "partial")
    assert report["reason_code"] == "outside_window"
    assert (directory / "manifest.json").is_file()
    assert report["llm"]["known_tokens"] == 0
    if stage == "initial":
        assert report["tasks"] == []
    assert any(kind == ("request_rejected" if stage == "initial" else "authorization_rejected")
               and payload["reason_code"] == "outside_window"
               for kind, _, payload in _events(directory))
    execute.assert_not_called()
    environment.assert_not_called()
    ready.assert_not_called()
    images.assert_not_called()
    process.assert_not_called()
    provider.assert_not_called()
