import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from auditoria.contracts import AuditRequest, LabPolicy, Task, TaskResult, TaskStatus
from auditoria.agentes.agente_ipv4_credenciales import run_hydra
from auditoria.policy import PolicyError, authorize_request
from auditoria.store import RunStore
from auditoria.agentes.agente_administrador import build_graph


BASE = Path(__file__).resolve().parents[1]


def inputs():
    request = AuditRequest.model_validate_json(
        (BASE / "examples/solicitud.credentials-pilot.json").read_text())
    now = datetime.now(timezone.utc)
    request = request.model_copy(update={
        "not_before": now - timedelta(minutes=1),
        "not_after": now + timedelta(minutes=5),
    })
    policy = LabPolicy.model_validate_json(
        (BASE / "config/credentials_pilot.policy.json").read_text())
    return request, policy


@pytest.mark.parametrize("ref,ports,reason", [
    ("unknown", [2222], "credential_ref_denied"),
    ("ssh_synthetic_1", [22], "port_denied"),
])
def test_credential_scope_rejected(ref, ports, reason):
    request, policy = inputs()
    target = request.targets[0].model_copy(update={"credential_ref": ref, "ports": ports})
    request = request.model_copy(update={"targets": [target]})
    with pytest.raises(PolicyError) as error:
        authorize_request(request, policy)
    assert error.value.reason_code == reason


def test_credential_pilot_policy_rejects_neighboring_host():
    request, policy = inputs()
    target = request.targets[0].model_copy(update={"address": "192.168.57.12"})
    request = request.model_copy(update={"targets": [target]})
    with pytest.raises(PolicyError) as error:
        authorize_request(request, policy)
    assert error.value.reason_code == "target_out_of_scope"


def test_hydra_evidence_never_contains_password(tmp_path, monkeypatch):
    request, policy = inputs()
    profile = policy.credential_profiles[0]
    secret = "synthetic-only-test-password"
    monkeypatch.setenv(profile.password_env, secret)
    monkeypatch.setattr("auditoria.agentes.agente_ipv4_credenciales.check_route", lambda address, interface: None)

    def fake_run(command, **kwargs):
        password_path = Path(command[command.index("-P") + 1])
        assert password_path.read_text().strip() == secret
        assert password_path.stat().st_mode & 0o077 == 0
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(json.dumps({
            "success": True, "quantityfound": 1, "errormessages": [],
            "results": [{"host": "192.168.57.11", "port": 2222,
                         "service": "ssh", "login": "labuser", "password": secret}],
        }))
        return SimpleNamespace(returncode=0, stdout=f"password: {secret}", stderr="")

    monkeypatch.setattr("auditoria.agentes.agente_ipv4_credenciales.subprocess.run", fake_run)
    target = request.targets[0]
    task = Task(task_id="credential_test", agent_type="ipv4_credentials", target=target,
                protocol="tcp", action_profile="hydra_ssh_single_v1", timeout_seconds=30)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        result = run_hydra(task, profile, store, timeout_seconds=30)
    finally:
        store.close()
    assert result.status == TaskStatus.COMPLETED
    assert result.authentication.outcome == "accepted"
    assert secret not in result.model_dump_json()
    assert secret.encode() not in (tmp_path / "run" / result.evidence_ref).read_bytes()


def test_no_ssh_discovery_skips_authentication(tmp_path, monkeypatch):
    request, policy = inputs()
    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_nmap", lambda task, store, timeout_seconds: TaskResult(
        task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS))
    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_hydra", lambda *args, **kwargs: pytest.fail(
        "Hydra no debe ejecutarse sin SSH observado"))
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=True).invoke({
            "request": request, "policy": policy, "tasks": [], "results": [], "report": {},
        })
    finally:
        store.close()
    assert state["results"][1].reason_code == "no_applicable"
    assert state["report"]["status"] == "complete"
