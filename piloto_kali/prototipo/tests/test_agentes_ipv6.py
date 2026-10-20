from datetime import datetime, timedelta, timezone
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from auditoria.agentes.agente_administrador import build_graph
from auditoria.agentes.agente_ipv6_ndp_slaac import run_ndp
from auditoria.contracts import AuditRequest, Category, LabPolicy, Target, Task
from auditoria.ipv6_lab import IPv6LabError, INTERFACE, SUBNET, TARGET, UDP_PORT
from auditoria.policy import PolicyError, authorize_request
from auditoria.store import RunStore


BASE = Path(__file__).resolve().parents[1]


def inputs():
    now = datetime.now(timezone.utc)
    request = AuditRequest(
        audit_id="ipv6_test", operator="test", authorization_ref="lab-test",
        scope_ipv6=[SUBNET], categories=[Category.IPV6_NDP, Category.IPV6_FRAGMENTATION],
        targets=[Target(asset_id="obj_ipv6", address=TARGET, interface=INTERFACE, ports=[UDP_PORT])],
        not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=1),
        max_runtime_seconds=120, max_attempts=1, token_budget=0,
    )
    policy = LabPolicy.model_validate_json((BASE / "config/ipv6_pilot.policy.json").read_text())
    return request, policy


def test_ipv6_plan_is_serial_and_dry_run_sends_nothing(tmp_path, monkeypatch):
    request, policy = inputs()
    authorize_request(request, policy)
    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_ndp",
                        lambda *args, **kwargs: pytest.fail("no se debe enviar RA"))
    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_fragmentation",
                        lambda *args, **kwargs: pytest.fail("no se deben enviar fragmentos"))
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=False).invoke({
            "request": request, "policy": policy, "tasks": [], "results": [], "report": {},
        })
    finally:
        store.close()
    assert [task.agent_type for task in state["tasks"]] == ["ipv6_ndp", "ipv6_fragmentation"]
    assert state["tasks"][1].dependencies == [state["tasks"][0].task_id]
    assert [task["agent_name"] for task in state["report"]["tasks"]] == [
        "Agente IPv6 NDP/SLAAC", "Agente IPv6 de Fragmentación"]


def test_ipv6_policy_rejects_unapproved_interface():
    request, policy = inputs()
    target = request.targets[0].model_copy(update={"interface": "eth0"})
    with pytest.raises(PolicyError) as error:
        authorize_request(request.model_copy(update={"targets": [target]}), policy)
    assert error.value.reason_code == "interface_denied"


def test_ndp_agent_rejects_different_target_before_docker(tmp_path, monkeypatch):
    monkeypatch.setattr("auditoria.agentes.agente_ipv6_ndp_slaac.verify_ipv6_lab",
                        lambda: pytest.fail("no debe acceder a Docker"))
    task = Task(task_id="ipv6_wrong", agent_type="ipv6_ndp",
                target=Target(asset_id="other", address="fd57:2026:9:28::21",
                              interface=INTERFACE, ports=[]), protocol="icmpv6",
                action_profile="ipv6_ra_mtu_v1", timeout_seconds=30)
    store = RunStore(tmp_path / "run", "ipv6_wrong")
    try:
        with pytest.raises(IPv6LabError):
            run_ndp(task, store, timeout_seconds=30)
    finally:
        store.close()


def test_fragment_profiles_build_bounded_control_and_overlap():
    pytest.importorskip("scapy")
    from scapy.layers.inet6 import IPv6ExtHdrFragment

    path = BASE.parent / "despliegue/ipv6_sender.py"
    spec = spec_from_file_location("ipv6_sender_test", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    control, _ = module.packets_for("control", "aa:bb:cc:dd:ee:ff", "1234567890abcdef")
    overlap, _ = module.packets_for("overlap", "aa:bb:cc:dd:ee:ff", "1234567890abcdef")
    assert len(control) == len(overlap) == 2
    assert control[0][IPv6ExtHdrFragment].offset == overlap[0][IPv6ExtHdrFragment].offset == 0
    assert overlap[1][IPv6ExtHdrFragment].offset == control[1][IPv6ExtHdrFragment].offset - 1
