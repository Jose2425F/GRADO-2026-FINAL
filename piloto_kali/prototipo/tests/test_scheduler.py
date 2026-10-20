import json

import pytest

from auditoria.scheduler import Scheduler


def scheduler(response=None):
    value = Scheduler.__new__(Scheduler)
    value.architecture = "single"
    value.aliases = {}
    value.asset_aliases = {}
    return value, []


def test_base_scheduler_never_opens_a_provider():
    with pytest.raises(TypeError, match="OpenAIScheduler"):
        Scheduler(None, architecture="single", budget=1000, deadline=60)


def test_bounded_per_role_context_and_single_agent_share_task_catalog(tmp_path):
    from auditoria.contracts import Task, Target

    targets = [
        Target(asset_id="a", address="192.168.57.11", interface="br-lab-audit", ports=[22]),
        Target(asset_id="b", address="192.168.57.21", interface="br-lab-audit", ports=[22]),
    ]
    tasks = [
        Task(
            task_id=f"t{i}",
            agent_type=role,
            target=targets[i % 2],
            protocol="tcp",
            action_profile="nmap_tcp_services_v1",
            timeout_seconds=20,
        )
        for i, role in enumerate(["ipv4_services", "ipv4_services", "ipv4_credentials"])
    ]
    s, _ = scheduler(None)
    prompts = []

    def choose(choices, context, role):
        prompts.append((choices, context, role))
        return choices[0]

    s.decide = choose
    s.architecture = "multiagent"
    assert s.select(tasks, [], tasks).task_id == "t0"
    assert [p[2] for p in prompts] == ["administrator", "ipv4_services"]
    assert [t["id"] for t in prompts[-1][1]["ready"]] == ["t000", "t001"]
    prompts.clear()
    s.architecture = "single"
    assert s.select(tasks, [], tasks).task_id == "t0"
    assert [p[2] for p in prompts] == ["single_agent"]
    assert [t["id"] for t in prompts[0][1]["ready"]] == ["t000", "t001", "t002"]


def test_model_context_uses_opaque_aliases_not_control_labels():
    from auditoria.contracts import Task, Target

    tasks = [
        Task(
            task_id="audit_obj_control_ssh",
            agent_type="ipv4_services",
            target=Target(
                asset_id="obj_control",
                address="192.168.57.21",
                interface="br-lab-audit",
                ports=[22],
            ),
            protocol="tcp",
            action_profile="nmap_tcp_services_v1",
            timeout_seconds=20,
        ),
        Task(
            task_id="audit_obj_vulnerable_ssh",
            agent_type="ipv4_services",
            target=Target(
                asset_id="obj_vulnerable",
                address="192.168.57.11",
                interface="br-lab-audit",
                ports=[22],
            ),
            protocol="tcp",
            action_profile="nmap_tcp_services_v1",
            timeout_seconds=20,
        ),
    ]
    s, _ = scheduler(None)
    contexts = []

    def choose(choices, context, role):
        contexts.append(json.dumps(context))
        return choices[0]

    s.decide = choose
    assert s.select(tasks, [], tasks).task_id == "audit_obj_control_ssh"
    assert not any(word in contexts[0] for word in ["obj_control", "obj_vulnerable", "192.168.57"])
