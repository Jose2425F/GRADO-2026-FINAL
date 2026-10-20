"""Valida integridad y controles antes de clasificar observaciones como candidatas."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import Task, TaskResult, TaskStatus


SUCCESSFUL = {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
NDP_CASES = {"GT-09", "GT-10", "GT-11", "GT-12"}
FRAGMENT_CASES = {"GT-13", "GT-14", "GT-15", "GT-16"}


def _matches(root: Path, reference: str | None, digest: str | None) -> bool:
    if not isinstance(reference, str) or not isinstance(digest, str):
        return False
    try:
        path = (root / reference).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == digest
    except (OSError, ValueError):
        return False


def load_run(root: Path) -> tuple[dict, list[Task], list[TaskResult]]:
    """Carga los contratos de una corrida; rechaza estructuras malformadas."""
    plan = json.loads((root / "plan.json").read_text(encoding="utf-8"))
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    if not isinstance(plan, list):
        raise ValueError("plan.json debe contener una lista de tareas")
    if (
        not isinstance(report, dict)
        or not isinstance(report.get("audit_id"), str)
        or not report["audit_id"]
        or not isinstance(report.get("tasks"), list)
    ):
        raise ValueError("report.json requiere audit_id y una lista de tareas")
    if any(not isinstance(item, dict) for item in report["tasks"]):
        raise ValueError("cada resultado de report.json debe ser un objeto")
    tasks = [Task.model_validate(item) for item in plan]
    results = [
        TaskResult.model_validate(
            {key: value for key, value in item.items() if key != "agent_name"}
        )
        for item in report["tasks"]
    ]
    return report, tasks, results


def validate_results(root: Path, tasks: list[Task], results: list[TaskResult]) -> list[dict]:
    """Una candidatura exige evidencia íntegra y efecto observado; nunca confirma vulnerabilidad."""
    task_by_id = {task.task_id: task for task in tasks}
    result_ids = [result.task_id for result in results]
    if (
        len(task_by_id) != len(tasks)
        or len(set(result_ids)) != len(result_ids)
        or set(result_ids) != set(task_by_id)
    ):
        raise ValueError("plan y resultados deben tener los mismos task_id únicos")
    validation = []
    for result in results:
        task = task_by_id[result.task_id]
        if task.action_profile.endswith("_v2"):
            from .v2_agent import validation_record

            validation.append(validation_record(root, task, result))
            continue
        observation = result.observations
        case_id = task.case_id
        # IPv4 puede no producir stderr; su ausencia no invalida el XML/JSON.
        diagnostic_required = case_id is not None
        diagnostic_ok = (
            _matches(root, result.diagnostic_ref, result.diagnostic_sha256)
            if diagnostic_required
            or result.diagnostic_ref is not None
            or result.diagnostic_sha256 is not None
            else None
        )
        packet_ok = _matches(root, result.evidence_ref, result.evidence_sha256)
        control_ok = (
            _matches(
                root, observation.get("control_pcap_ref"), observation.get("control_pcap_sha256")
            )
            if case_id in FRAGMENT_CASES
            else None
        )
        integrity = packet_ok and diagnostic_ok is not False and control_ok is not False
        has_artifacts = any(
            value is not None
            for value in (
                result.evidence_ref,
                result.evidence_sha256,
                result.diagnostic_ref,
                result.diagnostic_sha256,
                observation.get("control_pcap_ref"),
                observation.get("control_pcap_sha256"),
            )
        )
        evidence_valid = integrity if result.status in SUCCESSFUL or has_artifacts else None
        state, reason = "indeterminate", "insufficient_observation"
        if result.status not in SUCCESSFUL:
            reason = "task_not_completed"
        elif not integrity:
            reason = "evidence_incomplete_or_changed"
        elif case_id in NDP_CASES:
            effect = {
                "GT-09": "route_changed",
                "GT-10": "neighbor_changed",
                "GT-11": "dad_failed",
                "GT-12": "changed",
            }[case_id]
            if observation.get("restored") is not True:
                reason = "restoration_unverified"
            elif observation.get("packet_observed") is True:
                if observation.get(effect) is True:
                    state, reason = "candidate", "state_changed_after_probe"
                elif observation.get(effect) is False:
                    state, reason = "no_effect_observed", "state_unchanged"
        elif case_id in FRAGMENT_CASES:
            if observation.get("restored") is not True:
                reason = "restoration_unverified"
            elif (
                observation.get("control_received") is True
                and observation.get("variant_fragments_observed") is True
                and isinstance(observation.get("variant_udp_delivered"), bool)
            ):
                state = "observed"
                reason = (
                    "variant_delivered"
                    if observation["variant_udp_delivered"]
                    else "variant_not_delivered"
                )
        elif task.action_profile == "nmap_tcp_services_v1":
            state, reason = "observed", "service_inventory_recorded"
        elif task.action_profile.startswith("hydra_") and result.authentication is not None:
            if result.authentication.outcome in {"accepted", "rejected"}:
                state, reason = "observed", "authentication_" + result.authentication.outcome
        validation.append(
            {
                "task_id": result.task_id,
                "case_id": case_id,
                "asset_id": task.target.asset_id,
                "action_profile": task.action_profile,
                "state": state,
                "reason": reason,
                "evidence_integrity": {
                    "diagnostic": diagnostic_ok,
                    "packet": packet_ok,
                    "control_packet": control_ok,
                    "valid": evidence_valid,
                },
                "independent_confirmation": False,
            }
        )
    return validation


def compare_runs(first: Path, second: Path) -> list[dict]:
    """Compara cada activo/caso, incluyendo ausencias y comportamiento de fragmentación."""
    if first.resolve() == second.resolve():
        raise ValueError("las corridas deben ser distintas")

    def read_run(root: Path) -> tuple[str, dict[tuple[str, str], tuple[Task, dict]]]:
        report, tasks, results = load_run(root)
        records = validate_results(root, tasks, results)
        task_by_id = {task.task_id: task for task in tasks}
        cases = {}
        for record in records:
            if record["case_id"] is None:
                continue
            task = task_by_id[record["task_id"]]
            key = (task.target.asset_id, task.case_id)
            if key in cases:
                raise ValueError("una corrida no puede repetir un caso para el mismo activo")
            cases[key] = (task, record)
        return report["audit_id"], cases

    first_id, first_cases = read_run(first)
    second_id, second_cases = read_run(second)
    if first_id == second_id:
        raise ValueError("las corridas comparten audit_id")
    comparison = []
    for asset_id, case_id in sorted(first_cases.keys() | second_cases.keys()):
        a = first_cases.get((asset_id, case_id))
        b = second_cases.get((asset_id, case_id))
        reason = "case_missing"
        if a is not None and b is not None:
            first_task, first_record = a
            second_task, second_record = b
            same_context = (
                first_task.target == second_task.target
                and first_task.action_profile == second_task.action_profile
                and first_task.agent_type == second_task.agent_type
                and first_task.protocol == second_task.protocol
            )
            if not same_context:
                reason = "case_context_changed"
            elif first_record["state"] not in {
                "candidate",
                "observed",
                "no_effect_observed",
            } or second_record["state"] not in {"candidate", "observed", "no_effect_observed"}:
                reason = "observation_not_validated"
            elif (first_record["state"], first_record["reason"]) != (
                second_record["state"],
                second_record["reason"],
            ):
                reason = "behavior_changed"
            else:
                reason = "same_behavior"
        comparison.append(
            {
                "asset_id": asset_id,
                "case_id": case_id,
                "state": "reproduced" if reason == "same_behavior" else "not_reproduced",
                "reason": reason,
                "first_state": a[1]["state"] if a else None,
                "second_state": b[1]["state"] if b else None,
                "first_reason": a[1]["reason"] if a else None,
                "second_reason": b[1]["reason"] if b else None,
                "independent_confirmation": False,
            }
        )
    return comparison
