"""Hallazgos deduplicados por activo y condición causal; sin ground truth."""

from __future__ import annotations

import json
from pathlib import Path

from .contracts import LabPolicy, Task, TaskResult, TaskStatus
from .laboratorio import defect_key

REFERENCE = "https://cwe.mitre.org/data/definitions/1392.html"


def access_is_verified(
    root: Path, policy: LabPolicy, task: Task, result: TaskResult, record: dict
) -> bool:
    """Exige autenticación corroborada y ambos artefactos íntegros del mismo objetivo."""
    if task.action_profile == "http_application_dualstack_v2":
        from .v2_agent import adjudicate

        return bool(adjudicate(root, task, result))
    auth = result.authentication
    integrity = record.get("evidence_integrity", {})
    if (
        result.status not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
        or auth is None
        or auth.outcome != "accepted"
        or integrity.get("valid") is not True
        or integrity.get("diagnostic") is not True
        or auth.credential_ref != task.target.credential_ref
    ):
        return False
    profile = next((p for p in policy.credential_profiles if p.ref == auth.credential_ref), None)
    if profile is None or (auth.service, auth.port) != (profile.service, profile.port):
        return False
    if task.action_profile != f"hydra_{profile.service.replace('-', '_')}_single_v1":
        return False
    try:
        evidence = json.loads((root / result.evidence_ref).read_text())
        confirmation = json.loads((root / result.diagnostic_ref).read_text())
    except (OSError, ValueError, TypeError):
        return False
    if not all(
        isinstance(data, dict)
        and data.get("target") == task.target.address
        and data.get("port") == profile.port
        and data.get("credential_ref") == profile.ref
        and data.get("outcome") == "accepted"
        and data.get("service", profile.service) == profile.service
        for data in [evidence, confirmation]
    ):
        return False
    expected_tool = {
        "ssh": "paramiko",
        "ftp": "ftplib",
        "postgres": "psycopg",
        "http-get": "urllib-basic-auth",
    }[profile.service]
    return confirmation.get("tool") == expected_tool and evidence.get("tool") == "hydra"


def confirm_findings(
    root: Path,
    policy: LabPolicy,
    tasks: list[Task],
    results: list[TaskResult],
    validation: list[dict],
) -> list[dict]:
    records = {r["task_id"]: r for r in validation}
    by_task = {t.task_id: t for t in tasks}
    profiles = {p.ref: p for p in policy.credential_profiles}
    findings = {}
    for result in results:
        task = by_task[result.task_id]
        record = records[result.task_id]
        auth = result.authentication
        if task.action_profile.endswith("_v2"):
            from .v2_agent import adjudicate

            for finding in adjudicate(root, task, result):
                findings[(finding["asset_id"], finding["defect_key"])] = finding
            continue
        if not access_is_verified(root, policy, task, result, record):
            continue
        profile = profiles.get(auth.credential_ref)
        if profile is None or profile.condition is None:
            continue
        key = (task.target.asset_id, defect_key(profile))
        findings[key] = {
            "asset_id": task.target.asset_id,
            "address": task.target.address,
            "defect_key": key[1],
            "state": "verified",
            "severity": "high",
            "title": f"Credencial de laboratorio conocida aceptada en {profile.service}:{profile.port}",
            "condition": profile.condition,
            "reference": REFERENCE,
            "remediation": "Cambiar la credencial conocida, restringir el servicio y aplicar autenticación fuerte.",
            "task_id": task.task_id,
            "evidence_ref": result.evidence_ref,
            "confirmation_ref": result.diagnostic_ref,
            "independent_confirmation": True,
            "reproduction": "Un intento Hydra y un intento con cliente independiente; sin acciones posteriores.",
        }
    return list(findings.values())
