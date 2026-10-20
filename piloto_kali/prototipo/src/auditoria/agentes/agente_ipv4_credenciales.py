"""Agente IPv4 de Credenciales: autenticación finita y corroboración independiente."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from ..contracts import Authentication, CredentialProfile, Task, TaskResult, TaskStatus
from ..red import check_route
from ..store import RunStore


class CredentialUnavailable(RuntimeError):
    pass


def hydra_command(
    task: Task, profile: CredentialProfile, password_file: str, output_file: str
) -> list[str]:
    if task.action_profile != f"hydra_{profile.service.replace('-', '_')}_single_v1":
        raise ValueError("perfil de autenticación no implementado")
    if profile.port not in task.target.ports:
        raise ValueError("puerto de autenticación fuera del objetivo")
    command = [
        "hydra",
        "-l",
        profile.username,
        "-P",
        password_file,
        "-o",
        output_file,
        "-b",
        "json",
        "-t",
        "1",
        "-f",
        "-I",
        "-4",
        "-w",
        "5",
        "-s",
        str(profile.port),
        task.target.address,
        profile.service,
    ]
    if profile.service == "http-get":
        command.append("/manager/html")
    return command


def classify_hydra_json(data: dict, task: Task, profile: CredentialProfile) -> str:
    if not isinstance(data, dict):
        return "indeterminate"
    results = data.get("results")
    if not isinstance(results, list) or not isinstance(data.get("quantityfound"), int):
        return "indeterminate"
    if data.get("errormessages"):
        return "transport_error"
    if data["quantityfound"] == 0 and results == [] and data.get("success") is True:
        return "rejected"
    if data["quantityfound"] != 1 or len(results) != 1:
        return "indeterminate"
    item = results[0]
    if not isinstance(item, dict):
        return "indeterminate"
    if (
        item.get("host") != task.target.address
        or item.get("login") != profile.username
        or item.get("service") != profile.service
        or int(item.get("port", -1)) != profile.port
    ):
        return "indeterminate"
    return "accepted"


def run_hydra(
    task: Task, profile: CredentialProfile, store: RunStore, *, timeout_seconds: int
) -> TaskResult:
    started = time.monotonic()
    check_route(task.target.address, task.target.interface)
    password = os.environ.get(profile.password_env)
    if not password or "\n" in password or "\r" in password:
        raise CredentialUnavailable("credencial sintética ausente o inválida en el entorno")

    if profile.service == "http-get":
        from ..authentication import http_basic_challenge

        if not http_basic_challenge(task, profile, timeout=min(5, timeout_seconds)):
            return TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                reason_code="http_basic_challenge_missing",
            )
    public_command = hydra_command(
        task, profile, "<private-password-file>", "<private-result-file>"
    )
    with tempfile.TemporaryDirectory(prefix="auditoria-hydra-", dir="/dev/shm") as directory:
        password_path = Path(directory) / "passwords"
        password_path.write_text(password + "\n", encoding="utf-8")
        password_path.chmod(0o600)
        output_path = Path(directory) / "result.json"
        command = hydra_command(task, profile, str(password_path), str(output_path))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(0.01, timeout_seconds - (time.monotonic() - started)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            outcome, exit_code = "indeterminate", None
        else:
            exit_code = completed.returncode
            if exit_code != 0 or not output_path.exists():
                outcome = "transport_error"
            else:
                try:
                    data = json.loads(output_path.read_text(encoding="utf-8"))
                    outcome = classify_hydra_json(data, task, profile)
                except (OSError, ValueError, TypeError):
                    outcome = "indeterminate"

    observation = Authentication(
        credential_ref=profile.ref,
        service=profile.service,
        port=profile.port,
        outcome=outcome,
    )
    evidence = {
        "schema_version": "1",
        "tool": "hydra",
        "profile": task.action_profile,
        "target": task.target.address,
        "port": profile.port,
        "credential_ref": profile.ref,
        "username": profile.username,
        "service": profile.service,
        "outcome": outcome,
        "exit_code": exit_code,
        "attempts_max": 1,
    }
    ref, digest = store.evidence(
        task.task_id, "json", json.dumps(evidence, sort_keys=True).encode("utf-8")
    )
    status = (
        TaskStatus.COMPLETED
        if outcome == "accepted"
        else TaskStatus.COMPLETED_NO_FINDINGS
        if outcome == "rejected"
        else TaskStatus.FAILED
    )
    observations = {}
    diagnostic_ref, diagnostic_sha256 = None, None
    if outcome == "accepted" and profile.condition is not None:
        from ..authentication import corroborate

        remaining = int(timeout_seconds - (time.monotonic() - started))
        confirmation = (
            corroborate(task, profile, password, timeout=min(8, remaining))
            if remaining > 0
            else {"tool": "not_started", "outcome": "indeterminate"}
        )
        diagnostic_ref, diagnostic_sha256 = store.evidence(
            task.task_id + "_confirmation",
            "json",
            json.dumps(confirmation, sort_keys=True).encode("utf-8"),
        )
        observations = {
            "independent_authentication": confirmation["outcome"],
            "confirmation_tool": confirmation["tool"],
        }
    return TaskResult(
        task_id=task.task_id,
        status=status,
        reason_code=None if outcome in {"accepted", "rejected"} else outcome,
        authentication=observation,
        evidence_ref=ref,
        evidence_sha256=digest,
        command=public_command,
        observations=observations,
        diagnostic_ref=diagnostic_ref,
        diagnostic_sha256=diagnostic_sha256,
    )
