"""Agente IPv4 de Servicios: perfil Nmap autorizado, sin LLM todavía."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from ipaddress import ip_address

from ..contracts import Service, Task, TaskResult, TaskStatus
from ..red import check_route
from ..store import RunStore


def nmap_command(task: Task) -> list[str]:
    if task.action_profile != "nmap_tcp_services_v1":
        raise ValueError("perfil no implementado")
    if ip_address(task.target.address).version != 4:
        raise ValueError("este perfil solo admite IPv4")
    if not task.target.ports:
        raise ValueError("el perfil requiere puertos")
    return [
        "nmap", "-n", "-Pn", "-sT", "-sV", "--version-light",
        "--max-retries", "1", "--host-timeout", f"{task.timeout_seconds}s",
        "-e", task.target.interface,
        "-p", ",".join(str(port) for port in task.target.ports),
        "-oX", "-", task.target.address,
    ]


def parse_nmap_xml(raw: bytes) -> list[Service]:
    root = ET.fromstring(raw)
    services: list[Service] = []
    for port in root.findall(".//host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        entry = port.find("service")
        services.append(Service(
            port=int(port.attrib["portid"]),
            protocol=port.attrib["protocol"],
            state="open",
            name=entry.get("name") if entry is not None else None,
            product=entry.get("product") if entry is not None else None,
            version=entry.get("version") if entry is not None else None,
        ))
    return services


def run_nmap(task: Task, store: RunStore, *, timeout_seconds: int) -> TaskResult:
    command = nmap_command(task)
    check_route(task.target.address, task.target.interface)
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raw = exc.stdout or b""
        ref, digest = store.evidence(task.task_id, "xml", raw)
        diagnostics = exc.stderr or b""
        diag_ref, diag_hash = store.evidence(task.task_id, "txt", diagnostics)
        return TaskResult(task_id=task.task_id, status=TaskStatus.FAILED,
                          reason_code="timeout", evidence_ref=ref,
                          evidence_sha256=digest, diagnostic_ref=diag_ref,
                          diagnostic_sha256=diag_hash, command=command)
    raw = completed.stdout
    ref, digest = store.evidence(task.task_id, "xml", raw)
    diag_ref = diag_hash = None
    if completed.stderr:
        diag_ref, diag_hash = store.evidence(task.task_id, "txt", completed.stderr)
    if completed.returncode != 0:
        return TaskResult(task_id=task.task_id, status=TaskStatus.FAILED,
                          reason_code="nmap_failed", evidence_ref=ref,
                          evidence_sha256=digest, diagnostic_ref=diag_ref,
                          diagnostic_sha256=diag_hash, command=command)
    try:
        services = parse_nmap_xml(raw)
    except (ET.ParseError, KeyError, ValueError):
        return TaskResult(task_id=task.task_id, status=TaskStatus.FAILED,
                          reason_code="invalid_xml", evidence_ref=ref,
                          evidence_sha256=digest, diagnostic_ref=diag_ref,
                          diagnostic_sha256=diag_hash, command=command)
    return TaskResult(task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS,
                      services=services, evidence_ref=ref,
                      evidence_sha256=digest, diagnostic_ref=diag_ref,
                      diagnostic_sha256=diag_hash, command=command)
