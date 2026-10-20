"""Ciclo de vida del banco conocido, aislado y reproducible."""

from __future__ import annotations

import getpass
import os
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .contracts import AuditRequest, Category, CredentialProfile, LabPolicy, LabSegment, Target
from .lab import INTERFACE, SUBNET, LabError, verify_container_lab, _docker_inspect
from .ipv6_lab import verify_ipv6_lab, TARGET, INTERFACE as V6_INTERFACE, SUBNET as V6_SUBNET
from .casos_ipv6 import CASES
from .store import write_json

DEPLOY = Path(__file__).resolve().parents[3] / "despliegue"
SERVICES = [
    ("auth", 11, [21, 22], ["ftp_lab", "ssh_lab"]),
    ("tomcat", 13, [8080], ["tomcat_lab"]),
    ("postgres", 14, [5432], ["postgres_lab"]),
]


def prepare(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    env = root / "lab.env"
    if not env.exists():
        # O_EXCL y 0600 desde creación, sin ventana de permisos públicos.
        with os.fdopen(os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write("LAB_CONTROL_PASSWORD=" + secrets.token_hex(24) + "\n")
    policy = LabPolicy(
        policy_id="banco-docker-v1",
        segments=[
            LabSegment(
                name="ipv4", network=SUBNET, interface=INTERFACE, allowed_ports=[21, 22, 8080, 5432]
            ),
            LabSegment(
                name="ipv6", network=V6_SUBNET, interface=V6_INTERFACE, allowed_ports=[53000]
            ),
        ],
        allowed_categories=list(Category),
        allowed_case_ids=list(CASES),
        max_token_budget=60000,
        credential_profiles=[
            CredentialProfile(
                ref=ref,
                service=service,
                port=port,
                username="labuser",
                password_env="LAB_PROBE_PASSWORD",
                condition="default_credential",
            )
            for ref, service, port in [
                ("ssh_lab", "ssh", 22),
                ("ftp_lab", "ftp", 21),
                ("tomcat_lab", "http-get", 8080),
                ("postgres_lab", "postgres", 5432),
            ]
        ],
    )
    write_json(root / "policy.json", policy.model_dump(mode="json"))
    entries = []
    for control, offset in [(False, 0), (True, 10)]:
        for service, n, ports, refs in SERVICES:
            asset = f"obj_{service}_{'control' if control else 'lab'}"
            for ref in refs:
                profile = next(p for p in policy.credential_profiles if p.ref == ref)
                entries.append(
                    {
                        "asset_id": asset,
                        "defect_key": defect_key(profile),
                        "present": not control,
                        "credential_ref": ref,
                    }
                )
    # El evaluador es el único consumidor; nunca se adjunta al contexto LLM.
    write_json(
        root / "ground_truth.json",
        {
            "schema_version": "1",
            "bank": "docker-v1",
            "scope": "Cuatro configuraciones de credenciales débiles y cuatro controles negativos IPv4.",
            "ipv6_note": "GT-09 a GT-16 son IDs de perfiles; no implican ocho vulnerabilidades confirmadas. Evaluación IPv6 cualitativa hasta certificar sus condiciones.",
            "entries": entries,
        },
    )


def defect_key(profile: CredentialProfile) -> str:
    return f"{profile.service}:{profile.port}:{profile.condition}"


def compose(root: Path, action: str, *, ipv6: bool = True) -> None:
    if action not in {"up", "down", "reset"}:
        raise ValueError("acción de laboratorio desconocida")
    if not (root / "lab.env").is_file():
        raise LabError("ejecute primero laboratorio preparar")
    files = ["docker-compose.evaluacion.yml"] + (["docker-compose.ipv6.yml"] if ipv6 else [])
    for file in files:
        command = [
            "docker",
            "compose",
            "--env-file",
            str((root / "lab.env").resolve()),
            "-f",
            str(DEPLOY / file),
        ]
        # No capturar stdout: el operador ve la descarga; no imprimir config con secretos.
        options = ["up", "-d", "--build"] if action == "up" else ["down", "--volumes"]
        try:
            subprocess.run(command + options, check=True)
            if action == "reset":
                # Restaurar estado sin cambiar las imágenes de la comparación.
                subprocess.run(command + ["up", "-d", "--no-build", "--pull", "never"], check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LabError(
                "Docker no pudo completar la acción; revise la salida de Compose"
            ) from exc


def preflight(*, ipv6: bool = True, wait_seconds: int = 60) -> dict:
    end = time.monotonic() + wait_seconds
    while True:
        try:
            network = _docker_inspect("network", "lab_auditoria_ipv4")
            expected = {
                f"obj-{service}-{'control' if control else 'lab'}"
                for control in (False, True)
                for service, _, _, _ in SERVICES
            }
            actual = {entry.get("Name") for entry in network.get("Containers", {}).values()}
            if actual != expected:
                raise LabError(
                    "el puente IPv4 debe contener solo los seis objetivos del banco; baje el piloto anterior"
                )
            metadata = []
            for control, offset in [(False, 0), (True, 10)]:
                for service, n, ports, _ in SERVICES:
                    name = f"obj-{service}-{'control' if control else 'lab'}"
                    for port in ports:
                        metadata.append(
                            verify_container_lab(name, f"192.168.57.{n + offset}", port)
                        )
            result = {"bank": "docker-v1", "targets": metadata}
            if ipv6:
                result.update(verify_ipv6_lab())
            return result
        except (LabError, RuntimeError):
            if time.monotonic() >= end:
                raise
            time.sleep(1)


def request_for_lab(
    authorization: str,
    *,
    architecture: str = "multiagent",
    openai: bool = False,
    ipv6: bool = True,
    token_budget: int = 40000,
) -> AuditRequest:
    now = datetime.now(timezone.utc)
    targets = []
    for control, offset in [(False, 0), (True, 10)]:
        for service, n, ports, refs in SERVICES:
            targets.append(
                Target(
                    asset_id=f"obj_{service}_{'control' if control else 'lab'}",
                    address=f"192.168.57.{n + offset}",
                    interface=INTERFACE,
                    ports=ports,
                    credential_refs=refs,
                )
            )
    categories = [Category.IPV4_SERVICES, Category.IPV4_CREDENTIALS]
    if ipv6:
        categories += [Category.IPV6_NDP, Category.IPV6_FRAGMENTATION]
        targets.append(
            Target(asset_id="obj_ipv6", address=TARGET, interface=V6_INTERFACE, ports=[53000])
        )
    return AuditRequest(
        audit_id=f"demo_{architecture}_{now:%Y%m%dT%H%M%S}_{uuid4().hex[:6]}",
        operator=getpass.getuser(),
        authorization_ref=authorization,
        scope_ipv4=[SUBNET],
        scope_ipv6=[V6_SUBNET] if ipv6 else [],
        categories=categories,
        case_ids=list(CASES) if ipv6 else [],
        targets=targets,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(minutes=30),
        max_runtime_seconds=1200,
        max_attempts=1,
        token_budget=token_budget if openai else 0,
        architecture=architecture,
        llm_mode="scheduler" if openai else "disabled",
        llm_provider="openai",
    )


from contextlib import contextmanager
import fcntl
import threading

_operation_mutex = threading.RLock()
_operation_depth = 0


@contextmanager
def operation_lock():
    """Evita que otra CLI restaure el banco mientras hay una auditoría en curso."""
    global _operation_depth
    with _operation_mutex:
        if _operation_depth:
            _operation_depth += 1
            try:
                yield
            finally:
                _operation_depth -= 1
            return
        path = f"/tmp/auditoria-docker-{os.getuid()}.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LabError(
                    "otra operación del laboratorio está en curso; espere antes de auditar o restaurar"
                ) from exc
            _operation_depth = 1
            try:
                yield
            finally:
                _operation_depth = 0
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
