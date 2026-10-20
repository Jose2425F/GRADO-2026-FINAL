#!/usr/bin/env python3
"""Inventario RNF-06 defensivo y read-only; no ejecuta adaptadores ni sondas.

Lee /proc, metadatos de archivos, getcap y docker ps/container inspect con una
proyección cerrada (sin Env, Args, logs ni secretos). Escribe sólo un recibo nuevo.
No usa sudo, setcap, Docker exec, compose, API ni operaciones de red.
Con --isolation-receipt reutiliza exclusivamente las instantáneas ya tomadas por
RNF-08 y no invoca Docker. Los bancos v2 se consideran históricos.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CURRENT_CONTAINER = re.compile(r"(?:nova|nf[1-4])-[a-z0-9]+(?:-[a-z0-9]+)*")
LEGACY_CONTAINER = re.compile(r"v2-[a-z0-9]+(?:-[a-z0-9]+)*")
STATUS_KEYS = {"Name", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}
CAP_NAMES = ("CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE "
             "NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO "
             "SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG "
             "MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM "
             "BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE").split()


def decode_capabilities(value):
    mask = int(value, 16)
    return ["CAP_" + name for bit, name in enumerate(CAP_NAMES) if mask & (1 << bit)]


def container_scope(name):
    """Distingue los cinco bancos actuales del banco v2 histórico."""
    if CURRENT_CONTAINER.fullmatch(name):
        return "current_five_laboratories"
    if LEGACY_CONTAINER.fullmatch(name):
        return "legacy_v2"
    return None


def projected_process_status(value):
    """Proyecta sólo identidades y capacidades; nunca copia campos libres."""
    required = {"Uid", "Gid", "CapEff", "CapPrm", "CapBnd"}
    if not isinstance(value, dict) or not required.issubset(value):
        return {"available": False, "reason": "required_process_fields_missing"}
    result = {}
    for key in STATUS_KEYS - {"Name", "Groups"}:
        if key not in value:
            continue
        item = value[key]
        pattern = r"[0-9a-fA-F]{1,16}" if key.startswith("Cap") else r"\d+(?:\s+\d+)*"
        if not isinstance(item, str) or re.fullmatch(pattern, item) is None:
            return {"available": False, "reason": "invalid_process_field"}
        result[key] = item
    result["decoded_capabilities"] = {key: decode_capabilities(result[key])
        for key in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb") if key in result}
    result["available"] = True
    return result


def isolation_observations(root, paths):
    """Lee recibos RNF-08 reales; no vuelve a ejecutar Docker ni sondas."""
    prefixes = {"original": "nova", "integrado": "nova", "sucursal": "nf1", "comercial": "nf2", "mixto": "nf3", "reforzado": "nf4"}
    records, containers, seen = [], {}, set()
    for path in paths:
        path = path.resolve()
        if path.parent != (root / "docs/verificacion-postevaluacion").resolve():
            raise ValueError("isolation_receipt_outside_verification_folder")
        value = json.loads(path.read_text())
        lab, segment = value.get("lab"), value.get("segment")
        canonical_lab = "integrado" if lab == "original" else lab
        if (value.get("schema") != "novaflow-real-isolation-segment/1" or value.get("execution") != "REAL"
            or lab not in prefixes or segment not in {"corp", "dc", "dmz"} or (canonical_lab, segment) in seen):
            raise ValueError("invalid_or_duplicate_isolation_segment")
        seen.add((canonical_lab, segment))
        representative = value.get("representative", {}).get("source", "")
        suffix = {"corp": "app-crm", "dc": "sender", "dmz": "portal"}[segment]
        if representative != prefixes[lab] + "-" + suffix:
            raise ValueError("unexpected_isolation_representative")
        privilege = value.get("privileges", {})
        record = {"receipt": str(path.relative_to(root)), "lab": lab, "protocol_scenario": canonical_lab, "segment": segment,
            "source_status": value.get("status") if value.get("status") in {"PASS", "FAIL", "PARTIAL"} else "UNKNOWN",
            "representative": representative,
            "pid1": projected_process_status(privilege.get("pid1")),
            "exec_process": projected_process_status(privilege.get("exec_process"))}
        for key in ("exec_uid", "exec_euid", "exec_gid"):
            if type(privilege.get(key)) is int and privilege[key] >= 0:
                record[key] = privilege[key]
        records.append(record)
        for name, snapshot in value.get("container_snapshots", {}).items():
            if not name.startswith(prefixes[lab] + "-") or container_scope(name) != "current_five_laboratories":
                raise ValueError("unexpected_isolation_container")
            # Copy no Env, Args, logs, network state or probe destinations.
            containers[name] = {"name": name, "lab": lab, "observation_scope": "current_five_laboratories",
                "configured_user": snapshot.get("user"), "cap_add": snapshot.get("cap_add"),
                "cap_drop": snapshot.get("cap_drop"), "privileged": snapshot.get("privileged"),
                "running_at_observation": snapshot.get("running"), "source_receipt": str(path.relative_to(root))}
    complete = (len(seen) == 15 and all(r["pid1"]["available"] and r["exec_process"]["available"] for r in records))
    return {"available": bool(records), "method": "reuse_existing_RNF08_receipts_no_Docker_invocation",
        "coverage_complete_15_representatives": complete, "representative_processes": records,
        "containers": list(containers.values()),
        "scope_note": "Instantáneas reales de 3 representantes por cada uno de 5 bancos; no son procesos de los adaptadores ni acreditan todos los procesos."}


def process_status(pid):
    try:
        text = Path(f"/proc/{pid}/status").read_text()
    except (OSError, ValueError) as exc:
        return {"available": False, "error_type": type(exc).__name__}
    fields = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    result = {key: fields[key].strip() for key in STATUS_KEYS if key in fields}
    result["decoded_capabilities"] = {key: decode_capabilities(result[key]) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb") if key in result}
    result["available"] = True
    return result


def file_permissions(path, *, capabilities=False):
    candidate = Path(path)
    try:
        resolved = candidate.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        return {"path": str(candidate), "available": False, "error_type": type(exc).__name__}
    result = {"path": str(candidate), "resolved": str(resolved), "available": True,
        "uid": info.st_uid, "gid": info.st_gid, "mode_octal": oct(stat.S_IMODE(info.st_mode)),
        "setuid": bool(info.st_mode & stat.S_ISUID), "setgid": bool(info.st_mode & stat.S_ISGID),
        "effective_read": os.access(resolved, os.R_OK, effective_ids=True),
        "effective_write": os.access(resolved, os.W_OK, effective_ids=True),
        "effective_execute_or_search": os.access(resolved, os.X_OK, effective_ids=True)}
    if capabilities:
        getcap = shutil.which("getcap")
        if getcap:
            completed = subprocess.run([getcap, str(resolved)], capture_output=True, text=True, timeout=5, check=False)
            result["file_capabilities_available"] = completed.returncode == 0
            # Path is public metadata. Never execute the inspected binary.
            result["file_capabilities"] = completed.stdout.strip().removeprefix(str(resolved)).strip()
        else:
            result["file_capabilities_available"] = False
    return result


def source_facts(root, relative, anchors):
    text = (root / relative).read_text()
    lines = text.splitlines()
    tree = ast.parse(text)
    called = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    forbidden = {"os.setuid", "os.setgid", "os.setresuid", "os.setresgid", "os.seteuid", "os.setegid"}
    return {"path": relative,
        "references": [{"line": n + 1, "anchor": anchor} for anchor in anchors
                       for n, line in enumerate(lines) if anchor in line],
        "privilege_change_calls": sorted(called & forbidden),
        "sudo_or_setcap_literal": any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                                      and node.value in {"sudo", "setcap", "su"} for node in ast.walk(tree)),
        "subprocess_privilege_keywords": sorted({kw.arg for node in ast.walk(tree) if isinstance(node, ast.Call)
            for kw in node.keywords if kw.arg in {"user", "group", "extra_groups", "preexec_fn"}})}


def container_observations():
    docker = shutil.which("docker")
    if not docker:
        return {"available": False, "reason": "docker executable unavailable", "containers": []}
    listed = subprocess.run([docker, "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10, check=False)
    if listed.returncode:
        return {"available": False, "returncode": listed.returncode, "containers": []}
    names = [name for name in listed.stdout.splitlines() if container_scope(name)]
    # Do not fetch .Config.Env, .Args, logs or full inspect objects.
    template = ('{"name":{{json .Name}},"configured_user":{{json .Config.User}},'
        '"pid":{{json .State.Pid}},"running":{{json .State.Running}},'
        '"privileged":{{json .HostConfig.Privileged}},"cap_add":{{json .HostConfig.CapAdd}},'
        '"cap_drop":{{json .HostConfig.CapDrop}},"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},'
        '"security_opt":{{json .HostConfig.SecurityOpt}}}')
    if not names:
        return {"available": True, "containers": []}
    inspected = subprocess.run([docker, "container", "inspect", "--format", template, *names],
                               capture_output=True, text=True, timeout=15, check=False)
    if inspected.returncode:
        return {"available": False, "returncode": inspected.returncode, "containers": []}
    containers = []
    for line in inspected.stdout.splitlines():
        item = json.loads(line)
        item["observation_scope"] = container_scope(item["name"].removeprefix("/"))
        item["configured_user_interpretation"] = "root por defecto (Config.User vacío)" if not item["configured_user"] else item["configured_user"]
        item["effective_process"] = process_status(item["pid"]) if item["running"] and item["pid"] > 0 else {
            "available": False, "reason": "Contenedor detenido; PID 0 no acredita CapEff de una ejecución."}
        containers.append(item)
    return {"available": True, "containers": containers}


def active_auditor_processes(root):
    found = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            tokens = (directory / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        public_roles = [role for role in ("panel_observabilidad.py", "laboratorio_empresa.py", "auditoria.cli", "nmap", "hydra")
                        if any(token.decode(errors="replace").rsplit("/", 1)[-1] == role for token in tokens)]
        if public_roles:
            found.append({"pid": int(directory.name), "roles": public_roles, "status": process_status(directory.name)})
    return found


def verify(root, isolation_paths=None):
    sources = [
        source_facts(root, "piloto_kali/prototipo/src/auditoria/agentes/agente_ipv4_servicios.py", ['"nmap", "-n", "-Pn", "-sT"', "subprocess.run("]),
        source_facts(root, "piloto_kali/prototipo/src/auditoria/agentes/agente_ipv4_credenciales.py", ['"hydra",', "subprocess.run(", "password_path.chmod(0o600)"]),
        source_facts(root, "piloto_kali/prototipo/src/auditoria/lab_empresa.py", ["http.client.HTTPConnection", "def app_family", '"docker", "exec", "nova-sender"']),
        source_facts(root, "piloto_kali/prototipo/src/auditoria/lab_v2.py", ["http.client.HTTPConnection", '"docker", "exec", "v2-sender"']),
    ]
    binaries = {}
    for name, candidate in [("python_verifier", sys.executable), ("python_prototype", root / "piloto_kali/prototipo/.venv/bin/python"),
                            ("nmap", shutil.which("nmap")), ("hydra", shutil.which("hydra")), ("docker", shutil.which("docker"))]:
        binaries[name] = file_permissions(candidate, capabilities=True) if candidate else {"available": False}
    groups = [{"gid": group, "name": grp.getgrgid(group).gr_name} for group in os.getgroups()]
    own_status = process_status("self")
    containers = isolation_observations(root, isolation_paths) if isolation_paths else container_observations()
    compose_path = "piloto_kali/despliegue/empresa/docker-compose.empresa.yml"
    compose_lines = (root / compose_path).read_text().splitlines()
    dockerfile_path = "piloto_kali/despliegue/empresa/datacenter/Dockerfile.protocol"
    dockerfile_lines = (root / dockerfile_path).read_text().splitlines()
    configuration = {
        "compose_path": compose_path,
        "protocol_references": [{"line": n + 1, "text": line.strip()} for n, line in enumerate(compose_lines)
                                if n >= 163 and any(word in line for word in ("container_name:", "cap_add:"))],
        "protocol_dockerfile": dockerfile_path,
        "dockerfile_overrides_user": any(line.strip().upper().startswith("USER ") for line in dockerfile_lines),
        "interpretation": "Dockerfile sin USER y compose de protocolos sin user: conserva usuario root por defecto de la imagen; verificar CapEff exige proceso activo.",
    }
    configuration["current_suite_compose"] = []
    for compose in sorted((root / "piloto_kali/prototipo/.lab-suite").glob("*/compose.json")):
        value = json.loads(compose.read_text())
        configuration["current_suite_compose"].append({
            "scenario": compose.parent.name, "path": str(compose.relative_to(root)),
            "protocol_services": [{"service": name, "container_name": service.get("container_name"),
                                   "configured_user": service.get("user", ""),
                                   "cap_add": service.get("cap_add", []), "cap_drop": service.get("cap_drop", [])}
                                  for name, service in value.get("services", {}).items()
                                  if name in {"sender", "router", "receiver-a", "receiver-b"}],
        })
    checks = [
        {"name": "RNF06_USUARIO_Y_CAPEFF_HOST_OBSERVADOS", "result": "PASS" if own_status["available"] else "FAIL"},
        {"name": "RNF06_NMAP_HYDRA_SIN_SETID_NI_FILECAPS", "result": "PASS" if all(
            binaries[name].get("available") and binaries[name].get("file_capabilities_available")
            and not binaries[name]["setuid"] and not binaries[name]["setgid"] and not binaries[name]["file_capabilities"]
            for name in ("nmap", "hydra")) else "FAIL"},
        {"name": "RNF06_INVOCACIONES_SIN_CAMBIO_CREDENCIALES", "result": "PASS" if all(
            not item["privilege_change_calls"] and not item["sudo_or_setcap_literal"] and not item["subprocess_privilege_keywords"]
            for item in sources) else "FAIL"},
        {"name": "RNF06_DOCKER_CONFIGURACION_OBSERVADA", "result": "PASS" if containers["available"] else "FAIL"},
    ]
    if isolation_paths:
        checks.append({"name": "RNF06_CAPACIDADES_REALES_15_REPRESENTANTES_CINCO_BANCOS",
                       "result": "PASS" if containers["coverage_complete_15_representatives"] else "PARTIAL"})
    host_inference = "Hereda credenciales del auditor según invocación, sin setuid/setgid/filecaps o sustitución de usuario; no se ejecutó la herramienta."
    return {"schema_version": 1, "verification": "RNF06_PRIVILEGIOS_EFECTIVOS_READ_ONLY",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": "FAIL" if any(c["result"] == "FAIL" for c in checks) else "PARTIAL" if any(c["result"] == "PARTIAL" for c in checks) else "PASS",
        "proposed_status": "PARCIAL", "checks": checks,
        "identity": {"uid": os.getresuid(), "gid": os.getresgid(), "username": pwd.getpwuid(os.geteuid()).pw_name,
                     "groups": groups, "self_process": own_status, "parent_process": process_status(os.getppid())},
        "executables": binaries,
        "effective_path_permissions": [file_permissions(p) for p in [root, root / "piloto_kali/prototipo/corridas", Path("/dev/shm"), Path("/var/run/docker.sock")]],
        "source_invocations": sources, "protocol_configuration_evidence": configuration,
        "active_auditor_processes": active_auditor_processes(root),
        "docker_read_only_observation": containers,
        "adapters": {
            "services_nmap": {"location": "host", "profile": "nmap_tcp_services_v1 (-sT)", "inference": host_inference, "effective_execution_observed": False},
            "credentials_hydra": {"location": "host", "profile": "autenticación finita por TCP; archivo temporal 0600", "inference": host_inference, "effective_execution_observed": False},
            "application_http": {"location": "proceso Python del auditor", "profile": "http.client.HTTPConnection + cliente independiente", "inference": "Código en proceso sin cambio de UID/capacidades; sólo credenciales actuales del verificador observadas.", "effective_execution_observed": False},
            "protocols_scapy": {"location": "Docker nova-sender y nf1..nf4-sender; receptores/router para observar y restaurar", "profile": "Scapy por docker exec configurado en el código", "configured_privileges": "Los compose actuales declaran sender root por defecto+NET_RAW; receptores root+NET_ADMIN/NET_RAW; router añade SETUID/SETGID. La configuración v2 se etiqueta como histórica y no acredita los cinco bancos actuales.", "effective_execution_observed": False,
                "current_sender_representatives_observed": sum(r["segment"] == "dc" and r["exec_process"]["available"] for r in containers.get("representative_processes", []))}},
        "limitations": [
            "El verificador no ejecuta ningún adaptador; las credenciales de un proceso de auditoría histórico no se pueden recuperar desde su PID pasado.",
            "Contenedores detenidos o ausentes impiden leer sus capacidades efectivas; Config.User/CapAdd documentan configuración, no CapEff ejecutada.",
            "Scapy y las operaciones de estado IPv6 requieren capacidades en contenedores; no se cambian ni se amplían privilegios para probarlos.",
            "La pertenencia al grupo docker permite acceso al daemon: UID no root y CapEff=0 no demuestran por sí solos privilegio mínimo del conjunto.",
            "RNF-06 permanece PARCIAL; el PASS sólo acredita la recolección defensiva y los cotejos expresamente nombrados."],
        "actions": ["/proc read", "filesystem metadata and os.access", "getcap read"] + (
            ["read existing RNF08 process capability receipts; no Docker invocation"] if isolation_paths else ["docker ps -a", "docker container inspect projected fields"]),
        "not_performed": ["API", "network probes", "audit executions", "sudo", "setcap", "Docker exec/start/stop/compose", "privilege mutation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--isolation-receipt", type=Path, nargs="+",
                        help="Recibos de segmentos RNF-08 ya ejecutados; evita toda invocación de Docker.")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.parent != (ROOT / "docs/verificacion-postevaluacion").resolve() or output.suffix != ".json":
        parser.error("El recibo debe ser un JSON nuevo en docs/verificacion-postevaluacion.")
    receipt = verify(ROOT, args.isolation_receipt)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"result": receipt["result"], "proposed_status": receipt["proposed_status"], "output": str(output), "checks": len(receipt["checks"])}, ensure_ascii=False))
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
