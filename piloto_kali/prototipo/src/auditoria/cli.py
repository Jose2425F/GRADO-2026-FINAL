"""Interfaz del operador para validar y ejecutar corridas controladas."""

from __future__ import annotations

import hashlib
import json
import getpass
import os
import platform
import re
import shutil
import subprocess
import time
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import typer
from pydantic import ValidationError

from . import __version__
from .casos_ipv6 import CASES, selected_case_ids
from .contracts import AuditRequest, Category, LabPolicy, Target
from .lab import (
    ADDRESS,
    INTERFACE,
    PORT,
    SSH_ADDRESS,
    SSH_PORT,
    SUBNET,
    LabError,
    verify_pilot_lab,
    verify_ssh_pilot_lab,
)
from .ipv6_lab import (
    INTERFACE as IPV6_INTERFACE,
    SUBNET as IPV6_SUBNET,
    TARGET as IPV6_TARGET,
    UDP_PORT as IPV6_UDP_PORT,
    IPv6LabError,
    verify_ipv6_lab,
)
from .lab_virtual import VirtualLabError, load_config, preflight_virtual_lab
from .policy import PolicyError, authorize_request
from .store import RunStore, write_json
from .validation import compare_runs, load_run, validate_results
from .agentes.agente_administrador import build_graph
from .agentes import AGENT_NAMES
from .laboratorio import operation_lock

app = typer.Typer(help="Prototipo de auditoría dual-stack en laboratorio aislado.")


def load_inputs(
    request_path: Path, policy_path: Path, *, live: bool
) -> tuple[AuditRequest, LabPolicy]:
    request = AuditRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
    policy = LabPolicy.model_validate_json(policy_path.read_text(encoding="utf-8"))
    authorize_request(request, policy, live=live)
    return request, policy


def abort(exc: Exception) -> None:
    typer.secho(f"Rechazado: {exc}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2)


def lab_operation(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            with operation_lock():
                return function(*args, **kwargs)
        except (LabError, OSError) as exc:
            abort(exc)

    return guarded


def tool_identity(name: str) -> dict | None:
    path = shutil.which(name)
    if path is None:
        return None
    binary = Path(path).resolve()
    try:
        version_arg = "-h" if name == "hydra" else "--version"
        version = subprocess.run(
            [name, version_arg], capture_output=True, text=True, timeout=5, check=False
        ).stdout.splitlines()[0]
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    except (OSError, subprocess.SubprocessError, IndexError):
        version, digest = "unavailable", None
    return {"path": str(binary), "version": version, "sha256": digest}


def source_fingerprint() -> str:
    source = Path(__file__).resolve().parent
    deploy = source.parents[2] / "despliegue"
    paths = sorted(
        [p for p in source.rglob("*") if p.suffix in {".py", ".j2"}]
        + [source.parents[1] / name for name in ("pyproject.toml", "uv.lock")]
        + [
            p
            for p in deploy.rglob("*")
            if p.suffix in {".py", ".yml", ".sh"} or p.name.startswith("Dockerfile")
        ]
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(source.parents[2]).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def safe_console(value: str | None) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value or "")[:100]


def run_request(
    request: AuditRequest,
    policy: LabPolicy,
    salida: Path,
    *,
    live: bool,
    request_bytes: bytes,
    policy_bytes: bytes,
    lab_metadata: dict | None = None,
) -> dict:
    authorize_request(request, policy, live=live)
    if live and request.bank == "v2":
        from .lab_v2 import VERSION

        if not lab_metadata or lab_metadata.get("bank") != VERSION or lab_metadata.get("images_frozen") is not True:
            raise PolicyError("v2_preflight_required", "v2 requiere preflight e imágenes congeladas; use demo-v2 o experimento-v2")
    started = time.monotonic()
    run_name = f"{request.audit_id}_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{uuid4().hex[:8]}"
    store = RunStore(salida / run_name, request.audit_id)
    from .dashboard import process_identity

    runtime = {
        "pid": os.getpid(),
        "identity": process_identity(os.getpid()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
    }
    write_json(store.root / "runtime.json", runtime)
    try:
        lock_path = Path(__file__).resolve().parents[2] / "uv.lock"
        profiles = ["nmap_tcp_services_v1"] if Category.IPV4_SERVICES in request.categories else []
        if Category.IPV4_CREDENTIALS in request.categories:
            profiles.extend(
                f"hydra_{p.service.replace('-', '_')}_single_v1"
                for p in policy.credential_profiles
                if any(
                    p.ref in t.credential_refs + ([t.credential_ref] if t.credential_ref else [])
                    for t in request.targets
                )
            )
        if any(
            category in request.categories
            for category in (Category.IPV6_NDP, Category.IPV6_FRAGMENTATION)
        ):
            profiles.extend(
                CASES[case_id].action_profile for case_id in selected_case_ids(request.case_ids)
            )
        accepted = store.event(
            "controller", "request_accepted", payload={"mode": "live" if live else "dry_run"}
        )
        started = accepted.monotonic_ns / 1_000_000_000
        if request.bank == "v2":
            from .v2_agent import build_plan

            profiles = sorted({t.action_profile for t in build_plan(request)})
        manifest = {
            "schema_version": "1",
            "prototype_version": __version__,
            "source_sha256": source_fingerprint(),
            "execution_concurrency": (
                2 if live and request.architecture == "multiagent" and not request.stop_on_verified_access
                else 1
            ),
            "execution_policy": request.execution_policy,
            "stop_on_verified_access": request.stop_on_verified_access,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "policy_id": policy.policy_id,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "uv_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest()
            if lock_path.exists()
            else None,
            "mode": "live" if live else "dry_run",
            "llm_provider": request.llm_provider if request.token_budget else "disabled",
            "llm_model": None,
            "tool_profile": "+".join(profiles),
            "tools": {
                "nmap": tool_identity("nmap")
                if live and Category.IPV4_SERVICES in request.categories
                else None,
                "hydra": tool_identity("hydra")
                if live and Category.IPV4_CREDENTIALS in request.categories
                else None,
                "scapy": (
                    {"version": "2.7.0", "image_id": lab_metadata.get("sender_image_id")}
                    if live
                    and lab_metadata
                    and any(
                        category in request.categories
                        for category in (Category.IPV6_NDP, Category.IPV6_FRAGMENTATION)
                    )
                    else None
                ),
            },
            "lab": lab_metadata,
        }
        write_json(store.root / "manifest.json", manifest)
        write_json(store.root / "request.json", request.model_dump(mode="json"))
        write_json(store.root / "policy.json", policy.model_dump(mode="json"))
        graph = build_graph(store, live=live, started=started)
        state = graph.invoke(
            {"request": request, "policy": policy, "tasks": [], "results": [], "report": {}}
        )
        manifest["architecture"] = request.architecture
        manifest["llm_mode"] = request.llm_mode
        manifest["llm_config"] = {
            **state["report"]["llm"].get("configuration", {}),
            "pricing": state["report"]["llm"].get("pricing"),
        }
        manifest["llm_model"] = state["report"]["llm"].get("model")
        manifest["llm_status"] = state["report"]["llm"]["status"]
        write_json(store.root / "manifest.json", manifest)
        typer.echo(f"Corrida: {store.root.resolve()}")
        typer.echo(f"Estado: {state['report']['status']}; tareas: {len(state['results'])}")
        llm = state["report"]["llm"]
        typer.echo(
            f"IA: {llm['status']}; modelo: {safe_console(llm.get('model')) or '—'}; "
            f"tokens: {llm.get('total_tokens') if llm.get('total_tokens') is not None else 'sin medición completa'}; "
            f"reintentos HTTP 503: {llm.get('provider_retries', 0)}"
        )
        agent_by_task = {
            task.task_id: AGENT_NAMES.get(task.agent_type, task.agent_type)
            for task in state["tasks"]
        }
        for result in state["results"]:
            typer.echo(
                f"  {agent_by_task.get(result.task_id, result.task_id)} "
                f"[{result.task_id}]: {result.status}"
                + (f" ({result.reason_code})" if result.reason_code else "")
            )
            for service in result.services:
                typer.echo(
                    f"    {service.port}/{service.protocol} "
                    f"{safe_console(service.name)} {safe_console(service.product)}"
                )
            if result.authentication is not None:
                typer.echo(
                    f"    autenticación {result.authentication.service}/"
                    f"{result.authentication.port}: {result.authentication.outcome}"
                )
            if result.observations.get("case_id"):
                typer.echo(
                    f"    caso {result.observations.get('case_id')}: "
                    f"{result.observations.get('interpretation')}"
                )
        typer.echo(f"Informe JSON: {(store.root / 'report.json').resolve()}")
        state["run_path"] = str(store.root.resolve())
        return state
    finally:
        runtime.update(
            status="finished" if (store.root / "report.json").exists() else "interrupted",
            ended_at=datetime.now(timezone.utc).isoformat(),
        )
        write_json(store.root / "runtime.json", runtime)
        store.close()


@app.command()
def validar(
    solicitud: Path = typer.Argument(..., exists=True, readable=True),
    politica: Path = typer.Option(..., "--politica", exists=True, readable=True),
    ejecutar: bool = typer.Option(
        False, "--ejecutar", help="Comprueba además la ventana temporal actual."
    ),
) -> None:
    """Valida contratos y alcance sin enviar paquetes."""
    try:
        request, policy = load_inputs(solicitud, politica, live=ejecutar)
    except (OSError, ValidationError, PolicyError, ValueError) as exc:
        abort(exc)
    typer.echo(
        f"Válida: {request.audit_id}; política {policy.policy_id}; objetivos {len(request.targets)}"
    )


@app.command()
def auditar(
    solicitud: Path = typer.Argument(..., exists=True, readable=True),
    politica: Path = typer.Option(..., "--politica", exists=True, readable=True),
    salida: Path = typer.Option(Path("corridas"), "--salida", help="Directorio de corridas."),
    ejecutar: bool = typer.Option(
        False, "--ejecutar", help="Habilita Nmap tras validar alcance y ruta."
    ),
) -> None:
    """Genera plan, bitácora e informes; por defecto solo simula."""
    try:
        request, policy = load_inputs(solicitud, politica, live=ejecutar)
        state = run_request(
            request,
            policy,
            salida,
            live=ejecutar,
            request_bytes=solicitud.read_bytes(),
            policy_bytes=politica.read_bytes(),
        )
    except (OSError, ValidationError, PolicyError, ValueError) as exc:
        abort(exc)
    if state["report"]["status"] == "partial":
        raise typer.Exit(code=3)


@app.command("piloto-docker")
def piloto_docker(
    autorizacion: str = typer.Option(
        ..., "--autorizacion", help="Referencia de autorización del laboratorio."
    ),
    politica: Path = typer.Option(
        Path("config/lab_policy.example.json"), "--politica", exists=True, readable=True
    ),
    salida: Path = typer.Option(Path("corridas"), "--salida"),
) -> None:
    """Audita en vivo el Tomcat aislado después de comprobar su topología."""
    now = datetime.now(timezone.utc)
    try:
        request = AuditRequest(
            audit_id=f"piloto_docker_{now:%Y%m%dT%H%M%S}_{uuid4().hex[:6]}",
            operator=getpass.getuser(),
            authorization_ref=autorizacion,
            scope_ipv4=[SUBNET],
            categories=[Category.IPV4_SERVICES],
            targets=[
                Target(asset_id="obj_tomcat", address=ADDRESS, interface=INTERFACE, ports=[PORT])
            ],
            not_before=now - timedelta(minutes=1),
            not_after=now + timedelta(minutes=10),
            max_runtime_seconds=90,
            max_attempts=1,
            token_budget=0,
        )
        policy_bytes = politica.read_bytes()
        policy = LabPolicy.model_validate_json(policy_bytes)
        authorize_request(request, policy, live=True)
        lab_metadata = verify_pilot_lab()
        state = run_request(
            request,
            policy,
            salida,
            live=True,
            request_bytes=request.model_dump_json(indent=2).encode("utf-8"),
            policy_bytes=policy_bytes,
            lab_metadata=lab_metadata,
        )
    except (OSError, ValidationError, PolicyError, LabError, ValueError) as exc:
        abort(exc)
    if state["report"]["status"] != "complete":
        raise typer.Exit(code=3)
    if not any(service.port == PORT for result in state["results"] for service in result.services):
        typer.secho(
            "El escaneo terminó, pero Tomcat no apareció en el inventario.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=3)


@app.command("piloto-credenciales")
def piloto_credenciales(
    autorizacion: str = typer.Option(
        ..., "--autorizacion", help="Referencia de autorización del laboratorio."
    ),
    politica: Path = typer.Option(
        Path("config/credentials_pilot.policy.json"), "--politica", exists=True, readable=True
    ),
    salida: Path = typer.Option(Path("corridas"), "--salida"),
) -> None:
    """Ejecuta Nmap y un intento SSH sintético después de comprobar el laboratorio."""
    now = datetime.now(timezone.utc)
    try:
        request = AuditRequest(
            audit_id=f"piloto_credenciales_{now:%Y%m%dT%H%M%S}_{uuid4().hex[:6]}",
            operator=getpass.getuser(),
            authorization_ref=autorizacion,
            scope_ipv4=[f"{SSH_ADDRESS}/32"],
            categories=[Category.IPV4_SERVICES, Category.IPV4_CREDENTIALS],
            targets=[
                Target(
                    asset_id="obj_ssh",
                    address=SSH_ADDRESS,
                    interface=INTERFACE,
                    ports=[SSH_PORT],
                    credential_ref="ssh_synthetic_1",
                )
            ],
            not_before=now - timedelta(minutes=1),
            not_after=now + timedelta(minutes=10),
            max_runtime_seconds=120,
            max_attempts=1,
            token_budget=0,
        )
        policy_bytes = politica.read_bytes()
        policy = LabPolicy.model_validate_json(policy_bytes)
        authorize_request(request, policy, live=True)
        profile = next(p for p in policy.credential_profiles if p.ref == "ssh_synthetic_1")
        if not os.environ.get(profile.password_env):
            raise LabError("falta la credencial sintética en el entorno")
        lab_metadata = verify_ssh_pilot_lab()
        state = run_request(
            request,
            policy,
            salida,
            live=True,
            request_bytes=request.model_dump_json(indent=2).encode("utf-8"),
            policy_bytes=policy_bytes,
            lab_metadata=lab_metadata,
        )
    except (OSError, ValidationError, PolicyError, LabError, ValueError, StopIteration) as exc:
        abort(exc)
    if state["report"]["status"] != "complete":
        raise typer.Exit(code=3)
    if not any(result.authentication is not None for result in state["results"]):
        raise typer.Exit(code=3)


@app.command("piloto-ipv6")
def piloto_ipv6(
    autorizacion: str = typer.Option(
        ..., "--autorizacion", help="Referencia de autorización del laboratorio."
    ),
    politica: Path = typer.Option(
        Path("config/ipv6_pilot.policy.json"), "--politica", exists=True, readable=True
    ),
    salida: Path = typer.Option(Path("corridas"), "--salida"),
    caso: list[str] = typer.Option([], "--caso", help="Caso GT-09 a GT-16; se puede repetir."),
    completo: bool = typer.Option(
        False, "--completo", help="Ejecuta los ocho casos GT-09 a GT-16."
    ),
    openai: bool = typer.Option(
        False, "--openai", help="Planifica las tareas autorizadas con OpenAI."
    ),
) -> None:
    """Ejecuta casos IPv6 autorizados solo en el Docker interno verificado."""
    now = datetime.now(timezone.utc)
    try:
        if completo and caso:
            raise ValueError("elige --completo o --caso, no ambos")
        case_ids = list(CASES) if completo else caso
        active_cases = selected_case_ids(case_ids)
        if any(case_id not in CASES for case_id in active_cases):
            raise ValueError("case_id desconocido")
        categories = list(dict.fromkeys(CASES[case_id].category for case_id in active_cases))
        request = AuditRequest(
            audit_id=f"piloto_ipv6_{now:%Y%m%dT%H%M%S}_{uuid4().hex[:6]}",
            operator=getpass.getuser(),
            authorization_ref=autorizacion,
            scope_ipv6=[IPV6_SUBNET],
            categories=categories,
            case_ids=case_ids,
            targets=[
                Target(
                    asset_id="obj_ipv6",
                    address=IPV6_TARGET,
                    interface=IPV6_INTERFACE,
                    ports=[IPV6_UDP_PORT],
                )
            ],
            not_before=now - timedelta(minutes=1),
            not_after=now + timedelta(minutes=10),
            max_runtime_seconds=600 if completo else 120,
            max_attempts=1,
            token_budget=4096 if openai else 0,
            llm_provider="openai",
            llm_mode="scheduler" if openai else "disabled",
        )
        if openai:
            from .openai_provider import load_openai_config
            load_openai_config(Path(".lab"))
        policy_bytes = politica.read_bytes()
        policy = LabPolicy.model_validate_json(policy_bytes)
        authorize_request(request, policy, live=True)
        lab_metadata = verify_ipv6_lab()
        state = run_request(
            request,
            policy,
            salida,
            live=True,
            request_bytes=request.model_dump_json(indent=2).encode("utf-8"),
            policy_bytes=policy_bytes,
            lab_metadata=lab_metadata,
        )
    except (OSError, ValidationError, PolicyError, IPv6LabError, ValueError) as exc:
        abort(exc)
    if state["report"]["status"] != "complete":
        raise typer.Exit(code=3)


@app.command("preflight-lab-virtual")
def preflight_lab_virtual(
    config: Path = typer.Argument(..., exists=True, readable=True),
) -> None:
    """Comprueba interfaces, rutas y observador de la futura topología VM."""
    try:
        metadata = preflight_virtual_lab(load_config(config))
    except (OSError, ValidationError, ValueError, VirtualLabError) as exc:
        abort(exc)
    typer.echo(f"Laboratorio VM listo: {metadata['asset_id']} por {metadata['audit_interface']}")
    typer.echo(f"Observador: {metadata['observer_url']} vía {metadata['management_interface']}")


@app.command("validar-corrida")
def validar_corrida(
    corrida: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    """Recalcula hashes y clasifica observaciones desde una corrida guardada."""
    try:
        _, tasks, results = load_run(corrida)
        records = validate_results(corrida, tasks, results)
    except (OSError, KeyError, ValueError, ValidationError) as exc:
        abort(exc)
    for record in records:
        typer.echo(f"{record['task_id']}: {record['state']} ({record['reason']})")
    if any(record["evidence_integrity"]["valid"] is False for record in records):
        raise typer.Exit(code=3)


@app.command("comparar-corridas")
def comparar_corridas(
    primera: Path = typer.Argument(..., exists=True, file_okay=False),
    segunda: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    """Comprueba reproducibilidad sin convertirla en vulnerabilidad confirmada."""
    try:
        records = compare_runs(primera, segunda)
    except (OSError, KeyError, ValueError, ValidationError) as exc:
        abort(exc)
    for record in records:
        typer.echo(
            f"{record['asset_id']} / {record['case_id']}: {record['state']} ({record['reason']})"
        )
    if not records or any(record["state"] != "reproduced" for record in records):
        raise typer.Exit(code=3)


@app.command("laboratorio")
@lab_operation
def laboratorio(
    accion: str = typer.Argument("estado", help="preparar, levantar, estado, restaurar o bajar"),
    config: Path = typer.Option(Path(".lab"), "--config"),
    ipv6: bool = typer.Option(True, "--ipv6/--sin-ipv6"),
) -> None:
    """Crea y administra los objetivos vulnerables y controles protegidos en Docker."""
    from .laboratorio import prepare, compose, preflight

    try:
        if accion == "preparar":
            prepare(config)
            typer.echo(
                f"Configuración preparada: {config.resolve()}; secreto de control con permisos 0600."
            )
        elif accion in {"levantar", "restaurar", "bajar"}:
            compose(
                config, {"levantar": "up", "restaurar": "reset", "bajar": "down"}[accion], ipv6=ipv6
            )
            if accion != "bajar":
                metadata = preflight(ipv6=ipv6)
                write_json(config / "lab_manifest.json", metadata)
                typer.echo(
                    "Banco listo: seis objetivos IPv4"
                    + (" y dos contenedores IPv6." if ipv6 else ".")
                )
        elif accion == "estado":
            metadata = preflight(ipv6=ipv6, wait_seconds=0)
            typer.echo("Aislamiento, rutas y servicios comprobados.")
            typer.echo(f"Objetivos/puertos comprobados: {len(metadata['targets'])}")
        else:
            raise ValueError(
                "acción desconocida; use preparar, levantar, estado, restaurar o bajar"
            )
    except (OSError, ValueError, LabError, IPv6LabError) as exc:
        abort(exc)


def execute_demo(
    config: Path,
    salida: Path,
    autorizacion: str,
    arquitectura: str,
    ipv6: bool,
    live: bool,
    token_budget: int,
    *,
    openai: bool = False,
    stop_on_verified_access: bool = False,
) -> dict:
    from .laboratorio import request_for_lab, preflight

    if arquitectura not in {"single", "multiagent"}:
        raise ValueError("arquitectura debe ser single o multiagent")
    if openai and live:
        from .openai_provider import load_openai_config
        load_openai_config(config)
    request = request_for_lab(
        autorizacion, architecture=arquitectura, openai=openai, ipv6=ipv6, token_budget=token_budget
    )
    request = request.model_copy(update={"stop_on_verified_access": stop_on_verified_access})
    policy_bytes = (config / "policy.json").read_bytes()
    policy = LabPolicy.model_validate_json(policy_bytes)
    metadata = preflight(ipv6=ipv6) if live else None
    # Es una credencial sintética pública del banco, jamás una clave del usuario.
    previous = os.environ.get("LAB_PROBE_PASSWORD")
    os.environ["LAB_PROBE_PASSWORD"] = "lab2026"
    try:
        return run_request(
            request,
            policy,
            salida,
            live=live,
            request_bytes=request.model_dump_json(indent=2).encode(),
            policy_bytes=policy_bytes,
            lab_metadata=metadata,
        )
    finally:
        if previous is None:
            os.environ.pop("LAB_PROBE_PASSWORD", None)
        else:
            os.environ["LAB_PROBE_PASSWORD"] = previous


@app.command("demo")
@lab_operation
def demo(
    autorizacion: str = typer.Option(..., "--autorizacion"),
    arquitectura: str = typer.Option("multiagent", "--arquitectura"),
    openai: bool = typer.Option(False, "--openai", help="Planifica con GPT-6.1 Sol usando la configuración privada."),
    ipv6: bool = typer.Option(True, "--ipv6/--sin-ipv6"),
    ejecutar: bool = typer.Option(False, "--ejecutar"),
    config: Path = typer.Option(Path(".lab"), "--config"),
    salida: Path = typer.Option(Path("corridas/demo"), "--salida"),
    tokens: int = typer.Option(40000, "--tokens", min=256, max=60000),
    parar_al_confirmar_acceso: bool = typer.Option(
        False, "--parar-al-confirmar-acceso",
        help="Demo serial: cancela las tareas restantes tras autenticación corroborada. Sin KPI formales.",
    ),
) -> None:
    """Prueba el banco completo; añada --ejecutar para enviar las pruebas autorizadas."""
    try:
        state = execute_demo(
            config, salida, autorizacion, arquitectura, ipv6, ejecutar, tokens,
            openai=openai, stop_on_verified_access=parar_al_confirmar_acceso,
        )
        if ejecutar and not parar_al_confirmar_acceso:
            from .metrics import score_run

            truth = json.loads((config / "ground_truth.json").read_text())
            score = score_run(Path(state["run_path"]), truth)
            write_json(Path(state["run_path"]) / "evaluation.json", score)
            typer.echo(f"Banco IPv4: TP={score['TP']} FP={score['FP']} FN={score['FN']}")
        if parar_al_confirmar_acceso:
            stopped = state["report"]["execution_control"]["stopped"]
            typer.echo(
                "Plan simulado; la parada solo se comprueba al ejecutar las pruebas."
                if not ejecutar else "Acceso verificado; pruebas restantes canceladas."
                if stopped else "No se confirmó acceso; no se activó la parada."
            )
            typer.echo("Demo de acceso; no sustituye la evaluación completa del banco.")
    except (OSError, ValueError, LabError, IPv6LabError, PolicyError) as exc:
        abort(exc)
    if state["report"]["status"] == "partial" and not state["report"]["execution_control"]["stopped"]:
        raise typer.Exit(code=3)


@app.command("laboratorio-v2")
@lab_operation
def laboratorio_v2(
    accion: str = typer.Argument("estado", help="preparar, levantar, estado, certificar, restaurar o bajar"),
    config: Path = typer.Option(Path(".lab-v2"), "--config"),
    salida: Path = typer.Option(Path("corridas/certificacion_v2"), "--salida"),
    autorizacion: str = typer.Option("", "--autorizacion"),
) -> None:
    """Banco versionado de aplicaciones dual-stack, SLAAC y controles ND. Sin llamadas LLM."""
    from . import lab_v2

    try:
        if accion == "preparar":
            lab_v2.prepare(config)
            typer.echo(f"Banco v2 preparado: {config.resolve()}")
        elif accion in {"levantar", "restaurar", "bajar"}:
            lab_v2.compose(config, {"levantar": "up", "restaurar": "reset", "bajar": "down"}[accion])
            if accion != "bajar":
                metadata = lab_v2.preflight(config, freeze=True, allow_refreeze=accion == "levantar")
                write_json(config / "lab_manifest.json", metadata)
                typer.echo("Banco v2 listo: cuatro aplicaciones dual-stack, router RA, emisor y dos receptores.")
        elif accion == "estado":
            metadata = lab_v2.preflight(config)
            typer.echo(f"Banco v2 comprobado: {len(metadata['targets'])} contenedores; SLAAC correcto en ambos receptores.")
        elif accion == "certificar":
            root, result = lab_v2.certificate(config, salida, autorizacion)
            typer.echo(f"Certificación: {root.resolve()}")
            typer.echo(f"Estado: {result['status']}; comprobaciones: {result.get('checks_passed', 0)}/{len(result['checks'])}")
            if result["status"] != "certified":
                typer.echo(f"Motivo: {result.get('failure_reason', 'uno o más controles no cumplen el criterio')}")
                raise typer.Exit(code=3)
        else:
            raise ValueError("acción v2 desconocida")
    except (OSError, ValueError, LabError) as exc:
        abort(exc)


@app.command("validar-certificacion-v2")
def validar_certificacion_v2(
    corrida: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    """Comprueba integridad del certificado y sus evidencias sin tráfico."""
    from .lab_v2 import verify_certificate

    try:
        result = verify_certificate(corrida)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        abort(exc)
    typer.echo(f"Integridad: {result['valid']}; estados comprobados: {result['checked_states']}")
    if not result["valid"] or result["status"] != "certified":
        raise typer.Exit(code=3)


@app.command("evaluar-par")
def evaluar_par(
    single: Path = typer.Argument(..., exists=True, file_okay=False),
    multiagent: Path = typer.Argument(..., exists=True, file_okay=False),
    verdad: Path = typer.Option(Path(".lab/ground_truth.json"), "--verdad", exists=True),
    salida: Path = typer.Option(Path("comparacion.json"), "--salida"),
) -> None:
    """Calcula TP/FP/FN y KPI; comprueba equivalencia y uso real de LLM."""
    from .metrics import compare_pair

    try:
        result = compare_pair(single, multiagent, verdad)
        write_json(salida, result)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        abort(exc)
    typer.echo(f"Evaluación: {salida.resolve()}")
    typer.echo(f"Par apto para KPI formales: {result['eligible']}")
    if not result["eligible"]:
        typer.echo("Motivos: " + ", ".join(result["ineligibility_reasons"]))


@app.command("experimento")
@lab_operation
def experimento(
    autorizacion: str = typer.Option(..., "--autorizacion"),
    bloques: int = typer.Option(15, "--bloques", min=1, max=100),
    semilla: int = typer.Option(2026, "--semilla"),
    piloto: bool = typer.Option(
        False,
        "--piloto",
        help="Etiqueta el experimento como piloto, separado del estudio definitivo.",
    ),
    openai: bool = typer.Option(True, "--openai/--sin-ia", help="Usa OpenAI; --sin-ia limita el experimento a aceptación funcional."),
    ipv6: bool = typer.Option(True, "--ipv6/--sin-ipv6"),
    config: Path = typer.Option(Path(".lab"), "--config"),
    salida: Path = typer.Option(Path("experimentos"), "--salida"),
    tokens: int = typer.Option(40000, "--tokens", min=256, max=60000),
) -> None:
    """Ejecuta pares en orden aleatorio, restaura entre corridas y conserva los fallos."""
    import random
    from .laboratorio import compose
    from .metrics import summarize_experiment

    root = salida / f"experimento_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{uuid4().hex[:6]}"
    try:
        if openai:
            from .openai_provider import load_openai_config

            load_openai_config(config)
        root.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(config / "ground_truth.json", root / "ground_truth.json")
        shutil.copyfile(config / "policy.json", root / "policy.json")
        rng = random.Random(semilla)
        design = []
        for block in range(1, bloques + 1):
            order = ["single", "multiagent"]
            rng.shuffle(order)
            design.append({"block": block, "order": order})
        write_json(
            root / "design.json",
            {
                "seed": semilla,
                "blocks": design,
                "ipv6": ipv6,
                "llm_provider": "openai" if openai else "disabled",
                "tokens": tokens,
                "pilot": piloto,
            },
        )
        attempts = []
        write_json(root / "attempts.json", attempts)
        typer.echo(f"Experimento: {root.resolve()}")
        for design_block in design:
            for index, architecture in enumerate(design_block["order"], 1):
                # Restauración y preflight previos se contabilizan fuera del tiempo del auditor.
                reset_start = time.monotonic()
                compose(config, "reset", ipv6=ipv6)
                from .laboratorio import preflight

                preflight(ipv6=ipv6)
                attempt = {
                    "block": design_block["block"],
                    "order": index,
                    "architecture": architecture,
                    "status": "started",
                    "run_path": None,
                    "reset_seconds": round(time.monotonic() - reset_start, 6),
                }
                attempts.append(attempt)
                write_json(root / "attempts.json", attempts)
                try:
                    state = execute_demo(
                        root,
                        root / "corridas",
                        autorizacion,
                        architecture,
                        ipv6,
                        True,
                        tokens,
                        openai=openai,
                    )
                    attempt.update(status=state["report"]["status"], run_path=state["run_path"])
                    from .metrics import score_run

                    score = score_run(
                        Path(state["run_path"]),
                        json.loads((root / "ground_truth.json").read_text()),
                    )
                    write_json(Path(state["run_path"]) / "evaluation.json", score)
                except Exception as exc:
                    attempt.update(status="failed", reason=type(exc).__name__)
                finally:
                    write_json(root / "attempts.json", attempts)
                    summarize_experiment(root, root / "ground_truth.json")
        result = summarize_experiment(root, root / "ground_truth.json")
        typer.echo(
            f"Corridas iniciadas: {result['runs_started']}; pares aptos: {result['pairs_eligible']}"
        )
        typer.echo(f"Resultados: {(root / 'evaluation.json').resolve()} y runs.csv")
    except KeyboardInterrupt:
        typer.echo(
            "Interrumpido. Los intentos iniciados permanecen en attempts.json para evaluación."
        )
        raise typer.Exit(code=130)
    except (OSError, ValueError, LabError, IPv6LabError) as exc:
        abort(exc)


@app.command("evaluar-experimento")
def evaluar_experimento(
    experimento: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    """Recalcula CSV y evaluación de todos los intentos, incluso interrumpidos."""
    from .metrics import summarize_experiment

    try:
        summary = summarize_experiment(experimento, experimento / "ground_truth.json")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        abort(exc)
    typer.echo(f"Corridas: {summary['runs_started']}; pares aptos: {summary['pairs_eligible']}")


@app.command("panel")
def panel(
    corridas: Path = typer.Argument(Path("corridas"), file_okay=False),
    servir: bool = typer.Option(False, "--servir", help="Observa progreso real cada dos segundos."),
    puerto: int = typer.Option(8765, "--puerto", min=1024, max=65535),
    abrir: bool = typer.Option(True, "--abrir/--no-abrir", help="Abre el navegador al servir."),
) -> None:
    """Panel profesional de auditorías, agentes, bitácora y KPI; acceso local."""
    from .dashboard import build_dashboard, make_server

    try:
        if servir:
            import webbrowser

            server = make_server(corridas, puerto)
            url = f"http://127.0.0.1:{server.server_port}"
            typer.echo(f"Panel en vivo: {url} · Ctrl+C para cerrar el panel.")
            typer.echo("Observación local; las auditorías se ejecutan desde otra terminal.")
            if abrir:
                webbrowser.open(url)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return
        path = build_dashboard(corridas)
    except (OSError, ValueError) as exc:
        abort(exc)
    typer.echo(f"Panel: {path.resolve()}")


if __name__ == "__main__":
    app()


def execute_v2(config, credentials, output, authorization, architecture, *, live=True, llm=True, tokens=60000, stop=False):
    from . import lab_v2
    from .v2_agent import request as v2_request, policy as v2_policy
    if llm and live:
        from .openai_provider import load_openai_config
        load_openai_config(credentials)
    req=v2_request(authorization,architecture,tokens,llm,stop)
    pol=v2_policy()
    metadata=lab_v2.preflight(config) if live else None
    if metadata:
        metadata['sender_image_id']=next(t['image_id'] for t in metadata['targets'] if t['container']=='v2-sender')
    return run_request(req,pol,output,live=live,request_bytes=req.model_dump_json(indent=2).encode(),
                       policy_bytes=pol.model_dump_json(indent=2).encode(),lab_metadata=metadata)


def host_resources():
    memory = {line.split(':', 1)[0]: int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()}
    return {'cpu_count':os.cpu_count(),'load_average':list(os.getloadavg()),
            'memory_available_kb':memory['MemAvailable'],'swap_free_kb':memory['SwapFree']}


@app.command('demo-v2')
@lab_operation
def demo_v2(
    autorizacion: str = typer.Option(...,'--autorizacion'),
    arquitectura: str = typer.Option('multiagent','--arquitectura'),
    config: Path = typer.Option(Path('.lab-v2'),'--config'),
    credenciales: Path = typer.Option(Path('.lab'),'--credenciales'),
    salida: Path = typer.Option(Path('corridas/v2'),'--salida'),
    ejecutar: bool = typer.Option(False,'--ejecutar'),
    openai: bool = typer.Option(True,'--openai/--sin-ia'),
    tokens: int = typer.Option(60000,'--tokens',min=256,max=60000),
    parar: bool = typer.Option(False,'--parar-al-confirmar-acceso'),
):
    """Audita el banco v2 con el mismo controlador, planificador y reportes."""
    try:
        state=execute_v2(config,credenciales,salida,autorizacion,arquitectura,live=ejecutar,llm=openai,tokens=tokens,stop=parar)
    except (OSError,ValueError,LabError,PolicyError) as exc:
        abort(exc)
    if ejecutar and state['report']['status']!='complete' and not state['report']['execution_control']['stopped']:
        raise typer.Exit(3)


@app.command('experimento-v2')
@lab_operation
def experimento_v2(
    autorizacion: str = typer.Option(...,'--autorizacion'),
    bloques: int = typer.Option(15,'--bloques',min=1,max=30),
    semilla: int = typer.Option(20261012,'--semilla'),
    config: Path = typer.Option(Path('.lab-v2'),'--config'),
    credenciales: Path = typer.Option(Path('.lab'),'--credenciales'),
    salida: Path = typer.Option(Path('experimentos/v2'),'--salida'),
    tokens: int = typer.Option(60000,'--tokens',min=256,max=60000),
    piloto: bool = typer.Option(False,'--piloto'),
    costo_maximo: float = typer.Option(20.0,'--costo-maximo-usd',min=0.01,max=100),
):
    """Bloques emparejados v2 con API real, restauración, límites y conservación de intentos."""
    import random
    from . import lab_v2
    from .openai_provider import load_openai_config
    from .v2_agent import policy as v2_policy
    from .metrics import summarize_experiment
    root=salida/f'experimento_v2_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{uuid4().hex[:6]}'
    try:
        load_openai_config(credenciales)
        metadata=lab_v2.preflight(config)
        root.mkdir(parents=True,exist_ok=False)
        shutil.copyfile(config/'ground_truth.json',root/'ground_truth.json')
        write_json(root/'policy.json',v2_policy().model_dump(mode='json'))
        rng=random.Random(semilla);design=[]
        for block in range(1,bloques+1):
            order=['single','multiagent'];rng.shuffle(order);design.append({'block':block,'order':order})
        write_json(root/'design.json',{'seed':semilla,'blocks':design,'bank':'v2','llm_provider':'openai','tokens':tokens,
            'auditor_source_sha256':source_fingerprint(),
            'pilot':piloto,'cost_budget_usd':costo_maximo,'bank_manifest':metadata,'primary_outcome':'paired_recall_difference',
            'scope':'Estudio exploratorio del banco Docker certificado; sin garantía de potencia estadística.'})
        attempts=[];write_json(root/'attempts.json',attempts);total_cost=0.0
        typer.echo(f'Experimento v2: {root.resolve()}')
        for block in design:
            for index,architecture in enumerate(block['order'],1):
                # Reserva conservadora: todos los tokens al mayor precio del modelo.
                if total_cost+tokens*10/1_000_000>costo_maximo:
                    write_json(root/'stop.json',{'reason':'cost_budget_exhausted','known_cost_usd':total_cost});raise typer.Exit(3)
                reset=time.monotonic();lab_v2.compose(config,'reset');lab_v2.preflight(config)
                attempt={'block':block['block'],'order':index,'architecture':architecture,'status':'running',
                         'host_resources':host_resources(),
                         'restoration_seconds':round(time.monotonic()-reset,6)}
                attempts.append(attempt);write_json(root/'attempts.json',attempts)
                try:
                    state=execute_v2(config,credenciales,root/'runs',autorizacion,architecture,tokens=tokens)
                    attempt.update(status=state['report']['status'],run_path=state['run_path'])
                    llm=state['report']['llm'];cost=llm.get('cost_estimate_usd')
                    if cost is not None:total_cost+=cost
                    if llm.get('status')!='accepted' or not llm.get('usage_complete'):
                        # Un rechazo no se reintenta en corridas posteriores ni se oculta con respaldo.
                        write_json(root/'stop.json',{'reason':'provider_not_fully_accepted','block':block['block'],
                            'known_cost_usd':total_cost,'provider_reasons':sorted({c.get('reason','') for c in llm.get('calls',[]) if c.get('status')!='accepted'})})
                        raise typer.Exit(3)
                finally:
                    write_json(root/'attempts.json',attempts);summarize_experiment(root,root/'ground_truth.json')
        summary=summarize_experiment(root,root/'ground_truth.json')
        typer.echo(f"Corridas: {summary['runs_started']}; pares aptos: {summary['pairs_eligible']}; costo estimado USD {total_cost:.6f}")
    except (OSError,ValueError,LabError,PolicyError) as exc:
        abort(exc)
