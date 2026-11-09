"""Agente Administrador: grafo determinista de plan, ejecución y reporte."""

from __future__ import annotations

import time
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from ..casos_ipv6 import CASES, selected_case_ids
from ..contracts import AuditRequest, Category, LabPolicy, Task, TaskResult, TaskStatus
from ..ipv6_lab import IPv6LabError
from ..policy import PolicyError, authorize_request
from ..red import RouteDenied
from ..modulo_reportes import make_report, prepare_report, save_report
from ..findings import access_is_verified, confirm_findings
from ..validation import validate_results
from ..store import RunStore, write_json
from .agente_ipv4_credenciales import CredentialUnavailable, hydra_command, run_hydra
from .agente_ipv4_servicios import nmap_command, run_nmap
from .agente_ipv6_ndp_slaac import run_ndp
from .agente_ipv6_fragmentacion import run_fragmentation


class AuditState(TypedDict):
    request: AuditRequest
    policy: LabPolicy
    tasks: list[Task]
    results: list[TaskResult]
    report: dict
    llm_status: str
    llm_model: str | None
    execution_control: dict


def build_graph(store: RunStore, *, live: bool, started: float | None = None):
    started = time.monotonic() if started is None else started
    scheduler = None
    deadline = started + 3600

    def plan(state: AuditState) -> dict:
        nonlocal scheduler, deadline
        request = state["request"]
        deadline = started + request.max_runtime_seconds
        tasks = []
        case_order = selected_case_ids(request.case_ids)
        llm_status, llm_model = "disabled", None
        if live and request.llm_mode == "scheduler":
            try:
                from ..openai_provider import OpenAIScheduler

                scheduler = OpenAIScheduler(
                    store,
                    architecture=request.architecture,
                    budget=request.token_budget,
                    deadline=deadline,
                )
                llm_status, llm_model = "accepted", scheduler.config.model
                store.event("planner", "llm_ready", payload={"model": llm_model})
            except Exception as exc:
                llm_status = "fallback"
                store.event("planner", "llm_fallback", payload={"reason": type(exc).__name__})
        if request.bank == "v2":
            from ..v2_agent import build_plan

            tasks = build_plan(request)
        for target in ([] if request.bank == "v2" else request.targets):
            if ip_address(target.address).version == 4:
                services = Task(
                    task_id=f"{request.audit_id}_{target.asset_id}_services",
                    agent_type="ipv4_services",
                    target=target,
                    protocol="tcp",
                    action_profile="nmap_tcp_services_v1",
                    timeout_seconds=min(60, request.max_runtime_seconds),
                )
                tasks.append(services)
                if Category.IPV4_CREDENTIALS in request.categories:
                    refs = target.credential_refs + (
                        [target.credential_ref] if target.credential_ref else []
                    )
                    for ref in refs:
                        profile = next(
                            p for p in state["policy"].credential_profiles if p.ref == ref
                        )
                        auth_target = target.model_copy(
                            update={"credential_ref": ref, "credential_refs": []}
                        )
                        tasks.append(
                            Task(
                                task_id=f"{request.audit_id}_{target.asset_id}_credentials_{ref}",
                                agent_type="ipv4_credentials",
                                target=auth_target,
                                protocol="tcp",
                                action_profile=f"hydra_{profile.service.replace('-', '_')}_single_v1",
                                dependencies=[services.task_id],
                                timeout_seconds=min(45, request.max_runtime_seconds),
                            )
                        )
            else:
                previous = None
                for case_id in case_order:
                    case = CASES[case_id]
                    task_id = (
                        f"{request.audit_id}_{target.asset_id}_{case_id.lower().replace('-', '')}"
                    )
                    tasks.append(
                        Task(
                            task_id=task_id,
                            case_id=case_id,
                            agent_type=case.category.value,
                            target=target,
                            protocol="icmpv6" if case.category == Category.IPV6_NDP else "ipv6",
                            action_profile=case.action_profile,
                            dependencies=[previous] if previous else [],
                            timeout_seconds=min(45, request.max_runtime_seconds),
                        )
                    )
                    previous = task_id
        write_json(store.root / "plan.json", [task.model_dump(mode="json") for task in tasks])
        store.event("orchestration", "plan_created", payload={"task_count": len(tasks)})
        return {"tasks": tasks, "llm_status": llm_status, "llm_model": llm_model}

    def execute(state: AuditState) -> dict:
        results: list[TaskResult] = []
        by_id: dict[str, TaskResult] = {}
        pending = list(state["tasks"])
        try:
            return execute_pending(state, pending, results, by_id)
        finally:
            if scheduler is not None:
                scheduler.close()

    def execute_one(state, task, by_id):
        request = state["request"]
        # model_copy no valida actualizaciones: comprobar otra vez antes de cualquier adaptador.
        try:
            task = Task.model_validate(task.model_dump())
        except ValueError:
            return TaskResult(
                task_id=task.task_id, status=TaskStatus.BLOCKED, reason_code="profile_denied"
            )
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.CANCELLED,
                reason_code="runtime_budget_exhausted",
            )
        elif not live:
            if task.action_profile.startswith("hydra_"):
                profile = next(
                    p
                    for p in state["policy"].credential_profiles
                    if p.ref == task.target.credential_ref
                )
                command = hydra_command(
                    task, profile, "<private-password-file>", "<private-result-file>"
                )
            elif task.action_profile == "nmap_tcp_services_v1":
                command = nmap_command(task)
            else:
                command = ["scapy", task.action_profile, task.target.interface, task.target.address]
            result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.SKIPPED,
                reason_code="dry_run",
                command=command,
            )
        elif (
            task.dependencies
            and by_id[task.dependencies[0]].status
            not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
            and not (
                task.case_id and by_id[task.dependencies[0]].observations.get("restored") is True
            )
        ):
            result = TaskResult(
                task_id=task.task_id, status=TaskStatus.BLOCKED, reason_code="dependency_failed"
            )
        elif task.action_profile.startswith("hydra_") and not any(
            service.port
            in [
                p.port
                for p in state["policy"].credential_profiles
                if p.ref == task.target.credential_ref
            ]
            for service in by_id[task.dependencies[0]].services
        ):
            result = TaskResult(
                task_id=task.task_id, status=TaskStatus.SKIPPED, reason_code="no_applicable"
            )
        else:
            try:
                authorize_request(request, state["policy"], live=True)
                store.event(
                    "controller",
                    "task_admitted",
                    task_id=task.task_id,
                    payload={"profile": task.action_profile},
                )
                if request.bank == "v2":
                    from ..v2_agent import run_task

                    result = run_task(task, store)
                elif task.action_profile.startswith("hydra_"):
                    profile = next(
                        p
                        for p in state["policy"].credential_profiles
                        if p.ref == task.target.credential_ref
                    )
                    result = run_hydra(
                        task, profile, store, timeout_seconds=min(task.timeout_seconds, remaining)
                    )
                elif task.action_profile == "nmap_tcp_services_v1":
                    result = run_nmap(
                        task, store, timeout_seconds=min(task.timeout_seconds, remaining)
                    )
                elif task.agent_type == Category.IPV6_NDP:
                    result = run_ndp(
                        task, store, timeout_seconds=min(task.timeout_seconds, remaining)
                    )
                elif task.agent_type == Category.IPV6_FRAGMENTATION:
                    result = run_fragmentation(
                        task, store, timeout_seconds=min(task.timeout_seconds, remaining)
                    )
                else:
                    raise ValueError("perfil de tarea desconocido")
            except PolicyError as exc:
                result = TaskResult(
                    task_id=task.task_id, status=TaskStatus.BLOCKED, reason_code=exc.reason_code
                )
            except RouteDenied as exc:
                result = TaskResult(
                    task_id=task.task_id, status=TaskStatus.BLOCKED, reason_code="route_denied"
                )
                store.event(
                    "controller",
                    "route_denied",
                    task_id=task.task_id,
                    payload={"message": str(exc)[:300]},
                )
            except IPv6LabError as exc:
                result = TaskResult(
                    task_id=task.task_id,
                    status=TaskStatus.BLOCKED,
                    reason_code="ipv6_lab_unavailable",
                )
                store.event(
                    "controller",
                    "ipv6_lab_denied",
                    task_id=task.task_id,
                    payload={"message": str(exc)[:300]},
                )
            except CredentialUnavailable:
                result = TaskResult(
                    task_id=task.task_id,
                    status=TaskStatus.BLOCKED,
                    reason_code="credential_unavailable",
                )
            except (OSError, RuntimeError, ValueError) as exc:
                result = TaskResult(
                    task_id=task.task_id, status=TaskStatus.FAILED, reason_code="adapter_error"
                )
                store.event(
                    "adapter", "error", task_id=task.task_id, payload={"message": str(exc)[:300]}
                )
        return result

    def execute_pending(state, pending, results, by_id):
        request = state["request"]
        # La demo de acceso se serializa: al confirmar éxito no quedan pruebas en vuelo.
        concurrency = (
            2 if live and request.architecture == "multiagent" and not request.stop_on_verified_access
            else 1
        )
        running = {}
        control = {
            "policy": request.execution_policy,
            "stop_on_verified_access": request.stop_on_verified_access,
            "execution_concurrency": concurrency,
            "stopped": False,
            "reason": None,
            "trigger_task_id": None,
            "cancelled_tasks": 0,
        }

        def record_result(task, result):
            store.event(
                "orchestration",
                "task_terminal",
                task_id=result.task_id,
                payload={"status": result.status, "reason_code": result.reason_code},
            )
            results.append(result)
            by_id[result.task_id] = result
            if live and request.stop_on_verified_access and (result.authentication is not None or request.bank == "v2"):
                record = validate_results(store.root, [task], [result])[0]
                if access_is_verified(store.root, state["policy"], task, result, record):
                    control.update(
                        stopped=True, reason="verified_access", trigger_task_id=task.task_id
                    )
                    store.event(
                        "controller", "access_objective_reached", task_id=task.task_id,
                        payload={"independent_confirmation": True},
                    )

        def record(future):
            result = future.result()
            task = running.pop(future)
            record_result(task, result)

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            while pending or running:
                for future in list(running):
                    if future.done():
                        record(future)
                if control["stopped"]:
                    for task in pending:
                        record_result(task, TaskResult(
                            task_id=task.task_id, status=TaskStatus.CANCELLED,
                            reason_code="access_objective_reached",
                        ))
                    control["cancelled_tasks"] = len(pending)
                    pending.clear()
                    break
                active = list(running.values())
                ready = [
                    t
                    for t in pending
                    if all(d in by_id for d in t.dependencies)
                    and all(t.target.asset_id != a.target.asset_id for a in active)
                    and not (
                        t.case_id
                        and any(
                            a.case_id and a.target.interface == t.target.interface for a in active
                        )
                    )
                ]
                if ready and len(running) < concurrency:
                    # Favorece el despacho entre familias independientes para solapar ramas.
                    other_roles = [
                        t for t in ready if all(t.agent_type != a.agent_type for a in active)
                    ]
                    choices = other_roles or ready
                    selection = (
                        scheduler.select(choices, results, state["tasks"])
                        if scheduler is not None and time.monotonic() < deadline
                        else choices[0]
                    )
                    # Solo se despachan los objetos originales admitidos; nunca datos del LLM.
                    task = next((t for t in choices if t == selection), None)
                    if task is None:
                        store.event("controller", "task_selection_rejected")
                        task = choices[0]
                    pending.remove(task)
                    if concurrency == 1:
                        result = execute_one(state, task, by_id)
                        record_result(task, result)
                    else:
                        running[pool.submit(execute_one, state, task, by_id)] = task
                elif running:
                    completed, _ = wait(running, return_when=FIRST_COMPLETED)
                    for future in completed:
                        record(future)
                elif pending:
                    raise ValueError("plan con dependencias cíclicas o ausentes")
        return {"results": results, "execution_control": control}

    def publish(state: AuditState) -> dict:
        report = make_report(state["request"], state["tasks"], state["results"], live=live)
        report["execution_control"] = state["execution_control"]
        report["validation"] = validate_results(store.root, state["tasks"], state["results"])
        report["findings"] = confirm_findings(
            store.root, state["policy"], state["tasks"], state["results"], report["validation"]
        )
        report["llm"] = (
            scheduler.summary()
            if scheduler is not None
            else {
                "status": state.get("llm_status", "disabled"),
                "model": state.get("llm_model"),
                "total_tokens": 0 if not state["request"].token_budget else None,
                "usage_complete": not bool(state["request"].token_budget),
                "calls": [],
            }
        )
        report["architecture"] = state["request"].architecture
        report["metrics"] = {
            "elapsed_seconds": None,
            "tasks_planned": len(state["tasks"]),
            "tasks_completed": sum(
                r.status in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
                for r in state["results"]
            ),
            "verified_findings": len(report["findings"]),
        }
        report = prepare_report(report, state["request"])
        save_report(store.root, report)
        # Punto de medición: los informes JSON/HTML/PDF ya se persistieron.
        report["metrics"]["elapsed_seconds"] = round(time.monotonic() - started, 6)
        write_json(store.root / "report.json", report)
        write_json(store.root / "metrics.json", report["metrics"])
        store.event(
            "report", "report_saved", payload={"status": report["status"], **report["metrics"]}
        )
        return {"report": report}

    graph = StateGraph(AuditState)
    graph.add_node("plan", plan)
    graph.add_node("execute", execute)
    graph.add_node("publish", publish)
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "execute")
    graph.add_edge("execute", "publish")
    graph.add_edge("publish", END)
    return graph.compile()
