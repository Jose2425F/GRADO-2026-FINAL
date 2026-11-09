"""Orquestación ejecutable de los bancos de tesis mediante LangGraph.

El grafo admite tareas autorizadas, espera herramientas acotadas, valida evidencia,
revisa resultados y cierra la corrida. No ejecuta órdenes generadas por el LLM ni
recibe el ground truth del evaluador. No conserva cadenas de razonamiento.
"""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from importlib.metadata import version
from pathlib import Path
import sqlite3
import time
from typing import TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from auditoria.contracts import TaskResult, TaskStatus
from auditoria.lab import LabError


GRAPH_VERSION = "novaflow-langgraph-2"
NODES = ("preflight", "admission", "execution", "validation", "abort", "review", "close")
SUCCESS = {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
IPV6 = {"ipv6_ndp", "ipv6_fragmentation"}
FAILURE_STAGES = {"receiver_readiness", "ipv6_setup", "ipv6_probe", "ipv6_restore",
                  "evidence_persistence", "tool_execution", "authorization"}
FAILURE_CODES = {"execution_error", "tool_timeout", "tool_process_failed", "tool_transport_error",
    "evidence_write_failed", "tool_response_invalid", "scope_rejected", "invalid_tool_result",
    "ipv6_receiver_not_ready", "ipv6_setup_failed", "ipv6_probe_failed", "ipv6_restore_failed",
    "ipv6_capture_not_ready", "ipv6_capture_invalid", "ipv6_sender_failed",
    "docker_exec_failed", "docker_restart_failed", "docker_inspect_failed", "docker_operation_failed",
    "application_control_failed", "application_trace_unverified"}


class TaskExecutionError(Exception):
    """Etiqueta segura de etapa para adaptadores; no admite texto libre ni secretos."""
    def __init__(self, *, stage, reason_code):
        if stage not in FAILURE_STAGES or reason_code not in FAILURE_CODES:
            raise ValueError("invalid_execution_failure_label")
        self.stage = stage
        self.reason_code = reason_code
        super().__init__(reason_code)


def _safe_exception(exc):
    """Clasifica por tipo o mensaje LabError exacto; nunca registra str(exc)."""
    from subprocess import CalledProcessError, TimeoutExpired
    from urllib.error import HTTPError, URLError
    from auditoria.policy import PolicyError
    if isinstance(exc, TaskExecutionError):
        return {"exception_type":"TaskExecutionError", "stage":exc.stage, "reason_code":exc.reason_code}
    if isinstance(exc, LabError):
        known = {
            "receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto": ("receiver_readiness", "ipv6_receiver_not_ready"),
            "captura DAD NovaFlow no preparada": ("ipv6_probe", "ipv6_capture_not_ready"),
            "emisor DAD NovaFlow falló": ("ipv6_probe", "ipv6_sender_failed"),
            "captura NovaFlow fuera del perfil o sin prueba transmitida": ("ipv6_probe", "ipv6_capture_invalid"),
            "control positivo de recurso propio NovaFlow falló": ("tool_execution", "application_control_failed"),
            "control positivo de descarga NovaFlow falló": ("tool_execution", "application_control_failed"),
            "registro del servidor NovaFlow no corrobora las respuestas": ("tool_execution", "application_trace_unverified")}
        for operation, code in (("exec","docker_exec_failed"), ("restart","docker_restart_failed"), ("inspect","docker_inspect_failed")):
            known[f"Docker NovaFlow falló en {operation}; revise el estado del banco"] = ("ipv6_restore" if operation == "restart" else "tool_execution", code)
        # Sólo comparación contra literales propios; el mensaje no se serializa.
        stage, code = known.get(exc.args[0] if exc.args and isinstance(exc.args[0],str) else None,
                                ("tool_execution", "execution_error"))
        return {"exception_type":"LabError", "stage":stage, "reason_code":code}
    for kind, stage, code in ((TimeoutExpired,"tool_execution","tool_timeout"),
        (TimeoutError,"tool_execution","tool_timeout"), (CalledProcessError,"tool_execution","tool_process_failed"),
        (HTTPError,"tool_execution","tool_transport_error"), (URLError,"tool_execution","tool_transport_error"),
        (PolicyError,"authorization","scope_rejected"), (OSError,"tool_execution","tool_transport_error"),
        (ValueError,"tool_execution","tool_response_invalid")):
        if isinstance(exc,kind):
            return {"exception_type":kind.__name__, "stage":stage, "reason_code":code}
    return {"exception_type":"RuntimeError" if isinstance(exc,RuntimeError) else "Exception",
            "stage":"tool_execution", "reason_code":"execution_error"}


def engine_metadata():
    return {"engine": "langgraph", "version": version("langgraph"),
            "graph": GRAPH_VERSION, "graph_version": GRAPH_VERSION, "nodes": list(NODES),
            "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "checkpointing": "disabled", "decision_trace": "node_transitions_only"}


class AuditState(TypedDict):
    """Estado mínimo del control; sin prompts, secretos ni referencias del evaluador."""

    pending: list[str]
    running: list[str]
    completed: list[str]
    awaiting_validation: list[str]
    error: str | None
    transition_count: int
    closed: bool


class LangGraphOrchestrator:
    """Una instancia por corrida, con un ejecutor de herramientas de 1 o 2 plazas.

    Las herramientas pueden solaparse; admisión y validación son seriales y sólo
    el nodo de validación libera dependencias. El grafo determina cada siguiente
    fase y su condición de salida, en lugar de envolver un bucle externo.
    """

    def __init__(self, *, tasks, workers, deadline, store, prepare, execute,
                 terminal, close, authorize=None, clock=None, started=None,
                 reserve_seconds=240, repair_trace=None, task_limit=None, on_admission=None,
                 segments=None):
        if workers not in {1, 2}:
            raise ValueError("unsupported_execution_concurrency")
        self.tasks = list(tasks)
        self.by_id = {task.task_id: task for task in self.tasks}
        if len(self.by_id) != len(self.tasks):
            raise ValueError("duplicate_task_id")
        if task_limit is not None and (type(task_limit) is not int or not 0 <= task_limit <= len(self.tasks)):
            raise ValueError("invalid_task_limit")
        self.task_limit = len(self.tasks) if task_limit is None else task_limit
        self.admitted_task_ids = []
        self.admitted_at = {}
        self.attempt_ids = {}
        self.on_admission = on_admission or (lambda controller: None)
        self.segments = segments
        self.workers = workers
        self.deadline = deadline
        self.store = store
        self.prepare = prepare
        self.execute_task = execute
        self.record_terminal = terminal
        self.persist_close = close
        self.repair_trace = repair_trace
        self.authorize = authorize or (lambda task: None)
        self.clock = clock or time.monotonic
        self.started = self.clock() if started is None else started
        self.reserve_seconds = reserve_seconds
        self.scheduler = None
        self.completed = {}
        self.futures = {}
        self.finished = []
        self.transitions = []
        self.error = None
        self.execution_seconds = 0.0
        self.review_seconds = 0.0
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="langgraph-tool")
        self._closed = False
        self.compiled = self._build_graph()

    def _snapshot(self, state, **updates):
        return {**state, "running": [task.task_id for task in self.futures.values()],
                "completed": list(self.completed),
                "awaiting_validation": [task.task_id for task, _ in self.finished],
                "error": self.error, "transition_count": len(self.transitions), **updates}

    def _enter(self, name, state):
        self.transitions.append(name)
        self.store.event("orchestration", "graph_node_started", payload={
            "engine": "langgraph", "node": name, "sequence": len(self.transitions),
            "pending": len(state["pending"]), "running": len(self.futures),
            "completed": len(self.completed)})

    def _guard(self, name, action):
        def node(state):
            self._enter(name, state)
            try:
                result = action(state)
                outcome = "completed"
            except Exception as exc:
                self.error = ("lab_not_ready_or_kernel" if isinstance(exc, LabError) else
                              "llm_review_error" if name == "review" else "execution_or_configuration_error")
                self.store.event("orchestration", "graph_node_failed", payload={
                    "engine": "langgraph", "node": name, "reason_code": self.error,
                    "exception_type": type(exc).__name__})
                result = self._snapshot(state)
                outcome = "failed"
            try:
                self.store.event("orchestration", "graph_node_finished", payload={
                    "engine": "langgraph", "node": name, "status": outcome,
                    "pending": len(result["pending"]), "running": len(self.futures),
                    "completed": len(self.completed)})
            except sqlite3.Error:
                if name != "close" or not self._closed or self.repair_trace is None:
                    raise
                # El informe ya está escrito. Corregir su estado sin reabrir el
                # proveedor, repetir herramientas ni depender otra vez de SQLite.
                self.error = self.error or "graph_trace_error"
                self.repair_trace(self)
                result = self._snapshot(result, closed=True)
            return result
        return node

    def _build_graph(self):
        graph = StateGraph(AuditState)
        for name in NODES:
            graph.add_node(name, self._guard(name, getattr(self, "_" + name)))
        graph.add_edge(START, "preflight")
        graph.add_conditional_edges("preflight", lambda state: "abort" if state["error"] else "admission")
        graph.add_conditional_edges("admission", self._after_admission)
        graph.add_conditional_edges("execution", lambda state: "abort" if state["error"] else "validation")
        graph.add_conditional_edges("validation", lambda state: "abort" if state["error"] else "admission")
        graph.add_edge("abort", "review")
        graph.add_edge("review", "close")
        graph.add_edge("close", END)
        return graph.compile(name=GRAPH_VERSION)

    @staticmethod
    def _after_admission(state):
        if state["error"]:
            return "abort"
        return "execution" if state["running"] else "review"

    def _preflight(self, state):
        self.scheduler = self.prepare()
        return self._snapshot(state)

    def _terminal(self, task, result):
        if task.task_id in self.completed:
            return
        result = self.record_terminal(task, result)
        self.completed[task.task_id] = result

    def _propagate_failed_dependencies(self, pending):
        # Propagar fallos por toda la cadena, incluso si no queda ninguna tarea activa.
        changed = True
        while changed:
            changed = False
            for task_id in list(pending):
                task = self.by_id[task_id]
                if any(dep in self.completed and self.completed[dep].status not in SUCCESS for dep in task.dependencies):
                    pending.remove(task_id)
                    self._terminal(task, TaskResult(task_id=task_id, status=TaskStatus.BLOCKED,
                                                   reason_code="dependency_failed"))
                    changed = True

    def _admission(self, state):
        pending = list(state["pending"])
        unavailable = set()
        self._propagate_failed_dependencies(pending)
        while (pending and len(self.futures) < self.workers and len(self.admitted_task_ids) < self.task_limit
               and self.deadline - self.clock() >= self.reserve_seconds):
            active = list(self.futures.values())
            ready = [self.by_id[task_id] for task_id in pending
                     if task_id not in unavailable
                     if all(dep in self.completed and self.completed[dep].status in SUCCESS
                            for dep in self.by_id[task_id].dependencies)
                     and not any(item.target.asset_id == self.by_id[task_id].target.asset_id for item in active)
                     and not (self.by_id[task_id].agent_type in IPV6 and any(item.agent_type in IPV6 for item in active))]
            if not ready:
                break
            if self.scheduler:
                self.scheduler.detection_budget = {
                    'catalogue_size':len(self.tasks),'task_limit':self.task_limit,
                    'admitted_tasks':len(self.admitted_task_ids),
                    'remaining_slots':self.task_limit-len(self.admitted_task_ids)}
            choice = self.scheduler.select(ready, list(self.completed.values()), self.tasks) if self.scheduler else ready[0]
            if choice not in ready:
                raise ValueError("invalid_scheduler_choice")
            if self.deadline - self.clock() < self.reserve_seconds:
                break
            # Se vuelve a comprobar el alcance antes de cada despacho. El adaptador
            # conserva además su propia comprobación de objetivo/perfil al ejecutar.
            self.authorize(choice)
            if self.segments is not None:
                from .segmentos import SegmentBusy, SegmentQuarantined
                try:
                    self.segments.acquire(choice)
                except (SegmentBusy, SegmentQuarantined) as exc:
                    reason = "segment_busy" if isinstance(exc, SegmentBusy) else "segment_quarantined"
                    self.store.event("orchestration", "segment_admission_denied", task_id=choice.task_id,
                                     payload={"segment": choice.target.interface, "reason_code": reason})
                    unavailable.add(choice.task_id)
                    if reason == "segment_quarantined" or not self.futures:
                        pending.remove(choice.task_id)
                        self._terminal(choice, TaskResult(task_id=choice.task_id, status=TaskStatus.BLOCKED,
                                                          reason_code=reason))
                        self._propagate_failed_dependencies(pending)
                    continue
            pending.remove(choice.task_id)
            # La reserva precede al despacho: un fallo de herramienta o de
            # admisión no devuelve capacidad ni permite sobrepasar el tope.
            self.admitted_task_ids.append(choice.task_id)
            self.attempt_ids[choice.task_id] = uuid4().hex
            self.admitted_at[choice.task_id] = self.clock()
            self.on_admission(self)
            self.store.event("controller", "task_admitted", task_id=choice.task_id,
                             payload={"profile": choice.action_profile, "asset": choice.target.asset_id,
                                      "attempt_id": self.attempt_ids[choice.task_id],
                                      "engine": "langgraph", "executed_tasks": len(self.admitted_task_ids),
                                      "task_limit": self.task_limit, "catalogue_size": len(self.tasks)})
            self.futures[self._pool.submit(self.execute_task, choice)] = choice
        if len(self.admitted_task_ids) >= self.task_limit:
            for task_id in pending:
                self._terminal(self.by_id[task_id], TaskResult(task_id=task_id, status=TaskStatus.SKIPPED,
                    reason_code="task_budget_not_selected", observations={"selection_state": "not_selected"}))
            pending = []
        if not self.futures:
            for task_id in pending:
                self._terminal(self.by_id[task_id], TaskResult(task_id=task_id, status=TaskStatus.CANCELLED,
                               reason_code="runtime_or_dependency_budget_exhausted"))
            pending = []
        return self._snapshot(state, pending=pending)

    def _execution(self, state):
        finished, _ = wait(self.futures, return_when=FIRST_COMPLETED)
        for future in finished:
            task = self.futures.pop(future)
            try:
                result = future.result()
                if not isinstance(result, TaskResult) or result.task_id != task.task_id:
                    raise TaskExecutionError(stage="tool_execution",reason_code="invalid_tool_result")
            except Exception as exc:
                result = self._execution_failure(task,exc)
            finally:
                if self.segments is not None:
                    self.segments.release(task)
            result = result.model_copy(update={"attempt_id": self.attempt_ids[task.task_id]})
            self.finished.append((task, result))
        return self._snapshot(state)

    def _execution_failure(self, task, exc):
        primary = _safe_exception(exc)
        chain = []
        current = exc
        seen = set()
        while current is not None and id(current) not in seen and len(chain) < 5:
            seen.add(id(current));chain.append(_safe_exception(current))
            current = current.__cause__ if current.__cause__ is not None else current.__context__
        diagnostic = {"schema_version":1,"kind":"execution_failure", "task_id":task.task_id,
            "attempt_id":self.attempt_ids[task.task_id],
            "action_profile":task.action_profile, **primary, "exception_chain":chain,
            "admission_index":self.admitted_task_ids.index(task.task_id)+1,
            "task_limit":self.task_limit,"catalogue_size":len(self.tasks),
            "elapsed_since_admission_seconds":round(max(0,self.clock()-self.admitted_at[task.task_id]),6),
            "message_policy":"exception_messages_commands_and_responses_not_recorded"}
        reference = digest = None
        try:
            reference,digest = self.store.evidence(task.task_id+'_execution_failure','json',
                json.dumps(diagnostic,ensure_ascii=False,sort_keys=True).encode('utf-8'))
            (self.store.root/reference).chmod(0o600)
        except Exception:
            # La falta del diagnóstico nunca sustituye el fallo original ni
            # provoca un segundo intento de la herramienta.
            reference = digest = None
        observed = {"failure_stage":primary['stage'],"exception_type":primary['exception_type'],
                    "diagnostic_persisted":reference is not None}
        try:
            self.store.event('orchestration','tool_execution_failed',task_id=task.task_id,payload={
                'status':'failed', **primary,'diagnostic_ref':reference,'diagnostic_sha256':digest,
                'diagnostic_persisted':reference is not None,'engine':'langgraph'})
        except Exception:
            observed['diagnostic_event_saved'] = False
        return TaskResult(task_id=task.task_id,status=TaskStatus.FAILED,reason_code=primary['reason_code'],
                          diagnostic_ref=reference,diagnostic_sha256=digest,observations=observed)

    def _validation(self, state):
        while self.finished:
            task, result = self.finished[0]
            self._terminal(task, result)
            self.finished.pop(0)
        return self._snapshot(state)

    def _abort(self, state):
        # Nunca se cierra SQLite mientras una herramienta todavía escribe evidencia.
        # No se reintentan acciones ni se admiten trabajos nuevos después de un error.
        while self.futures:
            self._execution(state)
        self._validation(state)
        for task in self.tasks:
            if task.task_id not in self.completed:
                self._terminal(task, TaskResult(task_id=task.task_id, status=TaskStatus.BLOCKED,
                                               reason_code=self.error or "graph_execution_error"))
        return self._snapshot(state, pending=[])

    def _review(self, state):
        self.execution_seconds = round(self.clock() - self.started, 6)
        if self.scheduler and hasattr(self.scheduler, "review") and not self.error:
            self.scheduler.deadline = self.deadline
            self.scheduler.catalogue_tasks = self.tasks
            admitted = set(self.admitted_task_ids)
            executed_tasks = [task for task in self.tasks if task.task_id in admitted]
            executed_results = [result for task_id, result in self.completed.items() if task_id in admitted]
            started = self.clock()
            try:
                if executed_tasks:
                    self.scheduler.review(executed_tasks, executed_results, self.findings())
            finally:
                self.review_seconds = round(self.clock() - started, 6)
        return self._snapshot(state)

    def findings(self):
        # El adjudicador de la capa de integración publica sólo hallazgos corroborados.
        return self._get_findings() if hasattr(self, "_get_findings") else []

    def _close(self, state):
        self._pool.shutdown(wait=True)
        if self.segments is not None:
            for task in self.tasks:
                self.segments.release(task)
        self.persist_close(self)
        self._closed = True
        return self._snapshot(state, closed=True)

    def invoke(self, *, findings=None):
        self._get_findings = findings or (lambda: [])
        initial = AuditState(pending=list(self.by_id), running=[], completed=[],
                             awaiting_validation=[], error=None, transition_count=0, closed=False)
        try:
            # Tres pasos por tarea más fases terminales; el límite no depende del LLM.
            state = self.compiled.invoke(initial, {"recursion_limit": max(32, len(self.tasks) * 4 + 16)})
            if not state["closed"]:
                raise RuntimeError("graph_close_not_completed")
            return state
        except Exception:
            # Fallos del propio motor no deben dejar una corrida sin informe terminal.
            self.error = self.error or "graph_execution_error"
            if not self._closed:
                try:
                    self._abort(initial)
                finally:
                    self._pool.shutdown(wait=True)
                    if self.segments is not None:
                        for task in self.tasks:
                            self.segments.release(task)
                    self.persist_close(self)
                    self._closed = True
            raise
