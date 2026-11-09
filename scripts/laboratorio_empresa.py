#!/usr/bin/env python3
"""Conductor del laboratorio NovaFlow S.A.S.

Banco empresarial sintético que ejercita las cinco capacidades del auditor en un solo
alcance: servicios IPv4 (nmap), credenciales IPv4 (hydra), acceso de aplicación
dual-stack, NDP/SLAAC IPv6 y fragmentación IPv6. No modifica el diseño congelado v1/v2.

Uso (desde piloto_kali/prototipo con el venv activo, o con .venv/bin/python):

    python ../../scripts/laboratorio_empresa.py preparar
    python ../../scripts/laboratorio_empresa.py levantar
    python ../../scripts/laboratorio_empresa.py estado
    python ../../scripts/laboratorio_empresa.py auditar --arquitectura single
    python ../../scripts/laboratorio_empresa.py auditar --arquitectura multiagent
    python ../../scripts/laboratorio_empresa.py restaurar
    python ../../scripts/laboratorio_empresa.py bajar
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

PROTOTIPO = Path(__file__).resolve().parents[1] / "piloto_kali" / "prototipo"
sys.path.insert(0, str(PROTOTIPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auditoria import empresa_agent as agent  # noqa: E402
from auditoria import lab_empresa as lab  # noqa: E402
from auditoria.lab import LabError  # noqa: E402
from auditoria.policy import PolicyError  # noqa: E402
from auditoria.store import RunStore, write_json  # noqa: E402
from auditoria.modulo_reportes import prepare_report, report_scope, save_report  # noqa: E402

STATE = PROTOTIPO / ".lab-empresa"
RUNS = PROTOTIPO / "corridas" / "empresa"
CATEGORY_LABEL = {
    "ipv4_services": "Servicios IPv4 (descubrimiento nmap)",
    "ipv4_credentials": "Credenciales IPv4 (hydra + corroboración)",
    "application_access": "Acceso de aplicación dual-stack",
    "ipv6_ndp": "NDP / SLAAC IPv6",
    "ipv6_fragmentation": "Fragmentación IPv6",
}


def _print(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def cmd_preparar(_args):
    lab.prepare(STATE)
    print(f"[NovaFlow] Banco preparado en {STATE}")
    print("[NovaFlow] Secretos sintéticos en lab.env (0600). Ground truth y política escritos.")


def cmd_levantar(args):
    from tesis.restauracion_banco import build_images, prepare_images, restore_pinned
    lab.prepare(STATE)
    if getattr(args, 'construir', False):
        print("[NovaFlow] Construcción inicial explícita, anterior a la fijación de imágenes...")
        build_images(STATE)
    print("[NovaFlow] Fijando imágenes locales y recreando los tres segmentos sin construir ni descargar...")
    prepare_images(STATE)
    restore_pinned(STATE)
    print("[NovaFlow] Segmentos activos. Ejecute 'estado' para comprobar el banco.")


def cmd_bajar(_args):
    from tesis.restauracion_banco import PIN_NAME, down_pinned, kernel_ok
    kernel_ok()
    if (STATE / PIN_NAME).exists():
        down_pinned(STATE)
    else:
        lab.compose(STATE, "down")
    kernel_ok()
    print("[NovaFlow] Banco detenido y redes retiradas.")


def cmd_restaurar(_args):
    from tesis.restauracion_banco import restore_pinned
    print("[NovaFlow] Restaurando con las imágenes fijadas, sin construir ni descargar...")
    restore_pinned(STATE)
    print("[NovaFlow] Banco restaurado; identidad de imágenes comprobada.")


def cmd_estado(_args):
    report = lab.preflight(STATE)
    _print(f"Estado del banco {lab.COMPANY} ({report['bank']})")
    for segment, members in report["segments"].items():
        print(f"  {segment}: {', '.join(members)}")
    print(f"  SLAAC: {report['slaac']}")
    print(f"  Docker: {report['docker']}  Kernel: {report['kernel']}")
    print("  Laboratorio listo.")


def cmd_auditar(args):
    # La terminal y el panel comparten ejecución, evidencia y límites.
    from dualstack_panel import validate_options
    options=validate_options({'name':'Auditoría NovaFlow · terminal','authorization':args.autorizacion,
        'scope':'empresa','architecture':args.arquitectura,'ia':'openai' if args.openai else 'none','tokens':args.tokens})
    RUNS.mkdir(parents=True,exist_ok=True)
    import subprocess
    import tempfile
    from tesis.procesos import wait_bounded
    with tempfile.TemporaryDirectory(prefix='novaflow-terminal-') as temporary:
        job=Path(temporary)/'job.json'
        job.write_text(json.dumps({'options':options}),encoding='utf-8')
        job.chmod(0o600)
        process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--job',str(job),
                                  '--output',str(RUNS)],start_new_session=True)
        code,timed_out=wait_bounded(process,3780)
        if timed_out:
            print('[NovaFlow] Plazo agotado; evidencia parcial conservada. Restaure el banco antes de repetir.')
    print(f"Resultado en {RUNS}; también aparece en el historial del panel.")
    raise SystemExit(code)


def validation_for(root, task, result):
    # El adjudicador empresarial original intenta leer el XML de Nmap como JSON.
    # Adaptar únicamente este formato en la capa externa, sin alterar el banco.
    if task.action_profile == "nmap_tcp_services_v1":
        from auditoria.validation import validate_results
        from laboratorio_personal import parse_inventory
        record = validate_results(root, [task], [result])[0]
        if record["evidence_integrity"]["valid"] is True:
            try:
                parse_inventory((root / result.evidence_ref).read_bytes(), task)
            except (OSError, ValueError, ET.ParseError):
                record.update(state="indeterminate", reason="invalid_inventory_xml")
                record["evidence_integrity"]["valid"] = False
        return record, []
    return agent.validation_record(root, task, result), agent.adjudicate(root, task, result)


def _record_request_rejection(req, output, reason_code):
    """Conserva el rechazo antes del preflight, sin herramientas ni proveedor."""
    from tesis.orquestacion_langgraph import engine_metadata
    directory = output / (req.audit_id + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    store = RunStore(directory, req.audit_id)
    try:
        write_json(directory / "request.json", req.model_dump(mode="json"))
        write_json(directory / "plan.json", [])
        write_json(directory / "manifest.json", {"bank": "empresa", "mode": "live",
            "status": "rejected", "orchestration": engine_metadata()})
        write_json(directory / "report.json", {"audit_id": req.audit_id,
            "scope": report_scope(req),
            "architecture": req.architecture, "status": "rejected", "mode": "live",
            "purpose": "vulnerability_detection_instrumented_lab", "reason_code": reason_code,
            "error": reason_code, "tasks": [], "findings": [], "inventory": [], "validation": [],
            "metrics": {"elapsed_seconds": 0},
            "llm": {"status": "not_started" if req.llm_mode == "scheduler" else "disabled",
                    "known_tokens": 0, "usage_complete": True, "calls": [], "fallbacks": 0}})
        write_json(directory / "runtime.json", {"status": "finished",
            "ended_at": datetime.now(timezone.utc).isoformat(), "reason_code": reason_code})
        store.event("controller", "request_rejected", payload={"reason_code": reason_code,
                    "stage": "request", "engine": "langgraph"})
    finally:
        store.close()


def run_panel(options, output, *, study_context=None, bank_context=None):
    """Ejecuta el grafo LangGraph común a terminal, panel y cuatro variantes."""
    import hashlib
    import os
    from auditoria.dashboard import process_identity
    from auditoria.contracts import TaskResult, TaskStatus
    from tesis.orquestacion_langgraph import LangGraphOrchestrator, engine_metadata

    if study_context is not None:
        import re
        if (not isinstance(study_context, dict) or set(study_context) != {'study_id','phase','block','protocol_sha256'}
            or not isinstance(study_context.get('study_id'),str) or not re.fullmatch(r'estudio_novaflow_[0-9T]{15}',study_context['study_id'])
            or study_context.get('phase') not in {'acceptance','pilot','formal'}
            or type(study_context.get('block')) is not int or not 0 <= study_context['block'] <= 30
            or not isinstance(study_context.get('protocol_sha256'),str) or not re.fullmatch('[0-9a-f]{64}',study_context['protocol_sha256'])):
            raise ValueError('Contexto experimental interno inválido')
    engine=agent if bank_context is None else bank_context.agent
    bank=lab if bank_context is None else bank_context.lab
    bank_state=STATE if bank_context is None else bank_context.state
    validator=validation_for if bank_context is None else bank_context.validation
    req = engine.request(options["authorization"], architecture=options["architecture"],
                        tokens=options["tokens"], llm=options["ia"] == "openai")
    try:
        engine.authorize_empresa(req, engine.policy())
    except PolicyError as exc:
        _record_request_rejection(req, output, exc.reason_code)
        return 3
    from auditoria.secure_runtime import require_live_runtime, ProtectedRuntimeError
    try:
        require_live_runtime(bank='integrado' if bank_context is None else bank_context.id,
                             options=options, output=output)
    except ProtectedRuntimeError:
        _record_request_rejection(req, output, 'protected_runtime_required')
        print('protected_runtime_required: Inicia la auditoría desde el ejecutor protegido del operador.')
        return 3
    tasks = engine.build_plan(req)
    orchestration = engine_metadata()
    manual_context = options.get('manual_context')
    if manual_context is not None:
        import re
        if (not isinstance(manual_context, dict) or set(manual_context) != {'study_id', 'pair'}
            or not isinstance(manual_context.get('study_id'), str)
            or not re.fullmatch(r'langgraph_manual_[0-9]{8}', manual_context['study_id'])
            or type(manual_context.get('pair')) is not int or not 1 <= manual_context['pair'] <= 5):
            raise ValueError('Contexto de práctica LangGraph inválido')
        metadata = bank_context.metadata if bank_context is not None else {}
        manual_context = {**manual_context, 'scenario': metadata.get('id', metadata.get('scenario', 'integrado')),
                          'architecture': req.architecture}
    manual_protocol=None
    if manual_context is not None:
        from tesis.restauracion_manual import assert_run_claim
        manual_protocol=assert_run_claim(output,options,PROTOTIPO/'.manual-restorations.json')
    limited = req.llm_mode == 'scheduler'
    task_limit = len(tasks)*3//5 if limited else None
    detection_budget={'catalogue_size':len(tasks),'task_limit':task_limit,'applied':limited,
        'fraction':0.6 if limited else 1.0, 'executed_tasks':0, 'admitted_task_ids':[],
        'policy':'floor_60_percent_catalogue' if limited else 'full_catalogue_without_api'}
    directory = output / (req.audit_id + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    store = RunStore(directory, req.audit_id)
    started = time.monotonic(); deadline = started + req.max_runtime_seconds
    workers = 2 if req.architecture == "multiagent" else 1
    runtime = {"status": "running", "pid": os.getpid(), "identity": process_identity(os.getpid()),
               "started_at": datetime.now(timezone.utc).isoformat(), "orchestration_engine": "langgraph"}
    write_json(directory / "runtime.json", runtime)
    write_json(directory / "request.json", req.model_dump(mode="json"))
    write_json(directory / "plan.json", [t.model_dump(mode="json") for t in tasks])
    from auditoria.cli import source_fingerprint
    from tesis.entorno import dependency_receipt
    manifest = {"bank": "empresa", "mode": "live", "auditor_source_sha256": source_fingerprint(),
        "source_sha256":__import__("auditoria.cli",fromlist=["source_fingerprint"]).source_fingerprint(),
        "purpose": "vulnerability_detection_instrumented_lab", "expert_mode":bool(options.get("expert_mode")),
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'extensions_sha256':{name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in ['llm_especialistas.py','tesis/llm_contexto.py','tesis/candidatos.py','tesis/evaluacion.py','tesis/orquestacion_langgraph.py','tesis/restauracion_manual.py','tesis/protocolo_manual.py','tesis/evaluacion_manual.py','tesis/presupuesto_deteccion.py','tesis/protocolo_ipv6.py','tesis/restauracion_banco.py','tesis/segmentos.py','tesis/inventario.py','tesis/procesos.py','tesis/entorno.py']},
        'dependencies':dependency_receipt(PROTOTIPO),
        "orchestration": orchestration, "execution_concurrency": workers,
        **({"scenario":bank_context.metadata} if bank_context is not None else {}), "maximum_runtime_seconds": req.max_runtime_seconds,
        "protocol_isolation": "persistent_segment_lock_and_one_ipv6_task_at_a_time", "study": "preregistered_novaflow" if study_context else "manual_not_formal_cohort",
        **({'manual_context':manual_context} if manual_context else {}),
        'detection_budget':detection_budget,
        'catalogue_size':len(tasks),'task_limit':task_limit,'task_limit_fraction':detection_budget['fraction'],
        'task_limit_policy':detection_budget['policy'],'executed_tasks':0,
        **({'manual_protocol':manual_protocol} if manual_protocol else {}),
        **({'study_context':study_context} if study_context else {})}
    def save_manifest():
        temporary = directory/'.manifest.json.tmp'
        write_json(temporary,manifest)
        temporary.replace(directory/'manifest.json')
    save_manifest()
    store.event("controller", "request_accepted", payload={"mode": "live", "bank": "empresa", "engine": "langgraph"})
    results = []; findings = {}; validations = []
    terminal_results = {}
    complete = False
    authorization_rejection = None

    def authorize(task=None, *, stage):
        nonlocal authorization_rejection
        try:
            engine.authorize_empresa(req, engine.policy(), task=task)
        except PolicyError as exc:
            authorization_rejection = {"reason_code": exc.reason_code, "stage": stage,
                                       "task_id": task.task_id if task is not None else None}
            store.event("controller", "authorization_rejected",
                        task_id=authorization_rejection["task_id"], payload=authorization_rejection)
            raise

    def execute(task):
        # El ejecutor puede comenzar después de la admisión. Comprobar otra vez
        # evita emitir tráfico si la ventana o la solicitud cambiaron entretanto.
        authorize(task, stage="execution")
        from tesis.inventario import credential_block
        blocked = credential_block(task, controller.completed, bank)
        if blocked is not None:
            return blocked
        return engine.run_task(task, store)

    def terminal(task, result):
        # Si falla la bitácora después de agregar el resultado, el nodo de aborto
        # recupera exactamente este primer cierre; no duplica validaciones ni tareas.
        if task.task_id in terminal_results:
            return terminal_results[task.task_id]
        # Un fallo del validador se registra como fallo técnico, nunca como hallazgo.
        try:
            if result.status == TaskStatus.SKIPPED and result.reason_code == 'task_budget_not_selected':
                record, detected = {'task_id':task.task_id,'state':'not_selected',
                    'reason':'task_budget_not_selected','evidence_integrity':{'valid':None}}, []
            else:
                record, detected = validator(directory, task, result)
            if (not isinstance(record, dict) or not isinstance(detected, list)
                or any(not isinstance(finding, dict) or not all(isinstance(finding.get(key), str)
                       for key in ('asset_id', 'defect_key')) for finding in detected)):
                raise ValueError('invalid_validation_record')
        except Exception:
            record = {"task_id": task.task_id, "state": "indeterminate", "reason": "validation_error"}
            detected = []
            result = TaskResult(task_id=task.task_id, attempt_id=result.attempt_id,
                                status=TaskStatus.FAILED, reason_code="validation_error")
        if result.status in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS} and record.get("state") == "indeterminate":
            result = result.model_copy(update={"status": TaskStatus.FAILED, "reason_code": "evidence_not_validated"})
        results.append(result)
        validations.append(record)
        for finding in detected:
            findings[(finding['asset_id'], finding['defect_key'])] = finding
        terminal_results[task.task_id] = result
        store.event("orchestration", "task_terminal", task_id=task.task_id,
                    payload={"status": result.status.value, "reason_code": result.reason_code,
                             "attempt_id":result.attempt_id,"evidence_ref":result.evidence_ref,
                             "evidence_sha256":result.evidence_sha256,"diagnostic_ref":result.diagnostic_ref,
                             "findings": len(detected), "engine": "langgraph"})
        return result

    def prepare():
        authorize(stage="preflight")
        taint = int(Path('/proc/sys/kernel/tainted').read_text())
        if taint & ((1 << 7) | (1 << 14)): raise LabError("kernel_failure")
        bank.load_auditor_environment(bank_state)
        preflight = bank.preflight(bank_state)
        write_json(directory / "preflight.json", preflight)
        if bank_context is None and preflight.get('segments'):
            # El preflight acredita los nombres del catálogo. Una sola consulta
            # de lectura identifica sus imágenes, sin aceptar nombres del usuario.
            import re
            expected = {name for _, _, members in bank.NETWORKS.values() for name in members}
            segments = preflight['segments']
            if (not isinstance(segments, dict) or any(not isinstance(members, list) for members in segments.values())
                or {name for members in segments.values() for name in members} != expected):
                raise LabError('container_inventory_mismatch')
            raw = bank.docker('inspect', '--format', '{{.Name}} {{.Image}}', *sorted(expected))
            images = {}
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) != 2:
                    raise LabError('container_image_identity_invalid')
                name, image = parts[0].removeprefix('/'), parts[1]
                if name not in expected or name in images or not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
                    raise LabError('container_image_identity_invalid')
                images[name] = image
            if set(images) != expected:
                raise LabError('container_image_inventory_mismatch')
            source = preflight.get('source_sha256')
            if not isinstance(source, str) or not re.fullmatch(r'[a-f0-9]{64}', source):
                raise LabError('container_source_identity_invalid')
            manifest['scenario'] = {'id': 'integrado', 'version': bank.VERSION, 'source_sha256': source,
                                    'images': images,
                                    'fixture_sha256': hashlib.sha256((bank_state/'lab.env').read_bytes()).hexdigest()}
            save_manifest()
        store.event("orchestration", "plan_created", payload={"task_count": len(tasks), "engine": "langgraph"})
        # Sólo inicializa la API después del preflight; jamás incluye ground truth.
        if req.llm_mode == "scheduler":
            from auditoria.openai_provider import OpenAIScheduler, load_openai_config
            load_openai_config(PROTOTIPO / '.lab')
            SchedulerClass=OpenAIScheduler
            if options.get("expert_mode"):
                from llm_especialistas import ExpertScheduler
                SchedulerClass=ExpertScheduler
            scheduler = SchedulerClass(store, architecture=req.architecture,
                                        budget=req.token_budget, deadline=deadline-240)
            store.event('planner', 'llm_ready', payload={'model': scheduler.config.model})
            return scheduler
        return None

    def close(controller):
        from tesis.inventario import build_inventory
        nonlocal complete
        scheduler = controller.scheduler
        # El cierre del transporte y su resumen no pueden impedir la persistencia.
        if scheduler:
            try:
                scheduler.close()
            except Exception:
                controller.error = controller.error or 'provider_close_error'
        try:
            llm = scheduler.summary() if scheduler else {"status": "disabled" if req.llm_mode=='disabled' else 'not_started',
                "model": None, "known_tokens": 0, "usage_complete": True, "calls": [], "budget":req.token_budget, "fallbacks":0}
            if not isinstance(llm, dict) or not isinstance(llm.get('calls'), list):
                raise ValueError('invalid_provider_summary')
        except Exception:
            controller.error = controller.error or 'provider_summary_error'
            llm = {"status":"unavailable","model":None,"known_tokens":None,"usage_complete":False,
                   "calls":[],"budget":req.token_budget,"fallbacks":0}
        if scheduler and not llm.get('calls') and llm.get('status') != 'unavailable': llm['status']='not_needed'
        from tesis.llm_contexto import ROLE_MAP
        admitted = set(controller.admitted_task_ids)
        executed = [task for task in tasks if task.task_id in admitted]
        expected_roles = (['generalist'] if req.architecture == 'single' else
            list(dict.fromkeys(ROLE_MAP.get(str(task.agent_type),'network') for task in executed))) if executed and scheduler and options.get('expert_mode') else []
        llm['specialist_reviews_expected_roles'] = expected_roles
        complete = bool(tasks) and len(results)==len(tasks) and not controller.error and all(
            r.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS}
            or (r.status == TaskStatus.SKIPPED and r.reason_code == 'task_budget_not_selected') for r in results)
        detection_budget.update(executed_tasks=len(controller.admitted_task_ids),admitted_task_ids=list(controller.admitted_task_ids))
        manifest.update(detection_budget=dict(detection_budget),executed_tasks=len(controller.admitted_task_ids))
        try:
            save_manifest()
        except OSError:
            controller.error = controller.error or 'manifest_persistence_error'
            complete = False
        report = {"audit_id":req.audit_id,"operator":req.operator,"authorization_ref":req.authorization_ref,
                  "architecture":req.architecture,"status":"complete" if complete else "partial",
                  "mode":"live","purpose":"vulnerability_detection_instrumented_lab","findings":list(findings.values()),
                  "tasks":[r.model_dump(mode='json') for r in results],"validation":validations,
                  "inventory":build_inventory(tasks,results,targets=req.targets),"llm":llm,
                  "orchestration":{**orchestration,"transitions":list(controller.transitions),
                                   "transition_count":len(controller.transitions)},
                  **({'manual_context':manual_context} if manual_context else {}),
                  'detection_budget':dict(detection_budget),'catalogue_size':len(tasks),'task_limit':task_limit,
                  'task_limit_fraction':detection_budget['fraction'],'task_limit_policy':detection_budget['policy'],
                  'executed_tasks':len(controller.admitted_task_ids),
                  **({'manual_protocol':manual_protocol} if manual_protocol else {}),
                  "note":("Corrida registrada por el conductor experimental NovaFlow; fase en manifest.study_context. " if study_context else "Práctica NovaFlow separada de los estudios KPI. ")+"SLAAC y fragmentación son controles de conformidad.",
                  "metrics":{"elapsed_seconds":round(time.monotonic()-started,3),"execution_seconds":controller.execution_seconds,
                             "expert_review_seconds":controller.review_seconds},"error":controller.error}
        if authorization_rejection is not None:
            report.update(reason_code=authorization_rejection['reason_code'],
                          authorization_rejection=dict(authorization_rejection))
        try:
            from tesis.candidatos import for_results
            report['cve_candidates']=for_results(tasks,results)
        except Exception:
            report['cve_candidates']=[]
            report['candidate_note']='Candidatos no disponibles; hallazgos corroborados conservados.'
        try:
            report = prepare_report(report, req)
            save_report(directory, report)
            # El evaluador se ejecuta después del auditor y nunca alimenta el LLM.
            try:
                from tesis.evaluacion import score
                evaluation=score(directory,bank_state/'ground_truth.json',engine=engine,validator=validator,bank_id=bank.VERSION)
            except Exception:
                evaluation={'evidence_valid':False,'note':'Referencia o evidencia de evaluación no disponible.'}
            write_json(directory/'evaluation.json',evaluation)
            store.event('report','report_saved',payload={'status':report['status'],'findings':len(findings),'engine':'langgraph'})
            store.event('orchestration','graph_completed',payload={'engine':'langgraph','status':report['status'],
                        'transition_count':len(controller.transitions)})
        finally:
            runtime.update(status='finished',ended_at=datetime.now(timezone.utc).isoformat())
            write_json(directory/'runtime.json',runtime)

    def repair_trace(controller):
        nonlocal complete
        complete = False
        report = json.loads((directory/'report.json').read_text())
        report.update(status='partial', error=controller.error)
        report['orchestration']['trace_complete'] = False
        try:
            save_report(directory, report)
        finally:
            runtime.update(status='finished',ended_at=datetime.now(timezone.utc).isoformat())
            write_json(directory/'runtime.json',runtime)

    def record_admission(controller):
        detection_budget.update(executed_tasks=len(controller.admitted_task_ids),admitted_task_ids=list(controller.admitted_task_ids))
        manifest.update(detection_budget=dict(detection_budget),executed_tasks=len(controller.admitted_task_ids))
        save_manifest()

    try:
        from tesis.segmentos import DEFAULT_ROOT, SegmentGuard
        from auditoria.secure_runtime import require_protected_runtime
        segments = SegmentGuard(require_protected_runtime().get('segment_lock_root',DEFAULT_ROOT), store)
        controller = LangGraphOrchestrator(tasks=tasks, workers=workers, deadline=deadline, started=started,
            store=store, prepare=prepare, execute=execute, terminal=terminal,
            authorize=lambda task: authorize(task,stage="admission"), close=close, repair_trace=repair_trace,
            task_limit=task_limit,on_admission=record_admission,segments=segments)
        from tesis.protocolo_ipv6 import instrument_protocol
        with instrument_protocol(engine,bank,on_restored=segments.restored):
            controller.invoke(findings=lambda: list(findings.values()))
    finally:
        store.close()
    return 0 if complete else 3


def main():
    if "--job" in sys.argv:
        panel_parser = argparse.ArgumentParser()
        panel_parser.add_argument("--job", type=Path, required=True)
        panel_parser.add_argument("--output", type=Path, required=True)
        args = panel_parser.parse_args()
        from dualstack_panel import validate_options
        options = validate_options(json.loads(args.job.read_text())["options"])
        if options["scope"] != "empresa" or options["mode"] != "live":
            raise SystemExit("Perfil no admitido para NovaFlow.")
        raise SystemExit(run_panel(options, args.output))
    parser = argparse.ArgumentParser(description="Laboratorio NovaFlow S.A.S.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("preparar").set_defaults(func=cmd_preparar)
    levantar = sub.add_parser("levantar")
    levantar.add_argument('--construir', action='store_true',
        help='Construcción inicial explícita, permitida solo antes de fijar las imágenes del banco.')
    levantar.set_defaults(func=cmd_levantar)
    sub.add_parser("estado").set_defaults(func=cmd_estado)
    sub.add_parser("restaurar").set_defaults(func=cmd_restaurar)
    sub.add_parser("bajar").set_defaults(func=cmd_bajar)
    aud = sub.add_parser("auditar")
    aud.add_argument("--arquitectura", choices=["single", "multiagent"], default="multiagent")
    aud.add_argument('--openai', action='store_true', help='Usar el planificador configurado; consume API al ejecutar.')
    aud.add_argument('--tokens', type=int, default=6000)
    aud.add_argument('--autorizacion', default='LAB-PROPIO')
    aud.set_defaults(func=cmd_auditar)
    args = parser.parse_args()
    try:
        args.func(args)
    except LabError as exc:
        print(f"[NovaFlow][error] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
