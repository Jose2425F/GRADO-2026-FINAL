#!/usr/bin/env python3
"""Interfaz local unificada: configuración, ejecución, evidencia y arquitectura."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, select_autoescape
from auditoria.dashboard import collect_state, process_identity, read_json as dashboard_read_json
from panel_presentacion import ASSET_NAMES, STATUS_NAMES, executive_view, present_run, preliminary_findings
from panel_observabilidad import inspect_run
from laboratorio_personal import configuration as personal_configuration, resolve_targets, scope_hosts, signature as personal_signature

REPOSITORY = Path(__file__).resolve().parents[1]
PILOT = REPOSITORY / "piloto_kali" / "prototipo"
ASSETS = REPOSITORY / "scripts" / "dualstack_ui"
STUDY_PLAN = REPOSITORY / "docs" / "plan-evaluacion-empresa-2026-10-14" / "protocolo.json"
DIAGRAM = REPOSITORY / "docs" / "diagramas-finales" / "arquitectura-v2-historica.html"
CATALOG = [
    {"id": f"app_{letter}", "name": ASSET_NAMES[f"app_{letter}"], "kind": "Servicio empresarial simulado", "ipv4": f"192.168.59.{number}", "ipv6": f"fd57:2026:59::{number}", "tests": "Permisos de documentos, descargas y acceso administrativo"}
    for letter, number in zip("abcd", range(11, 15))
] + [
    {"id": f"receiver_{letter}", "name": ASSET_NAMES[f"receiver_{letter}"], "kind": "Puesto empresarial simulado", "ipv4": f"192.168.60.{number}", "ipv6": f"fd57:2026:60::{number}", "tests": "Configuración IPv6, vecinos y fragmentación"}
    for letter, number in zip("ab", (20, 21))
]


class ComparisonConfigurationError(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def study_summary():
    """Lectura de fuentes fijas públicas; ninguna llamada al proveedor."""
    def public_json(path):
        try:
            if path.is_symlink() or path.stat().st_size > 2_000_000:
                return {}
            value = json.loads(path.read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}
    plan = public_json(STUDY_PLAN)
    execution = public_json(STUDY_PLAN.parent / 'ejecucion.json')
    active = execution.get('status') in {'checking_api', 'running'} and execution.get('identity') is not None and process_identity(execution.get('pid')) == execution.get('identity')
    status = execution.get('status', plan.get('status', 'not_prepared'))
    if status in {'checking_api', 'running'} and not active:
        status = 'interrupted'
    previous = public_json(REPOSITORY / 'docs' / 'evaluacion-api-v2' / 'resumen.json')
    from auditoria.cli import source_fingerprint
    source_compatible=plan.get('auditor_source_sha256')==source_fingerprint()
    return {
        'status': status, 'active': active, 'scenario': 'Empresa Andina Demo',
        'runs_planned': plan.get('runs_planned', 30), 'pairs_planned': plan.get('blocks', 15),
        'budget_usd': plan.get('budget_usd', 20), 'api_calls_started': execution.get('api_calls_started') if execution else 0,
        'certification': plan.get('certification', {}), 'source_compatible':source_compatible,
        'readiness_note':'El protocolo conserva su versión.' if source_compatible else 'La versión actual difiere del protocolo preparado. Hay que fijar un protocolo compatible antes de iniciar el estudio; los resultados anteriores se conservan.',
        'previous': {'runs_started': previous.get('runs_started', 0), 'pairs_eligible': previous.get('pairs_eligible', 0),
                     'complete': previous.get('formal_cohort_complete', False),
                     'analysis': {k: {'mean': previous.get('analysis', {}).get(k, {}).get('mean'),
                                      'n': previous.get('analysis', {}).get(k, {}).get('n_defined', 0)}
                                  for k in ['TRTO_percent', 'IDE_percent', 'ETV_ratio']}}
    }


def validate_options(value: dict) -> dict:
    allowed = {"name", "authorization", "architecture", "ia", "tokens", "mode", "scope", "personal", "creds", "applications", "expert_mode", "scenario", "manual_context"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("La configuración contiene opciones no admitidas.")
    scope=value.get('scope','v2')
    if not isinstance(scope,str) or scope not in {'v2','personal','empresa'}:
        raise ValueError("Selecciona un alcance de auditoría admitido.")
    # Expande y limita conjuntamente CIDR/listas de ambas familias antes de crear un trabajo.
    personal=personal_configuration(value.get('personal')) if scope=='personal' else None
    if scope in {'v2','empresa'} and value.get('personal') is not None:
        raise ValueError('Las IP manuales pertenecen al modo Mi laboratorio.')
    name = value.get("name", "Auditoría de laboratorio")
    authorization = value.get("authorization", "")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80 or any(ord(c) < 32 for c in name):
        raise ValueError("Escribe un nombre de 1 a 80 caracteres.")
    if not isinstance(authorization, str) or not 1 <= len(authorization.strip()) <= 120 or any(ord(c) < 32 for c in authorization):
        raise ValueError("Indica la referencia de autorización de esta práctica.")
    architecture = value.get("architecture", "multiagent")
    ia = value.get("ia", "none")
    mode = value.get("mode", "live")
    if any(not isinstance(v,str) for v in [architecture,ia,mode]) or architecture not in {"single", "multiagent"} or ia not in {"none", "openai"} or mode not in {"live", "dry_run"}:
        raise ValueError("El modo de ejecución elegido no es válido.")
    if scope=='personal' and mode!='live':
        raise ValueError('Mi laboratorio realiza un inventario real; no admite la simulación de v2.')
    if scope=='empresa' and mode!='live':
        raise ValueError('La detección NovaFlow se ejecuta en vivo sobre el laboratorio instrumentado.')
    from tesis.presupuesto import DEFAULT_AUDIT_TOKENS, token_limit
    tokens = value.get("tokens", DEFAULT_AUDIT_TOKENS if scope=='empresa' else 6000)
    maximum=token_limit(scope)
    normalized_without_ai=scope in {'personal','empresa'} and ia=='none' and mode=='live' and tokens==0
    if isinstance(tokens, bool) or not isinstance(tokens, int) or not (256 <= tokens <= maximum or normalized_without_ai):
        raise ValueError(f"El límite de IA debe estar entre 256 y {maximum:,} tokens para este banco.".replace(',','.'))
    normalized={"name": name.strip(), "authorization": authorization.strip(), "architecture": architecture,
            "ia": ia, "mode": mode, "tokens": tokens if ia == "openai" and mode == "live" else 0, "scope": scope}
    if value.get('scenario') is not None:
        from tesis.laboratorios import profile
        if scope!='empresa' or not isinstance(value['scenario'],str):raise ValueError('Los escenarios pertenecen al banco empresarial.')
        profile(value['scenario']);normalized['scenario']=value['scenario']
    if personal is not None:normalized['personal']=personal
    creds=value.get('creds',False)
    if not isinstance(creds,bool):
        raise ValueError('La opción de credenciales no es válida.')
    if creds and scope!='personal':
        raise ValueError('La prueba de credenciales por defecto pertenece al modo Mi laboratorio por IP.')
    expert=value.get('expert_mode',False)
    if not isinstance(expert,bool):raise ValueError('La revisión especializada debe ser una opción válida.')
    if expert and (scope=='v2' or ia!='openai' or mode!='live'):
        raise ValueError('La revisión especializada requiere IA en el modo por IP o NovaFlow; v2 conserva su protocolo.')
    if expert:normalized['expert_mode']=True
    if value.get('manual_context') is not None:
        from tesis.evaluacion_manual import validate_context
        normalized['manual_context']=validate_context(value['manual_context'])
        if scope!='empresa' or ia!='openai' or mode!='live' or not expert:
            raise ValueError('La evaluación manual requiere un laboratorio NovaFlow, OpenAI y revisión especializada.')
    normalized['creds']=creds
    if value.get('applications'):
        if scope!='personal':raise ValueError('Las aplicaciones configurables pertenecen al alcance por IP.')
        from aplicaciones_personales import configure_applications
        normalized['applications']=configure_applications(value['applications'],personal)
    elif value.get('applications') not in (None,[]):
        raise ValueError('La lista de aplicaciones no es válida.')
    return normalized


def personal_options_signature(options):
    base=personal_signature(options['personal'])
    applications=options.get('applications',[])
    import hashlib
    return hashlib.sha256((base+json.dumps({'applications':applications,
        'authorization':options.get('authorization'),'creds':options.get('creds',False)},sort_keys=True)).encode()).hexdigest()


def command_for(options: dict, output: Path, pilot: Path = PILOT) -> list[str]:
    if options['scope']=='personal':
        return [str(pilot/'.venv/bin/python'),str(REPOSITORY/'scripts/laboratorio_personal.py'),
                '--job',str(output/'panel_job.json'),'--output',str(output)]
    if options['scope']=='empresa':
        return [str(pilot/'.venv/bin/python'),str(REPOSITORY/'scripts'/('laboratorio_suite.py' if options.get('scenario') else 'laboratorio_empresa.py')),
                '--job',str(output/'panel_job.json'),'--output',str(output)]
    command = [str(pilot / ".venv" / "bin" / "auditoria"), "demo-v2", "--autorizacion", options["authorization"],
               "--arquitectura", options["architecture"], "--salida", str(output)]
    if options["mode"] == "live":
        command.append("--ejecutar")
    if options["ia"] == "openai" and options["mode"] == "live":
        command += ["--openai", "--tokens", str(options["tokens"])]
    else:
        command.append("--sin-ia")
    return command


def friendly_error(output: str) -> str:
    # Nunca servir stdout completo: puede incluir rutas privadas o datos ajenos al contrato.
    reasons = {
        'prepare_local_images_before_restore': 'Primero completa Aceptar los cinco laboratorios sin IA para fijar las imágenes del banco.',
        'pinned_image_reference_changed': 'La configuración difiere de la referencia fijada. Revisa el banco antes de continuar; las imágenes no se reconstruyen al restaurar.',
        'restored_images_do_not_match_pinned_reference': 'La restauración no conserva las imágenes fijadas. No inicies una auditoría hasta resolver esta diferencia.',
        'owned_container_inventory_mismatch': 'Hay contenedores que comparten el proyecto Docker. Se detuvo la operación para proteger los demás laboratorios.',
        'foreign_or_invalid_container_identity': 'Un contenedor no corresponde al banco preparado. Se detuvo la operación para proteger los demás laboratorios.',
        "contenedores ajenos o faltantes": "El laboratorio está incompleto. Pulsa Restaurar laboratorio y vuelve a comprobarlo.",
        "imágenes v2 cambiaron": "Las imágenes no coinciden con las guardadas. Revisa el banco antes de iniciar otra auditoría.",
        "sin SLAAC": "Un receptor IPv6 no quedó listo. Restaura el laboratorio y vuelve a comprobarlo.",
        "Docker v2 falló": "Docker no pudo completar la operación. Comprueba que el servicio y el laboratorio estén disponibles.",
        "semilla": "La configuración del laboratorio no coincide con la preparada.",
        "lab.env": "La configuración privada del laboratorio no está disponible o sus permisos no son válidos.",
        "OPENAI": "La configuración privada de OpenAI no está disponible o no es válida. Puedes ejecutar sin IA.",
        "openai.json": "Revisa los permisos de la configuración privada de OpenAI o ejecuta sin IA.",
        "otra operación": "Hay otra operación del laboratorio en curso. Espera a que termine.",
        "bloqueo": "El laboratorio está ocupado por otra operación.",
    }
    return next((message for marker, message in reasons.items() if marker in output), "La operación no pudo completarse. Revisa el estado del laboratorio y el informe disponible.")


def kernel_warning():
    try:
        taint = int(Path('/proc/sys/kernel/tainted').read_text())
    except (OSError, ValueError):
        return None
    if taint & ((1 << 7) | (1 << 14)):
        return 'La auditoría real está bloqueada: Kali registró un fallo del kernel. Reinicia Kali y vuelve a comprobar el laboratorio. Restaurar contenedores no elimina este indicador.'
    return None


# Contenedores realmente activos por laboratorio, según Docker. El estado en memoria del
# panel queda viejo si un laboratorio se enciende o apaga por consola, desde otra sesión
# o al reiniciar la VM; la consola lo usa para mostrar Encendido/Apagado con la verdad.
_lab_runtime_cache = {'at': 0.0, 'value': {'available': False}}
_lab_runtime_lock = threading.Lock()


def label_interfaces(items):
    """Añade a cada interfaz el laboratorio y la zona que simula (br-nova-* y br-nf<n>-*)."""
    import re
    try:
        from tesis.laboratorios import catalog, profile
        labs = {'nova': ('integrado', 'NovaFlow · banco integrado', 0)}
        for row in catalog():
            index = profile(row['id'])['index']
            labs[f'nf{index}'] = (row['id'], row['name'], index)
    except (ImportError, KeyError, ValueError, TypeError):
        labs = {'nova': ('integrado', 'NovaFlow · banco integrado', 0)}
    zones = {'dmz': ('DMZ', 0), 'corp': ('Red corporativa', 1), 'dc': ('Datacenter', 2)}
    for item in items:
        match = re.fullmatch(r'br-(nova|nf\d+)-(dmz|corp|dc)', item.get('name', ''))
        if match and match.group(1) in labs:
            lab_id, lab_name, order = labs[match.group(1)]
            zone, zone_order = zones[match.group(2)]
            item.update(lab_id=lab_id, lab=lab_name, zone=zone, order=[order, zone_order])
        else:
            item.update(lab_id=None, lab=None, zone=None, order=[99, 0])
    return sorted(items, key=lambda item: (item['order'], item['name']))


def lab_runtime():
    with _lab_runtime_lock:
        if _lab_runtime_cache['at'] and time.monotonic() - _lab_runtime_cache['at'] < 4:
            return dict(_lab_runtime_cache['value'])
        try:
            names = subprocess.run(['docker', 'ps', '--format', '{{.Names}}'], capture_output=True, text=True,
                                   timeout=5, check=True).stdout.split()
            from tesis.laboratorios import catalog, profile
            value = {'available': True, 'integrado': sum(name.startswith('nova-') for name in names)}
            for row in catalog():
                prefix = f"nf{profile(row['id'])['index']}-"
                value[row['id']] = sum(name.startswith(prefix) for name in names)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
            value = {'available': False}
        _lab_runtime_cache.update(at=time.monotonic(), value=value)
        return dict(value)


class Operations:
    def __init__(self, root: Path, pilot: Path = PILOT, popen=subprocess.Popen):
        self.root, self.pilot, self.popen = root, pilot, popen
        self.lock = threading.RLock()
        self.jobs = []
        self.reserved = False
        self.lab = {"status": "unknown", "message": "Comprueba el laboratorio antes de iniciar.", "checked_at": None}
        self.personal_lab={"status":"unknown","message":"Indica las IP y comprueba sus rutas antes de iniciar.","signature":None}
        self.empresa_lab={"status":"unknown","message":"Comprueba NovaFlow antes de iniciar sus 32 tareas.","checked_at":None}
        self.scenario_labs={}
        self.process = None
        from tesis.restauracion_manual import RestorationBook
        self.restorations=RestorationBook(self.root.parent/'.manual-restorations.json')

    def snapshot(self):
        with self.lock:
            for job in self.jobs:
                if job["action"] == "audit" and not job["run_key"] and job["status"] in {"queued", "running", "stopping"}:
                    candidates = list((self.root / "panel" / job["id"]).glob("*/request.json"))
                    if candidates:
                        job["run_key"] = candidates[0].parent.relative_to(self.root).as_posix()
            lab = dict(self.lab)
            personal_lab=dict(self.personal_lab)
            empresa_lab=dict(self.empresa_lab)
            empresa_lab.update(self.restorations.public('integrado'))
            warning = kernel_warning()
            from tesis.estudio import public_status
            external = public_status()
            from laboratorio_suite import activity
            from tesis.laboratorios import catalog
            from tesis.laboratorios_estado import acceptance_status
            from aceptar_laboratorios import public_status as acceptance_five_status
            five_acceptance=acceptance_five_status()
            suite=activity()
            if warning:
                lab.update(status="error", message=warning)
                personal_lab.update(status='error',message=warning)
                empresa_lab.update(status='error',message=warning)
            return {"jobs": [dict(job) for job in self.jobs[-20:]], "lab": lab, 'personal_lab':personal_lab,
                    'empresa_lab':empresa_lab,
                    'scenario_labs':{row['id']:{**self.scenario_labs.get(row['id'],{'status':'unknown'}),**self.restorations.public(row['id'])} for row in catalog()},'scenario_catalog':catalog(),'lab_runtime':lab_runtime(),'suite_progress':suite,'suite_acceptance':acceptance_status(),
                    'execution_guard': {'blocked': bool(warning), 'reason': 'kernel_fault' if warning else None,
                                        'message': warning or ''},
                    'study_progress': external, 'acceptance_five': five_acceptance,
                    "busy": self.reserved or external.get('active',False) or suite.get('active',False) or five_acceptance.get('active',False) or any(job["status"] in {"queued", "running", "stopping"} for job in self.jobs)}

    @contextmanager
    def reserve(self):
        """Reserve synchronous network work without blocking state requests."""
        with self.lock:
            if self.snapshot()['busy'] or study_summary()['active'] or any(r['status']=='running' for r in collect_state(self.root)['runs']):
                raise ValueError('Hay una auditoría u operación activa. Espera a que termine.')
            self.reserved = True
        try:
            yield
        finally:
            with self.lock:
                self.reserved = False

    def start(self, action: str, options: dict | None = None):
        with self.lock:
            if self.snapshot()["busy"] or study_summary()['active'] or any(r["status"] == "running" for r in collect_state(self.root)["runs"]):
                raise ValueError("Hay una auditoría u operación activa. Espera a que termine.")
            if action == "audit":
                options = validate_options(options)
                from tesis.evaluacion_manual import ensure_empty_position
                ensure_empty_position(self.root,options)
                position=None
                if options.get('manual_context'):
                    from tesis.evaluacion_manual import validate_registered_start,summary as manual_summary
                    # Se leen todas las reservas; no sólo las últimas cien corridas.
                    position=validate_registered_start(options,[row for row in manual_summary([],self.root,lambda p,d:dashboard_read_json(p,self.root,d))['records'] if row['recorded']])
                    from aceptar_laboratorios import public_status as acceptance_five_status
                    if acceptance_five_status().get('accepted') is not True:
                        raise ValueError('Completa la aceptación sin IA de los cinco laboratorios en Laboratorio antes de registrar las corridas.')
                if options['scope']=='personal' and (self.personal_lab['status']!='ready' or self.personal_lab['signature']!=personal_options_signature(options)):
                    raise ValueError('Comprueba las IP y la interfaz actuales antes de iniciar Mi laboratorio.')
                if options['scope']=='v2' and options["mode"] == "live" and self.lab["status"] != "ready":
                    raise ValueError("Comprueba el laboratorio antes de iniciar la auditoría real.")
                if options['scope']=='empresa' and (self.scenario_labs.get(options['scenario'],{}).get('status') if options.get('scenario') else self.empresa_lab['status'])!='ready':
                    raise ValueError('Comprueba el banco NovaFlow antes de iniciar.')
                if options["mode"] == "live":
                    taint = int(Path("/proc/sys/kernel/tainted").read_text())
                    if taint & ((1 << 7) | (1 << 14)):
                        raise ValueError("El kernel conserva indicadores de fallo. Recupera la VM antes de ejecutar pruebas de red.")
            elif action=='personal_check':
                options=validate_options(options)
                if options['scope']!='personal':raise ValueError('Selecciona Mi laboratorio.')
            elif action in {'suite_check','suite_restore','suite_down'}:
                from tesis.laboratorios import profile
                if not isinstance(options,dict) or set(options)!={'scenario'} or not isinstance(options['scenario'],str):raise ValueError('Selecciona un escenario.')
                profile(options['scenario'])
            elif action=='acceptance_all':
                if options not in ({},None):raise ValueError('La aceptación sin IA no recibe configuración de auditoría.')
                options={}
            elif action not in {"check", "restore", "empresa_check", "empresa_restore", "empresa_down"}:
                raise ValueError("Operación no admitida.")
            if action in {'audit','personal_check'} and options.get('scope')=='personal':
                from autorizacion_personal import AuthorizationGuard
                AuthorizationGuard(options).verify()
            if action in {'check','restore','empresa_check','empresa_restore','empresa_down','suite_check','suite_restore','suite_down','acceptance_all'} and kernel_warning():
                raise ValueError(kernel_warning())
            operation_name = 'Comprobación' if action in {'check', 'personal_check', 'empresa_check','suite_check'} else 'Restauración'
            if action=='acceptance_all':operation_name='Aceptación de cinco laboratorios sin IA'
            if action in {'empresa_down','suite_down'}:operation_name='Cerrar laboratorio'
            job = {"id": uuid4().hex[:12], "action": action, "name": (options or {}).get("name", operation_name),
                   "status": "queued", "created_at": now(), "ended_at": None, "run_key": None,
                   "message": "Preparando la operación.", "options": options}
            if action=='audit' and options.get('manual_context'):
                from tesis.protocolo_manual import protocol
                receipt=self.restorations.claim(options.get('scenario') or 'integrado',job['id'])
                job['manual_protocol']={'protocol_sha256':protocol()['protocol_sha256'],
                    'sequence':position['sequence'],'restoration':receipt}
            elif action=='audit' and options['scope']=='empresa':
                self.restorations.invalidate(options.get('scenario') or 'integrado')
            elif action in {'empresa_restore','empresa_down','suite_restore','suite_down'}:
                self.restorations.invalidate(options['scenario'] if action.startswith('suite') else 'integrado')
            elif action=='acceptance_all':
                for scenario in ('integrado','sucursal','comercial','mixto','reforzado'):
                    self.restorations.invalidate(scenario)
            self.jobs.append(job)
            if action=='personal_check':
                self.personal_lab.update(status='checking',message='Comprobando rutas locales y disponibilidad de Nmap…')
            elif action in {'suite_check','suite_restore','suite_down'}:
                self.scenario_labs[options['scenario']]={'status':'checking' if action=='suite_check' else 'restoring','message':'Preparando el escenario seleccionado.'}
            elif action in {'empresa_check','empresa_restore','empresa_down'}:
                self.empresa_lab.update(status='checking' if action=='empresa_check' else 'restoring',message='Comprobando NovaFlow…' if action=='empresa_check' else 'Restaurando NovaFlow…')
            elif action not in {"audit",'acceptance_all'}:
                self.lab.update(status="checking" if action == "check" else "restoring", message="Comprobando el banco…" if action == "check" else "Restaurando los contenedores con sus imágenes guardadas…")
            thread = threading.Thread(target=self._run, args=(job,), daemon=True)
            thread.start()
            return dict(job)

    def _run(self, job):
        output = self.root / "panel" / job["id"]
        try:
            if job['action']=='personal_check':
                try:
                    from autorizacion_personal import AuthorizationGuard
                    authorization=AuthorizationGuard(job['options'])
                    targets=resolve_targets(job['options']['personal'],deadline=time.monotonic()+240)
                    authorization.check_targets(targets)
                    from aplicaciones_personales import load_session
                    for app in job['options'].get('applications',[]):load_session(app['session'])
                    message=f'Autorización vigente, rutas directas y Nmap disponibles para {len(targets)} objetivos. El alcance se verificará de nuevo antes de cada despacho.'
                    status='ready'
                except ValueError as exc:
                    message=str(exc);status='error'
                with self.lock:
                    self.personal_lab.update(status=status,message=message,signature=personal_options_signature(job['options']) if status=='ready' else None)
                    job.update(status='complete' if status=='ready' else 'failed',message=message,ended_at=now())
                return
            if job["action"] == "audit":
                output.mkdir(parents=True, exist_ok=False)
                (output / "panel_job.json").write_text(json.dumps({"name": job["name"], "created_at": job["created_at"], "options": job["options"],
                    **({'manual_protocol':job['manual_protocol']} if job.get('manual_protocol') else {})}, ensure_ascii=False), encoding="utf-8")
                from auditoria.store import write_json
                write_json(output/'panel_status.json',{'status':'queued','pid':os.getpid(),'identity':process_identity(os.getpid())})
                command = command_for(job["options"], output, self.pilot)
            elif job['action'] in {'suite_check','suite_restore','suite_down'}:
                command=[str(self.pilot/'.venv/bin/python'),str(REPOSITORY/'scripts/laboratorio_suite.py'),
                    'estado' if job['action']=='suite_check' else 'bajar' if job['action']=='suite_down' else 'levantar','--lab',job['options']['scenario']]
            elif job['action'] in {'empresa_check','empresa_restore','empresa_down'}:
                command=[str(self.pilot/'.venv/bin/python'),str(REPOSITORY/'scripts/laboratorio_empresa.py'),
                         'estado' if job['action']=='empresa_check' else 'bajar' if job['action']=='empresa_down' else 'restaurar']
            elif job['action']=='acceptance_all':
                command=[str(self.pilot/'.venv/bin/python'),str(REPOSITORY/'scripts/aceptar_laboratorios.py'),'aceptar']
            else:
                command = [str(self.pilot / ".venv" / "bin" / "auditoria"), "laboratorio-v2", "estado" if job["action"] == "check" else "restaurar"]
            # Un archivo temporal evita bloquear por stdout y permite que el hijo
            # termine aunque se cierre el panel. Nunca se sirve este contenido.
            with tempfile.TemporaryFile() as log:
                with self.lock:
                    process = self.popen(command, cwd=self.pilot, stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
                    self.process = process
                    job.update(status="running", message="Auditoría iniciada." if job["action"] == "audit" else 'Aceptación sin IA en curso: se comprueban cinco laboratorios con el catálogo completo.' if job['action']=='acceptance_all' else self.lab["message"])
                    if job['action']=='audit':
                        write_json(output/'panel_status.json',{'status':'running','pid':process.pid,'identity':process_identity(process.pid)})
                from tesis.procesos import wait_bounded
                maximum = 18600 if job['action']=='acceptance_all' else 3780 if job['action']=='audit' else 900
                code, timed_out = wait_bounded(process, maximum)
                log.seek(max(0, log.seek(0, os.SEEK_END) - 16000))
                tail = log.read().decode("utf-8", errors="replace")
            with self.lock:
                cancelled = job["status"] == "stopping"
                job.update(status="interrupted" if cancelled else "complete" if code == 0 else "partial" if code == 3 and job["action"] == "audit" else "failed", ended_at=now())
                if timed_out:
                    job.update(reason_code='controller_timeout',maximum_runtime_seconds=maximum)
                if job["action"] == "audit":
                    candidates = list(output.glob("*/request.json"))
                    if candidates:
                        job["run_key"] = candidates[0].parent.relative_to(self.root).as_posix()
                    job["message"] = "La auditoría superó el plazo y se detuvo. Se conserva la evidencia parcial; restaura el banco antes de repetir." if timed_out else "La auditoría se detuvo. Revisa la cobertura y restaura el banco antes de otra prueba." if cancelled else "El resultado está disponible." if code in {0, 3} and job["run_key"] else friendly_error(tail)
                    if cancelled or code not in {0, 3}:
                        self.lab.update(status="unknown", message="Vuelve a comprobar o restaurar el laboratorio.")
                    if job['options']['scope']=='empresa':
                        if job['options'].get('scenario'):self.scenario_labs[job['options']['scenario']]={'status':'unknown','message':'Comprueba o restaura este escenario antes de otra corrida.'}
                        else:self.empresa_lab.update(status='unknown',message='Comprueba o restaura NovaFlow antes de la siguiente corrida.')
                elif job['action']=='acceptance_all':
                    self.empresa_lab.update(status='unknown',message='Restaura y comprueba el laboratorio antes de registrar una corrida.')
                    self.scenario_labs.clear()
                    job['message']='Aceptación sin IA completada. Verifica los cinco laboratorios en Aceptación funcional.' if code==0 else 'La aceptación se detuvo. Revisa el laboratorio y la fase indicados antes de repetirla.'
                elif job['action'] in {'suite_check','suite_restore','suite_down'}:
                    if code==0 and job['action']=='suite_restore':self.restorations.restored(job['options']['scenario'],job['id'])
                    if code==0 and job['action']=='suite_check':self.restorations.checked(job['options']['scenario'])
                    self.scenario_labs[job['options']['scenario']]={'status':'unknown' if code==0 and job['action']=='suite_down' else 'ready' if code==0 else 'error','message':'Escenario cerrado.' if code==0 and job['action']=='suite_down' else 'Escenario listo; se comprobará de nuevo al auditar.' if code==0 else friendly_error(tail)}
                    job['message']=self.scenario_labs[job['options']['scenario']]['message']
                elif job['action'] in {'empresa_check','empresa_restore','empresa_down'}:
                    if code==0 and job['action']=='empresa_restore':self.restorations.restored('integrado',job['id'])
                    if code==0 and job['action']=='empresa_check':self.restorations.checked('integrado')
                    # Restaurar no sustituye la comprobación completa posterior.
                    self.empresa_lab.update(status='ready' if code==0 and job['action']=='empresa_check' else 'unknown' if code==0 else 'error',
                        message='Escenario original cerrado.' if code==0 and job['action']=='empresa_down' else 'NovaFlow listo: 10 objetivos auditables, 12 contenedores y 32 tareas.' if code==0 and job['action']=='empresa_check' else 'NovaFlow restaurado. Pulsa Comprobar antes de iniciar.' if code==0 else friendly_error(tail),checked_at=now())
                    job['message']=self.empresa_lab['message']
                else:
                    self.lab.update(status="ready" if code == 0 else "error", message="Laboratorio listo: 6 objetivos y 22 tareas de auditoría." if code == 0 else friendly_error(tail), checked_at=now())
                    job["message"] = self.lab["message"]
                self.process = None
        except (OSError, ValueError, subprocess.SubprocessError):
            with self.lock:
                job.update(status="failed", ended_at=now(), message="No se pudo iniciar el comando. Revisa el entorno virtual y el laboratorio.")
                self.process = None
                if job["action"] != "audit":
                    target=self.empresa_lab if job['action'].startswith('empresa_') else self.lab
                    target.update(status="error", message=job["message"], checked_at=now())
        finally:
            if job['action']=='audit' and (output/'panel_job.json').is_file():
                from auditoria.store import write_json
                write_json(output/'panel_status.json',{'status':job['status'],'ended_at':job.get('ended_at'),
                    'run_key':job.get('run_key'),'reason_code':job.get('reason_code'),
                    'maximum_runtime_seconds':job.get('maximum_runtime_seconds')})

    def stop(self):
        with self.lock:
            job = next((j for j in reversed(self.jobs) if j["action"] == "audit" and j["status"] == "running"), None)
            if not job or self.process is None:
                raise ValueError("No hay una auditoría iniciada desde este panel para detener.")
            os.killpg(self.process.pid, signal.SIGTERM)
            job.update(status="stopping", message="Deteniendo la auditoría. Su cobertura quedará incompleta.")
            return dict(job)


class Panel:
    def __init__(self, root: Path, *, operations=None, diagram: Path = DIAGRAM):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.operations = operations or Operations(self.root)
        self.diagram = diagram
        self.csrf = secrets.token_urlsafe(32)
        self.archive_panels = {}
        self.lock = threading.RLock()
        self.cached_at = 0
        self.cached = None
        self.environment = Environment(loader=FileSystemLoader(ASSETS), autoescape=select_autoescape(["html"]), auto_reload=True)
        self.environment.globals['asset_url'] = self.asset_url

    def asset_url(self, name: str):
        # Compute on each page render: edits are detected without a build, restart
        # or reliance on timestamps (which deployment tools may preserve).
        digest = hashlib.sha256((ASSETS / name).read_bytes()).hexdigest()[:16]
        return f'/{name}?v={digest}'

    def safe_file(self, path: Path, limit=8_000_000):
        try:
            relative = path.relative_to(self.root)
            current = self.root
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    return None
            if not path.resolve().is_relative_to(self.root) or not path.is_file() or path.stat().st_size > limit:
                return None
            return path.read_bytes()
        except (OSError, ValueError):
            return None

    def json_file(self, path: Path, default):
        data = self.safe_file(path)
        try:
            return json.loads(data) if data is not None else default
        except (ValueError, TypeError):
            return default

    def state(self):
        with self.lock:
            if self.cached is None or time.monotonic() - self.cached_at >= 1:
                state = collect_state(self.root)
                # Certificaciones y pruebas del proveedor no son auditorías de usuario.
                runs = [r for r in state["runs"] if r.get("tasks") or self.json_file(self.root/r['key']/'request.json',{}).get('bank') in {'personal','empresa'}]
                for run in runs:
                    directory = self.root / run["key"]
                    metadata = self.json_file(directory.parent / "panel_job.json", {})
                    request = self.json_file(directory / "request.json", {})
                    manifest = self.json_file(directory / "manifest.json", {})
                    from tesis.evaluacion_manual import public_orchestration, public_context
                    run['orchestration']=public_orchestration(manifest.get('orchestration'))
                    run['manual_context']=public_context(manifest.get('manual_context'))
                    run['scenario']=manifest.get('scenario',{}).get('id','integrado') if isinstance(manifest.get('scenario',{}),dict) else 'integrado'
                    run["name"] = metadata.get("name") or ("Inventario de mi laboratorio" if request.get('bank')=='personal' else "Detección NovaFlow S.A.S." if request.get('bank')=='empresa' else "Auditoría dual-stack v2" if request.get("bank") == "v2" else "Auditoría de laboratorio")
                    run["status_name"] = STATUS_NAMES.get(run["status"], run["status"])
                    run["bank"] = request.get("bank", "v1")
                    if request.get("token_budget", 0) and run["status"] in {"running", "interrupted"}:
                        # Un proceso interrumpido puede dejar una llamada enviada
                        # sin evento de cierre. Los tokens conocidos son un mínimo.
                        run["llm"]["usage_complete"] = False
                    if run['llm']['calls'] and request.get('llm_mode') == 'scheduler' and run['llm']['status'] == 'disabled':
                        # Un intento histórico puede carecer de llm_ready o cierre.
                        # Las decisiones registradas impiden presentarlo como sin IA.
                        run['llm']['status'] = 'interrupted' if run['status'] == 'interrupted' else 'unknown'
                    try:
                        run["started_display"] = datetime.fromisoformat(run["started_at"]).astimezone(ZoneInfo("America/New_York")).strftime("%d/%m/%Y · %H:%M")
                    except (ValueError, TypeError):
                        run["started_display"] = "Fecha no disponible"
                self.cached = {"runs": runs, "updated_at": state["updated_at"], "experiments": state["experiments"]}
                self.cached_at = time.monotonic()
            operations = self.operations.snapshot()
            credentials = PILOT / ".lab" / "openai.json"
            try:
                configured = (not credentials.is_symlink() and credentials.is_file() and not credentials.stat().st_mode & 0o077)
            except OSError:
                configured = False
            configured = configured or bool(os.environ.get("OPENAI_API_KEY", "").strip() and os.environ.get("OPENAI_MODEL", "").strip())
            study = study_summary()
            from tesis.workspace import archives
            from tesis.alcance import summary as thesis_summary, preparation
            thesis=thesis_summary(self.cached['runs'],archives(self.root),study,configured,preparation(REPOSITORY))
            from tesis.evaluacion_manual import summary as manual_summary
            manual=manual_summary(self.cached['runs'],self.root,self.json_file)
            return {**self.cached, **operations, "busy": operations["busy"] or study['active'] or any(r["status"] == "running" for r in self.cached["runs"]),
                    'manual_evaluation':manual,
                    "catalog": CATALOG, "report_tokens": 0, "diagram_available": self.diagram.is_file(), "openai_available": configured,
                    "interfaces":[name for _,name in socket.if_nameindex()],
                    "kpi_study": study,"thesis":thesis,"evaluation_references":__import__("referencia_laboratorio").list_references()}

    def reader(self, identifier):
        if not identifier:return self
        from tesis.workspace import archive_root
        root=archive_root(self.root,identifier)
        if identifier not in self.archive_panels:self.archive_panels[identifier]=Panel(root)
        return self.archive_panels[identifier]

    def detail(self, key: str):
        with self.lock:
            return self._detail(key)

    def _detail(self, key: str):
        if not isinstance(key, str) or not key or any(part in {"..", ".", ""} for part in key.split("/")) or "\\" in key:
            raise ValueError("Auditoría no disponible.")
        run = next((r for r in self.state()["runs"] if r["key"] == key), None)
        if not run:
            raise ValueError("Auditoría no disponible.")
        directory = self.root / key
        report = self.json_file(directory / "report.json", {})
        plan = self.json_file(directory / "plan.json", [])
        if not isinstance(report, dict) or not isinstance(plan, list):
            raise ValueError("El informe todavía no está disponible.")
        preliminary = preliminary_findings(directory, plan, run["tasks"], self.safe_file) if not report and run["bank"] == "v2" and run["mode"] == "live" else []
        brief = present_run(run, report, plan, preliminary)
        if run['bank']=='personal' and report:
            request=self.json_file(directory/'request.json',{})
            try:allowed={address for _,address in scope_hosts(request.get('personal'))}
            except ValueError:allowed=set()
            entries={item.get('address'):item for item in report.get('inventory',[]) if isinstance(item,dict) and item.get('address') in allowed}
            for item in brief['inventory']:
                host=entries.get(item['address'],{})
                item['host_state']=host.get('host_state','not_probed')
            for address,host in entries.items():
                if host.get('host_state')=='down' and host.get('task_id') is None:
                    brief['inventory'].append({'asset':'Host sin respuesta','address':address,'host_state':'down','ports':[],'services':[]})
            states={'completed','down','incomplete','not_requested','not_evaluated','not_supported','not_applicable','confirmed','not_detected'}
            coverage={}
            for item in report.get('coverage',[]):
                if not isinstance(item,dict) or item.get('address') not in allowed:continue
                value={'address':item['address']}
                for field in ['inventory_state','credentials_state','web_state']:
                    value[field]=item.get(field) if item.get(field) in states|{'not_configured'} else 'not_evaluated'
                for field in ['credential_attempts','confirmed_findings']:
                    number=item.get(field)
                    value[field]=number if type(number) is int and 0<=number<=5000 else 0
                checks=item.get('web_checks',{})
                value['web_checks']={k:checks.get(k) if checks.get(k) in {'not_configured','not_requested','incomplete','not_supported','confirmed','not_detected'} else 'not_configured'
                                     for k in ['object_authorization','file_boundary','ipv6_authorization_gap']} if isinstance(checks,dict) else {}
                coverage[value['address']]=value
            brief['coverage']=list(coverage.values())
            for item in brief['inventory']:item['coverage']=coverage.get(item['address'])
            down=sum(item.get('host_state')=='down' for item in brief['inventory'])
            if down:brief['summary']+=f' {down} hosts down: sin respuesta al descubrimiento; no se escanearon sus puertos.'
        observation = inspect_run(directory, self.root, run, report, plan, self.safe_file)
        from tesis.presentacion import inventory_from_results, candidates_for_view, actions_for_view
        if run['bank']=='empresa':brief['inventory']=inventory_from_results(report,plan,observation['technical'])
        from panel_metricas import operation_metrics
        from llm_especialistas import ROLE_NAMES
        from panel_observabilidad import event_rows
        rows=event_rows(directory/'events.sqlite3',directory)
        reviews=[];decisions=[]
        for _,stamp,component,kind,task_id,payload in rows:
            if kind=='specialist_review' and payload.get('role') in ROLE_NAMES:
                item={k:payload.get(k) for k in ['role','status','reason','known_tokens']}
                for field in ['interpretation','next_step','limitation']:
                    item[field]=payload.get(field,'')[:600] if isinstance(payload.get(field),str) else ''
                item['evidence_tasks']=[v for v in payload.get('evidence_tasks',[]) if isinstance(v,str) and __import__('re').fullmatch(r't[0-9]{3,5}',v)][:24]
                item['references']=[]
                for alias in item['evidence_tasks']:
                    index=int(alias[1:])
                    if index<len(plan):
                        task=plan[index];target=task.get('target',{})
                        item['references'].append({'ref':alias,'address':target.get('address',''),'profile':task.get('action_profile',''),'task_id':task.get('task_id','')})
                item['prioritized_actions']=actions_for_view(payload,plan)
                reviews.append(item)
            elif kind=='decision' and payload.get('phase')!='specialist_review':
                decisions.append({'role':payload.get('role'),'status':payload.get('status'),'tokens':payload.get('total_tokens'),'time':stamp})
        detail = {"run": run, "brief": brief, **observation, "executive": executive_view(brief),
                'metrics':operation_metrics(run,report),'assistance':{'expert_mode':bool(self.json_file(directory/'manifest.json',{}).get('expert_mode') or self.json_file(directory/'request.json',{}).get('expert_mode')),
                    'reviews':reviews,'decisions':decisions[-24:],'review_budget':report.get('llm',{}).get('review_budget'),
                    'review_seconds':report.get('llm',{}).get('specialist_review_seconds')}}
        budget=report.get('detection_budget',self.json_file(directory/'manifest.json',{}).get('detection_budget',{}))
        if isinstance(budget,dict):
            public_budget={key:budget[key] for key in ('catalogue_size','task_limit','executed_tasks')
                           if type(budget.get(key)) is int and 0<=budget[key]<=256}
            public_budget['applied']=budget.get('applied') is True
            public_budget['not_selected_tasks']=sum(isinstance(t,dict) and t.get('status')=='skipped'
                and t.get('reason_code')=='task_budget_not_selected' for t in report.get('tasks',[]))
            detail['detection_budget']=public_budget
        from panel_informe import report_view
        detail['cve_candidates']=candidates_for_view(report,plan,observation['technical'])
        detail['report_view']=report_view(run,brief,observation['technical'],detail['assistance'],plan,report.get('tasks',[]))
        return detail

    def comparison(self,single_key,multi_key,reference_key=None):
        from panel_metricas import compare_runs
        values=[]
        for key in [single_key,multi_key]:
            detail=self.detail(key);directory=self.root/key
            values.append({'run':detail['run'],**{name:self.json_file(directory/(name+'.json'),[] if name=='plan' else {}) for name in ['request','plan','manifest','report','evaluation']}})
        reference=None
        if reference_key:
            from referencia_laboratorio import load_reference,evaluate_reference
            try:
                record,reference=load_reference(reference_key)
                for key,value in zip([single_key,multi_key],values):value['evaluation']=evaluate_reference(self.root/key,value['request'],value['plan'],value['report'],record,reference)
            except ValueError as exc:
                raise ComparisonConfigurationError('La referencia no es válida.' if isinstance(exc,json.JSONDecodeError) else str(exc)) from None
        result=compare_runs(*values)
        if reference:
            result['reference']=reference
            result['evaluations']=[value['evaluation'] for value in values]
            try:
                created=datetime.fromisoformat(reference['created_at'])
                result['reference_predeclared']=all(created<=datetime.fromisoformat(v['run']['started_at']) for v in values)
            except (ValueError,TypeError,KeyError):result['reference_predeclared']=False
            result['detection_note']='Detección contrastada offline solo contra los casos declarados. Los hallazgos sin etiqueta se conservan sin contarlos como falsos positivos.'
            if any(e.get('unknown_negative_controls') for e in result['evaluations']):result['detection_note']+=' Hay controles negativos sin evaluar; IDE y ETV siguen pendientes.'
            if not result['reference_predeclared']:result['note']+=' La referencia se registró después de las corridas; no acredita una evaluación predefinida.'
        return result


# Resumen del estudio para la pantalla de acceso. Solo agregados (parejas aptas y KPI por
# laboratorio): sin direcciones, hallazgos ni nombres de corridas. Se recalcula cada 60 s.
LOGIN_STUDY_TARGETS = (
    ('TRTO_percent', 'TRTO', 'Reducción del tiempo', 30.0, ' %', 'menos tiempo para cerrar la auditoría'),
    ('IDE_percent', 'IDE', 'Detección adicional', 20.0, ' %', 'más hallazgos validados'),
    ('ETV_ratio', 'ETV', 'Eficiencia por token', 1.10, ' ×', 'detecciones por token frente al agente único'),
)
_login_study_cache = {'at': 0.0, 'value': None}
_login_study_lock = threading.Lock()


def _es_number(value, digits=1):
    return f'{value:,.{digits}f}'.replace(',', ' ').replace('.', ',')


def login_study(panel):
    with _login_study_lock:
        if _login_study_cache['at'] and time.monotonic() - _login_study_cache['at'] < 60:
            return _login_study_cache['value']
        try:
            manual = panel.state().get('manual_evaluation') or {}
        except Exception:
            manual = None
        if not isinstance(manual, dict) or not manual:
            value = None
        else:
            planned = manual.get('planned_pairs') or 25
            done = manual.get('completed_pairs') or 0
            analysis = manual.get('analysis') or {}
            kpis = []
            for key, code, label, target, suffix, meaning in LOGIN_STUDY_TARGETS:
                metric = analysis.get(key) or {}
                n = metric.get('n') or 0
                mean = metric.get('mean') if n else None
                digits = 2 if key == 'ETV_ratio' else 1
                ci = metric.get('mean_ci95_percentile_bootstrap')
                ok = isinstance(mean, (int, float))
                kpis.append({
                    'code': code, 'label': label, 'meaning': meaning, 'n': n,
                    'value': _es_number(mean, digits) + suffix if ok else None,
                    'target': '≥ ' + _es_number(target, 2 if key == 'ETV_ratio' else 0) + suffix,
                    'status': ('cumple' if mean >= target else 'no-cumple') if ok else 'pendiente',
                    'ratio': max(0.0, min(1.0, mean / (target * 2))) if ok and target else 0.0,
                    'ci': f'IC 95 %: {_es_number(ci[0], digits)} a {_es_number(ci[1], digits)}' if ok and isinstance(ci, list) and len(ci) == 2 else None,
                })
            labs = []
            for scenario in manual.get('scenarios') or []:
                cells = []
                for row in (scenario.get('pairs') or [])[:5]:
                    if row.get('eligible'):
                        cells.append('apta')
                    elif row.get('single') and row.get('multiagent'):
                        cells.append('excluida')
                    elif row.get('single') or row.get('multiagent'):
                        cells.append('en-curso')
                    else:
                        cells.append('pendiente')
                cells += ['pendiente'] * (5 - len(cells))
                name = str(scenario.get('label') or scenario.get('name') or scenario.get('id') or 'Laboratorio')
                name = name.replace('NovaFlow · ', '')
                labs.append({'name': name[:1].upper() + name[1:], 'done': scenario.get('completed_pairs') or 0, 'cells': cells})
            value = {
                'done': done, 'planned': planned, 'percent': round(100 * done / planned) if planned else 0,
                'runs': manual.get('completed_runs') or 0, 'runs_planned': manual.get('planned_runs') or 50,
                'kpis': kpis, 'labs': labs,
                'updated': datetime.now(ZoneInfo('America/Bogota')).strftime('%H:%M'),
            }
        _login_study_cache.update(at=time.monotonic(), value=value)
        return value


def make_server(panel: Panel, port: int = 8765, identity=None):
    server_panel=panel
    if identity:
        from centinela_tenancy import Workspaces
        workspaces=Workspaces(panel,identity)

        from centinela_publications import Publications
        deliveries = Publications(workspaces, identity)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def valid_host(self):
            return self.headers.get("Host") in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}

        def send(self, body: bytes, content_type: str, status=200, download=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'")
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            for key,value in getattr(self,"extra_headers",[]):
                self.send_header(key,value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionError:
                pass

        def json(self, value, status=200):
            self.send(json.dumps(value, ensure_ascii=False, allow_nan=False).encode(), "application/json; charset=utf-8", status)

        def cookies(self):
            from http.cookies import SimpleCookie
            cookie=SimpleCookie()
            try:cookie.load(self.headers.get('Cookie',''))
            except Exception:return {}
            return {k:v.value for k,v in cookie.items()}

        def redirect(self,path):
            self.extra_headers=[('Location',path)]
            self.send(b'', 'text/plain',303)

        def identify(self):
            self.user=identity.session(self.cookies().get('__Host-centinela_session','')) if identity else None
            if identity and not self.user:
                if urlsplit(self.path).path.startswith('/api/'):
                    self.json({'error':'Tu sesión ha caducado. Inicia sesión de nuevo.'},401)
                else:self.redirect('/login')
                return False
            return True

        def account_request(self):
            path=urlsplit(self.path).path
            if self.headers.get('Origin') != 'http://'+self.headers.get('Host',''):
                self.json({'error':'Origen no autorizado.'},403);return
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=8192 or self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ValueError('Solicitud no válida.')
                value=json.loads(self.rfile.read(size))
                if not isinstance(value,dict):raise ValueError('Solicitud no válida.')
                if path=='/api/auth/login':
                    challenge=self.cookies().get('__Host-centinela_login','')
                    if not challenge or not secrets.compare_digest(challenge,self.headers.get('X-CSRF-Token','')):
                        self.json({'error':'Recarga la página e inténtalo de nuevo.'},403);return
                    token=identity.login(value.get('username'),value.get('password'),self.headers.get('X-Real-IP',self.client_address[0]))
                    self.extra_headers=[('Set-Cookie','__Host-centinela_session='+token+'; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax'),('Set-Cookie','__Host-centinela_login=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict')]
                    self.json({'ok':True});return
                if not self.identify():return
                if not secrets.compare_digest(self.user['csrf'],self.headers.get('X-CSRF-Token','')):
                    self.json({'error':'Solicitud no autorizada.'},403);return
                if path=='/api/auth/logout':
                    identity.logout(self.user['token_hash'])
                    self.extra_headers=[('Set-Cookie','__Host-centinela_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax')]
                    self.json({'ok':True});return
                if path=='/api/auth/password':
                    identity.change_password(self.user,value.get('current_password'),value.get('password'))
                    self.json({'ok':True});return
                if self.user['role']!='admin':
                    self.json({'error':'Acceso reservado al administrador.'},403);return
                if path=='/api/admin/users/create':
                    uid=identity.create_user(value.get('username'),value.get('name'),value.get('password'),value.get('role','auditor'),self.user['id'])
                    workspaces.for_id(uid)
                    self.json({'id':uid},201);return
                if path=='/api/admin/users/update':
                    identity.update_user(self.user['id'],value.get('id'),value.get('role'),value.get('active'),value.get('password'))
                    self.json({'ok':True});return
                if path=='/api/admin/workspace':
                    identity.workspace(self.user,value.get('id'))
                    self.json({'ok':True});return
                if path in {'/api/admin/publish','/api/admin/unpublish'} and self.user.get('workspace') not in (None,self.user['id']):
                    self.json({'error':'La supervisión es de solo lectura. Vuelve a tu espacio para publicar.'},403);return
                if path=='/api/admin/publish':
                    self.json(deliveries.publish(self.user,value.get('key'),value.get('user')),201);return
                if path=='/api/admin/unpublish':
                    self.json(deliveries.unpublish(self.user,value.get('key'),value.get('user')));return
                self.json({'error':'No encontrado.'},404)
            except OSError:
                self.json({'error':'No se pudo guardar el cambio. Inténtalo de nuevo.'},503)
            except (ValueError,TypeError) as exc:
                self.json({'error':str(exc) if isinstance(exc,ValueError) and not isinstance(exc,json.JSONDecodeError) else 'Solicitud no válida.'},400)

        def do_GET(self):
            if not self.valid_host():
                self.json({"error": "Host no permitido"}, 403)
                return
            request = urlsplit(self.path)
            if identity:
                if request.path in {'/login.css','/login.js'}:
                    self.send((ASSETS/request.path[1:]).read_bytes(),'text/css' if request.path.endswith('.css') else 'text/javascript');return
                if request.path=='/login':
                    challenge=secrets.token_urlsafe(32)
                    self.extra_headers=[('Set-Cookie','__Host-centinela_login='+challenge+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800')]
                    self.send(workspaces.base.environment.get_template('login.html').render(csrf=challenge,study=login_study(workspaces.base)).encode(),'text/html; charset=utf-8');return
                if not self.identify():return
                panel=workspaces.for_session(self.user)
                if request.path in {'/account','/admin'}:
                    if request.path=='/admin' and self.user['role']!='admin':
                        self.json({'error':'Acceso reservado al administrador.'},403);return
                    self.send(panel.environment.get_template('account.html').render(current_user=self.user,csrf=self.user['csrf'],admin=request.path=='/admin').encode(),'text/html; charset=utf-8');return
                if request.path=='/api/admin/users':
                    if self.user['role']!='admin':
                        self.json({'error':'Acceso reservado al administrador.'},403);return
                    self.json({'users':identity.users()});return
                if request.path=='/api/lab/personal/interfaces':
                    if self.user['role']!='admin':
                        self.json({'error':'Acceso reservado al administrador.'},403);return
                    from descubrimiento_red import interfaces
                    self.json({'interfaces':label_interfaces(interfaces())});return
                if request.path=='/api/admin/publications':
                    if self.user['role']!='admin':
                        self.json({'error':'Acceso reservado al administrador.'},403);return
                    self.json({'publications':deliveries.listing(self.user)});return
                if request.path=='/':
                    owner=next((u for u in identity.users() if u['id']==(self.user.get('workspace') or self.user['id'])),self.user)
                    if self.user['role']!='admin' or owner['role']!='admin':
                        self.send(panel.environment.get_template('cliente.html').render(current_user=owner,csrf=self.user['csrf']).encode(),'text/html; charset=utf-8');return
                if request.path=='/api/me':
                    from centinela_identity import PUBLIC_USER
                    owner=next(u for u in identity.users() if u['id']==(self.user.get('workspace') or self.user['id']))
                    self.json({'user':{k:self.user[k] for k in PUBLIC_USER},'workspace':owner,'supervising':owner['id']!=self.user['id']});return
                if request.path=='/api-history' and self.user['id']!=workspaces.legacy_owner:
                    self.json({'error':'No disponible.'},403);return
            else:
                panel=server_panel
            query = parse_qs(request.query)
            try:
                if request.path == "/":
                    self.send(panel.environment.get_template("index.html").render(csrf=self.user['csrf'] if identity else panel.csrf,current_user=self.user if identity else None).encode(), "text/html; charset=utf-8")
                elif request.path in {"/app.js", "/workspace.js", "/styles.css", "/novaflow.css", "/interface.css", "/portal.css", "/portal.js", "/account.js", "/cliente.js"}:
                    self.send((ASSETS / request.path[1:]).read_bytes(), "text/javascript; charset=utf-8" if request.path.endswith(".js") else "text/css; charset=utf-8")
                elif request.path in {'/brand/wordmark.webp','/brand/emblem.webp'}:
                    self.send((ASSETS/request.path[1:]).read_bytes(),'image/webp')
                elif request.path == '/archive':
                    identifier=query.get('id',[''])[0]
                    reader=panel.reader(identifier)
                    if reader is panel:raise ValueError('Archivo no disponible.')
                    values=reader.state()['runs']
                    self.send(panel.environment.get_template('archive.html').render(runs=values,archive_id=identifier).encode(),'text/html; charset=utf-8')
                elif request.path == "/diagram":
                    self.send(panel.diagram.read_bytes(), "text/html; charset=utf-8")
                elif request.path == '/api/compare':
                    self.json(panel.comparison(query.get('single',[''])[0],query.get('multi',[''])[0],query.get('reference',[None])[0]))
                elif request.path == "/api/state":
                    self.json(panel.state())
                elif request.path == '/api/manual/export':
                    from tesis.exportacion_manual import export_csv,export_zip
                    from tesis.protocolo_manual import protocol
                    summary=panel.state()['manual_evaluation']
                    kind=query.get('format',['zip'])[0]
                    if kind=='csv':
                        self.send(export_csv(summary),'text/csv; charset=utf-8',download='evaluacion-langgraph-corridas.csv')
                    elif kind=='zip':
                        self.send(export_zip(summary,protocol()),'application/zip',download='evaluacion-langgraph.zip')
                    else:raise ValueError('Formato de exportación no admitido.')
                elif request.path == '/api-history':
                    self.send((REPOSITORY / 'docs/inventario-corridas-api/historial.html').read_bytes(), 'text/html; charset=utf-8')
                elif request.path == '/capabilities':
                    self.send((ASSETS / 'capabilities.html').read_bytes(), 'text/html; charset=utf-8')
                elif request.path == "/api/run":
                    self.json(panel.reader(query.get("archive",[None])[0]).detail(query.get("key", [""])[0]))
                elif request.path == "/report":
                    detail = panel.reader(query.get("archive",[None])[0]).detail(query.get("key", [""])[0])
                    if not detail["brief"]["final"]:
                        raise ValueError("El informe final requiere una auditoría real cerrada.")
                    audience = query.get('audience',['technical'])[0]
                    if audience not in {'technical','executive'}:
                        raise ValueError('Tipo de informe no admitido.')
                    html = panel.environment.get_template("report.html").render(**detail, audience=audience, archive_id=query.get("archive",[None])[0], status_names=STATUS_NAMES)
                    self.send(html.encode(), "text/html; charset=utf-8", download=f"informe-{'tecnico' if audience=='technical' else 'ejecutivo'}.html" if query.get("download") == ["1"] else None)
                elif request.path == "/download":
                    with panel.lock:
                        key = query.get("key", [""])[0]
                        detail = panel.detail(key)
                        file = {"pdf": "report.pdf", "html": "report.html"}.get(query.get("kind", [""])[0])
                        if not file or file not in detail["run"]["artifacts"]:
                            raise ValueError("Archivo no disponible.")
                        body = panel.safe_file(panel.root / key / file)
                        if body is None:
                            raise ValueError("Archivo no disponible.")
                        self.send(body, "application/pdf" if file.endswith(".pdf") else "text/html; charset=utf-8", download=file)
                else:
                    self.json({"error": "No encontrado"}, 404)
            except ComparisonConfigurationError as exc:
                self.json({'error':str(exc)},400)
            except (ValueError, OSError):
                self.json({"error": "Auditoría o archivo no disponible."}, 404)

        def do_POST(self):
            if not self.valid_host():
                self.json({"error": "Host no permitido"}, 403)
                return
            if identity:
                path=urlsplit(self.path).path
                if path.startswith('/api/auth/') or path.startswith('/api/admin/'):
                    self.account_request();return
                if not self.identify():return
                panel=workspaces.for_session(self.user)
                if self.user.get('workspace') and self.user['workspace']!=self.user['id']:
                    self.json({'error':'La supervisión es de solo lectura. Vuelve a tu espacio para ejecutar operaciones.'},403);return
                if self.user['role']!='admin':
                    self.json({'error':'Tu cuenta es de consulta. Novaflow ejecuta las auditorías y publica aquí sus resultados.'},403);return
            else:
                panel=server_panel
            origin = self.headers.get("Origin")
            if origin != "http://" + self.headers.get("Host", "") or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), self.user["csrf"] if identity else panel.csrf):
                self.json({"error": "Solicitud de control no autorizada."}, 403)
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                self.json({"error": "Usa una configuración JSON válida."}, 415)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 32768:
                    raise ValueError("La solicitud supera el tamaño permitido.")
                options = json.loads(self.rfile.read(size))
                if not isinstance(options,dict):
                    raise ValueError('La configuración debe ser un objeto JSON.')
                path = urlsplit(self.path).path
                if path == '/api/evaluation-reference':
                    from referencia_laboratorio import save_reference
                    if panel.state()['busy']:raise ValueError('Espera a que termine la auditoría para registrar una referencia nueva.')
                    self.json({'reference':save_reference(options)},201)
                    return
                elif path == '/api/web-session':
                    from aplicaciones_personales import save_session
                    with panel.operations.lock:
                        if panel.operations.snapshot()['busy']:raise ValueError('Espera a que termine la auditoría para cambiar sesiones.')
                        name=save_session(options)
                    self.json({'name':name,'message':'Sesión guardada de forma privada. El valor no se incluye en informes ni historial.'})
                    return
                elif path == "/api/audit":
                    if identity and options.get('scope') not in {'empresa','personal'}:raise ValueError('Elige la red de una empresa o un laboratorio de Centinela.')
                    job = panel.operations.start("audit", options)
                elif path in {"/api/lab/check", "/api/lab/restore"}:
                    if options != {}:
                        raise ValueError("Esta operación no recibe opciones.")
                    job = panel.operations.start("check" if path.endswith("check") else "restore")
                elif path=='/api/lab/personal/check':
                    job=panel.operations.start('personal_check',options)
                elif path=='/api/lab/personal/discover':
                    from descubrimiento_red import discover
                    if set(options)!={'interface','authorization'}:raise ValueError('Indica la interfaz y la referencia de autorización registrada.')
                    with panel.operations.reserve():
                        result=discover(options.get('interface'),authorization=options.get('authorization'))
                    self.json(result)
                    return
                elif path in {'/api/lab/empresa/check','/api/lab/empresa/restore','/api/lab/empresa/down'}:
                    if options!={}:raise ValueError('Esta operación no recibe opciones.')
                    job=panel.operations.start('empresa_'+path.rsplit('/',1)[-1])
                elif path in {'/api/lab/suite/check','/api/lab/suite/restore','/api/lab/suite/down'}:
                    job=panel.operations.start('suite_'+path.rsplit('/',1)[-1],options)
                elif path=='/api/lab/acceptance-all':
                    if options!={}:raise ValueError('La aceptación sin IA no recibe opciones.')
                    job=panel.operations.start('acceptance_all',{})
                elif path == "/api/stop":
                    if options != {}:
                        raise ValueError("Esta operación no recibe opciones.")
                    job = panel.operations.stop()
                else:
                    self.json({"error": "Operación no encontrada."}, 404)
                    return
                self.json({"job": job}, 202)
            except (ValueError, TypeError, OSError):
                # Validation errors here are authored messages, never subprocess output.
                error = sys.exception()
                self.json({"error": str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else "La configuración enviada no es válida."}, 400)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--runs", type=Path, default=PILOT / "corridas")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("El puerto debe estar entre 1024 y 65535.")
    panel = Panel(args.runs)
    try:
        from centinela_identity import IdentityStore
        identity=IdentityStore(os.environ.get('CENTINELA_DATA_DIR','/var/lib/centinela'))
        if not identity.users():raise ValueError('Configura la primera cuenta de administrador antes de iniciar.')
        server = make_server(panel, args.port, identity=identity)
    except OSError:
        parser.error("El puerto está ocupado. Cierra el panel anterior o usa --port con otro puerto.")
    print(f"Panel unificado: http://127.0.0.1:{server.server_port}/ · Ctrl+C para cerrar", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
