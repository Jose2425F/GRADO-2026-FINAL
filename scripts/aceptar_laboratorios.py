#!/usr/bin/env python3
"""Aceptación funcional completa de los cinco laboratorios, sin llamadas a la IA."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / 'piloto_kali/prototipo'
sys.path[:0] = [str(ROOT / 'scripts'), str(PILOT / 'src')]

from auditoria.dashboard import process_identity  # noqa: E402
from tesis.laboratorios import Context, STATE, catalog, private_json  # noqa: E402
from tesis.orquestacion_langgraph import engine_metadata  # noqa: E402
import laboratorio_suite as suite  # noqa: E402

RECEIPT = STATE / 'acceptance-five.json'
OUTPUT = PILOT / 'corridas/acceptance_five'
IDS = ('integrado', 'sucursal', 'comercial', 'mixto', 'reforzado')


def laboratory_catalog():
    return [{'id': 'integrado', 'name': 'NovaFlow · banco integrado', 'tasks': 32}, *catalog()]


def acceptance_options():
    """No incluye pertenencia a la muestra ni un presupuesto parcial."""
    return {'authorization': 'LAB-PROPIO', 'scope': 'empresa', 'architecture': 'single',
            'ia': 'none', 'tokens': 0, 'expert_mode': False, 'mode': 'live'}


def read_json(path, default=None):
    try:
        if path.is_symlink() or path.stat().st_size > 4_000_000:
            return default
        return json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return default


def artifact_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_result(output, expected_tasks):
    """No acepta el exit code como sustituto de evidencia y evaluación completas."""
    reports = list(output.glob('*/report.json'))
    if len(reports) != 1:
        return {'accepted': False, 'reason': 'report_not_unique'}
    directory = reports[0].parent
    report = read_json(directory / 'report.json', {})
    evaluation = read_json(directory / 'evaluation.json', {})
    manifest = read_json(directory / 'manifest.json', {})
    plan = read_json(directory / 'plan.json', [])
    request = read_json(directory / 'request.json', {})
    llm = report.get('llm', {})
    calls = llm.get('calls', [])
    graph = manifest.get('orchestration', {})
    budget = manifest.get('detection_budget', report.get('detection_budget', {}))
    zero_api = (isinstance(calls, list) and not calls and llm.get('status') == 'disabled'
                and llm.get('known_tokens', 0) == 0 and llm.get('total_tokens', 0) == 0)
    full_catalogue = (isinstance(plan, list) and len(plan) == expected_tasks
                      and evaluation.get('tasks_checked') == expected_tasks
                      and evaluation.get('tasks_valid') == expected_tasks
                      and budget.get('applied') is False and budget.get('task_limit') is None
                      and budget.get('catalogue_size') == expected_tasks)
    graph_valid = (graph.get('engine') == 'langgraph'
                   and all(graph.get(key) for key in ('version', 'graph', 'source_sha256'))
                   and graph == engine_metadata())
    accepted = (report.get('status') == 'complete' and evaluation.get('acceptance_passed') is True
                and evaluation.get('evidence_valid') is True and full_catalogue and graph_valid
                and zero_api and request.get('token_budget') == 0
                and request.get('llm_mode') == 'disabled' and not manifest.get('manual_context'))
    fields = ('tasks_checked', 'tasks_valid', 'TP', 'FP', 'FN', 'TN', 'acceptance_passed', 'evidence_valid')
    return {'accepted': bool(accepted), 'reason': None if accepted else 'acceptance_evidence_incomplete',
            'evaluation': {key: evaluation.get(key) for key in fields},
            'full_catalogue': full_catalogue, 'zero_api': zero_api, 'orchestration': graph,
            'artifacts': {name: artifact_hash(directory / name)
                          for name in ('report.json', 'evaluation.json', 'manifest.json', 'plan.json', 'request.json')
                          if (directory / name).is_file()},
            'directory': directory.relative_to(output).as_posix()}


def public_status(path=None):
    """Lectura para el panel; un recibo viejo o incompleto nunca acredita cinco bancos."""
    path = RECEIPT if path is None else Path(path)
    saved = read_json(path, {})
    if not isinstance(saved, dict) or not saved:
        return {'status': 'pending', 'active': False, 'accepted': False, 'completed_labs': 0,
                'total_labs': 5, 'known_tokens': 0, 'new_api_generations': 0, 'scenarios': []}
    rows = saved.get('scenarios', [])
    if not isinstance(rows, list):
        rows = []
    expected = {row['id']: row['tasks'] for row in laboratory_catalog()}
    completed = sum(row.get('status') == 'accepted' for row in rows if isinstance(row, dict))
    valid_rows = (len(rows) == 5 and {row.get('id') for row in rows if isinstance(row, dict)} == set(IDS)
                  and all(isinstance(row, dict) and row.get('status') == 'accepted'
                          and row.get('expected_tasks') == expected.get(row.get('id'))
                          and row.get('full_catalogue') is True and row.get('zero_api') is True
                          and row.get('evaluation', {}).get('acceptance_passed') is True
                          and row.get('evaluation', {}).get('evidence_valid') is True
                          and row.get('evaluation', {}).get('tasks_valid') == row.get('expected_tasks')
                          for row in rows))
    accepted = (saved.get('status') == 'accepted' and valid_rows
                and saved.get('orchestration') == engine_metadata()
                and saved.get('known_tokens') == 0 and saved.get('new_api_generations') == 0)
    alive = (saved.get('identity') is not None
             and process_identity(saved.get('pid', -1)) == saved.get('identity'))
    status = saved.get('status', 'pending')
    if status == 'running' and not alive:
        status = 'interrupted'
    if status == 'accepted' and not accepted:
        status = 'invalidated'
    return {key: saved.get(key) for key in ('started_at', 'finished_at', 'reason', 'run_id', 'orchestration')} | {
        'status': status, 'active': bool(alive and status == 'running'), 'accepted': bool(accepted),
        'completed_labs': completed, 'total_labs': 5, 'known_tokens': saved.get('known_tokens', 0),
        'new_api_generations': saved.get('new_api_generations', 0), 'scenarios': rows}


def update_phase(receipt_path, scenario, phase):
    saved = read_json(receipt_path, {})
    for row in saved.get('scenarios', []):
        if row.get('id') == scenario:
            row.update(status='running', phase=phase)
    private_json(receipt_path, saved)


def clear_owned_suite_banks():
    """Sólo proyectos generados del catálogo; nunca nombres o rutas del usuario."""
    for row in catalog():
        suite.kernel_ok()
        ctx = Context(row['id'])
        ctx.prepare()
        compose = read_json(ctx.lab.COMPOSE, {})
        if (compose.get('name') != 'novaflow-suite-' + ctx.id
            or not compose.get('services')
            or any(service.get('labels') != {'novaflow.suite': '1', 'novaflow.scenario': ctx.id}
                   for service in compose['services'].values())):
            raise ValueError('Proyecto suite no identificado como propio.')
        suite.compose(ctx, 'down')


def ensure_images_available(definition):
    import subprocess
    images = sorted({service.get('image') for service in definition.get('services', {}).values()
                     if service.get('image')})
    if not images:
        raise ValueError('lab_images_missing')
    checked = subprocess.run(['docker', 'image', 'inspect', *images], capture_output=True,
                             text=True, timeout=20)
    if checked.returncode:
        raise ValueError('lab_images_missing')


def run_slot(output):
    try:
        return _execute_slot(output)
    except Exception as exc:
        import subprocess
        spec = read_json(output / 'slot.json', {})
        state = read_json(Path(spec.get('receipt', str(RECEIPT))), {})
        phase = next((row.get('phase') for row in state.get('scenarios', [])
                      if row.get('id') == spec.get('scenario')), 'preparing')
        reason = ('kernel_failure' if 'kernel_failure' in str(exc) else
                  'lab_images_missing' if str(exc) == 'lab_images_missing' else
                  'operation_timeout' if isinstance(exc, subprocess.TimeoutExpired) else
                  'restoration_failed' if phase == 'restoring' else
                  'preflight_failed' if phase == 'checking' else
                  'cleanup_failed' if phase == 'closing' else 'execution_failed')
        private_json(output / 'worker_failure.json', {'reason': reason, 'failure_phase': phase,
                                                     'error_type': type(exc).__name__})
        raise


def _execute_slot(output):
    spec = read_json(output / 'slot.json', {})
    if (spec.get('parent_pid') != os.getppid()
        or spec.get('parent_identity') != process_identity(os.getppid())
        or spec.get('scenario') not in IDS or spec.get('options') != acceptance_options()):
        raise ValueError('Proceso de aceptación no autorizado.')
    scenario = spec['scenario']
    receipt_path = Path(spec['receipt'])
    suite.kernel_ok()
    update_phase(receipt_path, scenario, 'restoring')
    if scenario == 'integrado':
        from auditoria import lab_empresa
        from ejecutar_estudio_novaflow import wait_preflight
        from laboratorio_empresa import run_panel, STATE as original_state
        from tesis.restauracion_banco import prepare_images, restore_pinned, down_pinned
        lab_empresa.prepare(original_state)
        prepare_images(original_state)
        clear_owned_suite_banks()
        down_pinned(original_state)
        restore_pinned(original_state)
        try:
            suite.kernel_ok()
            update_phase(receipt_path, scenario, 'checking')
            wait_preflight(original_state)
            update_phase(receipt_path, scenario, 'running')
            code = run_panel(spec['options'], output)
            reports = list(output.glob('*/manifest.json'))
            if len(reports) == 1:
                manifest = read_json(reports[0], {})
                manifest.setdefault('scenario', {})['phase'] = 'acceptance'
                private_json(reports[0], manifest)
            return code
        finally:
            # No iniciar otra operación Docker tras un fallo del kernel.
            suite.kernel_ok()
            update_phase(receipt_path, scenario, 'closing')
            down_pinned(original_state)
    ctx = Context(scenario)
    ctx.prepare()
    ensure_images_available(read_json(ctx.lab.COMPOSE, {}))
    suite.compose(ctx, 'up')
    try:
        suite.kernel_ok()
        update_phase(receipt_path, scenario, 'checking')
        suite.ready(ctx)
        update_phase(receipt_path, scenario, 'running')
        return suite.audit(ctx, spec['options'], output)
    finally:
        suite.kernel_ok()
        update_phase(receipt_path, scenario, 'closing')
        suite.compose(ctx, 'down')


def accept_all():
    from ejecutar_estudio_novaflow import guarded
    suite.kernel_ok()
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_id = time.strftime('%Y%m%dT%H%M%S', time.gmtime()) + '_' + uuid4().hex[:8]
    if RECEIPT.exists():
        import shutil
        history = STATE / 'acceptance-five-history'
        history.mkdir(exist_ok=True, mode=0o700)
        shutil.copy2(RECEIPT, history / (run_id + '.json'))
    receipt = {'version': 'acceptance-five-1', 'status': 'running', 'run_id': run_id,
               'started_at': time.time(), 'pid': os.getpid(), 'identity': process_identity(os.getpid()),
               'orchestration': engine_metadata(), 'known_tokens': 0, 'new_api_generations': 0,
               'completed_labs': 0, 'total_labs': 5,
               'scenarios': [{'id': row['id'], 'name': row['name'], 'status': 'pending',
                              'phase': 'pending', 'expected_tasks': row['tasks']}
                             for row in laboratory_catalog()]}
    private_json(RECEIPT, receipt)
    try:
        for entry in receipt['scenarios']:
            suite.kernel_ok()
            output = OUTPUT / run_id / entry['id']
            output.mkdir(parents=True, exist_ok=False, mode=0o700)
            private_json(output / 'slot.json', {'scenario': entry['id'], 'options': acceptance_options(),
                         'parent_pid': os.getpid(), 'parent_identity': process_identity(os.getpid()),
                         'receipt': str(RECEIPT)})
            entry.update(status='running', phase='restoring', output=output.relative_to(PILOT / 'corridas').as_posix())
            private_json(RECEIPT, receipt)
            code = guarded([str(PILOT / '.venv/bin/python'), str(Path(__file__).resolve()),
                            '--slot', str(output)], STATE / 'acceptance-five.log', 2700)
            result = inspect_result(output, entry['expected_tasks'])
            failure = read_json(output / 'worker_failure.json', {})
            if isinstance(failure, dict) and failure:
                result.update({key: failure[key] for key in ('reason', 'failure_phase', 'error_type') if key in failure})
                result['accepted'] = False
            entry.update({key: value for key, value in result.items() if key != 'accepted'})
            entry.update(status='accepted' if code == 0 and result['accepted'] else 'failed', phase='finished')
            receipt['completed_labs'] = sum(row['status'] == 'accepted' for row in receipt['scenarios'])
            private_json(RECEIPT, receipt)
            if entry['status'] != 'accepted':
                receipt.update(status='stopped', reason=entry.get('reason') or 'worker_failed', finished_at=time.time())
                private_json(RECEIPT, receipt)
                return 3
        receipt.update(status='accepted', finished_at=time.time())
        private_json(RECEIPT, receipt)
        return 0
    except BaseException as exc:
        receipt.update(status='interrupted' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'stopped',
                       reason='kernel_failure' if 'kernel_failure' in str(exc) else type(exc).__name__,
                       finished_at=time.time())
        for entry in receipt['scenarios']:
            if entry['status'] == 'running':
                entry.update(status='failed', phase='stopped', reason=receipt['reason'])
        private_json(RECEIPT, receipt)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['aceptar', 'estado'], default='aceptar')
    parser.add_argument('--slot', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.slot:
        return run_slot(args.slot)
    if args.action == 'estado':
        print(json.dumps(public_status(), ensure_ascii=False, indent=2))
        return 0
    with suite.operation('acceptance_all', 'cinco'):
        return accept_all()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print('Aceptación detenida: ' + ('kernel_failure' if 'kernel_failure' in str(exc) else type(exc).__name__), file=sys.stderr)
        raise SystemExit(3)
