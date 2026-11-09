"""Operaciones del panel sobre la cola local del operador, sin Docker directo."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time

from operador_web import ExecutorClient, ExecutorError, TERMINAL

_cache = {'at': 0.0, 'value': {'available': False}}
_cache_lock = threading.Lock()


def configured():
    return bool(os.environ.get('CENTINELA_EXECUTOR_SOCKET'))


def health():
    if not configured(): return {'available': False}
    with _cache_lock:
        if time.monotonic() - _cache['at'] < 3: return dict(_cache['value'])
        try:
            value = ExecutorClient(os.environ['CENTINELA_EXECUTOR_SOCKET'], timeout=1).call('health')
        except (OSError, ValueError): value = {'available': False}
        _cache.update(at=time.monotonic(), value=value)
        return dict(value)


def supports(action, options):
    if action == 'audit': return options.get('scope') == 'empresa' and options.get('mode') == 'live'
    return action in {'empresa_check', 'empresa_restore', 'empresa_down', 'suite_check',
                      'suite_restore', 'suite_down', 'acceptance_all'}


class RemoteProcess:
    remote = True
    def __init__(self, client, identifier, owner, token):
        self.client, self.identifier, self.owner, self.token = client, identifier, owner, token
    def cancel(self):
        return self.client.call('cancel', job=self.identifier, owner=self.owner, token=self.token)


def run_job(operations, job, output):
    from dualstack_panel import now
    from auditoria.dashboard import process_identity
    from auditoria.store import write_json
    owner = getattr(operations, 'workspace_id', None)
    if not owner: raise ExecutorError('El trabajo necesita un espacio de usuario identificado.')
    client = ExecutorClient(os.environ['CENTINELA_EXECUTOR_SOCKET'])
    action = job['action']; options = job.get('options') or {}
    bank = options.get('scenario', 'integrado')
    kind = 'audit' if action == 'audit' else 'acceptance' if action == 'acceptance_all' else {
        'check': 'check', 'restore': 'prepare', 'down': 'down'}[action.rsplit('_', 1)[-1]]
    banks = ('integrado', 'sucursal', 'comercial', 'mixto', 'reforzado') if action == 'acceptance_all' else (bank,)
    output.mkdir(parents=True, exist_ok=False)
    if action == 'audit':
        write_json(output / 'panel_job.json', {'name': job['name'], 'created_at': job['created_at'], 'options': options})
        write_json(output / 'panel_status.json', {'status': 'queued', 'pid': os.getpid(), 'identity': process_identity(os.getpid())})
    result = None; accepted = None
    try:
        for bank in banks:
            submitted = client.call('submit', kind=kind, bank=bank, owner=owner, options=options if action == 'audit' else {})
            identifier, token = submitted['id'], submitted['token']
            accepted = (identifier, token)
            capability = output / '.protected_capability.json'
            write_json(capability, {'job': identifier, 'owner': owner, 'token': token})
            capability.chmod(0o600)
            with operations.lock:
                operations.process = RemoteProcess(client, identifier, owner, token)
                job.update(status='running', message='Auditoría iniciada.' if action == 'audit' else 'Operación del laboratorio en curso.')
                if action == 'audit': write_json(output / 'panel_status.json', {'status': 'running', 'pid': os.getpid(), 'identity': process_identity(os.getpid())})
            deadline = time.monotonic() + (3000 if kind in {'audit', 'acceptance'} else 960)
            while True:
                result = client.call('status', job=identifier, owner=owner, token=token)
                if result['status'] in TERMINAL: break
                if time.monotonic() > deadline:
                    client.call('cancel', job=identifier, owner=owner, token=token)
                    raise ExecutorError('La operación superó su plazo; se solicitó su terminación.')
                time.sleep(.5)
            accepted = None
            if result.get('artifact_bytes'):
                client.download(identifier, owner, token, output / bank if action == 'acceptance_all' else output)
            if result['status'] not in {'complete', 'partial'} or action == 'acceptance_all' and result['status'] != 'complete': break
        with operations.lock:
            status = result['status'] if result['status'] in {'complete', 'partial'} else 'interrupted' if result['status'] in {'interrupted', 'cancelled'} else 'failed'
            job.update(status=status, ended_at=now())
            if action == 'audit':
                candidates = list(output.rglob('request.json'))
                if candidates: job['run_key'] = candidates[0].parent.relative_to(operations.root).as_posix()
                job['message'] = 'El resultado está disponible.' if job.get('run_key') else 'La auditoría terminó sin un resultado disponible. Comprueba el laboratorio antes de repetir.'
                operations.empresa_lab.update(status='unknown', message='Comprueba el laboratorio antes de la siguiente auditoría.')
                if options.get('scenario'): operations.scenario_labs[bank] = {'status': 'unknown', 'message': 'Comprueba el escenario antes de la siguiente auditoría.'}
            elif action == 'acceptance_all':
                job['message'] = 'Aceptación de los cinco laboratorios completada.' if status == 'complete' else 'La aceptación conserva una incidencia. Revisa el último laboratorio.'
            else:
                good = status == 'complete'
                if good and kind == 'prepare': operations.restorations.restored(bank, job['id'])
                if good and kind == 'check': operations.restorations.checked(bank)
                state = 'ready' if good and kind == 'check' else 'unknown' if good else 'error'
                message = 'Laboratorio comprobado.' if state == 'ready' else 'Laboratorio preparado. Comprueba su estado antes de auditar.' if good and kind == 'prepare' else 'Laboratorio cerrado.' if good else 'No se completó la operación del laboratorio.'
                value = {'status': state, 'message': message, 'checked_at': now()}
                if bank == 'integrado': operations.empresa_lab.update(value)
                else: operations.scenario_labs[bank] = value
                job['message'] = message
    except (OSError, ValueError):
        # Cancelar una reserva no repite el trabajo ni una petición al proveedor.
        if accepted:
            try: client.call('cancel', job=accepted[0], owner=owner, token=accepted[1])
            except (OSError, ValueError): pass
        raise
    finally:
        with operations.lock: operations.process = None
        if action == 'audit':
            write_json(output / 'panel_status.json', {'status': job['status'], 'ended_at': job.get('ended_at'), 'run_key': job.get('run_key')})
