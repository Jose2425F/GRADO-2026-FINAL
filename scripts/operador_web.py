"""Cola local de operaciones cerradas del banco y transporte para el panel."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import zipfile

BANKS = ('integrado', 'sucursal', 'comercial', 'mixto', 'reforzado')
TERMINAL = {'complete', 'partial', 'failed', 'cancelled', 'interrupted'}
MAX_FRAME = 512 * 1024
CHUNK = 192 * 1024
IDENTIFIER = re.compile(r'[0-9a-f]{32}')


class ExecutorError(ValueError):
    pass


def send_frame(stream, value):
    raw = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_FRAME:
        raise ExecutorError('Respuesta del ejecutor demasiado extensa.')
    stream.sendall(struct.pack('!I', len(raw)) + raw)


def read_exact(stream, count, deadline=None):
    deadline = time.monotonic() + 15 if deadline is None else deadline
    parts = []
    while count:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise ExecutorError('El mensaje superó su plazo total.')
        if hasattr(stream, 'settimeout'): stream.settimeout(remaining)
        value = stream.recv(count)
        if not value:
            raise ExecutorError('El ejecutor cerró la conexión.')
        parts.append(value); count -= len(value)
    return b''.join(parts)


def receive_frame(stream, timeout=15):
    deadline = time.monotonic() + timeout
    size = struct.unpack('!I', read_exact(stream, 4, deadline))[0]
    if not 0 < size <= MAX_FRAME:
        raise ExecutorError('Mensaje del ejecutor fuera del límite.')
    raw = read_exact(stream, size, deadline)
    depth = 0; quoted = False; escaped = False
    for byte in raw:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64: raise ExecutorError('Mensaje JSON demasiado anidado.')
        elif byte in (93, 125): depth -= 1
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value: raise ExecutorError('Campo JSON duplicado.')
            value[key] = item
        return value
    def constant(_): raise ExecutorError('Número JSON no finito.')
    try: value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError): raise ExecutorError('Mensaje JSON fuera del contrato.') from None
    if not isinstance(value, dict):
        raise ExecutorError('Mensaje del ejecutor no válido.')
    return value


def valid_id(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def normalized_options(value, bank):
    from dualstack_panel import validate_options
    result = validate_options(value)
    if result['scope'] != 'empresa' or result['mode'] != 'live' or result.get('manual_context'):
        raise ExecutorError('La instalación admite auditorías de sus cinco laboratorios.')
    if result.get('applications') or result.get('creds'):
        raise ExecutorError('Configuración ajena al catálogo instalado.')
    expected = result.get('scenario', 'integrado')
    if expected != bank:
        raise ExecutorError('El escenario y las opciones no coinciden.')
    return result


class ExecutorClient:
    def __init__(self, path, timeout=15):
        self.path, self.timeout = str(path), timeout

    def call(self, action, **payload):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(self.timeout)
            stream.connect(self.path)
            send_frame(stream, {'action': action, **payload})
            value = receive_frame(stream, timeout=self.timeout)
        if value.get('ok') is not True:
            raise ExecutorError(value.get('error', 'La operación no está disponible.'))
        if action in {'status', 'cancel', 'submit'}:
            if not valid_id(value.get('id')) or not isinstance(value.get('status'), str) or value['status'] not in TERMINAL | {'queued', 'running'}:
                raise ExecutorError('Estado del ejecutor fuera del contrato.')
        if action == 'submit' and not re.fullmatch(r'[0-9a-f]{64}', value.get('token', '') if isinstance(value.get('token'), str) else ''):
            raise ExecutorError('La reserva no contiene una credencial válida.')
        if action == 'read' and not isinstance(value.get('data'), str):
            raise ExecutorError('Bloque de resultado fuera del contrato.')
        return value

    def download(self, job, owner, token, destination):
        destination = Path(destination)
        if destination.is_symlink() or any(p.is_symlink() for p in destination.parents):
            raise ExecutorError('No se admiten enlaces en el directorio de resultados.')
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        status = self.call('status', job=job, owner=owner, token=token)
        size, expected = status.get('artifact_bytes', 0), status.get('artifact_sha256')
        if type(size) is not int or not 0 < size <= 128 * 1024 * 1024 or not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ExecutorError('El resultado no tiene un manifiesto válido.')
        temporary = destination / ('.resultado-' + secrets.token_hex(8) + '.zip')
        digest = hashlib.sha256()
        try:
            with temporary.open('xb') as output:
                for offset in range(0, size, CHUNK):
                    value = self.call('read', job=job, owner=owner, token=token, offset=offset)
                    block = base64.b64decode(value['data'], validate=True)
                    if len(block) != min(CHUNK, size - offset):
                        raise ExecutorError('Resultado incompleto.')
                    digest.update(block); output.write(block)
            if not hmac.compare_digest(digest.hexdigest(), expected):
                raise ExecutorError('El resultado cambió durante la transferencia.')
            with zipfile.ZipFile(temporary) as archive:
                members = archive.infolist()
                if len(members) > 5000 or sum(m.file_size for m in members) > 128 * 1024 * 1024:
                    raise ExecutorError('Resultado fuera de los límites de extracción.')
                for member in members:
                    name = member.filename
                    parts = name.split('/')
                    if (name.startswith('/') or '\\' in name or any(p in {'', '.', '..'} for p in parts)
                            or stat.S_ISLNK(member.external_attr >> 16) or member.file_size > 32 * 1024 * 1024):
                        raise ExecutorError('Ruta no admitida en el resultado.')
                    target = destination.joinpath(*parts)
                    current = destination
                    for part in parts[:-1]:
                        current = current / part
                        if current.is_symlink():
                            raise ExecutorError('No se admiten enlaces en el resultado.')
                        current.mkdir(exist_ok=True, mode=0o700)
                    with target.open('xb') as output, archive.open(member) as source:
                        while block := source.read(65536): output.write(block)
                    target.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)


def public_job(job):
    return {key: job[key] for key in ('id', 'kind', 'bank', 'status', 'created_at', 'ended_at',
                                      'exit_code', 'error_code', 'artifact_bytes', 'artifact_sha256') if key in job}


class OperatorQueue:
    def __init__(self, base, spool, panel_uid, accounts, *, runner=None, owner_check=None):
        self.base, self.spool = Path(base), Path(spool)
        self.panel_uid, self.accounts = panel_uid, Path(accounts)
        self.jobs = {}; self.pending = queue.Queue(maxsize=32)
        self.lock = threading.RLock(); self.running = None
        self.runner = runner or self._run
        self.owner_check = owner_check or self._owner_exists
        self.bank_status = {bank: {'state': 'unknown', 'active_count': 0} for bank in BANKS}
        self.spool.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A restart never silently resumes an audit or repeats an API request.
        for path in self.spool.glob('*/state.json'):
            if path.is_symlink() or not valid_id(path.parent.name): continue
            data = json.loads(path.read_text())
            if data.get('status') not in TERMINAL:
                data.update(status='interrupted', error_code='operator_service_restarted', ended_at=time.time())
            self.jobs[data['id']] = data
            self._persist(data)

    def _owner_exists(self, owner):
        if not valid_id(owner) or self.accounts.is_symlink(): return False
        with sqlite3.connect(self.accounts.resolve().as_uri() + '?mode=ro', uri=True) as db:
            return db.execute('SELECT 1 FROM users WHERE id=? AND active=1', (owner,)).fetchone() is not None

    def _persist(self, job):
        directory = self.spool / job['id']; directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / 'state.json'; temporary = directory / '.state.new'
        with temporary.open('w') as output:
            json.dump(job, output, ensure_ascii=False); output.flush(); os.fsync(output.fileno())
        temporary.chmod(0o600); temporary.replace(target)

    def submit(self, request):
        if set(request) != {'action', 'kind', 'bank', 'owner', 'options'}:
            raise ExecutorError('Solicitud incompleta o con campos adicionales.')
        kind, bank, owner = request['kind'], request['bank'], request['owner']
        if not isinstance(kind, str) or kind not in {'audit', 'acceptance', 'prepare', 'check', 'recover', 'down'} or bank not in BANKS:
            raise ExecutorError('Operación no instalada.')
        if not valid_id(owner) or not self.owner_check(owner):
            raise ExecutorError('Espacio de trabajo no disponible.')
        options = normalized_options(request['options'], bank) if kind == 'audit' else request['options']
        if kind != 'audit' and options != {}:
            raise ExecutorError('Esta operación no recibe opciones de auditoría.')
        with self.lock:
            if any(j['owner'] == owner and j['status'] not in TERMINAL for j in self.jobs.values()):
                raise ExecutorError('Ya existe una operación activa para este espacio.')
            if self.pending.full(): raise ExecutorError('La cola está completa.')
            identifier, token = secrets.token_hex(16), secrets.token_hex(32)
            job = {'id': identifier, 'owner': owner, 'kind': kind, 'bank': bank, 'options': options,
                   'token_sha256': hashlib.sha256(token.encode()).hexdigest(), 'status': 'queued',
                   'created_at': time.time(), 'cancel_requested': False}
            self.jobs[identifier] = job; self._persist(job); self.pending.put(identifier)
            return {'ok': True, **public_job(job), 'token': token}

    def authorize(self, request):
        if not valid_id(request.get('job')) or not valid_id(request.get('owner')):
            raise ExecutorError('Trabajo no disponible.')
        token = request.get('token')
        if not isinstance(token, str) or not re.fullmatch(r'[0-9a-f]{64}', token):
            raise ExecutorError('Trabajo no disponible.')
        job = self.jobs.get(request['job'])
        if (not job or job['owner'] != request['owner'] or not self.owner_check(request['owner'])
                or not hmac.compare_digest(job['token_sha256'], hashlib.sha256(token.encode()).hexdigest())):
            raise ExecutorError('Trabajo no disponible.')
        return job

    def dispatch(self, request):
        action = request.get('action')
        if not isinstance(action, str): raise ExecutorError('Operación no admitida.')
        if action == 'health' and set(request) == {'action'}:
            try:
                from ejecutar_protegido import provider_configuration
                provider_configuration(self.base)
                configured = True
            except (ValueError, OSError, RuntimeError): configured = False
            return {'ok': True, 'available': True, 'busy': any(j['status'] not in TERMINAL for j in self.jobs.values()),
                    'supported_scopes': ['empresa'], 'banks': self.bank_status,
                    'api_configured': configured}
        if action == 'submit': return self.submit(request)
        expected = {'action', 'job', 'owner', 'token'} | ({'offset'} if action == 'read' else set())
        if action not in {'status', 'cancel', 'read'} or set(request) != expected:
            raise ExecutorError('Operación no admitida.')
        with self.lock:
            job = self.authorize(request)
            if action == 'status': return {'ok': True, **public_job(job)}
            if action == 'cancel':
                if job['status'] not in TERMINAL:
                    job['cancel_requested'] = True
                    if self.running and self.running[0] == job['id'] and self.running[1].poll() is None:
                        os.killpg(self.running[1].pid, signal.SIGTERM)
                    elif job['status'] == 'queued':
                        job.update(status='cancelled', ended_at=time.time())
                    self._persist(job)
                return {'ok': True, **public_job(job)}
            offset = request['offset']; size = job.get('artifact_bytes', 0)
            if job['status'] not in TERMINAL or type(offset) is not int or not 0 <= offset < size or offset % CHUNK:
                raise ExecutorError('Resultado no disponible.')
            with (self.spool / job['id'] / 'result.zip').open('rb') as source:
                source.seek(offset); block = source.read(CHUNK)
            return {'ok': True, 'data': base64.b64encode(block).decode()}

    def worker(self):
        while True:
            identifier = self.pending.get()
            try:
                with self.lock:
                    job = self.jobs[identifier]
                    if job['status'] in TERMINAL: continue
                    job['status'] = 'running'; self._persist(job)
                self.runner(job)
            except Exception as exc:
                with self.lock:
                    job.update(status='cancelled' if job.get('cancel_requested') else 'failed',
                               error_code='operator_failed', failure_type=type(exc).__name__, ended_at=time.time()); self._persist(job)
            finally:
                self.pending.task_done()

    def _invoke(self, job, argv, log_name, timeout):
        log_path = self.spool / job['id'] / log_name
        with log_path.open('wb') as log:
            with self.lock:
                if job.get('cancel_requested'): raise ExecutorError('Operación cancelada.')
                process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                    cwd=self.base / 'repo', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                                               'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
                self.running = (job['id'], process)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=10)
                raise ExecutorError('La operación superó su plazo.') from None
            finally:
                with self.lock: self.running = None
        return code, log_path

    def _run(self, job):
        python = str(self.base / 'venv/bin/python')
        launcher = str(self.base / 'repo/scripts/ejecutar_protegido.py')
        if job['kind'] in {'audit', 'acceptance', 'check'}:
            action = 'audit-live' if job['kind'] == 'audit' else 'audit' if job['kind'] == 'acceptance' else 'preflight'
            argv = [python, launcher, '--base', str(self.base), '--bank', job['bank'], '--action', action]
            if job['kind'] == 'audit':
                argv += ['--architecture', job['options']['architecture']]
                target = self.base / 'private' / ('job-' + job['id'] + '.json')
                with target.open('x') as stream: json.dump({'options': job['options']}, stream, ensure_ascii=False)
                target.chmod(0o600); argv += ['--job', str(target)]
            code, log = self._invoke(job, argv, 'operator.log', 2850 if action != 'preflight' else 900)
            if action == 'preflight':
                self.bank_status[job['bank']].update(state='ready' if code == 0 else 'error', checked_at=time.time())
            records = []
            for line in log.read_text(errors='replace').splitlines():
                try: records.append(json.loads(line))
                except ValueError: pass
            record = next((v for v in reversed(records) if isinstance(v, dict) and 'receipt' in v), {})
            receipt_path = Path(record.get('receipt', '/nonexistent'))
            valid_receipt = False
            if receipt_path.parent.parent == self.base / 'private' and receipt_path.name == 'operator.json' and not receipt_path.is_symlink():
                receipt = json.loads(receipt_path.read_text())
                run_id = receipt.get('run_id')
                valid_receipt = (isinstance(run_id, str) and receipt_path.parent.name == run_id
                    and receipt.get('bank') == job['bank'] and receipt.get('action') == action
                    and receipt.get('operator_exit_code') == code and receipt.get('roles_stopped_before_evaluation') is True
                    and Path(receipt.get('root', '/nonexistent')) == self.base / 'runtime' / run_id)
                if valid_receipt and job['kind'] != 'check':
                    self._export(job, receipt)
            if not valid_receipt or job['kind'] != 'check' and not job.get('artifact_bytes'):
                raise ExecutorError('El ejecutor no confirmó un cierre verificable de los roles y sus resultados.')
        else:
            argv = [python, str(self.base / 'repo/scripts/instalar_ejecutor_protegido.py'),
                    '--stage', str(self.base), '--bank', job['bank'], '--action', job['kind']]
            code, log = self._invoke(job, argv, 'control.log', 900)
            try:
                value = json.loads(log.read_text().splitlines()[-1])
            except (ValueError, IndexError): value = {}
            identity_ok = (isinstance(value, dict) and value.get('schema') == 'centinela-stage-control/1'
                and value.get('action') == job['kind'] and value.get('bank') == job['bank'])
            if not identity_ok: raise ExecutorError('El control no confirmó el laboratorio y la operación solicitados.')
            self.bank_status[job['bank']] = {key: value[key] for key in
                ('schema', 'ok', 'action', 'bank', 'state', 'active_count', 'quarantine_count', 'quarantined', 'running_containers') if key in value}
            good_state = (value.get('state') == 'prepared' and value.get('quarantine_count') == 0
                          if job['kind'] in {'prepare', 'recover'} else
                          value.get('state') in {'stopped', 'quarantined'} and value.get('running_containers') == 0)
            if value.get('ok') is not True or not good_state:
                raise ExecutorError('El laboratorio conserva una incidencia o necesita recuperación verificada.')
        with self.lock:
            job.update(status='cancelled' if job['cancel_requested'] else 'complete' if code == 0 else 'partial' if code == 3 and job.get('artifact_bytes') else 'failed',
                       exit_code=code, ended_at=time.time())
            if job['status'] == 'failed': job['error_code'] = 'operator_rejected'
            self._persist(job)

    def _export(self, job, receipt):
        root = Path(receipt['root'])
        if root.parent != self.base / 'runtime' or root.is_symlink(): raise ExecutorError('Resultado ajeno a la instalación.')
        output = root / 'output'
        archive_path = self.spool / job['id'] / 'result.zip'; total = 0; count = 0
        with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(output.rglob('*')):
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode): raise ExecutorError('Resultado con enlace no admitido.')
                if stat.S_ISDIR(info.st_mode): continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024:
                    raise ExecutorError('Archivo del resultado fuera del contrato.')
                total += info.st_size; count += 1
                if total > 128 * 1024 * 1024 or count > 5000: raise ExecutorError('Resultado demasiado extenso.')
                archive.write(path, path.relative_to(output).as_posix())
        archive_path.chmod(0o600)
        if archive_path.stat().st_size > 128 * 1024 * 1024: raise ExecutorError('Archivo comprimido demasiado extenso.')
        job.update(artifact_bytes=archive_path.stat().st_size, artifact_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())


def serve(queue_, path):
    path = Path(path)
    if path.exists(): raise ExecutorError('El socket ya existe; no se reemplaza automáticamente.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path)); os.chown(path, 0, queue_.panel_uid); path.chmod(0o660); server.listen(16)
        threading.Thread(target=queue_.worker, daemon=True).start()
        try:
            while True:
                connection, _ = server.accept()
                try:
                    connection.settimeout(15)
                    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid not in {0, queue_.panel_uid}: raise ExecutorError('Principal no admitido.')
                    send_frame(connection, queue_.dispatch(receive_frame(connection)))
                except (ValueError, OSError):
                    try: send_frame(connection, {'ok': False, 'error': 'La operación solicitada no está disponible.'})
                    except OSError: pass
                finally: connection.close()
        finally: path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--spool', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--panel-uid', type=int, required=True)
    parser.add_argument('--accounts', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Este servicio pertenece al operador.')
    from ejecutar_protegido import trusted
    trusted(__file__); trusted(args.base, directory=True); trusted(args.base / 'private', directory=True, private=True)
    sys.path[:0] = [str(args.base / 'repo/scripts'), str(args.base / 'repo/piloto_kali/prototipo/src')]
    trusted(args.spool.parent, directory=True); trusted(args.socket.parent, directory=True)
    if args.base.parent != Path('/var/tmp') or not re.fullmatch(r'c113-[0-9a-f]{12}', args.base.name): parser.error('Stage no admitido.')
    if not 1 <= args.panel_uid < 65530: parser.error('Principal del panel no admitido.')
    serve(OperatorQueue(args.base, args.spool, args.panel_uid, args.accounts), args.socket)


if __name__ == '__main__': main()
