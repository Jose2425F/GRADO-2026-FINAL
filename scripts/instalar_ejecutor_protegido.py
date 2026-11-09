#!/usr/bin/env python3
"""Instalación privada del operador y control cerrado de sus cinco bancos.

El panel sólo utiliza prepare/status/recover/down sobre un stage instalado.
La acción install es exclusiva de la consola root y recibe entradas fijadas por
SHA-256. No instala servicios, no cambia Nginx y nunca usa el Docker global.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time

BANKS = ('integrado', 'sucursal', 'comercial', 'mixto', 'reforzado')
COUNTS = dict(zip(BANKS, (12, 8, 10, 12, 14)))
IMAGES = ('novaflow-lab-credentials:local', 'novaflow-lab-protocol:local',
          'novaflow-lab-http:local', 'auditoria-lab-v2-app:local', 'postgres:16-alpine')
SHA = re.compile(r'[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
BASE_NAME = re.compile(r'c113-[0-9a-f]{12}')
DOCKER = '/usr/bin/docker'
ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_DIRECTORY = None


class InstallError(RuntimeError):
    """Los códigos cerrados son seguros para el stdout público del control."""


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def trusted(path, *, directory=False, private=False):
    path = Path(path)
    for current in (path, *path.parents):
        info = current.lstat()
        sticky = (current != path and stat.S_ISDIR(info.st_mode)
                  and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX))
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or (info.st_mode & 0o022 and not sticky):
            raise InstallError('untrusted_installation_path')
    info = path.stat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise InstallError('invalid_installation_file_type')
    if private and info.st_mode & 0o077:
        raise InstallError('private_permissions_required')
    return path


def stage_path(value):
    path = Path(value)
    if path.parent != Path('/var/tmp') or not BASE_NAME.fullmatch(path.name):
        raise InstallError('invalid_stage')
    return path


def kernel_ok():
    try:
        value = int(Path('/proc/sys/kernel/tainted').read_text())
    except (OSError, ValueError):
        raise InstallError('kernel_state_unavailable') from None
    if value & ((1 << 7) | (1 << 14)):
        raise InstallError('kernel_failure')
    return value


def private_json(path, data):
    path = Path(path)
    trusted(path.parent, directory=True)
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(5))
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run(argv, *, env=None, timeout=60):
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                   'LC_ALL': 'C.UTF-8', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    if env:
        environment.update(env)
    value = subprocess.run([str(x) for x in argv], capture_output=True, text=True,
                           timeout=timeout, env=environment)
    if value.returncode:
        # Docker/Compose diagnostics may contain synthetic environment values.
        # The caller gets a stable code; raw stderr is never forwarded to panel.
        if DIAGNOSTIC_DIRECTORY is not None:
            private_json(DIAGNOSTIC_DIRECTORY / ('command-error-' + secrets.token_hex(6) + '.json'),
                         {'argv':[str(x) for x in argv], 'exit_code':value.returncode,
                          'stdout':value.stdout[-64000:], 'stderr':value.stderr[-64000:],
                          'private_installation_diagnostic_not_for_public_export':True})
        raise InstallError('operator_command_failed')
    return value.stdout


def load_manifest(path, expected):
    if not isinstance(expected, str) or not SHA.fullmatch(expected):
        raise InstallError('manifest_hash_required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8_000_000:
            raise InstallError('invalid_manifest')
        raw = source.read()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise InstallError('manifest_hash_mismatch')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise InstallError('invalid_manifest')
    return data


def source_name(value):
    if not isinstance(value, str):
        raise InstallError('invalid_source_manifest_path')
    path = PurePosixPath(value)
    forbidden = {'.git', 'node_modules', '__pycache__', 'corridas', 'archivo_corridas', 'runtime', 'private'}
    if (not isinstance(value, str) or path.is_absolute() or not value
            or path.as_posix() != value or any(p in {'', '.', '..'} for p in value.split('/'))
            or any(p in forbidden or p.startswith(('.venv', '.lab')) for p in path.parts)
            or path.name == '.env' or path.suffix.lower() == '.docx'):
        raise InstallError('invalid_source_manifest_path')
    return path


def copy_sources(source, destination, mapping):
    if not mapping or any(not isinstance(h, str) or not SHA.fullmatch(h) for h in mapping.values()):
        raise InstallError('invalid_source_manifest')
    destination.mkdir(mode=0o700)
    for name, expected in sorted(mapping.items()):
        relative = source_name(name)
        target = destination / relative
        descriptor = os.open(source / relative, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise InstallError('source_not_regular')
            data = stream.read()
        if hashlib.sha256(data).hexdigest() != expected:
            raise InstallError('source_changed_during_install')
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o555 if info.st_mode & 0o111 else 0o444)
    for path in sorted(destination.rglob('*'), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    destination.chmod(0o555)


def protect_tree(path):
    for entry in sorted(path.rglob('*'), reverse=True):
        if entry.is_symlink():
            continue
        entry.chmod(0o555 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o444)
    path.chmod(0o555)


def venv_inventory(folder):
    """Mapa puro para fijar el entorno validado antes de llamar al instalador."""
    result = {}
    for parent, directories, files in os.walk(folder, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in {'__pycache__', 'lib64'})
        for name in sorted(files):
            if name.endswith('.pyc'): continue
            path = Path(parent) / name
            if not path.is_file(): raise InstallError('venv_contains_nonregular_file')
            result[path.relative_to(folder).as_posix()] = digest(path)
    return result


def copy_bytes(source, target):
    """No propaga xattrs/capabilities ni bits setuid del entorno de origen."""
    shutil.copyfile(source, target)
    os.chmod(target, 0o755 if os.stat(source).st_mode & 0o111 else 0o644)
    return target


def copy_python(venv, interpreter, stdlib, base, staging, *, expected_venv=None):
    """Copia bytes; ningún enlace de ejecución queda bajo el HOME del operador."""
    interpreter = trusted(Path(interpreter).resolve())
    stdlib = trusted(Path(stdlib).resolve(), directory=True)
    python = staging / 'python'
    (python / 'bin').mkdir(parents=True, mode=0o700)
    (python / 'lib').mkdir(mode=0o700)
    shutil.copyfile(interpreter, python / 'bin/python3.13')
    (python / 'bin/python3.13').chmod(0o555)
    shutil.copytree(stdlib, python / 'lib/python3.13', symlinks=False, copy_function=copy_bytes,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'site-packages', 'dist-packages'))
    target = staging / 'venv'
    shutil.copytree(venv, target, symlinks=False, copy_function=copy_bytes,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'lib64'))
    actual_venv = venv_inventory(target)
    if expected_venv is not None and actual_venv != expected_venv:
        raise InstallError('venv_changed_since_validation')
    removed = []
    for path in list(target.rglob('*.pth')) + list(target.rglob('__editable__*')):
        if path.is_file():
            removed.append(str(path.relative_to(target))); path.unlink()
    for path in target.rglob('direct_url.json'):
        removed.append(str(path.relative_to(target))); path.unlink()
    for name in ('python', 'python3', 'python3.13'):
        path = target / 'bin' / name
        path.unlink(missing_ok=True)
        path.symlink_to(base / 'python/bin/python3.13')
    (target / 'pyvenv.cfg').write_text('home = ' + str(base / 'python/bin') +
                                     '\ninclude-system-site-packages = false\nversion = 3.13.15\n')
    package = target / 'lib/python3.13/site-packages/auditoria'
    if package.exists():
        if package.is_dir(): shutil.rmtree(package)
        else: package.unlink()
    package.symlink_to(base / 'repo/piloto_kali/prototipo/src/auditoria', target_is_directory=True)
    for path in (target / 'bin').iterdir():
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if data.startswith(b'#!') and b'python' in data.split(b'\n', 1)[0]:
            path.write_bytes(b'#!' + str(base / 'venv/bin/python').encode() + b'\n' + data.split(b'\n', 1)[1])
    protect_tree(python); protect_tree(target)
    return {'python': python, 'venv': target, 'removed_editable_or_pth': sorted(removed),
            'interpreter_source': str(interpreter), 'interpreter_sha256': digest(interpreter),
            'validated_venv_files': len(actual_venv), 'venv_manifest_matched': expected_venv is not None}


def archive_images(path, expected_hash, expected_images):
    if (set(expected_images) != set(IMAGES)
            or any(not isinstance(x, str) or not IMAGE_ID.fullmatch(x) for x in expected_images.values())
            or not isinstance(expected_hash, str) or not SHA.fullmatch(expected_hash)):
        raise InstallError('invalid_image_registry')
    if digest(path) != expected_hash:
        raise InstallError('image_archive_hash_mismatch')
    # Read metadata only; never extract a caller-controlled TAR into the host.
    with tarfile.open(path, 'r:') as archive:
        member = archive.getmember('manifest.json')
        if not member.isfile() or member.size > 1_000_000:
            raise InstallError('invalid_image_archive')
        rows = json.load(archive.extractfile(member))
        if not isinstance(rows, list) or len(rows) != len(IMAGES) or any(not isinstance(row, dict) for row in rows):
            raise InstallError('invalid_image_archive')
        actual = set()
        for row in rows:
            config = row.get('Config')
            if not isinstance(config, str) or PurePosixPath(config).is_absolute() or '..' in PurePosixPath(config).parts:
                raise InstallError('invalid_image_archive')
            item = archive.getmember(config)
            if not item.isfile() or item.size > 10_000_000:
                raise InstallError('invalid_image_archive')
            actual.add('sha256:' + hashlib.sha256(archive.extractfile(item).read()).hexdigest())
    if actual != set(expected_images.values()):
        raise InstallError('image_archive_registry_mismatch')
    return {'sha256': expected_hash, 'bytes': Path(path).stat().st_size, 'images': expected_images}


def load_stage(base, *, code=True):
    base = stage_path(base)
    trusted(base, directory=True); trusted(base / 'private', directory=True, private=True)
    data = json.loads(trusted(base / 'private/bootstrap.json', private=True).read_text())
    if (data.get('namespace') != base.name or data.get('root') != str(base)
            or data.get('protected_repo') != str(base / 'repo')
            or data.get('docker_host') != 'unix://' + str(base / 'private/docker.sock')):
        raise InstallError('bootstrap_identity_mismatch')
    if code:
        expected = base / 'repo/scripts/instalar_ejecutor_protegido.py'
        if Path(__file__).resolve() != expected:
            raise InstallError('control_requires_installed_code')
        trusted(expected); trusted(base / 'repo', directory=True)
    if Path('/run/netns', data['namespace']).stat().st_ino != data['network_namespace_inode']:
        raise InstallError('namespace_identity_changed')
    sock = base / 'private/docker.sock'
    info = sock.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise InstallError('daemon_socket_not_private')
    return data


def docker(base, *args, timeout=60):
    # Public control validates its installed entry once, before this helper.
    # Initial installation also calls it from the reviewed operator installer.
    manifest = load_stage(base, code=False)
    return run([DOCKER, '--host', manifest['docker_host'], *args], timeout=timeout)


@contextmanager
def operator_lock(base):
    path = base / 'private/operator-run.lock'
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError('operator_lock_identity_changed')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError('stage_busy') from None
        yield
    finally:
        os.close(descriptor)


def bank_record(base, bank):
    if bank not in BANKS:
        raise InstallError('invalid_bank')
    path = base / 'private' / ('bank-' + bank + '.json')
    data = json.loads(trusted(path, private=True).read_text())
    if data.get('bank') != bank or data.get('stage') != str(base) or len(data.get('containers', [])) != COUNTS[bank]:
        raise InstallError('bank_registry_invalid')
    return data


def inspect_owned(base, record):
    rows = []
    template = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}}}'
    for item in record['containers']:
        if not re.fullmatch(r'[0-9a-f]{64}', item.get('id', '')):
            raise InstallError('bank_registry_invalid')
        actual = json.loads(docker(base, 'container', 'inspect', '--format', template, item['id']))
        if any(actual[key] != item[key] for key in ('id', 'name', 'image')):
            raise InstallError('container_identity_changed')
        rows.append(actual)
    return rows


def quarantine_count(base, bank, record):
    folder = base / 'runtime/segment-locks' / bank
    if not folder.exists():
        return 0
    info = folder.lstat()
    if (folder.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 65531 or info.st_gid != 65531
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise InstallError('quarantine_directory_invalid')
    return sum(os.path.lexists(folder / (hashlib.sha256(segment.encode()).hexdigest() + '.json'))
               for segment in record['segments'])


def response(bank, action, *, state, active=0, quarantines=0, ok=True, error=None, running=None):
    row = {'schema': 'centinela-stage-control/1', 'ok': ok, 'action': action, 'bank': bank,
           'state': state, 'active_count': active, 'quarantine_count': quarantines,
           'quarantined': quarantines > 0}
    if error: row['error_code'] = error
    if running is not None: row['running_containers'] = running
    return row


def add_imports(base):
    sys.path[:0] = [str(base / 'repo/scripts'), str(base / 'repo/piloto_kali/prototipo/src')]


def audit_processes(record):
    namespace = record['audit_namespace']
    if (not re.fullmatch(r'c113a_[0-9a-f]{8}', namespace)
            or Path('/run/netns', namespace).stat().st_ino != record['audit_namespace_inode']):
        raise InstallError('audit_namespace_identity_changed')
    return run(['/usr/sbin/ip', 'netns', 'pids', namespace]).split()


def control(base, bank, action):
    manifest = load_stage(base)
    if manifest.get('status') != 'prepared':
        raise InstallError('stage_not_prepared')
    if bank not in BANKS or action not in {'prepare', 'status', 'recover', 'down'}:
        raise InstallError('invalid_control_action')
    record = bank_record(base, bank)
    quarantines = quarantine_count(base, bank, record)
    try:
        with operator_lock(base):
            if action != 'status': kernel_ok()
            audit_pids = audit_processes(record)
            if audit_pids:
                if action == 'status':
                    return response(bank, action, state='active_or_orphaned', active=1,
                                    quarantines=quarantines)
                raise InstallError('audit_namespace_not_idle')
            actual = inspect_owned(base, record)
            if action == 'down':
                ids = [row['id'] for row in actual if row['running']]
                if ids: docker(base, 'container', 'stop', '--time', '5', *ids, timeout=90)
            elif action == 'prepare':
                ids = [row['id'] for row in actual if not row['running']]
                if ids: docker(base, 'container', 'start', *ids, timeout=90)
                add_imports(base)
                from tesis.red_auditoria import refresh_bank_live
                refresh_bank_live(record['network_receipt'])
            elif action == 'recover':
                add_imports(base)
                launcher = importlib.import_module('ejecutar_protegido')
                if launcher.ROOT != base / 'repo':
                    raise InstallError('launcher_not_from_stage')
                launcher.recover_protocols(base, bank)
            actual = inspect_owned(base, record)
            quarantines = quarantine_count(base, bank, record)
            running = sum(row['running'] for row in actual)
            state = 'quarantined' if quarantines else 'prepared' if running == COUNTS[bank] else 'stopped' if running == 0 else 'partial'
            return response(bank, action, state=state, quarantines=quarantines, running=running)
    except InstallError as error:
        if str(error) == 'stage_busy':
            return response(bank, action, state='busy', active=1, quarantines=quarantines,
                            ok=action == 'status', error=None if action == 'status' else 'stage_busy')
        raise


def daemon_supervisor(base):
    """Sólo se llama dentro del NETNS y un mount namespace privados nuevos."""
    trusted(base, directory=True)
    private = trusted(base / 'private', directory=True, private=True)
    config = json.loads(trusted(private / 'daemon-config.json', private=True).read_text())
    if os.readlink('/proc/self/ns/net') == config['host_netns']:
        raise InstallError('daemon_must_not_use_host_network')
    run(['/usr/bin/mount', '--make-rprivate', '/'])
    run(['/usr/bin/mount', '-t', 'cgroup2', 'none', '/sys/fs/cgroup'])
    (private / 'containerd.toml').write_text('version = 2\ndisabled_plugins = ["io.containerd.grpc.v1.cri"]\n')
    stream = (private / 'containerd.log').open('wb')
    containerd = subprocess.Popen(['/usr/bin/containerd', '--config', str(private / 'containerd.toml'),
        '--root', str(private / 'containerd-data'), '--state', str(private / 'containerd-state'),
        '--address', str(private / 'containerd.sock')], stdout=stream, stderr=subprocess.STDOUT,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    daemon = None
    def stop(*unused):
        stop_services(daemon, containerd)
        raise SystemExit(0)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(sig, stop)
    try:
        deadline = time.monotonic() + 25
        while not (private / 'containerd.sock').exists():
            if containerd.poll() is not None or time.monotonic() > deadline:
                raise InstallError('private_containerd_unavailable')
            time.sleep(0.1)
        daemon = subprocess.Popen(config['daemon'], stdout=sys.stdout, stderr=sys.stderr,
                                  env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
        private_json(private / 'child-pids.json', {'containerd': containerd.pid, 'dockerd': daemon.pid})
        code = daemon.wait()
    finally:
        if containerd.poll() is None: containerd.terminate(); containerd.wait(timeout=20)
    return code


def stop_services(daemon, containerd):
    # Docker still needs containerd to terminate its own container tasks.
    # Never stop the runtime before Docker has finished its shutdown.
    for child in (daemon, containerd):
        if child is None or child.poll() is not None: continue
        child.terminate()
        try: child.wait(timeout=30)
        except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=5)


def fixture_permissions(state):
    """Únicamente código público montado; los secretos siguen root0600."""
    state = trusted(state, directory=True, private=True)
    trusted(state / 'http_target.py').chmod(0o444)
    protocol = trusted(state / 'protocol', directory=True)
    expected = {'receiver.py', 'sender.py', 'radvd.conf'}
    if {path.name for path in protocol.iterdir()} != expected:
        raise InstallError('unexpected_protocol_fixture_file')
    for name in expected: trusted(protocol / name).chmod(0o444)
    protocol.chmod(0o555)


def expected_bank(base, bank, lab):
    names = sorted(name for _, _, members in lab.NETWORKS.values() for name in members)
    if len(names) != COUNTS[bank]: raise InstallError('catalog_count_changed')
    private_json(base / 'private' / ('expected-' + bank + '.json'), {'bank':bank, 'names':names})
    return names


def stop_new_banks(base, images):
    """Rollback sólo de los IDs y nombres de este daemon nuevo y sus catálogos."""
    expected = set()
    for bank in BANKS:
        path = base / 'private' / ('expected-' + bank + '.json')
        if path.exists():
            row = json.loads(trusted(path, private=True).read_text())
            if row.get('bank') != bank or len(row.get('names', [])) != COUNTS[bank]:
                raise InstallError('rollback_registry_invalid')
            expected.update(row['names'])
    ids = docker(base, 'ps', '-aq', '--no-trunc').splitlines()
    checked = []
    template = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}}}'
    for cid in ids:
        if not SHA.fullmatch(cid): raise InstallError('rollback_registry_invalid')
        row = json.loads(docker(base, 'container', 'inspect', '--format', template, cid))
        if row['id'] != cid or row['name'].removeprefix('/') not in expected or row['image'] not in images.values():
            raise InstallError('rollback_unregistered_container')
        if row['running']: checked.append(cid)
    if checked: docker(base, 'container', 'stop', '--time', '2', *checked, timeout=120)
    return {'registered_containers':len(ids), 'stop_requested_for':checked}


def topology(base, bank, container_names, networks):
    """Inspección cerrada; no expone Config.Env ni ejecuta comandos en el activo."""
    manifest = load_stage(base)
    ns = manifest['namespace']
    links = json.loads(run(['/usr/sbin/ip', '-n', ns, '-j', 'link', 'show']))
    addresses = json.loads(run(['/usr/sbin/ip', '-n', ns, '-j', 'addr', 'show']))
    containers = []
    template = '{"name":{{json .Name}},"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"networks":{{json .NetworkSettings.Networks}}}'
    for name in sorted(container_names):
        row = json.loads(docker(base, 'container', 'inspect', '--format', template, name))
        if not row['running']: raise InstallError('new_container_not_running')
        for kind, command in [('links', ['link', 'show']), ('addresses', ['addr', 'show'])]:
            row[kind] = json.loads(run(['/usr/bin/nsenter', '--target', str(row['pid']), '--net',
                                        '/usr/sbin/ip', '-j', *command]))
        containers.append(row)
    nets = []
    template = '{"name":{{json .Name}},"id":{{json .Id}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"ipam":{{json .IPAM.Config}},"options":{{json .Options}},"containers":{{json .Containers}}}'
    for name in sorted(networks):
        row = json.loads(docker(base, 'network', 'inspect', '--format', template, name))
        if not row['internal']: raise InstallError('network_not_internal')
        nets.append(row)
    return {'schema': 'centinela-isolated-topology/2', 'scenario': bank, 'namespace': ns,
            'docker_host': manifest['docker_host'], 'containers': containers, 'networks': nets,
            'namespace_links': links, 'namespace_addresses': addresses}


def prepare_initial_bank(base, bank):
    """Primera creación: sólo daemon nuevo; luego no se regenera el banco."""
    manifest = load_stage(base)
    kernel_ok(); add_imports(base)
    os.environ['DOCKER_HOST'] = manifest['docker_host']
    if bank == 'integrado':
        from auditoria import lab_empresa as lab
        from tesis.restauracion_banco import prepare_images, _restore_pinned
        state = base / 'repo/piloto_kali/prototipo/.lab-empresa'
        state.mkdir(mode=0o700)
        lab.prepare(state); expected_bank(base, bank, lab)
        prepare_images(state); _restore_pinned(state)
    else:
        from tesis.laboratorios import Context
        ctx = Context(bank); lab = ctx.lab; state = ctx.state
        ctx.prepare()
        fixture_permissions(state); expected_bank(base, bank, lab)
        data = json.loads(lab.COMPOSE.read_text())
        for service in data['services'].values():
            service['image'] = manifest['images'][service['image']]
            service['pull_policy'] = 'never'; service.pop('build', None)
        private_json(lab.COMPOSE, data)
        docker(base, 'compose', '--env-file', str(state / 'lab.env'), '-f', str(lab.COMPOSE),
               'up', '-d', '--no-build', '--pull', 'never', timeout=180)
        saved = json.loads((state / 'prepared.json').read_text())
        names = sorted(name for _, _, members in lab.NETWORKS.values() for name in members)
        saved['images'] = {name: json.loads(docker(base, 'container', 'inspect', '--format', '{{json .Image}}', name)) for name in names}
        saved['source_sha256'] = ctx.fingerprint()
        private_json(state / 'prepared.json', saved)
    expected = sorted(name for _, _, members in lab.NETWORKS.values() for name in members)
    if len(expected) != COUNTS[bank]: raise InstallError('catalog_count_changed')
    data = topology(base, bank, expected, lab.NETWORKS)
    for row in data['containers']:
        if row['image'] not in manifest['images'].values(): raise InstallError('container_image_not_pinned')
    target = base / 'private' / ('topologia-' + bank + '.json'); private_json(target, data)
    from tesis.red_auditoria import prepare_bank
    network_dir = base / 'private' / ('audit-' + bank + '-installed')
    network = prepare_bank(bank, target, network_dir)
    record = {'bank': bank, 'stage': str(base), 'state_directory': str(state),
              'containers': [{k:row[k] for k in ('id', 'name', 'image')} for row in data['containers']],
              'segments': sorted(bridge for bridge, _, _ in lab.NETWORKS.values()),
              'network_receipt': str(network_dir / 'receipt.json'),
              'audit_namespace': network['namespace'], 'audit_namespace_inode': network['namespace_inode']}
    private_json(base / 'private' / ('bank-' + bank + '.json'), record)
    return record


def nft_boundary_digest():
    """Consulta inmutable con libnftables; no requiere instalar el CLI nft."""
    library = ctypes.CDLL('libnftables.so.1')
    library.nft_ctx_new.argtypes = [ctypes.c_int]; library.nft_ctx_new.restype = ctypes.c_void_p
    library.nft_ctx_free.argtypes = [ctypes.c_void_p]
    library.nft_ctx_buffer_output.argtypes = [ctypes.c_void_p]
    library.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
    library.nft_ctx_output_set_flags.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    library.nft_ctx_input_set_flags.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    library.nft_ctx_get_output_buffer.argtypes = [ctypes.c_void_p]
    library.nft_ctx_get_output_buffer.restype = ctypes.c_char_p
    library.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.nft_run_cmd_from_buffer.restype = ctypes.c_int
    context = library.nft_ctx_new(0)
    if not context: raise InstallError('host_firewall_snapshot_unavailable')
    try:
        library.nft_ctx_buffer_output(context); library.nft_ctx_buffer_error(context)
        library.nft_ctx_input_set_flags(context, 1)  # NFT_CTX_INPUT_NO_DNS
        # libnftables.h: STATELESS=1<<2, JSON=1<<4. Only counters/runtime
        # state are omitted; the rule definitions remain part of the digest.
        library.nft_ctx_output_set_flags(context, (1 << 2) | (1 << 4))
        if library.nft_run_cmd_from_buffer(context, b'list ruleset\n'):
            raise InstallError('host_firewall_snapshot_unavailable')
        data = json.loads(library.nft_ctx_get_output_buffer(context) or b'{}')
        raw = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()
    finally:
        library.nft_ctx_free(context)


def host_boundary():
    return {'network_namespace': os.readlink('/proc/self/ns/net'),
            'routes4': json.loads(run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])),
            'routes6': json.loads(run(['/usr/sbin/ip', '-j', '-6', 'route', 'show', 'table', 'all'])),
            'nft_stateless_sha256': nft_boundary_digest()}


def namespace_defaults(base):
    """Los bridges futuros tampoco aprenden rutas por RA del propio banco."""
    base = stage_path(base)
    run(['/usr/sbin/ip', 'netns', 'exec', base.name, '/usr/sbin/sysctl', '-qw',
         'net.ipv4.ip_forward=0', 'net.ipv6.conf.all.forwarding=0',
         'net.ipv6.conf.all.accept_ra=0', 'net.ipv6.conf.default.accept_ra=0',
         'net.ipv6.conf.all.autoconf=0', 'net.ipv6.conf.default.autoconf=0',
         'net.ipv6.conf.all.router_solicitations=0', 'net.ipv6.conf.default.router_solicitations=0'])


def install(args):
    global DIAGNOSTIC_DIRECTORY
    kernel_ok(); base = stage_path(args.stage)
    mapping = load_manifest(args.source_map, args.source_map_sha256)
    expected_venv = load_manifest(args.venv_map, args.venv_map_sha256)
    if not expected_venv or any(not isinstance(h, str) or not SHA.fullmatch(h) for h in expected_venv.values()):
        raise InstallError('invalid_venv_manifest')
    images = load_manifest(args.images_json, args.images_json_sha256)
    archive = archive_images(args.archive, args.archive_sha256, images)
    if base.exists() or base.is_symlink(): raise InstallError('stage_already_exists')
    before = host_boundary()
    base.mkdir(mode=0o755); base.chmod(0o755)
    private = base / 'private'; private.mkdir(mode=0o700)
    DIAGNOSTIC_DIRECTORY = private
    staging = private / 'staging'; staging.mkdir(mode=0o700)
    backups = private / 'backups'; backups.mkdir(mode=0o700)
    private_json(backups / 'host-boundary-before.json', before)
    metadata = {'schema': 'centinela-isolated-bootstrap/2', 'root': str(base), 'namespace': base.name,
                'protected_repo': str(base / 'repo'), 'protected_venv': str(base / 'venv'),
                'docker_host': 'unix://' + str(private / 'docker.sock'), 'images': images,
                'image_archive': archive, 'created_at': datetime.now(timezone.utc).isoformat(),
                'source_manifest_sha256': args.source_map_sha256, 'operator_uid': 0,
                'role_uids': {'provider':65530, 'controller':65531, 'nmap':65532, 'hydra':65533},
                'status': 'installing', 'global_configuration_replaced': False}
    private_json(private / 'bootstrap.json', metadata)
    supervisor = None
    try:
        copy_sources(Path(args.source), staging / 'repo', mapping)
        copied = copy_python(Path(args.venv), args.python, args.stdlib, base, staging,
                             expected_venv=expected_venv)
        for name in ('repo', 'python', 'venv'):
            os.rename(staging / name, base / name)
        pilot = base / 'repo/piloto_kali/prototipo'
        (pilot / '.venv').symlink_to(base / 'venv', target_is_directory=True)
        private_json(private / 'source-map.json', mapping)
        private_json(private / 'python-copy.json', {k:str(v) if isinstance(v, Path) else v for k,v in copied.items()})
        code = 'import sys,json,auditoria;print(json.dumps({"prefix":sys.prefix,"base_prefix":sys.base_prefix,"paths":sys.path,"package":auditoria.__file__}))'
        checked = json.loads(run([base / 'venv/bin/python', '-I', '-B', '-c', code]))
        if (checked['base_prefix'] != str(base / 'python') or checked['prefix'] != str(base / 'venv')
                or any('/home/' in path for path in checked['paths'])):
            raise InstallError('python_still_uses_mutable_external_path')
        private_json(private / 'python-runtime.json', checked)
        run(['/usr/sbin/ip', 'netns', 'add', base.name])
        namespace_defaults(base)
        run(['/usr/sbin/ip', '-n', base.name, 'link', 'set', 'lo', 'up'])
        metadata['network_namespace_inode'] = Path('/run/netns', base.name).stat().st_ino
        command = ['/usr/sbin/dockerd', '--data-root', str(private / 'docker-data'),
            '--exec-root', str(private / 'exec'), '--pidfile', str(private / 'dockerd.pid'),
            '--host', metadata['docker_host'], '--bridge', 'none', '--iptables=false', '--ip6tables=false',
            '--ip-forward=false', '--ip-masq=false', '--userland-proxy=false',
            '--containerd', str(private / 'containerd.sock'), '--containerd-namespace', base.name,
            '--containerd-plugins-namespace', base.name + 'p', '--exec-opt', 'native.cgroupdriver=cgroupfs',
            '--cgroup-parent', '/' + base.name]
        private_json(private / 'daemon-config.json', {'daemon': command, 'host_netns': before['network_namespace']})
        log = (private / 'daemon.log').open('wb')
        script = base / 'repo/scripts/instalar_ejecutor_protegido.py'
        argv = ['/usr/sbin/ip', 'netns', 'exec', base.name, '/usr/bin/unshare', '--mount', '--propagation', 'private',
                '/usr/bin/python3', '-I', '-B', str(script), '--stage', str(base), '--internal-supervisor']
        supervisor = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        deadline = time.monotonic() + 60
        while True:
            if supervisor.poll() is not None: raise InstallError('isolated_daemon_failed')
            try:
                run([DOCKER, '--host', metadata['docker_host'], 'version', '--format', '{{.Server.Version}}'])
                break
            except (InstallError, subprocess.TimeoutExpired):
                if time.monotonic() > deadline: raise InstallError('isolated_daemon_timeout')
                time.sleep(0.25)
        os.chmod(private / 'docker.sock', 0o600)
        metadata['supervisor_pid'] = supervisor.pid
        metadata['supervisor_start_time'] = Path('/proc', str(supervisor.pid), 'stat').read_text().split()[21]
        metadata['daemon_command'] = command
        private_json(private / 'bootstrap.json', metadata)
        # A protected copy closes the TAR check/use race before the daemon reads it.
        protected_archive = private / 'images.tar'
        shutil.copyfile(args.archive, protected_archive); protected_archive.chmod(0o600)
        if digest(protected_archive) != args.archive_sha256: raise InstallError('image_archive_changed_during_copy')
        docker(base, 'image', 'load', '--input', str(protected_archive), timeout=240)
        loaded = set(docker(base, 'image', 'ls', '--no-trunc', '--format', '{{.ID}}').splitlines())
        if loaded != set(images.values()): raise InstallError('loaded_image_inventory_mismatch')
        for name, image in images.items():
            docker(base, 'image', 'tag', image, name)
        rows = []
        for bank in BANKS:
            available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))) * 1024
            if available < 768 * 1024 * 1024: raise InstallError('insufficient_memory_for_bank')
            argv = [base / 'venv/bin/python', '-I', '-B', script, '--stage', base, '--bank', bank, '--internal-prepare']
            raw = run(argv, env={'DOCKER_HOST':metadata['docker_host']}, timeout=300)
            rows.append(json.loads(raw))
        for family in ('-4', '-6'):
            routes = json.loads(run(['/usr/sbin/ip', '-n', base.name, '-j', family, 'route', 'show', 'table', 'all']))
            if any(row.get('dst') == 'default' for row in routes): raise InstallError('isolated_default_route_found')
        after = host_boundary(); private_json(backups / 'host-boundary-after.json', after)
        if before != after: raise InstallError('host_network_boundary_changed')
        metadata.update(status='prepared', banks=list(BANKS), containers=sum(COUNTS.values()),
                        no_external_default_route=True, host_network_configuration_unchanged=True,
                        finished_at=datetime.now(timezone.utc).isoformat())
        private_json(private / 'bootstrap.json', metadata)
        return {'schema':'centinela-stage-install/1', 'ok':True, 'stage':str(base), 'state':'prepared',
                'banks':list(BANKS), 'containers':sum(COUNTS.values()), 'source_manifest_sha256':args.source_map_sha256}
    except BaseException as error:
        metadata.update(status='failed', error_code=str(error) if isinstance(error, InstallError) else type(error).__name__,
                        evidence_preserved=True)
        private_json(private / 'bootstrap.json', metadata)
        # Preserve private state and namespaces for operator inspection. Never
        # run a broad Docker cleanup or delete historical data on a failed install.
        rollback = {'existing_configuration_replaced':False, 'private_state_and_namespaces_preserved':True}
        if supervisor is not None and supervisor.poll() is None:
            try: rollback['containers'] = stop_new_banks(base, images)
            except Exception as cleanup_error:
                rollback['container_cleanup_error'] = str(cleanup_error) if isinstance(cleanup_error, InstallError) else type(cleanup_error).__name__
            supervisor.terminate()
            try: supervisor.wait(timeout=45)
            except subprocess.TimeoutExpired: pass
        rollback['new_supervisor_stopped'] = supervisor is None or supervisor.poll() is not None
        metadata['rollback'] = rollback
        private_json(private / 'bootstrap.json', metadata)
        raise


def main(argv=None):
    global DIAGNOSTIC_DIRECTORY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--bank', choices=BANKS)
    parser.add_argument('--action', choices=('install','prepare','status','recover','down'))
    for name in ('source','source-map','venv-map','images-json','archive','venv','python','stdlib'):
        parser.add_argument('--' + name, type=Path)
    for name in ('source-map-sha256','venv-map-sha256','images-json-sha256','archive-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--internal-supervisor', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--internal-prepare', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if os.geteuid() != 0: parser.error('Esta entrada corresponde exclusivamente al operador root.')
    os.umask(0o077)
    try:
        base = stage_path(args.stage)
        if args.internal_supervisor:
            trusted(__file__); return daemon_supervisor(base)
        if args.internal_prepare:
            load_stage(base)
            if args.bank not in BANKS: raise InstallError('invalid_bank')
            DIAGNOSTIC_DIRECTORY = base / 'private'
            value = prepare_initial_bank(base, args.bank)
            print(json.dumps({'bank':args.bank,'containers':len(value['containers']),'prepared':True})); return 0
        if args.action == 'install':
            if any(getattr(args, name.replace('-', '_')) is None for name in
                   ('source','source-map','source-map-sha256','venv-map','venv-map-sha256','images-json','images-json-sha256','archive','archive-sha256','venv','python','stdlib')):
                raise InstallError('install_inputs_required')
            result = install(args)
        else:
            result = control(base, args.bank, args.action)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result['ok'] else 3
    except (InstallError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, InstallError) else 'operator_validation_failed'
        quarantines = 0
        known = False
        if args.action in {'prepare','status','recover','down'} and args.bank in BANKS:
            try:
                base = stage_path(args.stage)
                quarantines = quarantine_count(base, args.bank, bank_record(base, args.bank))
                known = True
            except (InstallError, OSError, ValueError, KeyError):
                pass
        value = response(args.bank, args.action, state='quarantined' if quarantines else 'failed',
                         quarantines=quarantines, ok=False, error=code)
        value['quarantine_state_known'] = known
        print(json.dumps(value))
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
