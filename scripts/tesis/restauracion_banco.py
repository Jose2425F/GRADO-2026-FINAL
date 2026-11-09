"""Restaura únicamente el banco integrado con imágenes locales fijadas por ID.

La preparación inicial puede resolver tags locales. Una restauración posterior
nunca construye, descarga ni vuelve a resolverlos para cambiar la referencia.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from uuid import uuid4

import yaml
from auditoria.lab import LabError
from .laboratorios import private_json

PIN_NAME = 'images-pinned.json'
COMPOSE_NAME = 'compose-pinned.json'
RECEIPT_NAME = 'restoration-images.json'
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
ISOLATED_PROJECT = 'novaflow-integrado-fijo'
DOCKER_ID = re.compile(r'[0-9a-f]{64}')


def kernel_ok():
    if int(Path('/proc/sys/kernel/tainted').read_text()) & ((1 << 7) | (1 << 14)):
        raise LabError('kernel_failure')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path):
    if path.is_symlink() or path.stat().st_size > 1_000_000:
        raise LabError('image_reference_invalid')
    return json.loads(path.read_text())


def _definition():
    from auditoria import lab_empresa
    source = lab_empresa.COMPOSE.resolve()
    definition = yaml.safe_load(source.read_text())
    expected = {name for _, _, members in lab_empresa.NETWORKS.values() for name in members}
    services = definition.get('services', {})
    names = {service.get('container_name') for service in services.values()}
    if (definition.get('name') != 'novaflow-lab' or names != expected or len(names) != len(services)
        or not services or any(not isinstance(service.get('image'), str) for service in services.values())):
        raise LabError('owned_compose_inventory_mismatch')
    return source, definition


def _command(state, compose, source):
    return ['docker', 'compose', '--project-name', ISOLATED_PROJECT, '--project-directory', str(source.parent),
            '--env-file', str((state / 'lab.env').resolve()), '-f', str(compose.resolve())]


def _run(command, *, timeout=20, allow_missing=False):
    kernel_ok()
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    kernel_ok()
    if result.returncode and not allow_missing:
        raise LabError('local_image_or_docker_operation_failed')
    return result


@contextmanager
def _locked(state):
    state = Path(state)
    if state.is_symlink():
        raise LabError('image_reference_invalid')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state / 'images-pinned.lock'
    if lock_path.is_symlink():
        raise LabError('image_reference_invalid')
    with lock_path.open('a') as lock:
        lock_path.chmod(0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LabError('image_operation_in_progress') from None
        try:
            yield state
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _image_id(reference):
    result = _run(['docker', 'image', 'inspect', '--format', '{{.Id}}', reference])
    image = result.stdout.strip()
    if not IMAGE_ID.fullmatch(image):
        raise LabError('local_image_identity_invalid')
    return image


def _load_pin(state):
    source, definition = _definition()
    pin = _read(state / PIN_NAME)
    project = definition['name'] if pin.get('version') == 1 else ISOLATED_PROJECT
    if (pin.get('version') not in {1, 2} or pin.get('project') != project
        or pin.get('source_compose_sha256') != digest(source)
        or pin.get('fixture_sha256') != digest(state / 'lab.env')
        or pin.get('compose_sha256') != digest(state / COMPOSE_NAME)):
        raise LabError('pinned_image_reference_changed')
    expected = {service['container_name'] for service in definition['services'].values()}
    images = pin.get('images', {})
    if set(images) != expected or any(not isinstance(image, str) or not IMAGE_ID.fullmatch(image) for image in images.values()):
        raise LabError('pinned_image_inventory_invalid')
    snapshot = _read(state / COMPOSE_NAME)
    if (snapshot.get('name') != project or set(snapshot.get('services', {})) != set(definition['services'])
        or any(service.get('image') != images.get(service.get('container_name'))
               or 'build' in service or service.get('pull_policy') != 'never'
               for service in snapshot['services'].values())):
        raise LabError('pinned_compose_invalid')
    return source, {**definition, 'name': project}, pin


def _objects(kind, names):
    if not names:
        return []
    result = _run(['docker', kind, 'inspect', '--format', '{{json .}}', *sorted(names)], allow_missing=True)
    try:
        objects = [json.loads(line) for line in result.stdout.splitlines() if line]
    except (ValueError, TypeError):
        raise LabError('legacy_inventory_invalid') from None
    if any(not isinstance(obj, dict) for obj in objects):
        raise LabError('legacy_inventory_invalid')
    return objects


def _network_definition(definition):
    networks = {}
    for key, network in definition.get('networks', {}).items():
        name = network.get('name')
        members = {}
        for service in definition['services'].values():
            if key in service.get('networks', {}):
                members[service['container_name']] = service['networks'][key]
        if not name or not members or network.get('internal') is not True:
            raise LabError('legacy_network_definition_invalid')
        networks[name] = {'key': key, 'definition': network, 'members': members}
    return networks


def _validate_network(obj, expected, *, empty=False):
    spec = expected['definition']
    labels = obj.get('Labels') or {}
    endpoints = obj.get('Containers') or {}
    if (not DOCKER_ID.fullmatch(obj.get('Id', '')) or obj.get('Internal') is not True
        or obj.get('Driver') != spec.get('driver', 'bridge')
        or bool(obj.get('EnableIPv6')) != bool(spec.get('enable_ipv6', False))
        or obj.get('Options', {}).get('com.docker.network.bridge.name') !=
           spec.get('driver_opts', {}).get('com.docker.network.bridge.name')
        or {row.get('Subnet') for row in obj.get('IPAM', {}).get('Config', [])} !=
           {row.get('subnet') for row in spec.get('ipam', {}).get('config', [])}
        or labels.get('com.docker.compose.project') != 'novaflow-lab'
        or labels.get('com.docker.compose.network') != expected['key']
        or any(value.get('Name') not in expected['members'] for value in endpoints.values())
        or (empty and endpoints)):
        raise LabError('legacy_network_not_exclusively_owned')


def _validate_legacy_container(obj, definition, networks):
    services = {service['container_name']: (key, service) for key, service in definition['services'].items()}
    name = str(obj.get('Name', '')).removeprefix('/')
    if name not in services or not DOCKER_ID.fullmatch(obj.get('Id', '')):
        raise LabError('legacy_container_not_exclusively_owned')
    key, service = services[name]
    labels = obj.get('Config', {}).get('Labels') or {}
    host = obj.get('HostConfig') or {}
    settings = obj.get('NetworkSettings') or {}
    attachments = settings.get('Networks') or {}
    expected_nets = {netname: spec['members'][name] for netname, spec in networks.items() if name in spec['members']}
    caps = lambda values: {value.upper().removeprefix('CAP_') for value in (values or [])}
    if (labels.get('com.docker.compose.project') != definition['name']
        or labels.get('com.docker.compose.service') != key
        or host.get('Privileged') is not False or host.get('NetworkMode') == 'host'
        or any((host.get('PortBindings') or {}).values()) or any((settings.get('Ports') or {}).values())
        or bool(host.get('ReadonlyRootfs')) != bool(service.get('read_only', False))
        or caps(host.get('CapAdd')) != caps(service.get('cap_add'))
        or caps(host.get('CapDrop')) != caps(service.get('cap_drop'))
        or set(host.get('SecurityOpt') or []) != set(service.get('security_opt') or [])
        or set(attachments) != set(expected_nets)):
        raise LabError('legacy_container_not_exclusively_owned')
    for network, config in expected_nets.items():
        actual = attachments[network]
        for field, configured, planned in [('IPAddress', 'IPv4Address', 'ipv4_address'),
                                            ('GlobalIPv6Address', 'IPv6Address', 'ipv6_address')]:
            if planned in config and (actual.get(field) or (actual.get('IPAMConfig') or {}).get(configured)) != config[planned]:
                raise LabError('legacy_container_address_mismatch')
    return name


def _retire_legacy(state, definition, receipt, *, dry_run=False):
    """Retira solo nombres cerrados del banco; nunca opera por el proyecto compartido."""
    networks = _network_definition(definition)
    names = {service['container_name'] for service in definition['services'].values()}
    containers = _objects('container', names)
    inspected = {}
    for obj in containers:
        name = _validate_legacy_container(obj, definition, networks)
        if name in inspected:
            raise LabError('legacy_inventory_invalid')
        inspected[name] = obj['Id']
    existing = {}
    for obj in _objects('network', networks):
        name = obj.get('Name')
        if name not in networks or name in existing:
            raise LabError('legacy_inventory_invalid')
        _validate_network(obj, networks[name])
        if any(identifier not in inspected.values() for identifier in (obj.get('Containers') or {})):
            raise LabError('legacy_network_not_exclusively_owned')
        existing[name] = obj['Id']
    receipt.update(validated_containers=inspected, validated_networks=existing, status='validated')
    if dry_run:
        return receipt
    private_json(state / 'migration-images.json', receipt)
    # Todos los controles anteriores ocurren antes de la primera operación destructiva.
    if inspected:
        _run(['docker', 'container', 'rm', '--force', *sorted(inspected.values())], timeout=120)
    for name, identifier in sorted(existing.items()):
        current = _objects('network', [identifier])
        if len(current) != 1 or current[0].get('Name') != name or current[0].get('Id') != identifier:
            raise LabError('legacy_network_identity_changed')
        _validate_network(current[0], networks[name], empty=True)
        _run(['docker', 'network', 'rm', identifier], timeout=60)


def check_legacy_migration(state):
    """Consulta solo lectura para revisar el alcance exacto de una migración v1."""
    _, definition, pin = _load_pin(Path(state))
    if pin['version'] == 2:
        return {'status': 'already_isolated', 'project': ISOLATED_PROJECT}
    return _retire_legacy(Path(state), definition, {}, dry_run=True)


def _isolate_project(state):
    source, definition, pin = _load_pin(state)
    if pin['version'] == 2:
        return pin
    archive = state / ('pin-v1-' + digest(state / PIN_NAME)[:16])
    if archive.is_symlink():
        raise LabError('image_reference_invalid')
    archive.mkdir(exist_ok=True, mode=0o700)
    for filename in (PIN_NAME, COMPOSE_NAME, RECEIPT_NAME):
        if (state / filename).is_file():
            _read(state / filename)
            if not (archive / filename).exists():
                shutil.copy2(state / filename, archive / filename)
                (archive / filename).chmod(0o600)
            else:
                _read(archive / filename)
                if filename != RECEIPT_NAME and digest(archive / filename) != digest(state / filename):
                    raise LabError('archived_image_reference_changed')
    receipt = {'status': 'verifying', 'migration_id': uuid4().hex,
               'created_at': datetime.now(timezone.utc).isoformat(),
               'old_project': definition['name'], 'new_project': ISOLATED_PROJECT,
               'preserved_images': pin['images'], 'archive': archive.name}
    try:
        _retire_legacy(state, definition, receipt)
        snapshot = _read(state / COMPOSE_NAME)
        snapshot['name'] = ISOLATED_PROJECT
        private_json(state / COMPOSE_NAME, snapshot)
        upgraded = {**pin, 'version': 2, 'project': ISOLATED_PROJECT,
                    'previous_pin_sha256': digest(archive / PIN_NAME),
                    'compose_sha256': digest(state / COMPOSE_NAME),
                    'migrated_at': datetime.now(timezone.utc).isoformat()}
        private_json(state / PIN_NAME, upgraded)
        receipt['status'] = 'migrated'
        return upgraded
    except Exception as exc:
        receipt.update(status='failed', reason=str(exc) if isinstance(exc, LabError) else type(exc).__name__)
        raise
    finally:
        private_json(state / 'migration-images.json', receipt)
        private_json(state / 'image-migrations' / (receipt['migration_id'] + '.json'), receipt)


def prepare_images(state):
    """Fija una vez imágenes ya disponibles localmente; no inicia contenedores."""
    with _locked(state) as state:
        kernel_ok()
        if (state / PIN_NAME).exists():
            return _isolate_project(state)
        source, definition = _definition()
        if not (state / 'lab.env').is_file():
            raise LabError('prepare_lab_before_pinning_images')
        resolved = {reference: _image_id(reference)
                    for reference in sorted({s['image'] for s in definition['services'].values()})}
        snapshot = {key: value for key, value in definition.items() if not key.startswith('x-')}
        snapshot = json.loads(json.dumps(snapshot))
        images = {}
        for service in snapshot['services'].values():
            image = resolved[service['image']]
            images[service['container_name']] = image
            service['image'] = image
            service.pop('build', None)
            service['pull_policy'] = 'never'
        private_json(state / COMPOSE_NAME, snapshot)
        pin = {'version': 1, 'project': definition['name'], 'created_at': datetime.now(timezone.utc).isoformat(),
               'source_compose_sha256': digest(source), 'fixture_sha256': digest(state / 'lab.env'),
               'compose_sha256': digest(state / COMPOSE_NAME), 'images': images,
               'resolved_local_references': resolved, 'policy': 'immutable_local_image_ids_no_build_no_pull'}
        private_json(state / PIN_NAME, pin)
        return _isolate_project(state)


def build_images(state):
    """Construcción inicial explícita; una referencia existente no se reemplaza."""
    with _locked(state) as state:
        kernel_ok()
        if (state / PIN_NAME).exists():
            raise LabError('images_already_pinned_build_denied')
        source, _ = _definition()
        _run([*_command(state, source, source), 'build'], timeout=600)


def _containers(definition, *, allow_missing):
    names = {service['container_name'] for service in definition['services'].values()}
    owned = _run(['docker', 'ps', '--all', '--filter', 'label=com.docker.compose.project=' + definition['name'],
                  '--format', '{{.Names}}'], timeout=15)
    if any(name not in names for name in owned.stdout.splitlines() if name):
        raise LabError('owned_container_inventory_mismatch')
    fmt = '{{json .Name}}\t{{json .Image}}\t{{json .Config.Labels}}'
    result = _run(['docker', 'inspect', '--format', fmt, *sorted(names)], allow_missing=allow_missing)
    actual = {}
    expected_services = {service['container_name']: key for key, service in definition['services'].items()}
    for line in result.stdout.splitlines():
        if allow_missing and not line.strip():
            continue
        fields = line.split('\t')
        if len(fields) != 3:
            raise LabError('container_image_identity_invalid')
        name, image, labels = [json.loads(value) for value in fields]
        name = name.removeprefix('/')
        if (name not in names or name in actual or not isinstance(labels, dict)
            or labels.get('com.docker.compose.project') != definition['name']
            or labels.get('com.docker.compose.service') != expected_services[name]
            or not isinstance(image, str) or not IMAGE_ID.fullmatch(image)):
            raise LabError('foreign_or_invalid_container_identity')
        actual[name] = image
    if not allow_missing and set(actual) != names:
        raise LabError('container_image_inventory_mismatch')
    return actual


def restore_pinned(state):
    """Excluye auditorías mientras restaura y verifica también el estado de red."""
    from auditoria import lab_empresa
    from .segmentos import DEFAULT_ROOT, SegmentGuard
    def checked():
        receipt = _restore_pinned(state)
        return {"images": receipt, "preflight": lab_empresa.preflight(state)}
    proof = SegmentGuard(DEFAULT_ROOT).recover(
        [bridge for bridge, _, _ in lab_empresa.NETWORKS.values()], checked)
    return proof["images"]


def _restore_pinned(state):
    """Recrea con los IDs congelados y comprueba identidad antes/después."""
    with _locked(state) as state:
        kernel_ok()
        if not (state / PIN_NAME).is_file():
            raise LabError('prepare_local_images_before_restore')
        source, definition, pin = _load_pin(state)
        if pin['version'] != 2:
            raise LabError('prepare_images_for_isolated_project')
        receipt = {'status': 'verifying', 'baseline_sha256': digest(state / PIN_NAME),
                   'expected_images': pin['images'], 'before': {}, 'after': {}}
        try:
            for image in sorted(set(pin['images'].values())):
                if _image_id(image) != image:
                    raise LabError('pinned_image_identity_mismatch')
            receipt['before'] = _containers(definition, allow_missing=True)
            private_json(state / RECEIPT_NAME, receipt)
            _run([*_command(state, state / COMPOSE_NAME, source), 'up', '-d', '--no-build',
                  '--pull', 'never', '--force-recreate'], timeout=180)
            receipt['after'] = _containers(definition, allow_missing=False)
            if receipt['after'] != pin['images']:
                raise LabError('restored_images_do_not_match_pinned_reference')
            receipt.update(status='restored', finished_at=datetime.now(timezone.utc).isoformat())
            private_json(state / RECEIPT_NAME, receipt)
            return receipt
        except Exception as exc:
            receipt.update(status='failed', reason=str(exc) if isinstance(exc, LabError) else type(exc).__name__)
            private_json(state / RECEIPT_NAME, receipt)
            raise


def down_pinned(state):
    with _locked(state) as state:
        source, definition, pin = _load_pin(state)
        if pin['version'] != 2:
            raise LabError('prepare_images_for_isolated_project')
        _containers(definition, allow_missing=True)
        _run([*_command(state, state / COMPOSE_NAME, source), 'down', '--volumes'], timeout=180)
