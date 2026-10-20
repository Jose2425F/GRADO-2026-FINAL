from argparse import Namespace
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'piloto_kali/prototipo/src')]

from tesis import restauracion_banco as restore
from auditoria.lab import LabError


A = 'sha256:' + 'a' * 64
B = 'sha256:' + 'b' * 64
C = 'sha256:' + 'c' * 64


@pytest.fixture
def bank(tmp_path, monkeypatch):
    """Docker is entirely simulated; unrecognized subprocesses always fail."""
    source = tmp_path / 'original' / 'docker-compose.yml'
    source.parent.mkdir()
    definition = {'name': 'novaflow-lab', 'services': {
        'web': {'container_name': 'nova-web', 'image': 'local-web:latest',
                'build': './web', 'volumes': ['./target.py:/app/target.py:ro'],
                'networks': {'inside': {'ipv4_address': '192.168.71.11'}}},
        'db': {'container_name': 'nova-db', 'image': 'local-db:latest',
               'networks': {'inside': {'ipv4_address': '192.168.71.12'}}}},
        'networks': {'inside': {'name':'nova_dmz','internal': True,
                     'driver_opts':{'com.docker.network.bridge.name':'br-nova-dmz'},
                     'ipam':{'config':[{'subnet':'192.168.71.0/24'}]}}}}
    source.write_text(json.dumps(definition))
    state = tmp_path / 'private'; state.mkdir()
    (state / 'lab.env').write_text('LAB_FIXTURE_SEED=synthetic\n')
    monkeypatch.setattr(restore, '_definition', lambda: (source, copy.deepcopy(definition)))
    monkeypatch.setattr(restore, 'kernel_ok', lambda: None)
    monkeypatch.setattr(restore, '_objects', lambda *_: [])
    simulation = SimpleNamespace(source=source, definition=definition, state=state,
        references={'local-web:latest': A, 'local-db:latest': B, A: A, B: B},
        containers={}, calls=[], extra_names=[], wrong_labels=False, wrong_after=False)

    def run(command, **kwargs):
        simulation.calls.append((command, kwargs))
        assert kwargs.get('capture_output') is True and kwargs.get('text') is True
        assert 0 < kwargs['timeout'] <= 600 and 'shell' not in kwargs
        if command[:3] == ['docker', 'image', 'inspect']:
            image = simulation.references.get(command[-1])
            return SimpleNamespace(returncode=0 if image else 1, stdout=(image or '') + '\n')
        if command[:3] == ['docker', 'ps', '--all']:
            return SimpleNamespace(returncode=0, stdout='\n'.join([*simulation.containers, *simulation.extra_names]))
        if command[:3] == ['docker', 'inspect', '--format']:
            rows = []
            for name, image in simulation.containers.items():
                service = next(key for key, value in definition['services'].items() if value['container_name'] == name)
                labels = {'com.docker.compose.project': 'foreign' if simulation.wrong_labels else restore.ISOLATED_PROJECT,
                          'com.docker.compose.service': service}
                rows.append('\t'.join(json.dumps(value) for value in ['/' + name, image, labels]))
            return SimpleNamespace(returncode=0 if simulation.containers else 1, stdout='\n'.join(rows))
        if command[:2] == ['docker', 'compose']:
            assert command[command.index('--project-directory') + 1] == str(source.parent)
            if 'up' in command:
                assert command[-6:] == ['up', '-d', '--no-build', '--pull', 'never', '--force-recreate']
                snapshot = json.loads((state / restore.COMPOSE_NAME).read_text())
                simulation.containers = {s['container_name']: s['image'] for s in snapshot['services'].values()}
                if simulation.wrong_after:
                    simulation.containers['nova-web'] = C
            elif 'down' in command:
                simulation.containers = {}
            elif command[-1] != 'build':
                raise AssertionError('Unexpected compose command')
            return SimpleNamespace(returncode=0, stdout='')
        raise AssertionError('Unexpected real subprocess: ' + repr(command))

    monkeypatch.setattr(restore.subprocess, 'run', run)
    return simulation


def test_preparation_pins_local_ids_without_build_pull_or_source_changes(bank):
    original = bank.source.read_bytes()
    pin = restore.prepare_images(bank.state)
    snapshot = json.loads((bank.state / restore.COMPOSE_NAME).read_text())
    assert pin['images'] == {'nova-web': A, 'nova-db': B}
    assert pin['version'] == 2 and pin['project'] == restore.ISOLATED_PROJECT
    assert snapshot['name'] == restore.ISOLATED_PROJECT
    assert [call[0][-1] for call in bank.calls] == ['local-db:latest', 'local-web:latest']
    assert all('build' not in value and value['pull_policy'] == 'never' for value in snapshot['services'].values())
    assert snapshot['services']['web']['volumes'] == ['./target.py:/app/target.py:ro']
    assert bank.source.read_bytes() == original
    assert (bank.state / restore.PIN_NAME).stat().st_mode & 0o077 == 0
    assert (bank.state / restore.COMPOSE_NAME).stat().st_mode & 0o077 == 0


def test_restore_keeps_exact_ids_when_local_tags_change(bank):
    restore.prepare_images(bank.state)
    bank.references['local-web:latest'] = C
    bank.calls.clear()
    first = restore.restore_pinned(bank.state)
    second = restore.restore_pinned(bank.state)
    inspected = [command[-1] for command, _ in bank.calls if command[:3] == ['docker', 'image', 'inspect']]
    assert inspected == [A, B, A, B]
    assert first['status'] == second['status'] == 'restored'
    assert first['before'] == {} and second['before'] == {'nova-web': A, 'nova-db': B}
    assert first['after'] == second['after'] == {'nova-web': A, 'nova-db': B}
    assert not any('build' in command or 'pull' in command for command, _ in bank.calls)
    assert restore.prepare_images(bank.state)['images'] == first['after']


def test_identity_mismatch_is_rejected_and_preserved_in_receipt(bank):
    restore.prepare_images(bank.state)
    bank.wrong_after = True
    with pytest.raises(LabError, match='restored_images_do_not_match'):
        restore.restore_pinned(bank.state)
    receipt = json.loads((bank.state / restore.RECEIPT_NAME).read_text())
    assert receipt['status'] == 'failed' and receipt['after']['nova-web'] == C
    assert receipt['expected_images']['nova-web'] == A


def test_missing_pinned_image_never_starts_compose(bank):
    restore.prepare_images(bank.state)
    del bank.references[A]
    bank.calls.clear()
    with pytest.raises(LabError, match='local_image_or_docker_operation_failed'):
        restore.restore_pinned(bank.state)
    assert not any(command[:2] == ['docker', 'compose'] for command, _ in bank.calls)


@pytest.mark.parametrize('filename', ['source', 'lab.env', restore.COMPOSE_NAME])
def test_source_fixture_or_snapshot_mutation_is_rejected_before_docker(bank, filename):
    restore.prepare_images(bank.state)
    path = bank.source if filename == 'source' else bank.state / filename
    path.write_text(path.read_text() + '\n')
    bank.calls.clear()
    with pytest.raises(LabError, match='pinned_image_reference_changed'):
        restore.restore_pinned(bank.state)
    assert bank.calls == []


@pytest.mark.parametrize('foreign', ['label', 'extra'])
def test_foreign_project_or_extra_container_denies_mutation(bank, foreign):
    restore.prepare_images(bank.state)
    if foreign == 'label':
        bank.containers = {'nova-web': A}; bank.wrong_labels = True
    else:
        bank.extra_names = ['unrelated-container']
    bank.calls.clear()
    with pytest.raises(LabError, match='foreign_or_invalid|owned_container_inventory'):
        restore.restore_pinned(bank.state)
    assert not any(command[:2] == ['docker', 'compose'] for command, _ in bank.calls)


def test_missing_baseline_is_not_silently_recreated(bank):
    with pytest.raises(LabError, match='prepare_local_images_before_restore'):
        restore.restore_pinned(bank.state)
    assert bank.calls == []


def test_absent_containers_accept_empty_inspect_newline_only_when_missing_allowed(bank,monkeypatch):
    def run(command, **_kwargs):
        return SimpleNamespace(returncode=1 if command[1] == 'inspect' else 0, stdout='\n')
    monkeypatch.setattr(restore, '_run', run)
    assert restore._containers(bank.definition,allow_missing=True) == {}
    with pytest.raises(LabError,match='container_image_identity_invalid'):
        restore._containers(bank.definition,allow_missing=False)


@pytest.mark.parametrize('malformed',['not-json\n','{}\n','\t\n'])
def test_absent_container_tolerance_does_not_allow_malformed_nonempty_rows(bank,monkeypatch,malformed):
    def run(command, **_kwargs):
        return SimpleNamespace(returncode=1 if command[1] == 'inspect' else 0,
                               stdout=malformed if command[1] == 'inspect' else '')
    monkeypatch.setattr(restore, '_run', run)
    if malformed.strip():
        with pytest.raises(LabError,match='container_image_identity_invalid'):
            restore._containers(bank.definition,allow_missing=True)
    else:
        assert restore._containers(bank.definition,allow_missing=True) == {}


def test_initial_build_is_explicit_and_forbidden_after_pinning(bank):
    restore.build_images(bank.state)
    assert bank.calls[-1][0][-1] == 'build'
    restore.prepare_images(bank.state)
    bank.calls.clear()
    with pytest.raises(LabError, match='images_already_pinned_build_denied'):
        restore.build_images(bank.state)
    assert bank.calls == []


def test_kernel_failure_precedes_docker(bank, monkeypatch):
    monkeypatch.setattr(restore, 'kernel_ok', lambda: (_ for _ in ()).throw(LabError('kernel_failure')))
    with pytest.raises(LabError, match='kernel_failure'):
        restore.prepare_images(bank.state)
    assert bank.calls == []


def test_cli_initial_up_and_restore_share_pinned_operations(monkeypatch, tmp_path):
    import laboratorio_empresa as cli
    calls = []
    monkeypatch.setattr(cli, 'STATE', tmp_path)
    monkeypatch.setattr(cli.lab, 'prepare', lambda path: calls.append(('prepare', path)))
    monkeypatch.setattr(restore, 'build_images', lambda path: calls.append(('build', path)))
    monkeypatch.setattr(restore, 'prepare_images', lambda path: calls.append(('pin', path)))
    monkeypatch.setattr(restore, 'restore_pinned', lambda path: calls.append(('restore', path)))
    cli.cmd_levantar(Namespace(construir=False))
    cli.cmd_restaurar(Namespace())
    assert calls == [('prepare', tmp_path), ('pin', tmp_path), ('restore', tmp_path), ('restore', tmp_path)]
    calls.clear()
    cli.cmd_levantar(Namespace(construir=True))
    assert [name for name, _ in calls] == ['prepare', 'build', 'pin', 'restore']


def test_down_uses_pinned_project_and_owned_containers(bank):
    restore.prepare_images(bank.state)
    restore.restore_pinned(bank.state)
    restore.down_pinned(bank.state)
    assert bank.containers == {}
    assert bank.calls[-1][0][-2:] == ['down', '--volumes']


@pytest.fixture
def legacy(bank, monkeypatch):
    """Simulates shared project labels, but isolated names and physical networks."""
    containers = {}
    for i, (service, spec) in enumerate(bank.definition['services'].items(), start=1):
        containers[spec['container_name']] = {
            'Id':str(i) * 64, 'Name':'/' + spec['container_name'],
            'Config':{'Labels':{'com.docker.compose.project':'novaflow-lab','com.docker.compose.service':service}},
            'HostConfig':{'Privileged':False,'ReadonlyRootfs':False,'PortBindings':{},
                          'CapAdd':None,'CapDrop':None,'SecurityOpt':None},
            'NetworkSettings':{'Ports':{}, 'Networks':{
                'nova_dmz':{'IPAddress':spec['networks']['inside']['ipv4_address']}}}}
    network = {'Id':'f'*64,'Name':'nova_dmz','Internal':True,'Driver':'bridge',
        'Options':{'com.docker.network.bridge.name':'br-nova-dmz'},
        'IPAM':{'Config':[{'Subnet':'192.168.71.0/24'}]},
        'Labels':{'com.docker.compose.project':'novaflow-lab','com.docker.compose.network':'inside'},
        'Containers':{obj['Id']:{'Name':name} for name,obj in containers.items()}}
    fixture = SimpleNamespace(containers=containers, network=network, mutations=[], queries=[])

    def objects(kind, names):
        fixture.queries.append((kind, set(names)))
        if kind == 'container':
            return [copy.deepcopy(obj) for name,obj in fixture.containers.items() if name in names]
        if kind == 'network':
            return [copy.deepcopy(network)] if network['Name'] in names or network['Id'] in names else []
        raise AssertionError(kind)

    def run(command, **_kwargs):
        fixture.mutations.append(command)
        if command[:4] == ['docker','container','rm','--force']:
            for identifier in command[4:]:
                assert identifier in {obj['Id'] for obj in fixture.containers.values()}
                network['Containers'].pop(identifier, None)
        elif command[:3] == ['docker','network','rm']:
            assert not network['Containers'] and command[3] == network['Id']
        else:
            raise AssertionError('Unexpected migration subprocess')
        return SimpleNamespace(returncode=0,stdout='')

    monkeypatch.setattr(restore, '_objects', objects)
    monkeypatch.setattr(restore, '_run', run)
    return fixture


def test_migration_removes_only_catalogue_ids_even_if_project_labels_are_shared(bank, legacy):
    receipt = {}
    restore._retire_legacy(bank.state,bank.definition,receipt)
    assert legacy.mutations == [
        ['docker','container','rm','--force','1'*64,'2'*64],
        ['docker','network','rm','f'*64]]
    assert legacy.queries[0] == ('container',{'nova-web','nova-db'})
    assert not any('down' in command for command in legacy.mutations)
    assert receipt['validated_containers'] == {'nova-web':'1'*64,'nova-db':'2'*64}


def test_migration_has_a_read_only_inventory_check(bank,legacy):
    preview = restore._retire_legacy(bank.state, bank.definition, {}, dry_run=True)
    assert preview['validated_containers'] == {'nova-web':'1'*64,'nova-db':'2'*64}
    assert legacy.mutations == []
    assert not (bank.state / 'migration-images.json').exists()


@pytest.mark.parametrize('defect', ['foreign_service','foreign_project','public_port','privileged',
                                   'wrong_address','foreign_network_endpoint','external_network','wrong_bridge'])
def test_migration_rejects_foreign_or_modified_profiles_before_any_removal(bank,legacy,defect):
    web = legacy.containers['nova-web']
    if defect == 'foreign_service': web['Config']['Labels']['com.docker.compose.service'] = 'other'
    if defect == 'foreign_project': web['Config']['Labels']['com.docker.compose.project'] = 'foreign'
    if defect == 'public_port': web['HostConfig']['PortBindings'] = {'22/tcp':[{'HostPort':'2222'}]}
    if defect == 'privileged': web['HostConfig']['Privileged'] = True
    if defect == 'wrong_address': web['NetworkSettings']['Networks']['nova_dmz']['IPAddress'] = '8.8.8.8'
    if defect == 'foreign_network_endpoint': legacy.network['Containers']['e'*64] = {'Name':'medio-portal'}
    if defect == 'external_network': legacy.network['Internal'] = False
    if defect == 'wrong_bridge': legacy.network['Options']['com.docker.network.bridge.name'] = 'br-foreign'
    with pytest.raises(LabError, match='legacy_'):
        restore._retire_legacy(bank.state,bank.definition,{})
    assert legacy.mutations == []


def test_v1_upgrade_preserves_baseline_bytes_and_never_resolves_tags_again(bank, monkeypatch):
    restore.prepare_images(bank.state)
    archive = next(bank.state.glob('pin-v1-*'))
    old_pin = (archive / restore.PIN_NAME).read_bytes()
    old_compose = (archive / restore.COMPOSE_NAME).read_bytes()
    (bank.state / restore.PIN_NAME).write_bytes(old_pin)
    (bank.state / restore.COMPOSE_NAME).write_bytes(old_compose)
    monkeypatch.setattr(restore, '_image_id', lambda _: (_ for _ in ()).throw(AssertionError('Must not repin')))
    upgraded = restore.prepare_images(bank.state)
    assert upgraded['version'] == 2 and upgraded['project'] == restore.ISOLATED_PROJECT
    assert upgraded['images'] == json.loads(old_pin)['images']
    assert (archive / restore.PIN_NAME).read_bytes() == old_pin
    assert (archive / restore.COMPOSE_NAME).read_bytes() == old_compose
