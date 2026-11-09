"""Contratos del instalador; ningún Docker, namespace o servicio real se ejecuta."""
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import instalar_ejecutor_protegido as installer


@pytest.mark.parametrize('value', ['/tmp/c113-0123456789ab', '/var/tmp/c113-../x',
                                   '/var/tmp/c113-0123456789ab/x', '/var/tmp/c113-123',
                                   '/var/tmp/c113-0123456789AB'])
def test_stage_scope_rejects_paths_outside_closed_installation(value):
    with pytest.raises(installer.InstallError, match='invalid_stage'):
        installer.stage_path(value)


def test_stage_accepts_only_exact_nonce():
    assert installer.stage_path('/var/tmp/c113-0123456789ab') == Path('/var/tmp/c113-0123456789ab')


@pytest.mark.parametrize('name', ['../secret', '/etc/shadow', 'a/../b', 'a//b', './a',
                                  '.env', '.lab-x/env', '.venv/a', '.git/config',
                                  'node_modules/x', 'private/openai.json', 'report.docx', None])
def test_source_manifest_does_not_accept_secret_or_traversal_paths(name):
    with pytest.raises(installer.InstallError):
        installer.source_name(name)


def test_manifest_must_match_explicit_hash_and_must_not_be_symlink(tmp_path):
    path = tmp_path / 'manifest.json'; path.write_text('{"file.py":"abc"}')
    expected = installer.digest(path)
    assert installer.load_manifest(path, expected) == {'file.py':'abc'}
    with pytest.raises(installer.InstallError, match='manifest_hash_mismatch'):
        installer.load_manifest(path, '0' * 64)
    link = tmp_path / 'link'; link.symlink_to(path)
    with pytest.raises(OSError): installer.load_manifest(link, expected)


def unprotect(folder):
    if folder.exists():
        for entry in folder.rglob('*'):
            if not entry.is_symlink(): entry.chmod(0o700 if entry.is_dir() else 0o600)
        folder.chmod(0o700)


def test_source_snapshot_is_by_bytes_and_drops_special_mode_bits(tmp_path):
    source = tmp_path / 'source'; source.mkdir(); file = source / 'script.py'
    file.write_text('pass\n'); file.chmod(0o4755)
    dest = tmp_path / 'snapshot'
    try:
        installer.copy_sources(source, dest, {'script.py':installer.digest(file)})
        assert (dest / 'script.py').read_bytes() == file.read_bytes()
        assert stat.S_IMODE((dest / 'script.py').stat().st_mode) == 0o555
        assert stat.S_IMODE(dest.stat().st_mode) == 0o555
    finally: unprotect(dest)


def test_dependency_copy_does_not_propagate_xattrs_or_setuid(tmp_path):
    source = tmp_path / 'source'; target = tmp_path / 'target'
    source.write_bytes(b'fixture'); source.chmod(0o4755)
    os.setxattr(source, 'user.centinela-probe', b'not forwarded')
    installer.copy_bytes(source, target)
    assert target.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert 'user.centinela-probe' not in os.listxattr(target)


def test_source_change_is_rejected_before_unverified_bytes_are_published(tmp_path):
    source = tmp_path / 'source'; source.mkdir(); (source / 'a.py').write_text('changed')
    dest = tmp_path / 'snapshot'
    with pytest.raises(installer.InstallError, match='source_changed'):
        installer.copy_sources(source, dest, {'a.py':'0' * 64})
    assert not (dest / 'a.py').exists()


def test_source_symlink_is_never_followed(tmp_path):
    source = tmp_path / 'source'; source.mkdir(); real = tmp_path / 'secret'; real.write_text('private')
    (source / 'a.py').symlink_to(real)
    with pytest.raises(OSError):
        installer.copy_sources(source, tmp_path / 'snapshot', {'a.py':installer.digest(real)})


def test_python_copy_removes_mutable_editable_paths_and_copies_stdlib(tmp_path, monkeypatch):
    python = tmp_path / 'original-python'; python.write_bytes(b'not executed')
    stdlib = tmp_path / 'stdlib'; stdlib.mkdir(); (stdlib / 'os.py').write_text('stdlib fixture')
    venv = tmp_path / 'source-venv'; (venv / 'bin').mkdir(parents=True)
    (venv / 'bin/python').symlink_to(python)
    package = venv / 'lib/python3.13/site-packages'; package.mkdir(parents=True)
    (package / 'editable.pth').write_text('/home/kali/mutable/source')
    (package / '__editable__finder.py').write_text('not executed')
    (package / 'dist-info').mkdir(); (package / 'dist-info/direct_url.json').write_text('{}')
    (venv / 'bin/tool').write_text('#!/home/kali/mutable/python\npass\n')
    base = Path('/var/tmp/c113-0123456789ab'); staging = tmp_path / 'staging'; staging.mkdir()
    monkeypatch.setattr(installer, 'trusted', lambda path, **kwargs: Path(path))
    try:
        result = installer.copy_python(venv, python, stdlib, base, staging,
                                       expected_venv=installer.venv_inventory(venv))
        target = staging / 'venv'
        assert (staging / 'python/lib/python3.13/os.py').read_text() == 'stdlib fixture'
        assert not list(target.rglob('*.pth'))
        assert not list(target.rglob('__editable__*'))
        assert not list(target.rglob('direct_url.json'))
        assert (target / 'bin/python').readlink() == base / 'python/bin/python3.13'
        assert (target / 'lib/python3.13/site-packages/auditoria').readlink() == base / 'repo/piloto_kali/prototipo/src/auditoria'
        assert '/home/kali' not in (target / 'pyvenv.cfg').read_text()
        assert (target / 'bin/tool').read_text().splitlines()[0] == '#!' + str(base / 'venv/bin/python')
        assert len(result['removed_editable_or_pth']) == 3
        assert result['venv_manifest_matched']
    finally: unprotect(staging)


def test_venv_tampering_is_rejected_before_any_copied_interpreter_is_executed(tmp_path, monkeypatch):
    python = tmp_path / 'python'; python.write_bytes(b'not executed')
    stdlib = tmp_path / 'stdlib'; stdlib.mkdir(); (stdlib / 'os.py').write_text('fixture')
    venv = tmp_path / 'venv'; (venv / 'bin').mkdir(parents=True)
    (venv / 'bin/python').write_bytes(b'old dependency snapshot')
    expected = installer.venv_inventory(venv)
    (venv / 'bin/python').write_bytes(b'tampered dependency')
    staging = tmp_path / 'staging'; staging.mkdir()
    monkeypatch.setattr(installer, 'trusted', lambda path, **kwargs: Path(path))
    try:
        with pytest.raises(installer.InstallError, match='venv_changed_since_validation'):
            installer.copy_python(venv, python, stdlib, Path('/var/tmp/c113-0123456789ab'),
                                  staging, expected_venv=expected)
    finally: unprotect(staging)


def image_tar(tmp_path, *, bad_config=False):
    archive = tmp_path / 'images.tar'; configs = []; images = {}
    for i, name in enumerate(installer.IMAGES):
        data = json.dumps({'image':i}).encode(); digest = hashlib.sha256(data).hexdigest()
        configs.append((digest + '.json', data)); images[name] = 'sha256:' + digest
    rows = [{'Config':name, 'RepoTags':[], 'Layers':[]} for name, _ in configs]
    if bad_config: rows[0]['Config'] = '../outside'
    with tarfile.open(archive, 'w') as tar:
        for name, data in configs + [('manifest.json', json.dumps(rows).encode())]:
            info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))
    return archive, images


def test_image_tar_requires_exact_config_digests_and_is_not_extracted(tmp_path):
    archive, images = image_tar(tmp_path)
    receipt = installer.archive_images(archive, installer.digest(archive), images)
    assert receipt['images'] == images
    assert sorted(p.name for p in tmp_path.iterdir()) == ['images.tar']
    images[installer.IMAGES[0]] = 'sha256:' + '0' * 64
    with pytest.raises(installer.InstallError, match='registry_mismatch'):
        installer.archive_images(archive, installer.digest(archive), images)


def test_image_tar_rejects_traversal_metadata(tmp_path):
    archive, images = image_tar(tmp_path, bad_config=True)
    with pytest.raises(installer.InstallError, match='invalid_image_archive'):
        installer.archive_images(archive, installer.digest(archive), images)


@pytest.fixture
def control_fixture(monkeypatch):
    base = Path('/var/tmp/c113-0123456789ab')
    record = {'bank':'integrado', 'stage':str(base), 'segments':['corp','dmz','dc'],
              'network_receipt':str(base / 'private/audit-integrado-installed/receipt.json'),
              'containers':[{'id':f'{i:064x}', 'name':'/fixture-' + str(i), 'image':'sha256:' + 'a' * 64} for i in range(12)]}
    monkeypatch.setattr(installer, 'load_stage', Mock(return_value={'status':'prepared'}))
    monkeypatch.setattr(installer, 'bank_record', Mock(return_value=record))
    monkeypatch.setattr(installer, 'quarantine_count', Mock(return_value=0))
    monkeypatch.setattr(installer, 'kernel_ok', Mock(return_value=0))
    monkeypatch.setattr(installer, 'audit_processes', Mock(return_value=[]))
    monkeypatch.setattr(installer, 'add_imports', Mock())
    entered = {'lock':False}
    @contextmanager
    def lock(base):
        entered['lock'] = True
        try: yield
        finally: entered['lock'] = False
    monkeypatch.setattr(installer, 'operator_lock', lock)
    return base, record, entered


def test_down_uses_only_registered_ids_and_does_not_clear_quarantine(control_fixture, monkeypatch):
    base, record, _ = control_fixture
    running = [{**row,'running':True} for row in record['containers']]
    stopped = [{**row,'running':False} for row in record['containers']]
    monkeypatch.setattr(installer, 'inspect_owned', Mock(side_effect=[running, stopped]))
    monkeypatch.setattr(installer, 'quarantine_count', Mock(return_value=2))
    docker = Mock(); monkeypatch.setattr(installer, 'docker', docker)
    result = installer.control(base, 'integrado', 'down')
    docker.assert_called_once_with(base, 'container', 'stop', '--time', '5',
                                   *[row['id'] for row in running], timeout=90)
    assert result['running_containers'] == 0 and result['quarantined']
    assert result['quarantine_count'] == 2


def test_mutating_control_is_denied_before_docker_if_kernel_guard_fails(control_fixture, monkeypatch):
    base, _, _ = control_fixture
    monkeypatch.setattr(installer, 'kernel_ok', Mock(side_effect=installer.InstallError('kernel_failure')))
    inspect = Mock(); monkeypatch.setattr(installer, 'inspect_owned', inspect)
    with pytest.raises(installer.InstallError, match='kernel_failure'):
        installer.control(base, 'integrado', 'down')
    inspect.assert_not_called()


@pytest.mark.parametrize('action', ['prepare','down','recover'])
def test_control_rejects_orphaned_audit_process_before_mutating_bank(control_fixture, monkeypatch, action):
    base, _, _ = control_fixture
    monkeypatch.setattr(installer, 'audit_processes', Mock(return_value=['123']))
    inspect = Mock(); monkeypatch.setattr(installer, 'inspect_owned', inspect)
    with pytest.raises(installer.InstallError, match='audit_namespace_not_idle'):
        installer.control(base, 'integrado', action)
    inspect.assert_not_called()


def test_status_reports_busy_without_trying_to_stop_anything(control_fixture, monkeypatch):
    base, _, _ = control_fixture
    @contextmanager
    def busy(base):
        raise installer.InstallError('stage_busy')
        yield
    monkeypatch.setattr(installer, 'operator_lock', busy)
    inspect = Mock(); monkeypatch.setattr(installer, 'inspect_owned', inspect)
    result = installer.control(base, 'integrado', 'status')
    assert result['ok'] and result['state'] == 'busy' and result['active_count'] == 1
    inspect.assert_not_called()


def test_recover_shares_lock_and_calls_only_the_installed_launcher(control_fixture, monkeypatch):
    base, record, entered = control_fixture
    actual = [{**row,'running':True} for row in record['containers']]
    monkeypatch.setattr(installer, 'inspect_owned', Mock(return_value=actual))
    def recover(target, bank):
        assert entered['lock'] and target == base and bank == 'integrado'
    launcher = SimpleNamespace(ROOT=base / 'repo', recover_protocols=Mock(side_effect=recover))
    monkeypatch.setattr(installer.importlib, 'import_module', Mock(return_value=launcher))
    assert installer.control(base, 'integrado', 'recover')['state'] == 'prepared'
    launcher.recover_protocols.assert_called_once_with(base, 'integrado')


def test_prepare_starts_only_missing_registered_ids_then_refreshes(control_fixture, monkeypatch):
    base, record, _ = control_fixture
    before = [{**row,'running':i > 0} for i,row in enumerate(record['containers'])]
    after = [{**row,'running':True} for row in record['containers']]
    monkeypatch.setattr(installer, 'inspect_owned', Mock(side_effect=[before, after]))
    docker = Mock(); monkeypatch.setattr(installer, 'docker', docker)
    import tesis.red_auditoria as network
    refresh = Mock(); monkeypatch.setattr(network, 'refresh_bank_live', refresh)
    assert installer.control(base, 'integrado', 'prepare')['state'] == 'prepared'
    docker.assert_called_once_with(base, 'container', 'start', before[0]['id'], timeout=90)
    refresh.assert_called_once_with(record['network_receipt'])


def test_docker_helper_never_uses_the_global_daemon(monkeypatch):
    base = Path('/var/tmp/c113-0123456789ab')
    host = 'unix://' + str(base / 'private/docker.sock')
    monkeypatch.setattr(installer, 'load_stage', Mock(return_value={'docker_host':host}))
    command = Mock(return_value=''); monkeypatch.setattr(installer, 'run', command)
    installer.docker(base, 'container', 'inspect', 'fixed-id')
    command.assert_called_once_with(['/usr/bin/docker','--host',host,'container','inspect','fixed-id'], timeout=60)


def test_install_tainted_kernel_does_not_read_sources_or_create_stage(monkeypatch, tmp_path):
    monkeypatch.setattr(installer, 'kernel_ok', Mock(side_effect=installer.InstallError('kernel_failure')))
    manifest = Mock(); monkeypatch.setattr(installer, 'load_manifest', manifest)
    with pytest.raises(installer.InstallError, match='kernel_failure'):
        installer.install(SimpleNamespace(stage=tmp_path / 'not-created'))
    manifest.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_control_cannot_publish_a_partial_installation(control_fixture, monkeypatch):
    base, _, _ = control_fixture
    monkeypatch.setattr(installer, 'load_stage', Mock(return_value={'status':'installing'}))
    read = Mock(); monkeypatch.setattr(installer, 'bank_record', read)
    with pytest.raises(installer.InstallError, match='stage_not_prepared'):
        installer.control(base, 'integrado', 'prepare')
    read.assert_not_called()


def test_runtime_control_cannot_be_invoked_from_a_mutable_workspace(tmp_path, monkeypatch):
    base = tmp_path / 'stage'; (base / 'private').mkdir(parents=True)
    (base / 'private/bootstrap.json').write_text(json.dumps({'namespace':base.name,'root':str(base),
        'protected_repo':str(base / 'repo'),'docker_host':'unix://' + str(base / 'private/docker.sock')}))
    monkeypatch.setattr(installer, 'stage_path', lambda value: base)
    monkeypatch.setattr(installer, 'trusted', lambda path, **kwargs: Path(path))
    with pytest.raises(installer.InstallError, match='control_requires_installed_code'):
        installer.load_stage(base)


def test_cli_never_accepts_control_from_an_unprivileged_caller(monkeypatch):
    monkeypatch.setattr(installer.os, 'geteuid', lambda:1000)
    control = Mock(); monkeypatch.setattr(installer, 'control', control)
    with pytest.raises(SystemExit) as denied:
        installer.main(['--stage','/var/tmp/c113-0123456789ab','--bank','integrado','--action','status'])
    assert denied.value.code == 2
    control.assert_not_called()


def test_network_defaults_can_only_be_written_inside_the_new_namespace(monkeypatch):
    run = Mock(); monkeypatch.setattr(installer, 'run', run)
    installer.namespace_defaults(Path('/var/tmp/c113-0123456789ab'))
    args = run.call_args.args[0]
    assert args[:6] == ['/usr/sbin/ip','netns','exec','c113-0123456789ab','/usr/sbin/sysctl','-qw']
    assert 'net.ipv6.conf.default.accept_ra=0' in args
    assert 'net.ipv6.conf.default.autoconf=0' in args
    assert 'net.ipv4.ip_forward=0' in args
    run.reset_mock()
    with pytest.raises(installer.InstallError): installer.namespace_defaults(Path('/run/netns/default'))
    run.assert_not_called()


def test_failed_control_reply_does_not_report_retained_quarantine_as_clear(monkeypatch, capsys):
    monkeypatch.setattr(installer.os, 'geteuid', lambda:0)
    monkeypatch.setattr(installer.os, 'umask', Mock())
    monkeypatch.setattr(installer, 'control', Mock(side_effect=installer.InstallError('kernel_failure')))
    monkeypatch.setattr(installer, 'bank_record', Mock(return_value={'segments':['corp']}))
    monkeypatch.setattr(installer, 'quarantine_count', Mock(return_value=1))
    code = installer.main(['--stage','/var/tmp/c113-0123456789ab','--bank','integrado','--action','recover'])
    value = json.loads(capsys.readouterr().out)
    assert code == 3 and not value['ok']
    assert value['quarantined'] and value['quarantine_count'] == 1
    assert value['quarantine_state_known'] and value['state'] == 'quarantined'
    assert value['error_code'] == 'kernel_failure'


@pytest.mark.parametrize('failed', [False, True])
def test_host_firewall_snapshot_uses_only_readonly_libnftables_query(monkeypatch, failed):
    functions = ['nft_ctx_new','nft_ctx_free','nft_ctx_buffer_output','nft_ctx_buffer_error',
                 'nft_ctx_output_set_flags','nft_ctx_input_set_flags','nft_ctx_get_output_buffer',
                 'nft_run_cmd_from_buffer']
    library = SimpleNamespace(**{name:Mock() for name in functions})
    library.nft_ctx_new.return_value = 42
    library.nft_ctx_get_output_buffer.return_value = b'{"nftables":[]}'
    library.nft_run_cmd_from_buffer.return_value = int(failed)
    monkeypatch.setattr(installer.ctypes, 'CDLL', Mock(return_value=library))
    if failed:
        with pytest.raises(installer.InstallError, match='host_firewall_snapshot_unavailable'):
            installer.nft_boundary_digest()
    else:
        result = installer.nft_boundary_digest()
        assert len(result) == 64
    library.nft_ctx_input_set_flags.assert_called_once_with(42, 1)
    library.nft_ctx_output_set_flags.assert_called_once_with(42, (1 << 2) | (1 << 4))
    library.nft_run_cmd_from_buffer.assert_called_once_with(42, b'list ruleset\n')
    library.nft_ctx_free.assert_called_once_with(42)


def test_only_public_bind_fixture_code_is_readable_and_secrets_stay_private(tmp_path, monkeypatch):
    state = tmp_path / 'state'; state.mkdir(mode=0o700)
    (state / 'protocol').mkdir(mode=0o700)
    for name in ('receiver.py','sender.py','radvd.conf'):
        path = state / 'protocol' / name; path.write_text('public fixture'); path.chmod(0o600)
    for name in ('http_target.py','lab.env','ground_truth.json'):
        path = state / name; path.write_text('fixture'); path.chmod(0o600)
    monkeypatch.setattr(installer, 'trusted', lambda path, **kwargs: Path(path))
    try:
        installer.fixture_permissions(state)
        assert stat.S_IMODE((state / 'protocol').stat().st_mode) == 0o555
        assert stat.S_IMODE((state / 'http_target.py').stat().st_mode) == 0o444
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in (state / 'protocol').iterdir())
        assert stat.S_IMODE((state / 'lab.env').stat().st_mode) == 0o600
        assert stat.S_IMODE((state / 'ground_truth.json').stat().st_mode) == 0o600
    finally: unprotect(state)


def test_supervisor_waits_for_docker_before_terminating_containerd():
    calls = []
    def process(name):
        return SimpleNamespace(poll=lambda:None, terminate=lambda:calls.append(('terminate',name)),
            wait=lambda **kwargs:calls.append(('wait',name)), kill=lambda:calls.append(('kill',name)))
    installer.stop_services(process('docker'), process('containerd'))
    assert calls == [('terminate','docker'),('wait','docker'),('terminate','containerd'),('wait','containerd')]


@pytest.mark.parametrize('foreign', [False, True])
def test_failed_install_rollback_uses_only_registered_own_ids(tmp_path, monkeypatch, foreign):
    base = tmp_path / 'stage'; (base / 'private').mkdir(parents=True)
    names = ['fixture-' + str(i) for i in range(12)]
    (base / 'private/expected-integrado.json').write_text(json.dumps({'bank':'integrado','names':names}))
    monkeypatch.setattr(installer, 'trusted', lambda path, **kwargs: Path(path))
    cid = 'a' * 64; image = 'sha256:' + 'b' * 64
    row = {'id':cid, 'name':'/foreign' if foreign else '/' + names[0], 'image':image, 'running':True}
    docker = Mock(side_effect=[cid + '\n',json.dumps(row),''])
    monkeypatch.setattr(installer, 'docker', docker)
    if foreign:
        with pytest.raises(installer.InstallError, match='rollback_unregistered_container'):
            installer.stop_new_banks(base, {'base':image})
        assert docker.call_count == 2
    else:
        result = installer.stop_new_banks(base, {'base':image})
        assert result['stop_requested_for'] == [cid]
        assert docker.call_args.args == (base,'container','stop','--time','2',cid)


@pytest.mark.parametrize('private_diagnostics', [False, True])
def test_failed_command_never_forwards_private_diagnostics_to_stdout(tmp_path, monkeypatch, capsys, private_diagnostics):
    monkeypatch.setattr(installer, 'DIAGNOSTIC_DIRECTORY', tmp_path if private_diagnostics else None)
    monkeypatch.setattr(installer.subprocess, 'run', Mock(return_value=SimpleNamespace(
        returncode=1,stdout='SYNTHETIC_PRIVATE_DIAGNOSTIC',stderr='SYNTHETIC_ERROR')))
    private = Mock(); monkeypatch.setattr(installer, 'private_json', private)
    with pytest.raises(installer.InstallError) as error: installer.run(['fixed-command'])
    assert str(error.value) == 'operator_command_failed'
    assert capsys.readouterr().out == ''
    assert private.call_count == int(private_diagnostics)
