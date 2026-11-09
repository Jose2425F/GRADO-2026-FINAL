"""Contrato local: ámbitos cerrados, propietario y custodia de resultados."""
import base64
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from operador_web import (BANKS, CHUNK, MAX_FRAME, ExecutorClient, ExecutorError,
                          OperatorQueue, normalized_options, receive_frame)

OWNER = 'a' * 32
OTHER = 'b' * 32


def options():
    return {'scope': 'empresa', 'mode': 'live', 'name': 'Aceptación del banco',
            'authorization': 'LAB-PROPIO', 'architecture': 'single', 'ia': 'none', 'tokens': 0}


@pytest.fixture
def operator(tmp_path):
    return OperatorQueue(tmp_path / 'stage', tmp_path / 'jobs', 1000, tmp_path / 'accounts',
                         owner_check=lambda owner: owner in {OWNER, OTHER}, runner=lambda job: None)


def submit(operator, owner=OWNER, **fields):
    return operator.dispatch({'action': 'submit', 'owner': owner, 'bank': 'integrado',
                              'kind': 'audit', 'options': options(), **fields})


def auth(job, owner=OWNER, **fields):
    return {'action': 'status', 'job': job['id'], 'owner': owner, 'token': job['token'], **fields}


def test_owner_and_capability_required_for_status_cancel_and_result(operator):
    job = submit(operator)
    assert operator.dispatch(auth(job))['status'] == 'queued'
    for action in ('status', 'cancel', 'read'):
        for changed in ({'owner': OTHER}, {'token': '0' * 64}):
            value = auth(job, action=action, **changed)
            if action == 'read': value['offset'] = 0
            with pytest.raises(ExecutorError): operator.dispatch(value)
    assert operator.jobs[job['id']]['status'] == 'queued'
    assert 'token' not in json.loads((operator.spool / job['id'] / 'state.json').read_text())
    assert job['token'] not in (operator.spool / job['id'] / 'state.json').read_text()


@pytest.mark.parametrize('change', [
    {'command': '/bin/sh'}, {'kind': 'docker'}, {'bank': 'terceros'}, {'owner': '../outside'},
    {'kind': []}, {'bank': []}, {'options': {**options(), 'scope': 'personal'}},
    {'options': {**options(), 'scenario': 'sucursal'}},
    {'options': {**options(), 'tokens': True}},
    {'options': {**options(), 'base_url': 'https://example.invalid'}},
])
def test_submission_rejects_uninstalled_or_arbitrary_options(operator, change):
    with pytest.raises((ExecutorError, ValueError)): submit(operator, **change)
    assert operator.jobs == {}


def test_only_one_pending_job_per_owner_and_fifo_between_owners(operator):
    first = submit(operator)
    with pytest.raises(ExecutorError): submit(operator)
    second = submit(operator, OTHER)
    assert operator.pending.get_nowait() == first['id']
    assert operator.pending.get_nowait() == second['id']


def test_control_options_closed_and_audit_mode_is_normalized(operator):
    assert normalized_options(options(), 'integrado')['tokens'] == 0
    with pytest.raises(ExecutorError): submit(operator, kind='prepare')
    job = submit(operator, kind='prepare', options={})
    assert operator.jobs[job['id']]['options'] == {}


def test_queued_cancel_is_durable_without_spawning_tools(operator):
    job = submit(operator)
    result = operator.dispatch(auth(job, action='cancel'))
    assert result['status'] == 'cancelled'
    assert operator.running is None
    assert json.loads((operator.spool / job['id'] / 'state.json').read_text())['cancel_requested']


def test_restart_marks_work_interrupted_and_never_requeues(operator):
    job = submit(operator)
    restored = OperatorQueue(operator.base, operator.spool, 1000, operator.accounts,
                             owner_check=lambda _: True, runner=lambda _: pytest.fail('No automatic retry'))
    assert restored.dispatch(auth(job))['status'] == 'interrupted'
    assert restored.pending.empty()


@pytest.mark.parametrize('value', [{}, {'action': []}, {'action': 'status'},
                                   {'action': 'health', 'extra': 1}])
def test_malformed_request_is_rejected_without_crashing_service(operator, value):
    with pytest.raises(ExecutorError): operator.dispatch(value)


def archive_bytes(name, content=b'contenido'):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive: archive.writestr(name, content)
    return stream.getvalue()


def archive_client(raw, digest=None):
    client = ExecutorClient('/unused')
    def call(action, **payload):
        if action == 'status': return {'artifact_bytes': len(raw), 'artifact_sha256': digest or hashlib.sha256(raw).hexdigest()}
        offset = payload['offset']
        return {'data': base64.b64encode(raw[offset:offset + CHUNK]).decode()}
    client.call = call
    return client


@pytest.mark.parametrize('name', ['../fuera.txt', '/fuera.txt', 'a/../../fuera', 'a\\fuera', 'a//fuera'])
def test_download_refuses_archive_path_escape_and_cleans_temporary(tmp_path, name):
    client = archive_client(archive_bytes(name))
    with pytest.raises(ExecutorError): client.download('job', OWNER, 'token', tmp_path / 'output')
    assert not (tmp_path / 'fuera.txt').exists()
    assert not list((tmp_path / 'output').glob('*.zip'))


def test_download_checks_sha_before_extract_and_preserves_existing_files(tmp_path):
    root = tmp_path / 'output'
    with pytest.raises(ExecutorError): archive_client(archive_bytes('run/report.json'), '0' * 64).download('job', OWNER, 'token', root)
    assert not (root / 'run').exists()
    archive_client(archive_bytes('run/report.json')).download('job', OWNER, 'token', root)
    assert (root / 'run/report.json').read_bytes() == b'contenido'
    with pytest.raises(FileExistsError): archive_client(archive_bytes('run/report.json')).download('job', OWNER, 'token', root)
    assert (root / 'run/report.json').read_bytes() == b'contenido'


def test_export_refuses_symlink_and_does_not_read_private_target(operator, tmp_path):
    job = submit(operator); record = operator.jobs[job['id']]
    run = operator.base / 'runtime/run'; output = run / 'output'; output.mkdir(parents=True)
    private = tmp_path / 'private'; private.write_text('valor reservado')
    (output / 'link').symlink_to(private)
    with pytest.raises(ExecutorError): operator._export(record, {'root': str(run)})
    assert 'artifact_sha256' not in record


def test_frame_limit_applies_before_reading_request_body():
    class Stream:
        def recv(self, count):
            assert count == 4
            return struct.pack('!I', MAX_FRAME + 1)
    with pytest.raises(ExecutorError): receive_frame(Stream())
