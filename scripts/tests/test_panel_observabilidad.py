"""La consola publica diagnósticos tipados, nunca contenido libre de excepciones."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]

from auditoria.store import RunStore
from panel_observabilidad import FAILURE_REASONS,inspect_run


def project(tmp_path,records,*,diagnostic=None):
    directory=tmp_path/'run'
    store=RunStore(directory,'projection')
    try:
        if diagnostic is not None:
            store.evidence('task_execution_failure','json',diagnostic)
        for kind,payload in records:
            store.event('orchestration',kind,task_id='task',payload=payload)
    finally:store.close()
    task={'task_id':'task','action_profile':'ipv6_na_neighbor_v2',
          'target':{'asset_id':'receiver_a','address':'fd57:2026:70:1::10'}}
    def read(path):
        try:return path.read_bytes()
        except OSError:return None
    return inspect_run(directory,tmp_path,{'mode':'live','bank':'empresa','tasks':[]},
                       {'tasks':[]},[task],read)


def test_safe_failure_is_translated_and_links_only_verified_diagnostic(tmp_path):
    diagnostic=b'{"schema_version":1,"stage":"ipv6_probe"}'
    digest=hashlib.sha256(diagnostic).hexdigest()
    payload={'engine':'langgraph','stage':'ipv6_probe','reason_code':'ipv6_probe_failed',
             'exception_type':'TaskExecutionError','diagnostic_ref':'evidence/task_execution_failure.json',
             'diagnostic_sha256':digest,'diagnostic_persisted':True,
             'message':'PRIVATE_MESSAGE','command':['PRIVATE_COMMAND'],'api_key':'PRIVATE_KEY',
             'prompt':'PRIVATE_PROMPT','response':'PRIVATE_RESPONSE'}
    detail=project(tmp_path,[('tool_execution_failed',payload)],diagnostic=diagnostic)
    line=detail['console']['lines'][0]
    assert line['level']=='error' and line['kind']=='FALLO'
    assert line['failure_phase']=='sonda IPv6' and line['reason_code']=='ipv6_probe_failed'
    assert 'La sonda IPv6 no pudo completar' in line['text']
    assert line['exception_type']=='TaskExecutionError'
    assert line['diagnostic_ref']==payload['diagnostic_ref'] and line['diagnostic_sha256']==digest
    assert digest in line['text'] and 'PRIVATE_' not in json.dumps(detail)


@pytest.mark.parametrize('untrusted',[
    {'stage':'PRIVATE_STAGE','reason_code':'PRIVATE_REASON','exception_type':'PRIVATE_CLASS'},
    {'stage':['PRIVATE_STAGE'],'reason_code':{'PRIVATE_REASON':True},'exception_type':['PRIVATE_CLASS']},
])
def test_unknown_error_labels_and_paths_are_not_published(tmp_path,untrusted):
    detail=project(tmp_path,[('tool_execution_failed',{'engine':'langgraph',**untrusted,
        'diagnostic_ref':'/PRIVATE_PATH/secret.json','diagnostic_sha256':'PRIVATE_HASH',
        'diagnostic_persisted':True,'stderr':'PRIVATE_STDERR'})])
    line=detail['console']['lines'][0]
    assert line['failure_stage']=='tool_execution' and line['reason_code']=='execution_error'
    assert line['exception_type'] is None and line['diagnostic_ref']==line['diagnostic_sha256']==''
    assert 'PRIVATE_' not in json.dumps(detail)


def test_changed_diagnostic_is_not_presented_as_verified(tmp_path):
    detail=project(tmp_path,[('tool_execution_failed',{'engine':'langgraph','stage':'ipv6_probe',
        'reason_code':'ipv6_probe_failed','exception_type':'TaskExecutionError',
        'diagnostic_ref':'evidence/task_execution_failure.json','diagnostic_sha256':'0'*64,
        'diagnostic_persisted':True})],diagnostic=b'{}')
    line=detail['console']['lines'][0]
    assert line['diagnostic_ref']==line['diagnostic_sha256']==''
    assert 'SHA-256' not in line['text']


def test_preprobe_recovery_is_not_reported_as_a_probe_or_confirmed_finding(tmp_path):
    common={'stage':'receiver_readiness','attempt':1,'probe_sent':False,'secret':'PRIVATE_VALUE'}
    detail=project(tmp_path,[('receiver_recovery_started',common),
        ('receiver_recovery_finished',{**common,'status':'recovered'})])
    lines=detail['console']['lines']
    assert len(lines)==2 and all(line['kind']=='RECUPERACIÓN' for line in lines)
    assert 'antes de enviar la sonda' in lines[0]['text']
    assert 'todavía no se ha enviado' in lines[1]['text']
    assert all('hallazgo' in line['text'] for line in lines)
    assert 'PRIVATE_' not in json.dumps(detail)


@pytest.mark.parametrize('wrong',[
    {'attempt':2},{'attempt':True},{'probe_sent':True},{'stage':'PRIVATE_STAGE'},
])
def test_recovery_projection_rejects_events_outside_closed_contract(tmp_path,wrong):
    payload={'stage':'receiver_readiness','attempt':1,'probe_sent':False,**wrong}
    assert not project(tmp_path,[('receiver_recovery_started',payload)])['console']['lines']


def test_all_execution_failure_codes_have_spanish_projection():
    from tesis.orquestacion_langgraph import FAILURE_CODES
    assert set(FAILURE_REASONS)==FAILURE_CODES
