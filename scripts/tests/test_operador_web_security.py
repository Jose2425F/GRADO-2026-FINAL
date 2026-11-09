"""Security/recovery regressions with files, in-memory frames and fake launchers."""
import base64
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import operador_web
from operador_web import CHUNK,ExecutorClient,ExecutorError,OperatorQueue,receive_frame

OWNER='d'*32
OTHER='e'*32


def options():
    return {'scope':'empresa','mode':'live','name':'fixture','authorization':'UNIT-TEST',
            'architecture':'single','ia':'none','tokens':0}


@pytest.fixture
def queue(tmp_path):
    base=tmp_path/'stage';(base/'private').mkdir(parents=True)
    return OperatorQueue(base,tmp_path/'spool',1000,tmp_path/'accounts',owner_check=lambda _:True,runner=lambda _:None)


def submit(queue,kind='audit'):
    return queue.submit({'action':'submit','kind':kind,'bank':'integrado','owner':OWNER,
                         'options':options() if kind=='audit' else {}})


@pytest.mark.parametrize('receipt_kind',['missing','roles_active','wrong_bank'])
def test_exit_zero_without_valid_matching_result_is_not_completed(queue,monkeypatch,receipt_kind):
    created=submit(queue);value=queue.jobs[created['id']]
    log=queue.spool/value['id']/'operator.log'
    if receipt_kind=='missing':log.write_text('launcher exited without receipt\n')
    else:
        root=queue.base/'runtime/run-fixture';(root/'output').mkdir(parents=True)
        (root/'output/report.json').write_text('{"status":"complete"}')
        private=queue.base/'private/run-fixture';private.mkdir()
        receipt=private/'operator.json'
        receipt.write_text(json.dumps({'root':str(root),'bank':'sucursal' if receipt_kind=='wrong_bank' else 'integrado',
                                      'roles_stopped_before_evaluation':receipt_kind!='roles_active'}))
        log.write_text(json.dumps({'receipt':str(receipt)})+'\n')
    monkeypatch.setattr(queue,'_invoke',lambda *a,**k:(0,log))
    queue.runner=queue._run
    original_get=queue.pending.get;calls=[]
    def one_job():
        if calls:raise StopIteration('bounded test worker')
        calls.append(True);return original_get()
    monkeypatch.setattr(queue.pending,'get',one_job)
    with pytest.raises(StopIteration,match='bounded test worker'):queue.worker()
    assert value['status']=='failed'
    assert value['ended_at'] is not None


@pytest.mark.parametrize('bad',[
    b'{"x":'+b'['*50000+b'0'+b']'*50000+b'}',
    b'{"x":NaN}',
    b'{"action":"status","action":"cancel"}',
],ids=['excessive-nesting','non-finite-number','duplicate-action'])
def test_malformed_frames_are_closed_errors_not_unhandled_or_ambiguous(bad):
    class Stream:
        def __init__(self):self.data=io.BytesIO(struct.pack('!I',len(bad))+bad)
        def recv(self,count):return self.data.read(count)
    with pytest.raises(ExecutorError):receive_frame(Stream())


def test_restart_does_not_reexecute_and_retains_historical_capability(queue):
    created=submit(queue);called=[]
    restored=OperatorQueue(queue.base,queue.spool,1000,queue.accounts,
                           owner_check=lambda _:True,runner=lambda value:called.append(value))
    assert restored.pending.empty() and not called
    assert restored.dispatch({'action':'status','job':created['id'],'owner':OWNER,'token':created['token']})['status']=='interrupted'
    for action in ['status','cancel','read']:
        request={'action':action,'job':created['id'],'owner':OTHER,'token':created['token']}
        if action=='read':request['offset']=0
        with pytest.raises(ExecutorError):restored.dispatch(request)


def archive_client():
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as archive:archive.writestr('audit/report.json','{"synthetic":true}')
    raw=stream.getvalue();client=ExecutorClient('/unused')
    def call(action,**payload):
        if action=='status':return {'artifact_bytes':len(raw),'artifact_sha256':hashlib.sha256(raw).hexdigest()}
        offset=payload['offset'];return {'data':base64.b64encode(raw[offset:offset+CHUNK]).decode()}
    client.call=call
    return client


def test_download_refuses_symlinked_destination_root(tmp_path):
    outside=tmp_path/'outside';outside.mkdir()
    destination=tmp_path/'workspace';destination.symlink_to(outside,target_is_directory=True)
    with pytest.raises(ExecutorError):archive_client().download('job',OWNER,'unused',destination)
    assert not list(outside.iterdir())


def test_export_rejects_hardlinked_files(queue,tmp_path):
    created=submit(queue);value=queue.jobs[created['id']]
    root=queue.base/'runtime/run-fixture';output=root/'output';output.mkdir(parents=True)
    source=tmp_path/'outside';source.write_text('synthetic private fixture')
    (output/'linked').hardlink_to(source)
    with pytest.raises(ExecutorError):queue._export(value,{'root':str(root)})
    assert 'artifact_sha256' not in value


@pytest.mark.parametrize('result',[
    None,
    {'schema':'centinela-stage-control/1','ok':False,'action':'prepare','bank':'integrado','state':'busy'},
    {'schema':'centinela-stage-control/1','ok':True,'action':'down','bank':'integrado','state':'stopped'},
    {'schema':'centinela-stage-control/1','ok':True,'action':'prepare','bank':'sucursal','state':'prepared'},
    {'schema':'centinela-stage-control/1','ok':True,'action':'prepare','bank':'integrado','state':'quarantined',
     'quarantine_count':1,'quarantined':True},
])
def test_control_exit_zero_requires_matching_success_receipt(queue,monkeypatch,result):
    created=submit(queue,kind='prepare');value=queue.jobs[created['id']]
    log=queue.spool/value['id']/'control.log'
    if result is not None:
        result={'active_count':0,'quarantine_count':0,'quarantined':False,'running_containers':12,**result}
    log.write_text('missing JSON\n' if result is None else json.dumps(result)+'\n')
    monkeypatch.setattr(queue,'_invoke',lambda *a,**k:(0,log))
    queue.runner=queue._run;original_get=queue.pending.get;calls=[]
    def one_job():
        if calls:raise StopIteration('bounded test worker')
        calls.append(True);return original_get()
    monkeypatch.setattr(queue.pending,'get',one_job)
    with pytest.raises(StopIteration,match='bounded test worker'):queue.worker()
    assert value['status'] in {'failed','partial'}
    assert queue.bank_status['integrado']['state']!='prepared'


@pytest.mark.parametrize('kind,state,running',[('prepare','prepared',12),('recover','prepared',12),('down','stopped',0)])
def test_matching_success_control_receipt_completes_without_live_installer(queue,monkeypatch,kind,state,running):
    created=submit(queue,kind=kind);value=queue.jobs[created['id']]
    log=queue.spool/value['id']/'control.log'
    result={'schema':'centinela-stage-control/1','ok':True,'action':kind,'bank':'integrado','state':state,
            'active_count':0,'quarantine_count':0,'quarantined':False,'running_containers':running}
    log.write_text(json.dumps(result)+'\n')
    monkeypatch.setattr(queue,'_invoke',lambda *a,**k:(0,log))
    queue._run(value)
    assert value['status']=='complete'
    assert queue.bank_status['integrado']==result


def test_frame_budget_is_total_and_cannot_be_extended_by_trickling_bytes(monkeypatch):
    clock=[0.0];raw=b'{"action":"health"}'
    monkeypatch.setattr(operador_web.time,'monotonic',lambda:clock[0])
    class Stream:
        timeout=15.0
        def __init__(self):self.data=io.BytesIO(struct.pack('!I',len(raw))+raw)
        def gettimeout(self):return self.timeout
        def settimeout(self,timeout):self.timeout=timeout
        def recv(self,count):
            if self.timeout is not None and self.timeout<7:
                raise TimeoutError('synthetic total read deadline')
            clock[0]+=7
            return self.data.read(1)
    with pytest.raises((ExecutorError,TimeoutError)):receive_frame(Stream())

