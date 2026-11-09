"""Panel/IPC terminal-state boundaries; all operator responses are synthetic."""
import base64
import hashlib
import json
import io
from pathlib import Path
import struct
import sys
import zipfile

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import panel_ejecutor
import operador_web
from dualstack_panel import Operations

OWNER='a'*32
TOKEN='b'*64


def job(action='audit'):
    return {'id':'c'*12,'action':action,'name':'fixture local','created_at':'fixture',
            'status':'queued','ended_at':None,'run_key':None,'message':'fixture',
            'options':{'scope':'empresa','mode':'live','name':'fixture local',
                       'authorization':'UNIT-TEST','architecture':'single','ia':'none','tokens':0} if action=='audit' else {}}


@pytest.fixture
def operations(tmp_path,monkeypatch):
    monkeypatch.setenv('CENTINELA_EXECUTOR_SOCKET','/unused/synthetic.sock')
    value=Operations(tmp_path/'runs');value.root.mkdir();value.workspace_id=OWNER
    return value


class SyntheticClient:
    def __init__(self,statuses=('complete',),*,submitted=None,polled=None):
        self.statuses=list(statuses);self.submitted=submitted;self.polled=polled
        self.calls=[];self.index=-1
    def call(self,action,**payload):
        self.calls.append((action,payload))
        if action=='submit':
            self.index+=1
            return self.submitted if self.submitted is not None else {'ok':True,'id':str(self.index).zfill(32),'token':TOKEN,'status':'queued'}
        if action=='status':
            return self.polled if self.polled is not None else {'ok':True,'id':str(self.index).zfill(32),'status':self.statuses[self.index],'artifact_bytes':0}
        if action=='cancel':return {'ok':True,'id':str(self.index).zfill(32),'status':'cancelled'}
        raise AssertionError(action)
    def download(self,*args):raise AssertionError('No download requested by this fixture')


def wire(monkeypatch,client):
    """Keep the production ExecutorClient parser/validation; replace only bytes."""
    class Stream:
        def __init__(self,*args,**kwargs):self.buffer=None
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def connect(self,path):pass
        def sendall(self,raw):
            value=json.loads(raw[4:]);action=value.pop('action')
            reply=json.dumps(client.call(action,**value)).encode()
            self.buffer=io.BytesIO(struct.pack('!I',len(reply))+reply)
        def recv(self,count):return self.buffer.read(count)
    monkeypatch.setattr(operador_web.socket,'socket',Stream)


def test_partial_acceptance_is_not_erased_by_later_completed_banks(operations,monkeypatch):
    client=SyntheticClient(('partial','complete','complete','complete','complete'))
    wire(monkeypatch,client)
    value=job('acceptance_all');operations.jobs.append(value)
    operations._run(value)
    assert value['status']=='partial'
    assert operations.process is None
    assert 'completada.' not in value['message']


@pytest.mark.parametrize('submitted,polled',[
    ({'ok':True,'status':'queued','token':TOKEN},None),
    ({'ok':True,'id':'0'*32,'status':'queued'},None),
    (None,{'ok':True,'id':'0'*32}),
    (None,{'ok':True,'id':'0'*32,'status':[]}),
    (None,{'ok':True,'id':'0'*32,'status':'complete','artifact_bytes':'not-an-integer'}),
    (None,{'ok':True,'id':'0'*32,'status':'complete','artifact_bytes':1,'artifact_sha256':[1]}),
])
def test_invalid_remote_metadata_becomes_terminal_failure(operations,monkeypatch,submitted,polled):
    client=SyntheticClient(submitted=submitted,polled=polled)
    wire(monkeypatch,client)
    value=job();operations.jobs.append(value)
    operations._run(value)
    assert value['status']=='failed'
    assert value['ended_at'] is not None
    assert operations.process is None
    saved=json.loads((operations.root/'panel'/value['id']/'panel_status.json').read_text())
    assert saved['status']=='failed'


def test_poll_failure_releases_process_and_preserves_other_company_evidence(operations,monkeypatch):
    marker=operations.root.parent/'other-company'/'old-audit'/'report.json'
    marker.parent.mkdir(parents=True);marker.write_text('{"historical":true}')
    before=marker.read_bytes();client=SyntheticClient()
    original=client.call
    def fail_status(action,**payload):
        if action=='status':raise OSError('synthetic IPC unavailable')
        return original(action,**payload)
    client.call=fail_status
    wire(monkeypatch,client)
    value=job();operations.jobs.append(value);operations._run(value)
    assert value['status']=='failed'
    assert operations.process is None
    assert marker.read_bytes()==before
    assert len([call for call in client.calls if call[0]=='cancel'])==1


def test_every_status_and_cancel_keeps_workspace_owner_and_token(operations,monkeypatch):
    class Client(SyntheticClient):
        def call(self,action,**payload):
            result=super().call(action,**payload)
            if action=='status' and len([c for c in self.calls if c[0]=='status'])==1:
                operations.process.cancel()
            return result
    client=Client(('cancelled',));wire(monkeypatch,client)
    value=job();operations.jobs.append(value);operations._run(value)
    assert value['status']=='interrupted'
    assert operations.process is None
    for action,payload in client.calls:
        assert payload['owner']==OWNER
        if action in {'status','cancel'}:
            assert payload['job']=='0'*32
            assert payload['token']==TOKEN
    capability=operations.root/'panel'/value['id']/'.protected_capability.json'
    assert capability.stat().st_mode&0o777==0o600


@pytest.mark.parametrize('status',['complete','partial'])
def test_protected_runs_layout_is_associated_with_its_panel_job(operations,monkeypatch,status):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w') as archive:
        archive.writestr('runs/audit-fixture/request.json','{"audit_id":"fixture","bank":"integrado"}')
        archive.writestr('runs/audit-fixture/report.json',json.dumps({'audit_id':'fixture','status':status}))
    raw=data.getvalue()
    class Client(SyntheticClient):
        def call(self,action,**payload):
            if action=='read':
                self.calls.append((action,payload));offset=payload['offset']
                return {'ok':True,'data':base64.b64encode(raw[offset:offset+operador_web.CHUNK]).decode()}
            value=super().call(action,**payload)
            if action=='status':value.update(artifact_bytes=len(raw),artifact_sha256=hashlib.sha256(raw).hexdigest())
            return value
    client=Client((status,));wire(monkeypatch,client)
    value=job();operations.jobs.append(value);operations._run(value)
    assert value['status']==status
    assert value['run_key']==f'panel/{value["id"]}/runs/audit-fixture'
    assert value['message']=='El resultado está disponible.'
    saved=json.loads((operations.root/'panel'/value['id']/'panel_status.json').read_text())
    assert saved['status']==status and saved['run_key']==value['run_key']
    report=json.loads((operations.root/value['run_key']/'report.json').read_text())
    assert report['status']==status

