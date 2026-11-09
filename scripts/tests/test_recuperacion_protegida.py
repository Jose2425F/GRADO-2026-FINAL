"""Contratos del delta; las conexiones reales se validan después de154."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

import pytest

HERE=Path(__file__).resolve().parents[1]
REPO=HERE.parent
sys.path[:0]=[str(REPO/'scripts'),str(REPO/'piloto_kali/prototipo/src')]

def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def example():
    uid=os.getuid();principal={'pid':12345,'start_time':'67890','boot_id':'a'*36}
    identity={'Uid':' '.join([str(uid)]*4),'Gid':' '.join([str(uid)]*4),'Groups':'','NoNewPrivs':'1',
        'pid':12345,'start_time':'67890','netns':87654,
        **{k:'0000000000000000' for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}}
    return principal,{'version':1,'bank':'integrado','principal':principal,'identity':identity,
        'full_preflight_verified':True,'catalogue_tasks':0,'api_calls':0,
        'preflight':{'bank':'fixture','source_sha256':'1'*64,'segments':{'corp':['target']}}}


@pytest.mark.parametrize('mutate',[
    lambda d:d['principal'].update(pid=99999),
    lambda d:d['identity'].update(netns=99999),
    lambda d:d.update(full_preflight_verified=1),
    lambda d:d.update(catalogue_tasks=False),
    lambda d:d['preflight'].update(segments={}),
    lambda d:d['preflight'].update(source_sha256='2'*64),
])
def test_operator_rejects_incomplete_or_foreign_preflight(tmp_path,monkeypatch,mutate):
    executor=load('delta_executor','ejecutar_protegido.py');principal,proof=example()
    principal=copy.deepcopy(principal);mutate(proof)
    monkeypatch.setattr(executor,'UIDS',{'controller':os.getuid()})
    lab=types.SimpleNamespace(VERSION='fixture',NETWORKS={'corp':('bridge',set(),{'target'})},source_hash=lambda:'1'*64)
    monkeypatch.setattr(executor,'bank_modules',lambda *args:(lab,None))
    monkeypatch.setattr(executor,'write_json',lambda *args,**kwargs:pytest.fail('Se fijó una prueba no válida.'))
    (tmp_path/'preflight-proof.json').write_text(json.dumps(proof))
    with pytest.raises(executor.OperatorError):
        executor.preflight_evaluation(tmp_path,tmp_path,tmp_path,'integrado',tmp_path,principal,87654)


def test_controller_preflight_never_calls_graph_or_tools(tmp_path,monkeypatch):
    entry=load('delta_entry','ejecucion_protegida_controlador.py')
    from auditoria import secure_runtime,tool_worker,lab_empresa,empresa_agent
    principal,proof=example();data={'output':str(tmp_path),'state':str(tmp_path),'bank':'integrado',
        'action':'preflight','principal':principal,'acceptance_checks':False}
    monkeypatch.setattr(secure_runtime,'require_protected_runtime',lambda:data)
    monkeypatch.setattr(tool_worker,'identity',lambda:proof['identity'])
    monkeypatch.setattr(lab_empresa,'load_auditor_environment',lambda _:None)
    calls=[]
    monkeypatch.setattr(lab_empresa,'preflight',lambda _:(calls.append('health') or proof['preflight']))
    monkeypatch.setattr(empresa_agent,'run_task',lambda *args:pytest.fail('Se ejecutó una tarea de auditoría.'))
    module=types.ModuleType('dualstack_panel')
    module.validate_options=lambda *args:pytest.fail('La comprobación llegó al camino de auditoría.')
    monkeypatch.setitem(sys.modules,'dualstack_panel',module)
    read_fd,write_fd=os.pipe();os.write(write_fd,b'go');os.close(write_fd)
    monkeypatch.setattr(sys,'argv',['entry','--gate-fd',str(read_fd),'--descriptor',str(tmp_path/'descriptor.json')])
    assert entry.main()==0
    result=json.loads((tmp_path/'preflight-proof.json').read_text())
    assert calls==['health'] and result['full_preflight_verified'] is True
    assert result['catalogue_tasks']==0 and result['api_calls']==0
    assert not (tmp_path/'runs').exists()


@pytest.mark.parametrize('tainted',[1<<7,1<<14,(1<<7)|(1<<14)])
def test_kernel_failure_blocks_health_and_recovery_before_any_operation(tmp_path,monkeypatch,tainted):
    from auditoria import secure_runtime,tool_worker,lab_empresa
    from auditoria.lab import LabError
    entry=load('guarded_delta_entry','ejecucion_protegida_controlador.py')
    executor=load('guarded_delta_executor','ejecutar_protegido.py')
    principal,proof=example()
    marker=tmp_path/'quarantine.json';marker.write_text('{"state":"recovery_in_progress"}\n');before=marker.read_bytes()
    original=Path.read_text
    def read_text(path,*args,**kwargs):
        if path==Path('/proc/sys/kernel/tainted'):return str(tainted)+'\n'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read_text)
    data={'output':str(tmp_path),'state':str(tmp_path),'bank':'integrado','action':'preflight',
          'principal':principal,'acceptance_checks':False}
    monkeypatch.setattr(secure_runtime,'require_protected_runtime',lambda:data)
    monkeypatch.setattr(tool_worker,'identity',lambda:proof['identity'])
    monkeypatch.setattr(lab_empresa,'load_auditor_environment',lambda *args:pytest.fail('Se cargó el banco con kernel fallido.'))
    monkeypatch.setattr(lab_empresa,'preflight',lambda *args:pytest.fail('Se emitió tráfico de salud con kernel fallido.'))
    read_fd,write_fd=os.pipe();os.write(write_fd,b'go');os.close(write_fd)
    monkeypatch.setattr(sys,'argv',['entry','--gate-fd',str(read_fd),'--descriptor',str(tmp_path/'descriptor.json')])
    with pytest.raises(LabError,match='kernel_failure'):entry.main()
    monkeypatch.setattr(executor.os,'geteuid',lambda:0)
    monkeypatch.setattr(executor,'trusted',lambda *args,**kwargs:pytest.fail('La recuperación comenzó operaciones antes de verificar el kernel.'))
    monkeypatch.setattr(executor,'run',lambda *args,**kwargs:pytest.fail('Se ejecutó Docker con kernel fallido.'))
    with pytest.raises(LabError,match='kernel_failure'):executor.recover_protocols(tmp_path,'integrado')
    assert marker.read_bytes()==before
    assert not (tmp_path/'preflight-proof.json').exists()
