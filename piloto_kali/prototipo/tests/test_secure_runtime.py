"""La autorización instalada no se reemplaza por variables elegidas por el usuario."""
import copy
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from auditoria import secure_runtime as S


def sample(tmp_path, monkeypatch):
    source=tmp_path/'source.py';source.write_text('trusted\n')
    descriptor=tmp_path/'descriptor.json'
    own={'pid':123,'start_time':'42','netns':99,'Uid':'65531\t65531\t65531\t65531',
         'Gid':'65531\t65531\t65531\t65531','Groups':'','NoNewPrivs':'1',
         **{k:'0000000000000000' for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}}
    data={'version':1,'expires_at':10**12,'controller_uid':65531,
          'principal':{'pid':123,'start_time':'42','boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()},
          'audit_netns':99,'bank':'integrado','options':{'ia':'none'},'output':str(tmp_path/'output'),
          'source_hashes':{str(source):hashlib.sha256(source.read_bytes()).hexdigest()},
          'broker_socket':'/protected/broker.sock','worker_sockets':{'nmap':'/protected/nmap.sock','hydra':'/protected/hydra.sock'}}
    descriptor.write_text(json.dumps(data))
    monkeypatch.setenv('CENTINELA_RUNTIME_DESCRIPTOR',str(descriptor));monkeypatch.setenv('CENTINELA_PROTECTED_RUNTIME','1')
    monkeypatch.setenv('CENTINELA_BROKER_SOCKET',data['broker_socket'])
    for role,endpoint in data['worker_sockets'].items():monkeypatch.setenv('CENTINELA_'+role.upper()+'_SOCKET',endpoint)
    # Sólo esta fixture simula la instalación root; las negativas de permisos
    # ejercitan protected_file sin reemplazarlo en otros tests.
    monkeypatch.setattr(S,'protected_file',lambda path:Path(path))
    monkeypatch.setattr(S,'identity',lambda:own)
    return descriptor,data,own,source


def test_missing_descriptor_rejects_even_root(monkeypatch):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    with pytest.raises(S.ProtectedRuntimeError,match='ejecutor protegido'):
        S.require_live_runtime(bank='integrado')


def test_complete_identity_options_bank_and_output_are_pinned(tmp_path,monkeypatch):
    descriptor,data,own,source=sample(tmp_path,monkeypatch)
    assert S.require_live_runtime(bank='integrado',options={'ia':'none'},output=tmp_path/'output'/'runs')==data


@pytest.mark.parametrize('field,value',[('pid',124),('start_time','43'),('netns',100),
 ('Uid','0 0 0 0'),('Uid','65531 65531 0 65531'),('Gid','65531 65531 0 65531'),
 ('Groups','0'),('CapEff','1'),('CapBnd','1'),('CapInh','1'),('CapPrm','1'),('CapAmb','1'),('NoNewPrivs','0')])
def test_mismatched_effective_saved_or_bounding_privileges_rejected(tmp_path,monkeypatch,field,value):
    descriptor,data,own,source=sample(tmp_path,monkeypatch);own[field]=value
    with pytest.raises(S.ProtectedRuntimeError):S.require_live_runtime(bank='integrado')


@pytest.mark.parametrize('change',[{'bank':'sucursal'},{'principal':{'pid':123,'start_time':'42','boot_id':'oldboot'}},
 {'expires_at':0},{'source_hashes':{}},{'version':2}])
def test_descriptor_scope_expiry_boot_and_manifest_enforced(tmp_path,monkeypatch,change):
    descriptor,data,own,source=sample(tmp_path,monkeypatch);data.update(change);descriptor.write_text(json.dumps(data))
    with pytest.raises(S.ProtectedRuntimeError):S.require_live_runtime(bank='integrado')


def test_source_or_transport_cannot_be_changed(tmp_path,monkeypatch):
    descriptor,data,own,source=sample(tmp_path,monkeypatch);source.write_text('changed')
    with pytest.raises(S.ProtectedRuntimeError,match='componente'):S.require_live_runtime(bank='integrado')


@pytest.mark.parametrize('key,value',[('CENTINELA_PROTECTED_RUNTIME','0'),('CENTINELA_BROKER_SOCKET','/other'),
 ('CENTINELA_NMAP_SOCKET','/other'),('CENTINELA_HYDRA_SOCKET','/other')])
def test_client_cannot_replace_role_endpoints(tmp_path,monkeypatch,key,value):
    sample(tmp_path,monkeypatch);monkeypatch.setenv(key,value)
    with pytest.raises(S.ProtectedRuntimeError):S.require_live_runtime(bank='integrado')


def test_options_and_output_cannot_expand_the_operator_request(tmp_path,monkeypatch):
    sample(tmp_path,monkeypatch)
    with pytest.raises(S.ProtectedRuntimeError):S.require_live_runtime(bank='integrado',options={'ia':'openai'})
    with pytest.raises(S.ProtectedRuntimeError):S.require_live_runtime(bank='integrado',output=tmp_path/'elsewhere')


def test_untrusted_files_and_relative_paths_never_attest(tmp_path):
    path=tmp_path/'policy.json';path.write_text('{}')
    with pytest.raises(S.ProtectedRuntimeError):S.protected_file(path)
    with pytest.raises(S.ProtectedRuntimeError):S.protected_file('policy.json')
