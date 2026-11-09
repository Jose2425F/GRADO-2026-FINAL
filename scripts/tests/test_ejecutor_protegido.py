"""Contratos del instalador de roles; no crea redes ni ejecuta herramientas."""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ejecutar_protegido as executor


def test_nonroot_cannot_start_operator(monkeypatch):
    monkeypatch.setattr(sys,'argv',['ejecutar_protegido.py','--base','/var/tmp/c113-0123456789ab','--bank','integrado'])
    monkeypatch.setattr(executor.os,'geteuid',lambda:65531)
    monkeypatch.setattr(executor,'execute',lambda *args:pytest.fail('El actor alcanzó la preparación privilegiada.'))
    with pytest.raises(SystemExit) as error:executor.main()
    assert error.value.code==2


def test_caller_cannot_choose_an_arbitrary_root_destination(monkeypatch):
    monkeypatch.setattr(sys,'argv',['ejecutar_protegido.py','--base','/etc','--bank','integrado'])
    monkeypatch.setattr(executor.os,'geteuid',lambda:0)
    monkeypatch.setattr(executor,'execute',lambda *args:pytest.fail('Se aceptó una ruta ajena al stage.'))
    with pytest.raises(SystemExit) as error:executor.main()
    assert error.value.code==2


def test_catalogue_policies_do_not_export_passwords_or_task_ids():
    from auditoria import lab_empresa,empresa_agent
    env={name:'sentinel-private-'+name for name in lab_empresa.KNOWN_ENVS}
    policies,count=executor.policies(lab_empresa,empresa_agent,env,
        {'pid':12345,'start_time':'67890'},123456,time.time()+300)
    assert count==32
    assert policies['nmap']['worker_uid']==65532
    assert policies['hydra']['worker_uid']==65533
    encoded=json.dumps(policies)
    assert all(password not in encoded for password in env.values())
    assert lab_empresa.BASTION_GUESS not in encoded
    assert all('task_id' not in row['task'] and 'dependencies' not in row['task']
               for row in policies['hydra']['credential_profiles'])
    assert all(row['argv'][4]=='{password}' and row['argv'][6]=='{output}'
               for row in policies['hydra']['commands'])
    assert all(command[:3]==['nmap','-n','-Pn'] for command in policies['nmap']['commands'])


def test_cleanup_leases_descendants_across_sessions_without_pid_reuse(monkeypatch):
    from unittest.mock import Mock
    process=Mock(pid=123,_centinela_start_time='100',_centinela_uid=65532,_centinela_stopped=False)
    table={123:{'pid':123,'ppid':1,'session':123,'pgrp':123,'start_time':'100','uid':65532,'state':'S'},
           124:{'pid':124,'ppid':123,'session':124,'pgrp':124,'start_time':'101','uid':65532,'state':'S'},
           125:{'pid':125,'ppid':124,'session':124,'pgrp':124,'start_time':'102','uid':65532,'state':'S'}}
    signaled=[];terminated=False
    def send(fd,sig):
        nonlocal terminated
        signaled.append((fd,sig))
        if sig==executor.signal.SIGTERM:terminated=True
    monkeypatch.setattr(executor,'_processes',lambda:{} if terminated else table)
    monkeypatch.setattr(executor.os,'pidfd_open',lambda pid:pid+1000)
    monkeypatch.setattr(executor.signal,'pidfd_send_signal',send)
    closed=[];monkeypatch.setattr(executor.os,'close',closed.append)
    monkeypatch.setattr(executor.select,'select',lambda readers,writers,errors,timeout:(readers,[],[]))
    executor.stop_process(process)
    assert {fd for fd,sig in signaled if sig==executor.signal.SIGSTOP}=={1123,1124,1125}
    assert {fd for fd,sig in signaled if sig==executor.signal.SIGKILL}=={1123,1124,1125}
    assert sorted(closed)==[1123,1124,1125]
    process.wait.assert_called_once_with(timeout=5)
    assert process._centinela_stopped is True
    before=list(signaled);executor.stop_process(process);assert signaled==before


def test_cleanup_rejects_reused_pid_without_signaling(monkeypatch):
    from unittest.mock import Mock
    process=Mock(pid=123,_centinela_start_time='100',_centinela_uid=65532,_centinela_stopped=False)
    monkeypatch.setattr(executor,'_processes',lambda:{123:{'start_time':'changed'}})
    send=Mock();monkeypatch.setattr(executor.signal,'pidfd_send_signal',send)
    with pytest.raises(executor.OperatorError,match='reutilizado'):executor.stop_process(process)
    send.assert_not_called()


def test_operator_termination_signal_restores_handlers_and_cannot_interrupt_cleanup(monkeypatch):
    from unittest.mock import Mock
    monkeypatch.setattr(sys,'argv',['ejecutar_protegido.py','--base','/var/tmp/c113-0123456789ab','--bank','integrado'])
    monkeypatch.setattr(executor.os,'geteuid',lambda:0)
    monkeypatch.setattr(executor,'trusted',lambda path,**kwargs:Path(path))
    monkeypatch.setattr(executor.os,'open',lambda *args,**kwargs:123)
    closed=[];monkeypatch.setattr(executor.os,'close',closed.append)
    monkeypatch.setattr(executor.fcntl,'flock',lambda *args:None)
    original={signal:object() for signal in [executor.signal.SIGTERM,executor.signal.SIGHUP,executor.signal.SIGINT]}
    handlers=dict(original)
    def install(signal,handler):
        previous=handlers[signal];handlers[signal]=handler;return previous
    monkeypatch.setattr(executor.signal,'signal',install)
    def execute(*args):
        handler=handlers[executor.signal.SIGTERM]
        try:handler(executor.signal.SIGTERM,None)
        except KeyboardInterrupt:
            # A repeated signal cannot interrupt the active finally cleanup.
            assert handler(executor.signal.SIGTERM,None) is None
            raise
    monkeypatch.setattr(executor,'execute',execute)
    with pytest.raises(KeyboardInterrupt):executor.main()
    assert handlers==original
    assert closed==[123]


@pytest.mark.parametrize('bank',executor.SCENARIOS)
def test_every_bank_policy_preserves_exact_catalogue_and_password_hashes(bank):
    from auditoria.agentes.agente_ipv4_credenciales import hydra_command
    lab,agent=executor.bank_modules(bank)
    environment={name:'synthetic-test-'+name for name in lab.KNOWN_ENVS}
    policies,count=executor.policies(lab,agent,environment,{'pid':123,'start_time':'456'},123456,time.time()+60)
    tasks=agent.build_plan(agent.request('LAB-PROPIO',architecture='single',tokens=0,llm=False))
    assert count==len(tasks)=={'integrado':32,'sucursal':25,'comercial':28,'mixto':32,'reforzado':37}[bank]
    credential_tasks=[task for task in tasks if task.action_profile.startswith('hydra_')]
    assert len(policies['hydra']['commands'])==len(policies['hydra']['credential_profiles'])==len(credential_tasks)
    for task,row,command in zip(credential_tasks,policies['hydra']['credential_profiles'],policies['hydra']['commands']):
        service=task.action_profile.removeprefix('hydra_').removesuffix('_single_v1').replace('_','-')
        port=next(port for name,port in lab.CREDENTIALS[task.target.asset_id]['services'] if name==service)
        profile=agent._credential_profile(task.target.asset_id,service,port)
        password=lab.BASTION_GUESS if profile.password_env=='LAB_NOVA_BASTION_GUESS' else environment[profile.password_env]
        import hashlib
        assert row['password_sha256']==command['password_sha256']==hashlib.sha256(password.encode()).hexdigest()
        assert command['argv']==hydra_command(task,profile,'{password}','{output}')
        assert row['profile']==profile.model_dump(mode='json')
    encoded=json.dumps(policies)
    assert all(secret not in encoded for secret in environment.values())
    assert lab.BASTION_GUESS not in encoded
