"""Rechazos reales de IPC y perfiles antes del catálogo de aceptación.

El operador comprueba UIDs y procesos ajenos mientras el principal espera su
gate. El principal comprueba los perfiles desde su propio PID autorizado.
Ninguna solicitud negativa contiene un objetivo ni un comando ejecutable libre.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]


def _exact(connection,size):
    result=b''
    while len(result)<size:
        chunk=connection.recv(size-len(result))
        if not chunk:raise OSError('La conexión terminó sin respuesta completa.')
        result+=chunk
    return result


def _rpc(path,value,*,broker=False):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(4);connection.connect(str(path))
        raw=json.dumps(value,separators=(',',':')).encode()
        connection.sendall(raw+b'\n' if broker else struct.pack('!I',len(raw))+raw)
        if broker:
            with connection.makefile('rb') as stream:
                response=stream.readline(1_000_001)
            if not response.endswith(b'\n') or len(response)>1_000_000:
                raise ValueError('Respuesta del broker fuera de tamaño.')
            return json.loads(response)
        size=struct.unpack('!I',_exact(connection,4))[0]
        if not 0<size<=1_000_000:raise ValueError('Respuesta IPC fuera de tamaño.')
        return json.loads(_exact(connection,size))


def _identity():
    from auditoria.tool_worker import identity
    return identity()


def _saved_root(uid):
    """Proceso de prueba real: saved UID/GID 0, pero todos sus caps son cero."""
    library=ctypes.CDLL(None,use_errno=True)
    last=int(Path('/proc/sys/kernel/cap_last_cap').read_text())
    for cap in range(last+1):
        if library.prctl(24,cap,0,0,0):raise OSError(ctypes.get_errno(),'PR_CAPBSET_DROP')
    os.setgroups([]);os.setresgid(uid,uid,0);os.setresuid(uid,uid,0)
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    header=Header(0x20080522,0);data=(Data*2)()
    if library.capset(ctypes.byref(header),ctypes.byref(data)):raise OSError(ctypes.get_errno(),'capset')
    if library.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),'PR_SET_NO_NEW_PRIVS')


def _probe(spec):
    if spec.get('saved_root'):_saved_root(65531)
    result={'identity':_identity(),'tests':[]}
    for row in spec['tests']:
        item={'name':row['name'],'endpoint':row.get('endpoint'),'expected':row.get('expected')}
        try:
            if row.get('kind')=='missing_descriptor':
                os.environ.pop('CENTINELA_RUNTIME_DESCRIPTOR',None)
                from auditoria.secure_runtime import require_protected_runtime
                require_protected_runtime();item['unexpected_admission']=True
            else:
                item['response']=_rpc(row['endpoint'],row['request'],broker=row.get('broker',False))
        except Exception as exc:item.update(error=type(exc).__name__,reason=str(exc)[:600],errno=getattr(exc,'errno',None))
        expected=row.get('expected')
        if expected=='PermissionError':item['passed']=item.get('error')=='PermissionError' and item.get('errno')==13
        elif expected=='missing_descriptor':item['passed']=item.get('error')=='ProtectedRuntimeError' and 'falta' in item.get('reason','')
        elif isinstance(expected,str):
            response=item.get('response',{})
            item['passed']=response.get('error',response.get('reason'))==expected
        else:item['passed']=False
        result['tests'].append(item)
    result['passed']=all(row['passed'] for row in result['tests'])
    return result


def _entries(path):
    if not Path(path).exists():return []
    rows=[]
    for line in Path(path).read_text().splitlines():
        try:rows.append(json.loads(line))
        except ValueError:pass
    return rows


def operator_selftest(descriptor_path,private,network_path):
    """Llamada root anterior a go; no arranca ni modifica servicios protegidos."""
    if os.geteuid()!=0:raise ValueError('Sólo el operador puede preparar estas pruebas.')
    from tesis.red_auditoria import _trusted,_write
    data=json.loads(_trusted(descriptor_path).read_text())
    network=json.loads(_trusted(network_path).read_text());private=_trusted(private,directory=True)
    python=sys.executable;module=Path(__file__).resolve();start=time.time()
    report={'schema':'centinela-role-negative-operator/1','started_at':start,'api_calls':0,
            'principal_gate_released':False,'namespace':network['namespace'],'probes':[]}
    broker_request={'version':1,'args':['id'],'timeout':1,'stream':False}
    worker_request={'args':['id'],'timeout':1,'password':None}
    def invoke(name,uid,tests,*,saved_root=False):
        spec={'tests':tests,'saved_root':saved_root}
        argv=['ip','netns','exec',network['namespace']]
        if not saved_root:
            argv+=['setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups',
                   '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs']
        argv+=[python,'-I','-B',str(module),'--probe',json.dumps(spec,separators=(',',':'))]
        completed=subprocess.run(argv,text=True,capture_output=True,timeout=18,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},cwd=str(ROOT))
        if completed.returncode:raise RuntimeError('Falló el proceso de rechazo '+name+': '+completed.stderr[:1000])
        value=json.loads(completed.stdout);value['name']=name
        report['probes'].append(value)
    endpoints={'broker':data['broker_socket'],**data['worker_sockets']}
    tests=[{'name':'same-uid-wrong-pid-broker','endpoint':endpoints['broker'],'broker':True,
            'request':broker_request,'expected':'broker_peer_process_denied'}]
    tests +=[{'name':'same-uid-wrong-pid-'+role,'endpoint':endpoint,'request':worker_request,
             'expected':'worker_peer_denied'} for role,endpoint in data['worker_sockets'].items()]
    tests.append({'name':'missing-runtime-descriptor','kind':'missing_descriptor','expected':'missing_descriptor'})
    invoke('unprivileged-controller-uid-foreign-process',65531,tests)
    for role,uid in [('nmap',65532),('hydra',65533)]:
        rows=[{'name':role+'-cannot-access-'+other,'endpoint':endpoint,'broker':other=='broker',
            'request':broker_request if other=='broker' else worker_request,'expected':'PermissionError'}
            for other,endpoint in endpoints.items()]
        rows.append({'name':role+'-cannot-access-docker-daemon','endpoint':network['docker_host'].removeprefix('unix://'),
                     'broker':True,'request':broker_request,'expected':'PermissionError'})
        invoke(role+'-uid-dac-isolation',uid,rows)
    invoke('saved-root-id-with-zero-capabilities',65531,[
        {'name':'saved-root-id-broker-denied','endpoint':endpoints['broker'],'broker':True,
         'request':broker_request,'expected':'broker_peer_privileges_denied'},
        {'name':'saved-root-id-worker-denied','endpoint':endpoints['nmap'],'request':worker_request,
         'expected':'worker_peer_denied'}],saved_root=True)
    # Un descriptor de gate inválido debe terminar antes de emitir solicitudes.
    bad_gate=['ip','netns','exec',network['namespace'],'setpriv','--reuid=65531','--regid=65531',
        '--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
        python,'-I','-B',str(ROOT/'scripts/ejecucion_protegida_controlador.py'),
        '--gate-fd','999999','--descriptor',str(descriptor_path)]
    result=subprocess.run(bad_gate,text=True,capture_output=True,timeout=5,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'},cwd=str(ROOT))
    report['missing_gate']={'exit_code':result.returncode,'reason':result.stderr[-1000:],
                            'passed':result.returncode!=0 and 'Bad file descriptor' in result.stderr}
    end=time.time();logs={'broker':private/'broker-audit.jsonl',
        **{role:Path(descriptor_path).parent/role/'audit.jsonl' for role in ['nmap','hydra']}}
    report['log_window']={'started_at':start,'ended_at':end}
    report['events']={role:[r for r in _entries(path) if start<=r.get('time',0)<=end] for role,path in logs.items()}
    report['unexpected_admissions']=[{'role':role,**row} for role,rows in report['events'].items() for row in rows
        if row.get('event') in {'admitted','tool_started','tool_finished','child_identity'}]
    report['passed']=all(r['passed'] for r in report['probes']) and report['missing_gate']['passed'] and not report['unexpected_admissions']
    report['finished_at_utc']=datetime.now(timezone.utc).isoformat()
    _write(private/'role-negative-operator.json',report)
    return report


def controller_selftest(data):
    """Perfiles rechazados desde el PID principal ya admitido por el operador."""
    from auditoria.secure_runtime import require_protected_runtime
    from auditoria.agentes.agente_ipv4_servicios import nmap_command
    require_protected_runtime();start=time.time();rows=[]
    if data['bank']=='integrado':
        from auditoria import empresa_agent as agent,lab_empresa as lab
    else:
        from tesis.laboratorios import Context
        context=Context(data['bank'],state_root=Path(data['state']).parent);agent,lab=context.agent,context.lab
    tasks=agent.build_plan(agent.request('LAB-PROPIO',architecture='single',tokens=0,llm=False))
    nmap=next(t for t in tasks if t.action_profile=='nmap_tcp_services_v1')
    credential=next(t for t in tasks if t.action_profile.startswith('hydra_'))
    valid_container=lab.CREDENTIALS[credential.target.asset_id]['container']
    def reject(name,endpoint,message,*,broker=False):
        response=_rpc(endpoint,message,broker=broker)
        reason=response.get('error',response.get('reason'))
        passed=(isinstance(reason,str) and reason in {'broker_operation_denied','worker_profile_denied'}
                and response.get('ok') is not True and 'exit_code' not in response and 'result' not in response)
        # No contraseñas, perfiles ni mensajes completos en la copia del actor.
        rows.append({'name':name,'passed':passed,'reason':reason,'response_keys':sorted(response)})
        if not passed:raise RuntimeError('Una prueba negativa admitió una operación: '+name)
    for name,args in [('docker-compose',['compose','up']),('docker-run',['run','--rm','alpine','id']),
        ('docker-id',['id']),('docker-exec-shell',['exec',valid_container,'sh','-c','id']),
        ('docker-exec-freestyle',['exec',valid_container,'id'])]:
        reject(name,data['broker_socket'],{'version':1,'args':args,'timeout':1,'stream':False},broker=True)
    command=nmap_command(nmap);other=command[:-1]+['192.0.2.123']
    for name,args in [('nmap-other-target',other),('nmap-extra-script',command+['--script','/tmp/centinela-forbidden.nse']),
                     ('nmap-freestyle',['id'])]:
        reject(name,data['worker_sockets']['nmap'],{'args':args,'timeout':1,'password':None})
    service=credential.action_profile.removeprefix('hydra_').removesuffix('_single_v1').replace('_','-')
    port=next(p for s,p in lab.CREDENTIALS[credential.target.asset_id]['services'] if s==service)
    profile=agent._credential_profile(credential.target.asset_id,service,port)
    env={k:v for line in (Path(data['state'])/'lab.env').read_text().splitlines() if '=' in line for k,v in [line.split('=',1)]}
    password=lab.BASTION_GUESS if profile.password_env=='LAB_NOVA_BASTION_GUESS' else env[profile.password_env]
    original={'operation':'credential','task':credential.model_dump(mode='json'),'profile':profile.model_dump(mode='json'),
              'password':password,'timeout':1}
    mutations=[]
    message=copy.deepcopy(original);message['password']=password+'-selftest-'+uuid4().hex;mutations.append(('hydra-mutated-password',message))
    message=copy.deepcopy(original);message['task']['target']['address']='192.0.2.123';mutations.append(('hydra-mutated-task-target',message))
    message=copy.deepcopy(original);message['profile']['username']=profile.username+'x';mutations.append(('hydra-mutated-profile',message))
    for name,message in mutations:reject(name,data['worker_sockets']['hydra'],message)
    end=time.time();report={'schema':'centinela-role-negative-controller/1','started_at':start,'ended_at':end,
        'identity':_identity(),'bank':data['bank'],'tests':rows,'passed':all(r['passed'] for r in rows),
        'raw_passwords_saved':False,'api_calls':0}
    (Path(data['output'])/'role-negative-controller.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--probe',required=True)
    arguments=parser.parse_args();print(json.dumps(_probe(json.loads(arguments.probe))))
