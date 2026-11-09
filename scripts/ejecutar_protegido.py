#!/usr/bin/env python3
"""Ejecutor del operador para catálogos cerrados en una instalación aislada.

Debe instalarse como código root de sólo lectura. El controlador y las
herramientas reciben UIDs distintos; la autoridad Docker queda en el broker.
Esta entrada acepta exclusivamente los cinco bancos instalados y no recibe
rutas de salida, comandos, imágenes, redes ni secretos del llamante.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

SCENARIOS=('integrado','sucursal','comercial','mixto','reforzado')
UIDS={'controller':65531,'nmap':65532,'hydra':65533}
ROOT=Path(__file__).resolve().parents[1]


class OperatorError(RuntimeError):
    pass


def trusted(path, *, directory=False, private=False):
    path=Path(path)
    for current in [path,*path.parents]:
        info=current.lstat()
        sticky=current!=path and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode&stat.S_ISVTX
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 and not sticky:
            raise OperatorError('La instalación debe ser propiedad de root y no modificable por terceros.')
    mode=path.stat().st_mode
    if (not stat.S_ISDIR(mode) if directory else not stat.S_ISREG(mode)):
        raise OperatorError('Tipo de archivo de instalación incorrecto.')
    if private and mode&0o077:raise OperatorError('El estado privado debe tener permisos 0600/0700.')
    return path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path,data,*,mode=0o600,gid=0):
    path=Path(path);trusted(path.parent,directory=True)
    temporary=path.with_name('.'+path.name+'-'+secrets.token_hex(5))
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchown(descriptor,0,gid);os.fchmod(descriptor,mode)
        with os.fdopen(descriptor,'w') as stream:
            json.dump(data,stream,ensure_ascii=False,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)


def root_directory(path,mode=0o755):
    path=Path(path);trusted(path.parent,directory=True)
    path.mkdir(mode=mode,exist_ok=False);os.chmod(path,mode)
    return path


def actor_directory(path,uid):
    path=Path(path);trusted(path.parent,directory=True)
    path.mkdir(mode=0o700,exist_ok=False);os.chown(path,uid,uid)
    return path


def persistent_locks(base,bank):
    """La cuarentena de un banco sobrevive al proceso y a nuevas corridas."""
    parent=base/'runtime/segment-locks'
    if parent.exists():trusted(parent,directory=True)
    else:root_directory(parent)
    path=parent/bank
    if not path.exists():return actor_directory(path,UIDS['controller'])
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid!=UIDS['controller'] or info.st_gid!=UIDS['controller']
            or stat.S_IMODE(info.st_mode)!=0o700):
        raise OperatorError('El directorio persistente de cuarentena cambió de identidad o permisos.')
    return path


def run(argv,*,timeout=30):
    value=subprocess.run([str(x) for x in argv],capture_output=True,text=True,timeout=timeout,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    if value.returncode:raise OperatorError('Falló operación de instalación: '+value.stderr[:1000])
    return value.stdout


def source_hashes():
    # Sólo se fijan archivos regulares de la instalación, nunca datos del actor.
    paths=list((ROOT/'scripts').rglob('*.py'))+list((ROOT/'piloto_kali/prototipo/src').rglob('*.py'))
    return {str(p):digest(trusted(p)) for p in sorted(paths) if not p.is_symlink()}


def prepare_tools(base):
    """Instala Nmap sin las file capabilities del paquete de Kali.

    Sólo copia bytes a un inode nuevo del stage. El ejecutable del sistema,
    sus atributos y sus capacidades permanecen intactos.
    """
    source=trusted('/usr/lib/nmap/nmap');folder=base/'tools'
    if folder.exists():trusted(folder,directory=True)
    else:root_directory(folder)
    target=folder/'nmap'
    if not target.exists():
        descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o555)
        with os.fdopen(descriptor,'wb') as stream:stream.write(source.read_bytes())
        target.chmod(0o555)
    trusted(target)
    if digest(source)!=digest(target) or 'security.capability' in os.listxattr(target):
        raise OperatorError('La copia Nmap protegida cambió o conserva file capabilities.')
    return {'nmap':target,'hydra':trusted('/usr/bin/hydra')}, {
        'nmap_source':str(source),'nmap_executable':str(target),'nmap_sha256':digest(target),
        'source_file_capabilities':run(['/usr/sbin/getcap',source]).strip(),
        'source_file_capability_attribute_present':'security.capability' in os.listxattr(source),
        'copy_file_capability_attribute_present':False,'system_executable_or_capabilities_modified':False}


def select_network(base,bank):
    from tesis.red_auditoria import prepare_bank
    private=base/'private'
    found=[]
    for path in private.glob('audit-'+bank+'*/receipt.json'):
        data=json.loads(trusted(path,private=True).read_text())
        if data.get('ready') and not data.get('cleanup') and data.get('scenario')==bank:
            if data.get('role_uids')!=UIDS:raise OperatorError('Roles de red incompatibles con la instalación.')
            if Path('/run/netns',data['namespace']).stat().st_ino!=data['namespace_inode']:
                raise OperatorError('Cambió la identidad del namespace de auditoría.')
            found.append((path,data))
    if len(found)>1:raise OperatorError('Hay más de una red activa para el banco; el operador debe resolver la ambigüedad.')
    if found:
        path,data=found[0]
        if run(['/usr/sbin/ip','netns','pids',data['namespace']]).strip():
            raise OperatorError('La red del banco ya contiene procesos; no se inicia otro controlador.')
        return path,data
    folder=private/('audit-'+bank+'-'+secrets.token_hex(4))
    data=prepare_bank(bank,private/('topologia-'+bank+'.json'),folder)
    return folder/'receipt.json',data


def bank_modules(bank,state=None):
    if bank=='integrado':
        from auditoria import lab_empresa,empresa_agent
        return lab_empresa,empresa_agent
    from tesis.laboratorios import Context
    context=Context(bank,**({'state_root':state.parent} if state is not None else {}))
    return context.lab,context.agent


def state_snapshot(base,bank,runroot):
    lab,_=bank_modules(bank)
    original=ROOT/'piloto_kali/prototipo'/('.lab-empresa' if bank=='integrado' else '.lab-suite/'+bank)
    trusted(original,directory=True)
    truth=trusted(original/'ground_truth.json');os.chmod(truth,0o600)
    if bank=='integrado':
        from tesis.restauracion_banco import _load_pin
        _,_,pin=_load_pin(original)
        preparation={'pin_version':pin['version'],'pin_sha256':digest(original/'images-pinned.json'),
                     'source_sha256':lab.source_hash(),'images':pin['images']}
    else:
        from tesis.laboratorios import Context
        context=Context(bank)
        prepared=json.loads(trusted(original/'prepared.json',private=True).read_text())
        if (prepared.get('source_sha256')!=context.fingerprint()
                or prepared.get('ground_truth_sha256')!=digest(trusted(original/'ground_truth.json',private=True))):
            raise OperatorError('El escenario preparado cambió desde su fijación por el operador.')
        preparation={'source_and_reference_match_prepared':True,'source_sha256':context.fingerprint(),
                     'prepared_sha256':digest(original/'prepared.json'),'images':prepared.get('images',{})}
    states=root_directory(runroot/'states')
    state=root_directory(states/bank)
    # Datos necesarios por el adaptador; las etiquetas de referencia, las
    # contraseñas reales protegidas y el estado del operador permanecen fuera.
    names=['compose.json','http_target.py','images-pinned.json','compose-pinned.json','restoration-images.json']
    for name in names:
        src=original/name
        if src.exists():
            content=trusted(src).read_bytes();target=state/name
            descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o444)
            with os.fdopen(descriptor,'wb') as stream:stream.write(content)
            os.chmod(target,0o444)
    if (original/'protocol').exists():
        protocol=root_directory(state/'protocol')
        for src in sorted((original/'protocol').iterdir()):
            if src.is_file() and not src.is_symlink():
                trusted(src);target=protocol/src.name;target.write_bytes(src.read_bytes());target.chmod(0o444)
    env={k:v for line in trusted(original/'lab.env',private=True).read_text().splitlines()
         if '=' in line for k,v in [line.split('=',1)]}
    known=('LAB_FIXTURE_SEED',*lab.KNOWN_ENVS)
    selected={key:env[key] for key in known if key in env}
    if any(key not in selected for key in lab.KNOWN_ENVS):raise OperatorError('Faltan credenciales sintéticas conocidas del catálogo.')
    target=state/'lab.env';descriptor=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:stream.write(''.join(k+'='+v+'\n' for k,v in selected.items()))
    os.chown(target,UIDS['controller'],UIDS['controller'])
    write_json(state/'policy.json',{'bank':lab.VERSION,'operator_reference':'labels_and_actual_secrets_retained_in_private_state'},mode=0o444)
    return state,env,{'private_original':str(original),'actor_state':str(state),
        'known_environment_names':sorted(selected),'actual_secrets_or_ground_truth_copied':False,
        'actor_environment_sha256':digest(target),'operator_preparation_check':preparation}


def policies(lab,agent,env,controller,netns,expires,*,executables=None):
    from auditoria.agentes.agente_ipv4_servicios import nmap_command
    from auditoria.agentes.agente_ipv4_credenciales import hydra_command
    request=agent.request('LAB-PROPIO',architecture='single',tokens=0,llm=False)
    tasks=agent.build_plan(request);commands=[];credentials=[];hydra=[]
    for task in tasks:
        if task.action_profile=='nmap_tcp_services_v1':commands.append(nmap_command(task))
        elif task.action_profile.startswith('hydra_'):
            service=task.action_profile.removeprefix('hydra_').removesuffix('_single_v1').replace('_','-')
            port=next(port for name,port in lab.CREDENTIALS[task.target.asset_id]['services'] if name==service)
            profile=agent._credential_profile(task.target.asset_id,service,port)
            password=lab.BASTION_GUESS if profile.password_env=='LAB_NOVA_BASTION_GUESS' else env[profile.password_env]
            password_sha256=hashlib.sha256(password.encode()).hexdigest()
            task_key=task.model_dump(mode='json');task_key.pop('task_id');task_key.pop('dependencies')
            credentials.append({'task':task_key,'profile':profile.model_dump(mode='json'),'password_sha256':password_sha256})
            hydra.append({'argv':hydra_command(task,profile,'{password}','{output}'),'password_sha256':password_sha256})
    common={'version':1,'controller_uid':UIDS['controller'],'controller_gid':UIDS['controller'],
        'controller_pid':controller['pid'],'controller_start_time':controller['start_time'],
        'controller_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'netns':netns,'expires_at':expires}
    result={}
    for role,args,profiles in [('nmap',commands,[]),('hydra',hydra,credentials)]:
        executable=Path(executables[role]) if executables else Path('/usr/bin')/role
        trusted(executable)
        result[role]={**common,'role':role,'worker_uid':UIDS[role],'worker_gid':UIDS[role],
            'executable':str(executable),'executable_sha256':digest(executable),'commands':args,'credential_profiles':profiles}
    return result,len(tasks)


def create_listener(path):
    trusted(path.parent,directory=True)
    value=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    value.bind(str(path));os.chmod(path,0o660);os.chown(path,0,UIDS['controller']);value.listen(8)
    return value


def identity_when_ready(process,uid,deadline=8):
    from auditoria.tool_worker import identity,unprivileged
    until=time.monotonic()+deadline
    while time.monotonic()<until:
        if process.poll() is not None:raise OperatorError('Un rol terminó antes de quedar preparado.')
        try:
            current=identity(process.pid)
            if unprivileged(current,uid) and current['Gid'].split()==[str(uid)]*4:return current
        except (OSError,ValueError):pass
        time.sleep(.025)
    raise OperatorError('El rol no retiró todos sus privilegios antes del plazo.')


def worker_when_ready(process,path,uid):
    until=time.monotonic()+12
    while time.monotonic()<until:
        if process.poll() is not None:raise OperatorError('El trabajador rechazó su instalación; consulte el registro privado.')
        if path.stat().st_size>1_000_000:raise OperatorError('Registro de preparación del trabajador inválido.')
        for line in path.read_text().splitlines():
            try:value=json.loads(line)
            except ValueError:continue
            if value.get('event')=='worker_started':
                return identity_when_ready(process,uid)
        time.sleep(.025)
    raise OperatorError('El trabajador no confirmó la apertura de su endpoint.')


def spawn_role(base,namespace,uid,gid,args,env,log,*,fds=()):
    trusted(log.parent,directory=True)
    descriptor=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    command=['/usr/sbin/ip','netns','exec',namespace,'/usr/bin/setpriv',
        '--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--inh-caps=-all',
        '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
        str(base/'venv/bin/python'),'-I','-B',*args]
    try:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=descriptor,stderr=subprocess.STDOUT,
            cwd=str(ROOT),env=env,pass_fds=tuple(fds),start_new_session=True)
        try:
            process._centinela_start_time=_processes()[process.pid]['start_time']
            process._centinela_uid=uid
        except BaseException:
            process.kill();process.wait();raise
        return process
    finally:os.close(descriptor)


def refresh_service(connection,receipt,allowed,event_path,stop):
    from tesis.red_auditoria import refresh_bank_live
    connection.settimeout(.5)
    def exact(size):
        value=b''
        while len(value)<size:
            try:chunk=connection.recv(size-len(value))
            except socket.timeout:
                if stop.is_set():return None
                continue
            if not chunk:return None
            value+=chunk
        return value
    descriptor=os.open(event_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w',buffering=1) as log:
        while not stop.is_set():
            header=exact(4)
            if header is None:return
            size=struct.unpack('!I',header)[0]
            if not 0<size<=4096:return
            raw=exact(size)
            if raw is None:return
            result={'ok':False}
            try:
                value=json.loads(raw)
                if set(value)!={'operation','container'} or value['operation']!='refresh' or value['container'] not in allowed:
                    raise OperatorError('refresh_request_denied')
                update=refresh_bank_live(receipt,container=value['container'])
                result={'ok':True};event={'event':'bridge_refreshed','container':value['container'],'result':update}
            except Exception as exc:event={'event':'bridge_refresh_denied','reason':type(exc).__name__}
            log.write(json.dumps({'time':time.time(),**event})+'\n');log.flush();os.fsync(log.fileno())
            data=json.dumps(result,separators=(',',':')).encode()
            try:connection.sendall(struct.pack('!I',len(data))+data)
            except OSError:return


def _processes():
    values={}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            fields=(path/'stat').read_text().rsplit(')',1)[1].split()
            uid=int(next(line.split()[1] for line in (path/'status').read_text().splitlines() if line.startswith('Uid:')))
            values[int(path.name)]={'pid':int(path.name),'ppid':int(fields[1]),'pgrp':int(fields[2]),
                'session':int(fields[3]),'start_time':fields[19],'uid':uid,'state':fields[0]}
        except (OSError,ValueError,IndexError,StopIteration):continue
    return values


def stop_process(process):
    """Stop only processes leased to this role, including separate tool sessions.

    A pidfd keeps each target attached to the observed process if Linux later
    reuses its numeric PID. Freeze parents before discovering children so a
    new tool cannot escape between inspection and termination.
    """
    if getattr(process,'_centinela_stopped',False) is True:return
    expected=getattr(process,'_centinela_start_time',None)
    uid=getattr(process,'_centinela_uid',None)
    if expected is None or uid is None:raise OperatorError('Falta la identidad fijada del proceso que debe terminar.')
    targets={};known={process.pid}
    def lease(row):
        if row['pid'] in targets:return False
        if row['uid'] not in {0,uid}:raise OperatorError('Un descendiente del rol cambió de identidad.')
        try:fd=os.pidfd_open(row['pid'])
        except ProcessLookupError:return False
        now=_processes().get(row['pid'])
        if now is None or now['start_time']!=row['start_time']:
            os.close(fd);return False
        targets[row['pid']]=(fd,row)
        try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
        except ProcessLookupError:pass
        known.add(row['pid']);return True
    try:
        table=_processes();leader=table.get(process.pid)
        if leader is not None:
            if leader['start_time']!=expected:raise OperatorError('El PID del rol fue reutilizado; se rechaza terminarlo.')
            lease(leader)
        for _ in range(16):
            changed=False
            for row in _processes().values():
                if row['start_time'].isdigit() and int(row['start_time'])>=int(expected) and (
                        row['ppid'] in known or row['session']==process.pid):
                    changed=lease(row) or changed
            if not changed:break
        else:raise OperatorError('El árbol de procesos del rol excede el límite de terminación.')
        for fd,row in reversed(list(targets.values())):
            try:
                signal.pidfd_send_signal(fd,signal.SIGTERM)
                signal.pidfd_send_signal(fd,signal.SIGCONT)
            except ProcessLookupError:pass
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            current=_processes()
            live=[row for _,row in targets.values() if (now:=current.get(row['pid'])) is not None
                  and now['start_time']==row['start_time'] and now['state']!='Z']
            if not live:break
            time.sleep(.025)
        for fd,row in reversed(list(targets.values())):
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
        process.wait(timeout=5)
        pending=[fd for fd,row in targets.values()]
        until=time.monotonic()+5
        while pending:
            remaining=until-time.monotonic()
            if remaining<=0:raise OperatorError('Un proceso del rol no confirmó su terminación.')
            finished,_,_=select.select(pending,[],[],remaining)
            pending=[fd for fd in pending if fd not in finished]
        process._centinela_stopped=True
    finally:
        # Even a second cleanup failure must never leave a leased task stopped.
        for fd,row in targets.values():
            try:
                signal.pidfd_send_signal(fd,signal.SIGKILL)
                signal.pidfd_send_signal(fd,signal.SIGCONT)
            except ProcessLookupError:pass
            finally:os.close(fd)


def evaluate_snapshot(output,private,runroot,bank,original):
    """El evaluador sólo lee una copia regular fijada después del controlador.

    No sigue enlaces del árbol del actor ni escribe como root dentro de él.
    La referencia reservada se consulta únicamente en esta fase del operador.
    """
    from tesis.evaluacion import score
    snapshot=root_directory(private/'evaluation-snapshot',0o700)
    total=0;files={}
    def copy_regular(source_fd,target,prefix=Path()):
        nonlocal total
        for entry in os.scandir(source_fd):
            destination=target/entry.name
            info=entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                root_directory(destination,0o700)
                child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=source_fd)
                try:copy_regular(child,destination,prefix/entry.name)
                finally:os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=16_000_000:
                descriptor=os.open(entry.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=source_fd)
                try:
                    current=os.fstat(descriptor)
                    if (current.st_ino,current.st_dev,current.st_size)!=(info.st_ino,info.st_dev,info.st_size):
                        raise OperatorError('La evidencia cambió durante su fijación.')
                    with os.fdopen(descriptor,'rb',closefd=False) as stream:content=stream.read(16_000_001)
                finally:os.close(descriptor)
                total+=len(content)
                if len(content)!=info.st_size or total>200_000_000:raise OperatorError('La evidencia supera el límite de fijación.')
                destination.write_bytes(content);destination.chmod(0o400)
                files[str(prefix/entry.name)]=hashlib.sha256(content).hexdigest()
            else:raise OperatorError('La evidencia contiene enlaces o archivos no admitidos.')
    source_fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:copy_regular(source_fd,snapshot)
    finally:os.close(source_fd)
    reports=list(snapshot.glob('runs/*/report.json'))
    if len(reports)!=1:raise OperatorError('Se esperaba exactamente un informe del controlador.')
    directory=reports[0].parent
    lab,agent=bank_modules(bank)
    if bank=='integrado':
        from laboratorio_empresa import validation_for
        validator=validation_for
    else:
        from tesis.laboratorios import Context
        validator=Context(bank).validation
    truth=trusted(original/'ground_truth.json',private=True)
    assessment=score(directory,truth,engine=agent,validator=validator,bank_id=lab.VERSION)
    report=json.loads(reports[0].read_text())
    result={'schema':'centinela-operator-evaluation/1','bank':bank,'separate_from_historical_campaign':True,
        'report_status':report.get('status'),'controller_report_sha256':digest(reports[0]),
        'reference_sha256':digest(truth),'reference_visible_to_controller':False,
        'snapshot':str(directory),'snapshot_file_hashes':files,'evaluation':assessment}
    write_json(private/'evaluation-operador.json',result)
    write_json(runroot/'evaluation-operador.json',{k:v for k,v in result.items() if k not in {'snapshot_file_hashes','snapshot'}},mode=0o444)
    return result


def execute(base,bank,architecture):
    from auditoria.tool_worker import identity
    from auditoria.privilege_broker import build_policy
    trusted(base,directory=True);trusted(base/'private',directory=True,private=True)
    manifest=json.loads(trusted(base/'private/bootstrap.json',private=True).read_text())
    if manifest['protected_repo']!=str(ROOT) or ROOT!=base/'repo':raise OperatorError('El ejecutor no pertenece al stage instalado.')
    if manifest['docker_host']!='unix://'+str(base/'private/docker.sock'):raise OperatorError('Daemon ajeno a la instalación.')
    daemon_socket=base/'private/docker.sock';socket_info=daemon_socket.lstat()
    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=0:
        raise OperatorError('El endpoint del daemon aislado no pertenece al operador.')
    # dockerd crea 0660 por defecto; el broker sólo acepta un endpoint privado.
    # El padre root0700 ya fue validado y no admite enlaces del llamante.
    os.chmod(daemon_socket,0o600)
    root_directory(base/'runtime') if not (base/'runtime').exists() else trusted(base/'runtime',directory=True)
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+bank+'-'+secrets.token_hex(4)
    runroot=root_directory(base/'runtime'/run_id)
    private=root_directory(base/'private'/run_id,0o700)
    receipt={'version':1,'run_id':run_id,'bank':bank,'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'status':'preparing','roles':UIDS,'api_calls':0,'original_daemon_mutations':False,'attempts':[],
        'operator_identity':identity(),'root':str(runroot)}
    write_json(private/'operator.json',receipt)
    processes=[];listeners=[];gates=[];refresh_stop=threading.Event();refresh_pair=None
    try:
        executables,receipt['tool_installation']=prepare_tools(base)
        network_path,network=select_network(base,bank)
        receipt['network_receipt']=str(network_path);receipt['audit_netns']=network['namespace_inode']
        version=run(['/usr/sbin/ip','netns','exec',network['namespace'],'/usr/bin/setpriv',
            '--reuid=65532','--regid=65532','--clear-groups','--inh-caps=-all',
            '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',executables['nmap'],'--version'])
        receipt['tool_installation']['nmap_unprivileged_version_probe']={
            'uid':65532,'gid':65532,'all_capabilities_removed':True,'no_new_privileges':True,
            'output':version,'scope':'version only, no targets or audit adapter'}
        state,environment,state_receipt=state_snapshot(base,bank,runroot);receipt['state']=state_receipt
        output=actor_directory(runroot/'output',UIDS['controller'])
        locks=persistent_locks(base,bank)
        receipt['persistent_segment_lock_root']=str(locks)
        homes=root_directory(runroot/'homes');actor_directory(homes/'controller',UIDS['controller'])
        endpoints=root_directory(runroot/'sockets')
        role_paths={role:root_directory(runroot/role) for role in ['nmap','hydra']}
        for role,path in role_paths.items():actor_directory(homes/role,UIDS[role])
        common={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
            'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'}
        sockets={role:str(endpoints/(role+'.sock')) for role in ['nmap','hydra']}
        broker_socket=str(endpoints/'broker.sock')
        descriptor_path=runroot/'descriptor.json'
        controller_env={**common,'HOME':str(homes/'controller'),'TMPDIR':str(homes/'controller'),
            'CENTINELA_PROTECTED_RUNTIME':'1','CENTINELA_BROKER_SOCKET':broker_socket,
            'CENTINELA_RUNTIME_DESCRIPTOR':str(descriptor_path),'CENTINELA_SEGMENT_LOCK_ROOT':str(locks),
            **{'CENTINELA_'+role.upper()+'_SOCKET':path for role,path in sockets.items()},
            **{'CENTINELA_'+role.upper()+'_UID':str(UIDS[role]) for role in sockets}}
        gate_read,gate_write=os.pipe();gates=[gate_read,gate_write]
        controller=spawn_role(base,network['namespace'],UIDS['controller'],UIDS['controller'],
            [str(ROOT/'scripts/ejecucion_protegida_controlador.py'),'--gate-fd',str(gate_read),'--descriptor',str(descriptor_path)],
            controller_env,private/'controller-stdout.log',fds=[gate_read]);processes.append(controller)
        os.close(gate_read);gates.remove(gate_read)
        controller_identity=identity_when_ready(controller,UIDS['controller'])
        receipt['controller_identity']=controller_identity
        expires=time.time()+3000
        lab,agent=bank_modules(bank,state)
        tool_policies,task_count=policies(lab,agent,environment,controller_identity,network['namespace_inode'],expires,
                                         executables=executables)
        pinned=source_hashes()
        broker_policy=build_policy(UIDS['controller'],UIDS['controller'],[lab],docker_endpoint=manifest['docker_host'],
            pinned_files=list(pinned),expires_at=expires,controller_pid=controller.pid)
        write_json(private/'broker-policy.json',broker_policy)
        options={'name':'Aceptación protegida '+bank,'authorization':'LAB-PROPIO','architecture':architecture,
            'ia':'none','tokens':0,'mode':'live','scope':'empresa','creds':False}
        if bank!='integrado':options['scenario']=bank
        descriptor={'version':1,'bank':bank,'controller_uid':UIDS['controller'],'controller_gid':UIDS['controller'],
            'principal':{'pid':controller.pid,'start_time':controller_identity['start_time'],
                         'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()},
            'audit_netns':network['namespace_inode'],'expires_at':expires,'source_hashes':pinned,
            'broker_socket':broker_socket,'worker_sockets':sockets,'state':str(state),'output':str(output),
            'segment_lock_root':str(locks),'options':options,'acceptance_checks':True}
        write_json(descriptor_path,descriptor,mode=0o444)
        receipt['descriptor_sha256']=digest(descriptor_path);receipt['catalogue_tasks']=task_count
        receipt['broker_policy_sha256']=digest(private/'broker-policy.json')
        for role in ['nmap','hydra']:
            policy_path=role_paths[role]/'policy.json';write_json(policy_path,tool_policies[role],mode=0o640,gid=UIDS[role])
            audit=role_paths[role]/'audit.jsonl';fd=os.open(audit,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            os.fchown(fd,UIDS[role],UIDS[role]);os.close(fd)
            listener=create_listener(Path(sockets[role]));listeners.append(listener)
            worker=spawn_role(base,network['namespace'],UIDS[role],UIDS[role],
                ['-m','auditoria.tool_worker','--policy',str(policy_path),'--listen-fd',str(listener.fileno()),'--audit-log',str(audit)],
                {**common,'HOME':str(homes/role),'TMPDIR':str(homes/role)},private/(role+'-stdout.log'),fds=[listener.fileno()])
            processes.append(worker);receipt[role+'_identity']=worker_when_ready(worker,audit,UIDS[role])
        refresh_pair=socket.socketpair();parent_fd,broker_fd=refresh_pair
        refresh_thread=threading.Thread(target=refresh_service,args=(parent_fd,network_path,set(broker_policy['containers']),private/'refresh.jsonl',refresh_stop),daemon=True)
        refresh_thread.start()
        broker=spawn_role(base,network['namespace'],0,UIDS['controller'],
            [str(ROOT/'piloto_kali/prototipo/src/auditoria/privilege_broker.py'),'--policy',str(private/'broker-policy.json'),'--socket',broker_socket,
             '--audit-log',str(private/'broker-audit.jsonl')],
            {**common,'HOME':str(private),'CENTINELA_REFRESH_FD':str(broker_fd.fileno())},private/'broker-stdout.log',fds=[broker_fd.fileno()])
        processes.append(broker);broker_fd.close()
        until=time.monotonic()+10
        while not Path(broker_socket).exists():
            if broker.poll() is not None:raise OperatorError('El broker rechazó su instalación; consulte el registro privado.')
            if time.monotonic()>=until:raise OperatorError('El broker no publicó su endpoint dentro del plazo.')
            time.sleep(.025)
        receipt['broker_identity']=identity(broker.pid)
        expected=receipt['broker_identity']
        if expected['Uid'].split()!=['0']*4 or expected['Gid'].split()!=[str(UIDS['controller'])]*4 or expected['Groups'] or expected['NoNewPrivs']!='1' or any(int(expected[k],16) for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']):
            raise OperatorError('El broker conserva privilegios de proceso no autorizados.')
        for worker in processes[1:]:
            if worker.poll() is not None:raise OperatorError('Un servicio protegido terminó antes de liberar al controlador.')
        from tesis.pruebas_roles import operator_selftest
        receipt['role_negative_checks']=operator_selftest(descriptor_path,private,network_path)
        if receipt['role_negative_checks'].get('passed') is not True:
            raise OperatorError('La comprobación previa de separación de roles no pasó.')
        receipt['status']='running';receipt['attempts'].append({'event':'controller_gate_released','time':time.time()})
        write_json(private/'operator.json',receipt)
        os.write(gate_write,b'go');os.close(gate_write);gates.remove(gate_write)
        print(json.dumps({'status':'running','run_id':run_id,'bank':bank,'controller_pid':controller.pid,
                          'private_receipt':str(private/'operator.json'),'output':str(output)}),flush=True)
        try:code=controller.wait(timeout=2700)
        except subprocess.TimeoutExpired:raise OperatorError('El controlador excedió su ventana de ejecución.')
        receipt['controller_exit_code']=code;receipt['status']='finished' if code==0 else 'controller_failed'
        # No role or inherited tool may still modify evidence during evaluation.
        for role_process in reversed(processes):stop_process(role_process)
        receipt['roles_stopped_before_evaluation']=True
        try:
            evaluation=evaluate_snapshot(output,private,runroot,bank,Path(state_receipt['private_original']))
            receipt['operator_evaluation']=evaluation['evaluation']
            if evaluation['evaluation'].get('acceptance_passed') is not True:
                receipt['status']='acceptance_failed';code=code or 4
        except Exception as exc:
            receipt['operator_evaluation_error']=type(exc).__name__+': '+str(exc)
            receipt['status']='acceptance_failed';code=code or 4
        receipt['operator_exit_code']=code
        return code,private/'operator.json'
    except BaseException as exc:
        receipt['status']='operator_failed';receipt['failure']=type(exc).__name__+': '+str(exc)
        receipt['attempts'].append({'event':'operator_rejection','time':time.time(),'reason':receipt['failure']})
        raise
    finally:
        for descriptor_fd in gates:
            try:os.close(descriptor_fd)
            except OSError:pass
        cleanup_errors=[]
        for process in reversed(processes):
            try:stop_process(process)
            except BaseException as exc:cleanup_errors.append(type(exc).__name__)
        if cleanup_errors:
            receipt['cleanup_errors']=cleanup_errors;receipt['status']='cleanup_failed'
        refresh_stop.set()
        if refresh_pair:
            for endpoint in refresh_pair:
                try:endpoint.close()
                except OSError:pass
        for listener in listeners:listener.close()
        receipt['ended_at_utc']=datetime.now(timezone.utc).isoformat()
        write_json(private/'operator.json',receipt)
        write_json(runroot/'operator-summary.json',{key:receipt[key] for key in ['version','run_id','bank','status','roles','api_calls','original_daemon_mutations','created_at_utc','ended_at_utc']}
            |{'private_receipt':str(private/'operator.json'),'controller_exit_code':receipt.get('controller_exit_code'),
              'catalogue_tasks':receipt.get('catalogue_tasks')},mode=0o444)
        if cleanup_errors:raise OperatorError('No se confirmó la terminación de todos los roles instalados.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',type=Path,required=True)
    parser.add_argument('--bank',choices=SCENARIOS,required=True)
    parser.add_argument('--architecture',choices=['single','multiagent'],default='single')
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Esta entrada corresponde exclusivamente al operador root.')
    if args.base.parent!=Path('/var/tmp') or not re.fullmatch(r'c113-[0-9a-f]{12}',args.base.name):
        parser.error('Stage no admitido; use una instalación c113 del operador.')
    trusted(__file__);trusted(ROOT,directory=True)
    sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]
    trusted(args.base/'private',directory=True,private=True)
    lock=args.base/'private/operator-run.lock'
    descriptor=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    prior_signals={}
    interrupted=False
    def terminate(signum,frame):
        nonlocal interrupted
        if not interrupted:
            interrupted=True
            raise KeyboardInterrupt('El operador recibió una señal de terminación.')
    try:
        for sig in [signal.SIGTERM,signal.SIGHUP,signal.SIGINT]:
            prior_signals[sig]=signal.signal(sig,terminate)
        fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        code,receipt=execute(args.base,args.bank,args.architecture)
        print(json.dumps({'status':'finished' if code==0 else 'failed','exit_code':code,'receipt':str(receipt)}))
        return code
    finally:
        for sig,handler in prior_signals.items():signal.signal(sig,handler)
        os.close(descriptor)


if __name__=='__main__':raise SystemExit(main())
