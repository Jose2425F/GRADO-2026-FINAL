"""Procesos de herramientas separados del controlador por UID y sockets privados.

El operador crea los sockets y los procesos antes de retirar privilegios.
El trabajador no recibe acceso al socket Docker ni al de otros roles.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace

MAX_MESSAGE=6_000_000
MAX_OUTPUT=2_100_000


class WorkerDenied(RuntimeError):
    pass


def identity(pid='self',*,namespace=True):
    status={}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key,_,value=line.partition(':');status[key]=value.strip()
    keys=['Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs']
    data={k:status.get(k,'') for k in keys}|{'pid':os.getpid() if pid=='self' else int(pid),
        'start_time':Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]}
    if namespace:data['netns']=os.stat(f'/proc/{pid}/ns/net').st_ino
    return data


def unprivileged(value,uid,gid=None):
    gid=uid if gid is None else gid
    try:
        return (type(uid) is int and uid>0 and type(gid) is int and gid>0
            and value['Uid'].split()==[str(uid)]*4
            and value['Gid'].split()==[str(gid)]*4 and not value['Groups'].strip()
            and value['NoNewPrivs']=='1'
            and all(int(value[k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']))
    except (KeyError,TypeError,ValueError,AttributeError):
        return False


def _protected_path(path,*,file=True):
    path=Path(path)
    if not path.is_absolute():raise WorkerDenied('worker_path_not_protected')
    for part in [path,*path.parents] if file else list(path.parents):
        info=part.lstat()
        sticky_ancestor=part!=path and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode&stat.S_ISVTX
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and not sticky_ancestor):
            raise WorkerDenied('worker_path_not_protected')
    return path


def _endpoint(path):
    path=_protected_path(path,file=False)
    info=path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o007:
        raise WorkerDenied('worker_endpoint_not_protected')
    return str(path)


def _timeout(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<value<=180:
        raise WorkerDenied('worker_timeout_invalid')
    return float(value)


def _read_private(path,limit,*,owner=None):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size>limit
            or (owner is not None and (info.st_uid!=owner or info.st_mode&0o077))):
            raise WorkerDenied('worker_private_file_invalid')
        data=os.read(descriptor,limit+1)
        if len(data)>limit:raise WorkerDenied('worker_output_limit')
        return data
    finally:os.close(descriptor)


def _audit_log(path):
    path=Path(path)
    if not path.is_absolute():raise WorkerDenied('worker_log_not_protected')
    # The leaf directory may belong to this worker only; all other ancestors
    # remain operator controlled. The controller cannot replace log entries.
    for parent in path.parents:
        info=parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid not in {0,os.geteuid()}
            or (info.st_mode&0o022 and not (info.st_uid==0 and info.st_mode&stat.S_ISVTX))
            or (info.st_uid!=0 and info.st_mode&0o077)):
            raise WorkerDenied('worker_log_not_protected')
    descriptor=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    info=os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        os.close(descriptor);raise WorkerDenied('worker_log_not_protected')
    return os.fdopen(descriptor,'a',buffering=1)


def _peer_allowed(policy,pid,uid,gid):
    peer=identity(pid,namespace=False)
    expected_gid=policy.get('controller_gid',policy['controller_uid'])
    if (uid!=policy['controller_uid'] or gid!=expected_gid
        or not unprivileged(peer,uid,expected_gid) or pid!=policy['controller_pid']
        or peer['start_time']!=policy['controller_start_time']
        or ('controller_boot_id' in policy and policy['controller_boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip())):
        raise WorkerDenied('worker_peer_denied')
    return peer


def _execute(policy,command,timeout,private,record):
    """Execute a pinned tool, observing its credentials before accepting output."""
    timeout=_timeout(timeout)
    _verify_executable(policy)
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        process=subprocess.Popen([policy['executable'],*command[1:]],stdin=subprocess.DEVNULL,
            stdout=stdout,stderr=stderr,env={'PATH':'/usr/bin:/bin','HOME':private,'LC_ALL':'C'},start_new_session=True)
        timed_out=False
        try:
            child=identity(process.pid,namespace=False)
            if not unprivileged(child,policy['worker_uid'],policy.get('worker_gid',policy['worker_uid'])):
                raise WorkerDenied('tool_identity_invalid')
            record('tool_identity',identity=child)
            try:process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:timed_out=True
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
        stdout.seek(0);stderr.seek(0)
        out=stdout.read(MAX_OUTPUT+1);err=stderr.read(65537)
        if len(out)>MAX_OUTPUT or len(err)>65536:raise WorkerDenied('worker_output_limit')
    return subprocess.CompletedProcess(command,process.returncode,out,err),timed_out


def _send(connection,data):
    raw=json.dumps(data,separators=(',',':')).encode()
    if len(raw)>MAX_MESSAGE:raise WorkerDenied('worker_output_limit')
    connection.sendall(struct.pack('!I',len(raw))+raw)


def _exact(connection,size):
    chunks=[]
    while size:
        value=connection.recv(min(size,65536))
        if not value:raise WorkerDenied('worker_connection_closed')
        chunks.append(value);size-=len(value)
    return b''.join(chunks)


def _receive(connection):
    size=struct.unpack('!I',_exact(connection,4))[0]
    if not 0<size<=MAX_MESSAGE:raise WorkerDenied('worker_message_limit')
    return json.loads(_exact(connection,size))


def validate_command(policy,args,password=None):
    if (not isinstance(args,list) or not 1<=len(args)<=64
        or any(not isinstance(x,str) or not 1<=len(x)<=4096 or any(ord(c)<32 for c in x) for x in args)):
        raise WorkerDenied('worker_command_invalid')
    if policy['role']=='nmap':
        if args not in policy['commands']:raise WorkerDenied('worker_profile_denied')
        if password is not None:raise WorkerDenied('worker_unexpected_secret')
        return None
    if policy['role']!='hydra':raise WorkerDenied('worker_role_denied')
    # Sólo el perfil ya construido por el catálogo, con archivos temporales
    # reemplazados por el trabajador. No se aceptan opciones adicionales.
    for item in policy['commands']:
        template=item['argv']
        if len(args)!=len(template):continue
        matches=all(x==y for i,(x,y) in enumerate(zip(args,template)) if i not in [4,6])
        if matches and isinstance(password,str) and hashlib.sha256(password.encode()).hexdigest()==item['password_sha256']:
            return item
    raise WorkerDenied('worker_profile_denied')


def load_policy(path):
    path=_protected_path(path)
    if not path.is_file() or path.stat().st_size>1_000_000:raise WorkerDenied('worker_policy_invalid')
    policy=json.loads(path.read_text())
    required={'version','role','controller_uid','controller_pid','controller_start_time','worker_uid','netns','expires_at','executable','executable_sha256','commands','credential_profiles'}
    optional={'controller_gid','worker_gid','controller_boot_id'}
    if not isinstance(policy,dict) or not required<=set(policy) or set(policy)-required-optional:
        raise WorkerDenied('worker_policy_invalid')
    for field in ['controller_uid','worker_uid','controller_pid','netns',*[x for x in ['controller_gid','worker_gid'] if x in policy]]:
        if type(policy[field]) is not int or policy[field]<=0:raise WorkerDenied('worker_policy_invalid')
    if (type(policy['version']) is not int or policy['version']!=1 or policy['role'] not in {'nmap','hydra'}
        or policy['worker_uid']==policy['controller_uid']
        or not isinstance(policy['controller_start_time'],str) or not policy['controller_start_time'].isdigit()
        or isinstance(policy['expires_at'],bool) or not isinstance(policy['expires_at'],(int,float))
        or not math.isfinite(policy['expires_at']) or time.time()>=policy['expires_at']
        or not isinstance(policy['commands'],list) or not isinstance(policy['credential_profiles'],list)):
        raise WorkerDenied('worker_policy_invalid')
    if 'controller_boot_id' in policy and policy['controller_boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        raise WorkerDenied('worker_policy_boot_changed')
    _verify_executable(policy)
    return policy


def _verify_executable(policy):
    executable=_protected_path(policy['executable'])
    info=executable.lstat()
    if (not stat.S_ISREG(info.st_mode) or not info.st_mode&0o111
        or not re.fullmatch('[a-f0-9]{64}',str(policy['executable_sha256']))
        or hashlib.sha256(executable.read_bytes()).hexdigest()!=policy['executable_sha256']):
        raise WorkerDenied('worker_executable_changed')


def serve(policy_path,listen_fd,audit_log):
    policy=load_policy(policy_path)
    own=identity()
    if not unprivileged(own,policy['worker_uid'],policy.get('worker_gid',policy['worker_uid'])) or own['netns']!=policy['netns']:
        raise WorkerDenied('worker_identity_invalid')
    os.umask(0o077)
    server=socket.socket(fileno=listen_fd)
    if server.family!=socket.AF_UNIX or server.type!=socket.SOCK_STREAM or not server.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN):
        raise WorkerDenied('worker_listener_invalid')
    _endpoint(server.getsockname())
    # Refresh SO_PEERCRED after the operator passes the prebound listener.
    server.listen(4)
    with _audit_log(audit_log) as log:
        def record(event,**fields):
            log.write(json.dumps({'time':time.time(),'role':policy['role'],'event':event,**fields},sort_keys=True)+'\n')
        record('worker_started',identity=own)
        while True:
            connection,_=server.accept()
            with connection:
                connection.settimeout(190)
                try:
                    peer_pid,peer_uid,peer_gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    _peer_allowed(policy,peer_pid,peer_uid,peer_gid)
                    if load_policy(policy_path)!=policy:raise WorkerDenied('worker_policy_changed')
                    message=_receive(connection)
                    if policy['role']=='hydra' and isinstance(message,dict) and message.get('operation')=='credential':
                        credential_operation(connection,policy,message,record)
                        continue
                    if not isinstance(message,dict) or set(message)!={'args','timeout','password'}:
                        raise WorkerDenied('worker_request_invalid')
                    timeout=message['timeout']
                    timeout=_timeout(timeout)
                    if time.time()>=policy['expires_at']:raise WorkerDenied('worker_policy_expired')
                    args=message['args'];validate_command(policy,args,message['password'])
                    command=[policy['executable'],*args[1:]]
                    with tempfile.TemporaryDirectory(prefix='centinela-'+policy['role']+'-') as private:
                        output=None
                        if policy['role']=='hydra':
                            password=Path(private)/'password';password.write_text(message['password']);password.chmod(0o600)
                            output=Path(private)/'result.json';command[4]=str(password);command[6]=str(output)
                        record('tool_started',peer_pid=peer_pid,profile_sha256=hashlib.sha256(json.dumps(args).encode()).hexdigest())
                        completed,timed_out=_execute(policy,command,timeout,private,record)
                        out,err=completed.stdout,completed.stderr
                        side_file=_read_private(output,MAX_OUTPUT,owner=os.geteuid()) if output and output.exists() else None
                        result={'returncode':completed.returncode,'stdout':base64.b64encode(out).decode(),
                                'stderr':base64.b64encode(err).decode(),'timed_out':timed_out,
                                'output_file':base64.b64encode(side_file).decode() if side_file is not None else None}
                        record('tool_finished',returncode=completed.returncode,timed_out=timed_out)
                        _send(connection,{'ok':True,'result':result})
                except Exception as exc:
                    record('request_denied',reason=str(exc) if isinstance(exc,WorkerDenied) else type(exc).__name__)
                    try:_send(connection,{'ok':False,'reason':str(exc) if isinstance(exc,WorkerDenied) else 'worker_request_failed'})
                    except (OSError,WorkerDenied):pass


def run_tool(args,*,timeout,capture_output=True,text=False,check=False,**kwargs):
    if kwargs or capture_output is not True or type(text) is not bool or type(check) is not bool:raise WorkerDenied('worker_subprocess_options_denied')
    if not isinstance(args,(list,tuple)) or not args or not isinstance(args[0],str):raise WorkerDenied('worker_command_invalid')
    role=Path(args[0]).name
    if role not in {'nmap','hydra'}:raise WorkerDenied('worker_role_denied')
    endpoint=os.environ.get('CENTINELA_'+role.upper()+'_SOCKET')
    if not endpoint:raise WorkerDenied('protected_worker_required')
    endpoint=_endpoint(endpoint)
    timeout=_timeout(timeout)
    password=None
    if role=='hydra':
        if len(args)<7:raise WorkerDenied('worker_command_invalid')
        source=Path(args[4])
        password=_read_private(source,4097,owner=os.geteuid()).decode().removesuffix('\n')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(float(timeout)+10);connection.connect(endpoint)
        _,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        expected={'nmap':65532,'hydra':65533}[role]
        if (uid,gid)!=(expected,expected):raise WorkerDenied('worker_server_identity_invalid')
        _send(connection,{'args':list(args),'timeout':timeout,'password':password})
        message=_receive(connection)
    if not isinstance(message,dict) or message.get('ok') is not True:raise WorkerDenied('worker_request_denied')
    result=message['result']
    if (not isinstance(result,dict) or set(result)!={'returncode','stdout','stderr','timed_out','output_file'}
        or type(result['returncode']) is not int or type(result['timed_out']) is not bool):raise WorkerDenied('worker_result_invalid')
    out=base64.b64decode(result['stdout'],validate=True);err=base64.b64decode(result['stderr'],validate=True)
    if len(out)>MAX_OUTPUT or len(err)>65536:raise WorkerDenied('worker_output_limit')
    if role=='hydra' and result['output_file'] is not None:
        output=Path(args[6])
        if output.parent!=Path(args[4]).parent or output.is_symlink():raise WorkerDenied('worker_output_path_invalid')
        raw=base64.b64decode(result['output_file'],validate=True)
        if len(raw)>MAX_OUTPUT:raise WorkerDenied('worker_output_limit')
        descriptor=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(descriptor,'wb') as file:file.write(raw)
        output.chmod(0o600)
    if result['timed_out']:raise subprocess.TimeoutExpired(args,timeout,output=out,stderr=err)
    if text:out=out.decode(errors='replace');err=err.decode(errors='replace')
    completed=subprocess.CompletedProcess(args,result['returncode'],out,err)
    if check:completed.check_returncode()
    return completed


def tool_runtime_enabled():
    return os.environ.get('CENTINELA_PROTECTED_RUNTIME')=='1'


def credential_operation(connection,policy,message,record):
    if set(message)!={'operation','task','profile','password','timeout'}:
        raise WorkerDenied('worker_request_invalid')
    if time.time()>=policy['expires_at']:raise WorkerDenied('worker_policy_expired')
    from .contracts import Task,CredentialProfile
    from .store import RunStore
    from .agentes import agente_ipv4_credenciales as adapter
    task=Task.model_validate(message['task']);profile=CredentialProfile.model_validate(message['profile'])
    task_key=task.model_dump(mode='json');task_key.pop('task_id');task_key.pop('dependencies')
    if not re.fullmatch('[A-Za-z0-9_-]{1,160}',task.task_id):raise WorkerDenied('worker_task_id_invalid')
    password=message['password']
    if not isinstance(password,str) or not 1<=len(password)<=4096 or any(c in password for c in '\r\n\x00'):raise WorkerDenied('worker_secret_invalid')
    digest=hashlib.sha256(password.encode()).hexdigest()
    if not any(row['task']==task_key and row['profile']==profile.model_dump(mode='json')
               and row['password_sha256']==digest for row in policy['credential_profiles']):
        raise WorkerDenied('worker_profile_denied')
    timeout=_timeout(message['timeout'])
    # El controlador revalida autorización antes del challenge, la herramienta
    # y su corroboración; una revocación no se convierte en un error de red.
    def authorize():
        if time.time()>=policy['expires_at']:raise WorkerDenied('worker_policy_expired')
        _send(connection,{'authorize':True})
        if _receive(connection)!={'authorized':True}:raise WorkerDenied('worker_authorization_revoked')
    with tempfile.TemporaryDirectory(prefix='centinela-credential-') as directory:
        previous_umask=os.umask(0o077)
        try:store=RunStore(Path(directory)/'run','credential')
        except BaseException:
            os.umask(previous_umask);raise
        old=os.environ.get(profile.password_env);os.environ[profile.password_env]=password
        runtime=os.environ.pop('CENTINELA_PROTECTED_RUNTIME',None)
        old_subprocess=adapter.subprocess
        def local_run(command,*,capture_output,text,timeout,check):
            if capture_output is not True or type(text) is not bool or type(check) is not bool:
                raise WorkerDenied('worker_subprocess_options_denied')
            validate_command(policy,list(command),password)
            if _read_private(command[4],4097,owner=os.geteuid()).decode()!=password+'\n':
                raise WorkerDenied('worker_secret_file_mismatch')
            record('tool_started',profile_sha256=hashlib.sha256(json.dumps([*command[:4],'<private>',command[5],'<private>',*command[7:]]).encode()).hexdigest())
            completed,timed_out=_execute(policy,list(command),timeout,directory,record)
            if timed_out:raise subprocess.TimeoutExpired(command,timeout)
            if text:completed.stdout=completed.stdout.decode(errors='replace');completed.stderr=completed.stderr.decode(errors='replace')
            if check:completed.check_returncode()
            return completed
        adapter.subprocess=SimpleNamespace(run=local_run,TimeoutExpired=subprocess.TimeoutExpired)
        try:
            record('credential_started',task_id=task.task_id,identity=identity())
            # La instancia trabajadora ejecuta el perfil localmente con su UID;
            # nunca recibe el entorno del proveedor ni el del daemon Docker.
            result=adapter.run_hydra(task,profile,store,timeout_seconds=timeout,authorize=authorize)
            files=[]
            for reference in [result.evidence_ref,result.diagnostic_ref]:
                if reference:
                    path=Path(directory)/'run'/reference
                    _evidence_path(reference)
                    raw=_read_private(path,MAX_OUTPUT,owner=os.geteuid())
                    files.append({'reference':reference,'data':base64.b64encode(raw).decode()})
            _send(connection,{'ok':True,'credential_result':result.model_dump(mode='json'),'files':files})
            record('credential_finished',task_id=task.task_id,status=result.status.value)
        finally:
            adapter.subprocess=old_subprocess
            if runtime is not None:os.environ['CENTINELA_PROTECTED_RUNTIME']=runtime
            else:os.environ.pop('CENTINELA_PROTECTED_RUNTIME',None)
            store.close()
            os.umask(previous_umask)
            if old is None:os.environ.pop(profile.password_env,None)
            else:os.environ[profile.password_env]=old


def _evidence_path(reference):
    if not isinstance(reference,str):raise WorkerDenied('worker_evidence_path_invalid')
    relative=Path(reference)
    if (relative.as_posix()!=reference or len(relative.parts)!=2 or relative.parts[0]!='evidence'
        or not re.fullmatch(r'[A-Za-z0-9_-]{1,180}\.json',relative.name)):
        raise WorkerDenied('worker_evidence_path_invalid')
    return relative


def run_credential(task,profile,store,*,timeout_seconds,authorize=None):
    from .contracts import TaskResult
    endpoint=os.environ.get('CENTINELA_HYDRA_SOCKET')
    if not endpoint:raise WorkerDenied('protected_worker_required')
    endpoint=_endpoint(endpoint)
    timeout_seconds=_timeout(timeout_seconds)
    password=os.environ.get(profile.password_env)
    if not password:raise WorkerDenied('worker_secret_missing')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(float(timeout_seconds)+15);connection.connect(endpoint)
        _,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if (uid,gid)!=(65533,65533):raise WorkerDenied('worker_server_identity_invalid')
        _send(connection,{'operation':'credential','task':task.model_dump(mode='json'),
            'profile':profile.model_dump(mode='json'),'password':password,'timeout':timeout_seconds})
        deadline=time.monotonic()+timeout_seconds+15
        challenges=0
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise WorkerDenied('worker_operation_timeout')
            connection.settimeout(remaining)
            message=_receive(connection)
            if message=={'authorize':True}:
                challenges+=1
                if challenges>4:raise WorkerDenied('worker_authorization_limit')
                try:
                    if authorize is not None:authorize()
                except BaseException:
                    _send(connection,{'authorized':False});raise
                _send(connection,{'authorized':True});continue
            break
    if not isinstance(message,dict) or message.get('ok') is not True:raise WorkerDenied('worker_request_denied')
    result=TaskResult.model_validate(message['credential_result'])
    if result.task_id!=task.task_id:raise WorkerDenied('worker_evidence_task_mismatch')
    expected={r for r in [result.evidence_ref,result.diagnostic_ref] if r}
    files=message['files']
    if not isinstance(files,list) or len(files)>2:raise WorkerDenied('worker_evidence_invalid')
    prepared={}
    for item in files:
        if not isinstance(item,dict) or set(item)!={'reference','data'}:raise WorkerDenied('worker_evidence_invalid')
        relative=_evidence_path(item['reference'])
        if item['reference'] in prepared:raise WorkerDenied('worker_evidence_duplicate')
        raw=base64.b64decode(item['data'],validate=True)
        if len(raw)>MAX_OUTPUT:raise WorkerDenied('worker_output_limit')
        original=result.evidence_sha256 if item['reference']==result.evidence_ref else result.diagnostic_sha256
        if hashlib.sha256(raw).hexdigest()!=original:raise WorkerDenied('worker_evidence_changed')
        prepared[item['reference']]=(relative.stem,raw)
    if set(prepared)!=expected:raise WorkerDenied('worker_evidence_missing')
    # Verify the complete transfer before writing any public evidence.
    for reference,(stem,raw) in prepared.items():
        saved,digest=store.evidence(stem,'json',raw)
        if saved!=reference:raise WorkerDenied('worker_evidence_path_invalid')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--policy',required=True)
    parser.add_argument('--listen-fd',required=True,type=int);parser.add_argument('--audit-log',required=True)
    options=parser.parse_args();serve(options.policy,options.listen_fd,options.audit_log)
