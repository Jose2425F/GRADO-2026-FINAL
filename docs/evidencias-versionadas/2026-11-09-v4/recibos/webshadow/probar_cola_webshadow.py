"""Aceptación temporal de cola+web sobre un stage protegido; ejecutar como root.

No contacta el panel existente ni instala unidades. Las contraseñas y sesiones
se mantienen en memoria; SQLite/logs/spool quedan privados y no son publicables.
--api-config sólo se utiliza después de cerrar con éxito la fase sin API.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode

WEB_UID = 65529
TERMINAL = {'complete', 'partial', 'failed', 'interrupted', 'cancelled'}


def saved(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)


def status_identity(pid):
    values = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'Uid','Gid','Groups','NoNewPrivs','CapInh','CapPrm','CapEff','CapBnd','CapAmb'}:
            values[key] = value.strip()
    return values


class BrowserHTTP:
    """Cookies manuales: HTTP loopback privado, sin llamar al dominio público."""
    def __init__(self, port):
        self.port, self.cookies, self.csrf = port, {}, None
    def call(self, method, path, value=None):
        headers = {'Host': f'127.0.0.1:{self.port}'}
        if self.cookies: headers['Cookie'] = '; '.join(k + '=' + v for k,v in self.cookies.items())
        body = None
        if value is not None:
            body = json.dumps(value).encode()
            headers.update({'Origin': f'http://127.0.0.1:{self.port}', 'Content-Type': 'application/json',
                            'X-CSRF-Token': self.csrf or self.cookies.get('__Host-centinela_login','')})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=40)
        try:
            connection.request(method,path,body=body,headers=headers)
            response = connection.getresponse(); raw = response.read(12_000_000)
            for key, value_ in response.getheaders():
                if key.lower() == 'set-cookie':
                    cookie = SimpleCookie(); cookie.load(value_)
                    for name,item in cookie.items():
                        if item.value:self.cookies[name]=item.value
                        else:self.cookies.pop(name,None)
            try: data=json.loads(raw)
            except ValueError:data=raw
            return response.status,data,raw
        finally:connection.close()
    def login(self, username, password):
        code,_,_=self.call('GET','/login'); assert code == 200
        code,_,_=self.call('POST','/api/auth/login',{'username':username,'password':password}); assert code == 200
        code,_,raw=self.call('GET','/'); assert code == 200
        matched=re.search(rb'<meta name="csrf-token" content="([^"]+)"',raw)
        assert matched,'csrf meta missing'
        self.csrf=matched[1].decode()
        code,me,_=self.call('GET','/api/me'); assert code == 200
        return me['user']['id']
    def state(self):
        code,value,_=self.call('GET','/api/state'); assert code == 200
        return value
    def action(self,path,value,*,seconds=2900):
        code,value_,_=self.call('POST',path,value)
        assert code == 202, f'operation request rejected HTTP {code}: '+(str(value_.get('error',''))[:200] if isinstance(value_,dict) else '')
        identifier=value_['job']['id']; deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            state=self.state()
            found=next((j for j in state['jobs'] if j['id']==identifier),None)
            if found and found['status'] in TERMINAL and not state['busy']:return found
            time.sleep(.7)
        raise RuntimeError('shadow_operation_timeout')


def stop(process):
    if process is None or process.poll() is not None:return
    os.killpg(process.pid,signal.SIGTERM)
    try:process.wait(timeout=65)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',required=True,type=Path)
    parser.add_argument('--artifacts',required=True,type=Path)
    parser.add_argument('--web-root',type=Path)
    parser.add_argument('--api-config',type=Path)
    parser.add_argument('--api-tokens',type=int,default=6000)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077)
    if not 256<=args.api_tokens<=60000:parser.error('API budget must be256..60000 tokens')
    base=args.stage
    if base.parent!=Path('/var/tmp') or not re.fullmatch(r'c113-[0-9a-f]{12}',base.name):parser.error('stage scope')
    if not args.artifacts.is_absolute():parser.error('absolute artifacts required')
    args.artifacts.mkdir(parents=True,exist_ok=False);args.artifacts.chmod(0o700)
    repo=base/'repo';webroot=args.web_root or repo;python=base/'venv/bin/python'
    sys.path[:0]=[str(repo/'scripts'),str(repo/'piloto_kali/prototipo/src')]
    from centinela_identity import IdentityStore
    from ejecutar_protegido import trusted
    trusted(base,directory=True);trusted(repo,directory=True);trusted(webroot,directory=True)
    root=Path('/var/tmp')/('centinela-shadow-v4-'+secrets.token_hex(6));root.mkdir(mode=0o755);root.chmod(0o755)
    data=root/'data';data.mkdir(mode=0o700)
    private=root/'private';private.mkdir(mode=0o700)
    sockets=root/'sockets';sockets.mkdir(mode=0o750);sockets.chmod(0o750);os.chown(sockets,0,WEB_UID)
    temporary=root/'tmp';temporary.mkdir(mode=0o700);os.chown(temporary,WEB_UID,WEB_UID)
    store=IdentityStore(data)
    passwords={name:secrets.token_urlsafe(32) for name in ['admin','empresa-a','empresa-b']}
    users={name:store.create_user('shadow-'+name,'Shadow '+name,passwords[name],
                                 'admin' if name=='admin' else 'auditor') for name in passwords}
    for path in [data,*data.rglob('*')]:os.chown(path,WEB_UID,WEB_UID)
    with socket.socket() as free:
        free.bind(('127.0.0.1',0));port=free.getsockname()[1]
    assert port!=8765
    endpoint=sockets/'control.sock';spool=base/'private'/('shadow-web-jobs-'+secrets.token_hex(5))
    proof={'schema':'centinela-webshadow-acceptance/1','stage':str(base),'web_root':str(webroot),'temporary_root':str(root),
           'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           'public_service_contacted':False,'systemd_or_nginx_modified':False,
           'transport_scope':'HTTP requests on private loopback, manually held Secure cookies; not a browser/TLS test',
           'none_architecture':'multiagent','api_architecture':'single',
           'provider_secret_published':False,'api_calls_before_none':0,'status':'running','checks':[],
           'source_sha256':{str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [repo/'scripts/operador_web.py',repo/'scripts/panel_ejecutor.py',repo/'scripts/dualstack_panel.py',
                repo/'scripts/ejecutar_protegido.py',repo/'piloto_kali/prototipo/src/auditoria/provider_proxy.py']},
           'web_source_sha256':{str(p.relative_to(webroot)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [webroot/'scripts/dualstack_panel.py',webroot/'scripts/panel_ejecutor.py',webroot/'scripts/dualstack_ui/app.js',
                webroot/'scripts/dualstack_ui/workspace.js']}}
    processes=[];logs=[];admin=company_a=company_b=None
    def settle_jobs():
        from operador_web import ExecutorClient
        client=ExecutorClient(endpoint,timeout=5)
        pending=[]
        for path in data.glob('workspaces/*/runs/panel/*/.protected_capability.json'):
            value=json.loads(path.read_text())
            if not (spool/value['job']/'state.json').is_file():continue
            arguments={'job':value['job'],'owner':value['owner'],'token':value['token']}
            state=client.call('status',**arguments)
            if state['status'] not in TERMINAL:
                client.call('cancel',**arguments);pending.append(arguments)
        deadline=time.monotonic()+100
        while pending and time.monotonic()<deadline:
            pending=[value for value in pending if client.call('status',**value)['status'] not in TERMINAL]
            if pending:time.sleep(.4)
        return not pending
    def latest_operator_receipt():
        candidates=sorted(spool.glob('*/operator.log'),key=lambda p:p.stat().st_mtime_ns)
        assert candidates,'operator_log_missing'
        values=[]
        for line in candidates[-1].read_text(errors='replace').splitlines():
            try:values.append(json.loads(line))
            except ValueError:pass
        record=next(v for v in reversed(values) if isinstance(v,dict) and 'receipt' in v)
        target=Path(record['receipt'])
        assert target.parent.parent==base/'private' and target.name=='operator.json'
        receipt=json.loads(target.read_text())
        assert receipt['roles_stopped_before_evaluation'] is True
        return receipt
    def checked(name,**fields):
        proof['checks'].append({'check':name,'passed':True,**fields});saved(args.artifacts/'summary.json',proof)
        print(json.dumps({'event':'shadow_check_passed','check':name},ensure_ascii=False),flush=True)
    try:
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
             'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1',
             'PYTHONPATH':str(repo/'piloto_kali/prototipo/src')+':'+str(repo/'scripts')}
        log=(private/'operator.log').open('wb');logs.append(log)
        operator=subprocess.Popen([str(python),str(repo/'scripts/operador_web.py'),'--base',str(base),'--spool',str(spool),
            '--socket',str(endpoint),'--panel-uid',str(WEB_UID),'--accounts',str(data/'accounts.sqlite3')],
            cwd=repo,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(operator)
        end=time.monotonic()+20
        while not endpoint.exists():
            assert operator.poll() is None,'operator_startup_failed'
            assert time.monotonic()<end,'operator_socket_timeout'
            time.sleep(.1)
        metadata=endpoint.stat();assert metadata.st_uid==0 and metadata.st_gid==WEB_UID and stat.S_IMODE(metadata.st_mode)==0o660
        checked('root_socket_mode',uid=metadata.st_uid,gid=metadata.st_gid,mode='0660')
        log=(private/'web.log').open('wb');logs.append(log)
        webenv={**env,'PYTHONPATH':str(webroot/'piloto_kali/prototipo/src')+':'+str(webroot/'scripts'),
                'CENTINELA_DATA_DIR':str(data),'HOME':str(data),'TMPDIR':str(temporary),
                'CENTINELA_EXECUTOR_SOCKET':str(endpoint),'DOCKER_HOST':'unix:///run/centinela-no-docker.sock',
                'LANGSMITH_TRACING':'false','LANGCHAIN_TRACING_V2':'false'}
        web=subprocess.Popen(['/usr/bin/setpriv','--reuid='+str(WEB_UID),'--regid='+str(WEB_UID),'--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',str(python),
            str(webroot/'scripts/dualstack_panel.py'),'--port',str(port),'--runs',str(data/'legacy-runs')],
            cwd=webroot,env=webenv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(web)
        end=time.monotonic()+30
        while True:
            assert web.poll() is None,'web_startup_failed'
            try:
                if BrowserHTTP(port).call('GET','/login')[0]==200:break
            except OSError:pass
            assert time.monotonic()<end,'web_response_timeout'
            time.sleep(.1)
        identity=status_identity(web.pid)
        assert identity['Uid'].split()==[str(WEB_UID)]*4 and identity['Gid'].split()==[str(WEB_UID)]*4
        assert not identity['Groups'] and identity['NoNewPrivs']=='1'
        assert all(int(identity[k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
        checked('web_privilege_separation',identity=identity)
        def negative_probe(uid, code):
            command=['/usr/bin/setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups',
                     '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',
                     str(python),'-I','-B','-c',code]
            value=subprocess.run(command,cwd=repo,env=env,capture_output=True,text=True,timeout=10,check=True)
            return json.loads(value.stdout)
        code=("import socket,json\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
              "try:\n s.connect("+repr(str(endpoint))+")\n result={'connected':True}\n"
              "except OSError as e:result={'connected':False,'errno':e.errno}\n"
              "s.close()\nprint(json.dumps(result))")
        wrong_uid=negative_probe(65531,code)
        assert wrong_uid=={'connected':False,'errno':13}
        code=("import os,socket,json\nout={}\n"
              "try:\n fd=os.open("+repr(str(base/'private/docker.sock'))+",os.O_RDONLY|os.O_NONBLOCK);os.close(fd);out['daemon_errno']=0\n"
              "except OSError as e:out['daemon_errno']=e.errno\n"
              "try:\n s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.close();out['raw_errno']=0\n"
              "except OSError as e:out['raw_errno']=e.errno\nprint(json.dumps(out))")
        # Opening a Unix socket as a file can report ENXIO after lookup; the
        # protected private parent must deny this web principal before lookup.
        denied=negative_probe(WEB_UID,code)
        assert denied=={'daemon_errno':13,'raw_errno':1}
        checked('real_unix_and_raw_negatives',wrong_uid_queue=wrong_uid,web_daemon_and_raw=denied)
        assert BrowserHTTP(port).call('GET','/api/state')[0]==401
        admin,company_a,company_b=[BrowserHTTP(port) for _ in range(3)]
        for name,browser in [('admin',admin),('empresa-a',company_a),('empresa-b',company_b)]:
            assert browser.login('shadow-'+name,passwords[name])==users[name]
        checked('three_real_logins_and_unauthenticated_denial')
        for path in ['/workspace.js','/styles.css','/novaflow.css','/interface.css','/portal.css','/portal.js','/cliente.js']:
            code,_,raw=admin.call('GET',path);assert code==200 and raw
        checked('seven_runtime_assets')
        assert company_a.call('GET','/api/admin/users')[0]==403
        assert company_b.call('POST','/api/audit',{})[0]==403
        assert company_b.call('POST','/api/admin/publish',{})[0]==403
        assert company_a.state()['runs']==company_b.state()['runs']==[]
        checked('company_roles_cannot_administer_execute_or_publish')
        dry={'name':'Empaquetado shadow v2 sin red','authorization':'LAB-PROPIO','architecture':'single',
             'scope':'v2','mode':'dry_run','ia':'none','tokens':6000,'creds':False}
        before=len(admin.state()['jobs'])
        code,_,_=admin.call('POST','/api/audit',dry)
        assert code==400 and len(admin.state()['jobs'])==before
        checked('unsupported_http_v2_dryrun_rejected_before_job',http_status=code,
                new_jobs=0,generation_calls=0)
        for endpoint_ in ['/api/lab/empresa/restore','/api/lab/empresa/check']:
            result=admin.action(endpoint_,{});assert result['status']=='complete',f'lab_operation_{result["status"]}'
            checked('protected_'+endpoint_.rsplit('/',1)[-1],job_id=result['id'],status=result['status'])
        value={'name':'Aceptación shadow sin API','authorization':'LAB-PROPIO','architecture':'multiagent','scope':'empresa',
               'mode':'live','ia':'none','tokens':0,'creds':False}
        result=admin.action('/api/audit',value);assert result['status']=='complete','none_audit_not_complete'
        source_key=result['run_key'];assert source_key
        code,detail,_=admin.call('GET','/api/run?'+urlencode({'key':source_key}));assert code==200 and detail['brief']['final']
        none_receipt=latest_operator_receipt()
        assert none_receipt['api_calls']==0 and none_receipt['operator_exit_code']==0
        checked('protected_none_audit_closed',job_id=result['id'],run_key=source_key,
                tasks_total=len(detail['run']['tasks']),api_calls=none_receipt['api_calls'],
                protected_run_id=none_receipt['run_id'],descriptor_sha256=none_receipt['descriptor_sha256'])
        code,_,_=admin.call('POST','/api/admin/publish',{'key':source_key,'user':users['empresa-a']});assert code==201
        deadline=time.monotonic()+10
        while True:
            available=company_a.state()['runs']
            if available:break
            assert time.monotonic()<deadline,'publication_timeout';time.sleep(.2)
        assert len(available)==1 and company_b.state()['runs']==[]
        delivered_key=available[0]['key']
        assert company_a.call('GET','/api/run?'+urlencode({'key':delivered_key}))[0]==200
        assert company_a.call('GET','/report?'+urlencode({'key':delivered_key}))[0]==200
        code,_,pdf=company_a.call('GET','/download?'+urlencode({'key':delivered_key,'kind':'pdf'}))
        assert code==200 and pdf.startswith(b'%PDF-')
        for key in [source_key,delivered_key]:
            assert company_b.call('GET','/api/run?'+urlencode({'key':key}))[0]==404
            assert company_b.call('GET','/download?'+urlencode({'key':key,'kind':'pdf'}))[0]==404
        checked('published_only_to_company_a_cross_company_reads_denied',pdf_sha256=hashlib.sha256(pdf).hexdigest(),
                company_a_runs=1,company_b_runs=0)
        assert admin.call('POST','/api/admin/unpublish',{'key':source_key,'user':users['empresa-a']})[0]==200
        time.sleep(1.2)
        assert company_a.state()['runs']==[]
        assert company_a.call('GET','/api/run?'+urlencode({'key':delivered_key}))[0]==404
        checked('unpublication_revokes_read_access')
        proof['none_phase_passed']=True;saved(args.artifacts/'none-approved.json',proof)
        if args.api_config:
            # Esta rama nunca se alcanza si cualquier comprobación sin API falla.
            from auditoria.provider_proxy import public_config
            info=args.api_config.lstat()
            assert stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not info.st_mode&0o077
            raw=args.api_config.read_bytes();configured=json.loads(raw);public_config(configured)
            target=base/'private/openai.json'
            if target.exists():raise RuntimeError('provider_configuration_already_exists')
            fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as output:output.write(raw)
            os.chown(target,0,0);del configured,raw
            result=admin.action('/api/lab/empresa/check',{});assert result['status']=='complete'
            value.update(name='Aceptación shadow API acotada',ia='openai',tokens=args.api_tokens,architecture='single')
            result=admin.action('/api/audit',value);assert result['status'] in {'complete','partial'}
            assert result.get('run_key')
            code,detail,_=admin.call('GET','/api/run?'+urlencode({'key':result['run_key']}));assert code==200
            api_receipt=latest_operator_receipt()
            usage=api_receipt['provider_usage']
            assert api_receipt['api_calls']>0 and usage['known_tokens']>0 and usage['usage_complete'] is True
            raw_report=json.loads((data/'workspaces'/users['admin']/'runs'/result['run_key']/'report.json').read_text())
            accepted=sum(c.get('status')=='accepted' for c in raw_report.get('llm',{}).get('calls',[]))
            assert accepted>0,'no_accepted_provider_response'
            checked('bounded_api_audit_closed',job_id=result['id'],status=result['status'],run_key=result['run_key'],
                    generation_calls=api_receipt['api_calls'],known_tokens=usage['known_tokens'],
                    usage_complete=usage['usage_complete'],accepted_decisions=accepted,
                    provider_uid=65530,protected_run_id=api_receipt['run_id'],
                    descriptor_sha256=api_receipt['descriptor_sha256'])
            proof['api_phase_run']=True
        else:proof['api_phase_run']=False
        for browser in [admin,company_a,company_b]:
            assert browser.call('POST','/api/auth/logout',{})[0]==200
            assert browser.call('GET','/api/state')[0]==401
        checked('three_sessions_revoked')
        proof['status']='passed'
    except BaseException as error:
        proof.update(status='failed',failure_type=type(error).__name__,failure=str(error)[:200])
        raise
    finally:
        try:
            settled=settle_jobs() if endpoint.exists() else True
        except Exception:
            settled=False
        proof['own_jobs_terminal_before_queue_stop']=settled
        if not settled:proof['status']='cleanup_incomplete'
        for process in reversed(processes):stop(process)
        for log in logs:log.close()
        proof['own_processes_stopped']=all(process.poll() is not None for process in processes)
        proof['private_material_not_publicable']=['temporary data SQLite','spool state capability hashes','session cookies','private logs']
        saved(args.artifacts/'summary.json',proof)
        print(json.dumps({'status':proof['status'],'summary':str(args.artifacts/'summary.json'),
                          'own_processes_stopped':proof['own_processes_stopped']},ensure_ascii=False),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
