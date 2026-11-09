"""Reabre sólo datos sintéticos para verificar presentación; no inicia auditorías/API."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode

from probar_cola_webshadow import BrowserHTTP, saved, stop, status_identity, WEB_UID


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-summary',type=Path,required=True)
    parser.add_argument('--web-root',type=Path,required=True)
    parser.add_argument('--artifacts',type=Path,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('root required')
    os.umask(0o077)
    previous=json.loads(args.previous_summary.read_text())
    assert previous['status']=='passed' and previous['none_phase_passed'] is True and previous['api_phase_run'] is True
    base=Path(previous['stage']);root=Path(previous['temporary_root']);data=root/'data';webroot=args.web_root
    assert base.parent==Path('/var/tmp') and root.parent==Path('/var/tmp') and root.name.startswith('centinela-shadow-v4-')
    assert (data/'accounts.sqlite3').stat().st_uid==WEB_UID
    sys.path[:0]=[str(base/'repo/scripts'),str(base/'repo/piloto_kali/prototipo/src')]
    from ejecutar_protegido import trusted
    from centinela_identity import IdentityStore
    trusted(webroot,directory=True)
    args.artifacts.mkdir(parents=True,exist_ok=False);args.artifacts.chmod(0o700)
    store=IdentityStore(data)
    users={user['username']:user for user in store.users()}
    assert set(users)=={'shadow-admin','shadow-empresa-a','shadow-empresa-b'}
    passwords={name:secrets.token_urlsafe(32) for name in users}
    for name,user in users.items():store.update_user('temporary-metadata-console',user['id'],user['role'],True,passwords[name])
    # IdentityStore only changes synthetic account hashes/sessions, not reports.
    os.chown(data/'accounts.sqlite3',WEB_UID,WEB_UID)
    adminroot=data/'workspaces'/users['shadow-admin']['id']/'runs'
    expected={}
    for job in adminroot.glob('panel/*/panel_job.json'):
        metadata=json.loads(job.read_text())
        for report in job.parent.glob('runs/*/report.json'):
            expected[report.parent.relative_to(adminroot).as_posix()]={'name':metadata['name'],'created_at':metadata['created_at']}
    assert len(expected)==2,'expected two existing audit results'
    selected=[]
    for key in expected:
        selected.extend(p for p in (adminroot/key).rglob('*') if p.is_file())
    original={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in selected}
    temp=root/('metadata-'+secrets.token_hex(4));temp.mkdir(mode=0o755);temp.chmod(0o755)
    sockets=temp/'sockets';sockets.mkdir(mode=0o750);sockets.chmod(0o750);os.chown(sockets,0,WEB_UID)
    private=temp/'private';private.mkdir(mode=0o700)
    temporary=temp/'tmp';temporary.mkdir(mode=0o700);os.chown(temporary,WEB_UID,WEB_UID)
    endpoint=sockets/'control.sock';python=base/'venv/bin/python'
    with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
    assert port!=8765
    proof={'schema':'centinela-shadow-metadata-recheck/1','status':'running','new_audits':0,'generation_calls':0,
           'source_summary_sha256':hashlib.sha256(args.previous_summary.read_bytes()).hexdigest(),
           'harness_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'stage':str(base),'web_root':str(webroot),
           'same_temporary_data':True,'original_report_file_count':len(original),'checks':[],
           'web_source_sha256':{str(p.relative_to(webroot)):hashlib.sha256(p.read_bytes()).hexdigest() for p in
               [webroot/'scripts/dualstack_panel.py',webroot/'scripts/centinela_publications.py',webroot/'scripts/dualstack_ui/app.js']}}
    processes=[];logs=[];browsers=[]
    try:
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONNOUSERSITE':'1',
             'PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':str(base/'repo/piloto_kali/prototipo/src')+':'+str(base/'repo/scripts')}
        log=(private/'operator.log').open('wb');logs.append(log)
        operator=subprocess.Popen([str(python),str(base/'repo/scripts/operador_web.py'),'--base',str(base),
            '--spool',str(base/'private'/('metadata-jobs-'+secrets.token_hex(5))),'--socket',str(endpoint),
            '--panel-uid',str(WEB_UID),'--accounts',str(data/'accounts.sqlite3')],cwd=base/'repo',env=env,
            stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(operator)
        deadline=time.monotonic()+20
        while not endpoint.exists():
            assert operator.poll() is None and time.monotonic()<deadline;time.sleep(.1)
        log=(private/'web.log').open('wb');logs.append(log)
        webenv={**env,'PYTHONPATH':str(webroot/'piloto_kali/prototipo/src')+':'+str(webroot/'scripts'),
            'HOME':str(data),'TMPDIR':str(temporary),'CENTINELA_DATA_DIR':str(data),'CENTINELA_EXECUTOR_SOCKET':str(endpoint),
            'DOCKER_HOST':'unix:///run/centinela-no-docker.sock','LANGSMITH_TRACING':'false','LANGCHAIN_TRACING_V2':'false'}
        web=subprocess.Popen(['/usr/bin/setpriv','--reuid='+str(WEB_UID),'--regid='+str(WEB_UID),'--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs',str(python),
            str(webroot/'scripts/dualstack_panel.py'),'--port',str(port),'--runs',str(data/'legacy-runs')],
            cwd=webroot,env=webenv,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(web)
        deadline=time.monotonic()+30
        while True:
            assert web.poll() is None and time.monotonic()<deadline
            try:
                if BrowserHTTP(port).call('GET','/login')[0]==200:break
            except OSError:pass
            time.sleep(.1)
        browsers=[BrowserHTTP(port) for _ in range(3)];admin,company_a,company_b=browsers
        for name,browser in zip(['shadow-admin','shadow-empresa-a','shadow-empresa-b'],browsers):
            assert browser.login(name,passwords[name])==users[name]['id']
        state=admin.state();actual={r['key']:r for r in state['runs']}
        assert set(actual)==set(expected)
        for key,metadata in expected.items():
            assert actual[key]['name']==metadata['name']
            code,_,_=admin.call('POST','/api/admin/publish',{'key':key,'user':users['shadow-empresa-a']['id']});assert code==201
        time.sleep(1.1)
        delivered=company_a.state()['runs'];assert len(delivered)==2 and company_b.state()['runs']==[]
        assert {r['name'] for r in delivered}=={v['name'] for v in expected.values()}
        for run in delivered:
            key=run['key'];parent=data/'workspaces'/users['shadow-empresa-a']['id']/'runs'/Path(key).parent
            metadata=json.loads((parent/'panel_job.json').read_text())
            source=next(v for v in expected.values() if v['name']==run['name'])
            assert metadata['created_at']==source['created_at']
            assert company_a.call('GET','/report?'+urlencode({'key':key}))[0]==200
            assert company_b.call('GET','/api/run?'+urlencode({'key':key}))[0]==404
        proof['checks'].append({'check':'both_original_names_and_dates_preserved_in_publications','passed':True,'results':2})
        for key in expected:
            assert admin.call('POST','/api/admin/unpublish',{'key':key,'user':users['shadow-empresa-a']['id']})[0]==200
        for browser in browsers:
            assert browser.call('POST','/api/auth/logout',{})[0]==200
        current={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in original}
        assert current==original,'original audit artifacts changed during presentation check'
        proof['original_reports_unchanged']=True
        proof['original_report_manifest_sha256']=hashlib.sha256(json.dumps(original,sort_keys=True).encode()).hexdigest()
        proof['status']='passed'
    except BaseException as error:
        proof.update(status='failed',failure_type=type(error).__name__,failure=str(error)[:200]);raise
    finally:
        for process in reversed(processes):stop(process)
        for log in logs:log.close()
        proof['own_processes_stopped']=all(process.poll() is not None for process in processes)
        saved(args.artifacts/'summary.json',proof)
        print(json.dumps({'status':proof['status'],'summary':str(args.artifacts/'summary.json'),
                          'new_audits':0,'generation_calls':0,'own_processes_stopped':proof['own_processes_stopped']}))
    return 0

if __name__=='__main__':raise SystemExit(main())
