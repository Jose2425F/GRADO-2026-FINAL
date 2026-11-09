"""Authentication, ownership and shared-resource regression tests; no real tools/API."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import threading
from unittest.mock import patch
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from centinela_identity import IdentityStore
from centinela_tenancy import Workspaces
from dualstack_panel import Panel,make_server,Operations
from auditoria.store import RunStore,write_json

PASSWORD='A-private-test-password-2026'

@pytest.fixture
def service(tmp_path):
    store=IdentityStore(tmp_path/'private')
    admin=store.create_user('admin','Admin',PASSWORD,'admin')
    alice=store.create_user('alice','Alice',PASSWORD)
    bob=store.create_user('bob','Bob',PASSWORD)
    (store.directory/'legacy-owner').write_text(admin)
    base=Panel(tmp_path/'legacy')
    server=make_server(base,0,identity=store)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield store,base,server,admin,alice,bob
    server.shutdown();server.server_close();thread.join(timeout=5)

def call(service,path,token=None,body=None,csrf=None,origin=True):
    port=service[2].server_port;conn=http.client.HTTPConnection('127.0.0.1',port,timeout=20)
    headers={}
    if token:headers['Cookie']='__Host-centinela_session='+token
    if body is not None:
        headers['Content-Type']='application/json'
        if csrf:headers['X-CSRF-Token']=csrf
        if origin:headers['Origin']=f'http://127.0.0.1:{port}'
    conn.request('POST' if body is not None else 'GET',path,body=json.dumps(body) if body is not None else None,headers=headers)
    response=conn.getresponse();result=(response.status,dict(response.getheaders()),response.read());conn.close();return result

def login(service,name):
    token=service[0].login(name,PASSWORD,'test-'+name)
    return token,service[0].session(token)['csrf']

def fixture_run(root,key):
    store=RunStore(root/key,'fixture_'+key)
    write_json(store.root/'request.json',{'audit_id':'fixture_'+key,'bank':'empresa','architecture':'single'})
    write_json(store.root/'manifest.json',{'mode':'dry_run'})
    write_json(store.root/'plan.json',[])
    store.close()

def finished_run(root, key='panel/job/audit'):
    fixture_run(root,key)
    write_json(root/key/'manifest.json',{'mode':'live'})
    write_json(root/key/'report.json',{'status':'complete','mode':'live','tasks':[],'findings':[]})
    write_json((root/key).parent/'panel_job.json',{'name':'Informe de empresa','created_at':'2026-11-08T00:00:00Z','options':{'secret':'PRIVATE'}})
    (root/key/'report.html').write_text('<html>Informe publicado</html>')
    return key

def published_runs(service, token):
    status,_,body=call(service,'/api/state',token)
    assert status==200
    return json.loads(body)['runs']

def test_publish_read_reports_and_withdraw_immediately(service):
    key=finished_run(service[1].root)
    admin,csrf=login(service,'admin');alice,_=login(service,'alice');bob,_=login(service,'bob')
    assert published_runs(service,alice)==[]  # Prime the one-second state cache.
    assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==201
    runs=published_runs(service,alice);assert len(runs)==1
    published=runs[0]['key'];assert runs[0]['name']=='Informe de empresa'
    for path in (f'/api/run?key={published}',f'/report?key={published}&audience=executive',f'/report?key={published}&audience=technical',f'/download?key={published}&kind=html'):
        assert call(service,path,alice)[0]==200
        assert call(service,path,bob)[0]==404
    assert published_runs(service,bob)==[]
    assert call(service,'/api/admin/unpublish',admin,{'key':key,'user':service[4]},csrf)[0]==200
    assert published_runs(service,alice)==[]
    for path in (f'/api/run?key={published}',f'/report?key={published}',f'/download?key={published}&kind=html'):
        assert call(service,path,alice)[0]==404

@pytest.mark.parametrize('invalid',['simulation','unfinished','symlink','inactive'])
def test_invalid_publications_are_rejected(service,invalid,tmp_path):
    key=finished_run(service[1].root)
    if invalid=='simulation':
        write_json(service[1].root/key/'report.json',{'status':'complete','mode':'dry_run','tasks':[]})
    elif invalid=='unfinished':
        write_json(service[1].root/key/'report.json',{'status':'running','mode':'live','tasks':[]})
    elif invalid=='symlink':
        secret=tmp_path/'secret';secret.write_text('not part of this audit')
        (service[1].root/key/'evidence-link').symlink_to(secret)
    else:service[0].update_user(service[3],service[4],'auditor',False)
    admin,csrf=login(service,'admin')
    assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==400
    assert not list((service[0].directory/'workspaces'/service[4]/'runs').rglob('publicacion.json'))

def test_publications_are_scoped_to_the_publishing_admin(service):
    key=finished_run(service[1].root)
    second=service[0].create_user('admin2','Segundo administrador',PASSWORD,'admin')
    finished_run(service[0].directory/'workspaces'/second/'runs',key)
    admin,csrf=login(service,'admin');other,other_csrf=login(service,'admin2');alice,_=login(service,'alice')
    for token,challenge in ((admin,csrf),(other,other_csrf)):
        assert call(service,'/api/admin/publish',token,{'key':key,'user':service[4]},challenge)[0]==201
    assert len(published_runs(service,alice))==2
    for token in (admin,other):
        entries=json.loads(call(service,'/api/admin/publications',token)[2])['publications'][key]
        assert len(entries)==1
    assert call(service,'/api/admin/unpublish',admin,{'key':key,'user':service[4]},csrf)[0]==200
    assert len(published_runs(service,alice))==1
    assert call(service,'/api/admin/unpublish',admin,{'key':key,'user':service[4]},csrf)[0]==400
    assert call(service,'/api/admin/unpublish',other,{'key':key,'user':service[4]},other_csrf)[0]==200

def test_supervision_and_company_accounts_cannot_publish(service):
    key=finished_run(service[1].root)
    admin,csrf=login(service,'admin');alice,ac=login(service,'alice')
    assert call(service,'/api/admin/workspace',admin,{'id':service[4]},csrf)[0]==200
    for path in ('/api/admin/publish','/api/admin/unpublish'):
        for token,challenge in ((admin,csrf),(alice,ac)):
            assert call(service,path,token,{'key':key,'user':service[5]},challenge)[0]==403

def test_failed_copy_is_invisible_and_republish_replaces_stale_files(service):
    import shutil
    key=finished_run(service[1].root)
    admin,csrf=login(service,'admin');alice,_=login(service,'alice')
    original=shutil.copytree
    def interrupted(*args,**kwargs):
        original(*args,**kwargs)
        raise OSError('private filesystem information')
    with patch('shutil.copytree',side_effect=interrupted):
        status,_,body=call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)
        assert status==503 and b'private filesystem' not in body
    assert published_runs(service,alice)==[]
    assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==201
    published=published_runs(service,alice)[0]['key']
    (service[1].root/key/'report.html').unlink()
    with patch('shutil.copytree',side_effect=interrupted):
        assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==503
    assert call(service,f'/download?key={published}&kind=html',alice)[0]==200
    assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==201
    assert len(published_runs(service,alice))==1
    assert call(service,f'/download?key={published}&kind=html',alice)[0]==404

def test_copy_is_not_visible_until_commit_and_legacy_publications_can_be_withdrawn(service):
    import shutil
    key=finished_run(service[1].root)
    admin,csrf=login(service,'admin');alice,_=login(service,'alice')
    original=shutil.copytree
    def observe_copy(src,dst,*args,**kwargs):
        result=original(src,dst,*args,**kwargs)
        assert published_runs(service,alice)==[]
        return result
    with patch('shutil.copytree',side_effect=observe_copy):
        assert call(service,'/api/admin/publish',admin,{'key':key,'user':service[4]},csrf)[0]==201
    assert len(published_runs(service,alice))==1
    assert call(service,'/api/admin/unpublish',admin,{'key':key,'user':service[4]},csrf)[0]==200
    legacy=service[0].directory/'workspaces'/service[4]/'runs'/'publicadas'/'job'/'audit'
    shutil.copytree(service[1].root/key,legacy)
    write_json(legacy/'publicacion.json',{'source_key':key,'published_by':service[3],'published_at':'2026-11-07'})
    pubs=json.loads(call(service,'/api/admin/publications',admin)[2])['publications']
    assert pubs[key][0]['key']=='publicadas/job/audit'
    assert call(service,'/api/admin/unpublish',admin,{'key':key,'user':service[4]},csrf)[0]==200
    assert not legacy.exists()

def test_admin_audit_http_lifecycle_and_company_delivery_with_fake_executor(service):
    admin,csrf=login(service,'admin');alice,_=login(service,'alice')
    completed=threading.Event();commands=[]
    original=Operations._run
    class Process:
        pid=os.getpid()
        def wait(self, timeout=None):return 0
    def fake_process(command,**kwargs):
        commands.append(command)
        if '--output' in command:
            finished_run(Path(command[command.index('--output')+1]),'generated-audit')
        return Process()
    def execute(operations,job):
        operations.popen=fake_process
        try:original(operations,job)
        finally:completed.set()
    with patch.object(Operations,'_run',execute):
        assert call(service,'/api/lab/empresa/check',admin,{},csrf)[0]==202
        assert completed.wait(10);completed.clear()
        options={'name':'Auditoría entregable','scope':'empresa','authorization':'TEST-OWNED','architecture':'single','ia':'none','tokens':0,'mode':'live'}
        status,_,body=call(service,'/api/audit',admin,options,csrf)
        assert status==202,body
        assert completed.wait(10)
    jobs=json.loads(call(service,'/api/state',admin)[2])['jobs']
    job=next(j for j in jobs if j['action']=='audit')
    assert job['status']=='complete' and job['run_key']
    assert commands[-1][commands[-1].index('--output')+1].startswith(str(service[1].root))
    assert published_runs(service,alice)==[]
    assert call(service,'/api/admin/publish',admin,{'key':job['run_key'],'user':service[4]},csrf)[0]==201
    assert len(published_runs(service,alice))==1

def test_anonymous_cannot_read_any_audit_surface(service):
    for path in ('/api/state','/api/run?key=anything','/api/admin/users','/api/me','/api/manual/export'):
        assert call(service,path)[0]==401
    for path in ('/','/report?key=anything','/download?key=anything','/archive?id=anything','/account','/admin'):
        status,headers,_=call(service,path);assert status==303 and headers['Location']=='/login'
    assert call(service,'/login')[0]==200

def test_browser_login_issues_secure_cookie_and_checks_challenge(service):
    port=service[2].server_port
    status,headers,body=call(service,'/login')
    challenge=re.search(rb'name="csrf-token" content="([^"]+)"',body).group(1).decode()
    assert 'Secure' in headers['Set-Cookie'] and 'HttpOnly' in headers['Set-Cookie']
    assert call(service,'/api/auth/login',body={'username':'alice','password':PASSWORD},csrf=challenge)[0]==403
    conn=http.client.HTTPConnection('127.0.0.1',port)
    conn.request('POST','/api/auth/login',json.dumps({'username':'alice','password':PASSWORD}),{'Cookie':'__Host-centinela_login='+challenge,'Content-Type':'application/json','X-CSRF-Token':challenge,'Origin':f'http://127.0.0.1:{port}'})
    r=conn.getresponse();cookies=[v for k,v in r.getheaders() if k.lower()=='set-cookie'];assert r.status==200;r.read();conn.close()
    assert any('__Host-centinela_session=' in c and 'HttpOnly' in c and 'Secure' in c and 'SameSite=Lax' in c for c in cookies)

def test_user_cannot_read_other_users_runs_even_with_known_keys(service):
    store,base,_,admin,alice,bob=service
    root=store.directory/'workspaces'/alice/'runs';fixture_run(root,'alice-private')
    fixture_run(store.directory/'workspaces'/bob/'runs','bob-private')
    fixture_run(base.root,'legacy-private')
    a,csrf=login(service,'alice');b,_=login(service,'bob')
    data=json.loads(call(service,'/api/state',a)[2]);assert [r['key'] for r in data['runs']]==['alice-private']
    assert b'bob-private' not in json.dumps(data).encode() and b'legacy-private' not in json.dumps(data).encode()
    for path in ('/api/run?key=bob-private','/report?key=bob-private','/download?key=bob-private&kind=html','/api/run?key=../'+bob+'/runs/bob-private','/api/run?archive=other&key=bob-private'):
        assert call(service,path,a)[0]==404
    assert b'alice-private' not in call(service,'/api/state',b)[2]
    assert call(service,'/api/admin/users',a)[0]==403
    assert call(service,'/api/admin/workspace',a,{'id':bob},csrf)[0]==403
    assert call(service,'/api/lab/acceptance-all',a,{},csrf)[0]==403
    assert call(service,'/api/stop',a,{},csrf,origin=False)[0]==403

def test_admin_supervision_is_read_only_and_preserves_user_ownership(service):
    store,base,_,admin,alice,bob=service
    fixture_run(store.directory/'workspaces'/alice/'runs','alice-only')
    token,csrf=login(service,'admin')
    assert call(service,'/api/admin/workspace',token,{'id':alice},csrf)[0]==200
    assert [r['key'] for r in json.loads(call(service,'/api/state',token)[2])['runs']]==['alice-only']
    assert call(service,'/api/audit',token,{},csrf)[0]==403
    assert call(service,'/api/stop',token,{},csrf)[0]==403
    assert call(service,'/api/admin/workspace',token,{},csrf)[0]==200
    assert b'alice-only' not in call(service,'/api/state',token)[2]

def test_creation_roles_reset_revocation_and_password_change(service):
    admin,csrf=login(service,'admin');alice,ac=login(service,'alice')
    assert call(service,'/api/admin/users/create',alice,{'username':'hacker','name':'Hacker','password':PASSWORD,'role':'admin'},ac)[0]==403
    assert call(service,'/api/admin/users/create',admin,{'username':'newuser','name':'New User','password':PASSWORD,'role':'auditor'},csrf)[0]==201
    assert call(service,'/api/admin/users/update',admin,{'id':service[3],'role':'auditor','active':True},csrf)[0]==400
    assert call(service,'/api/admin/users/update',admin,{'id':service[4],'role':'auditor','active':False},csrf)[0]==200
    assert call(service,'/api/state',alice)[0]==401
    bob,bc=login(service,'bob')
    assert call(service,'/api/auth/password',bob,{'current_password':'incorrect','password':PASSWORD+'new'},bc)[0]==400
    assert call(service,'/api/auth/password',bob,{'current_password':PASSWORD,'password':PASSWORD+'new'},bc)[0]==200
    assert call(service,'/api/state',bob)[0]==401
    with pytest.raises(ValueError):service[0].login('bob',PASSWORD,'x')
    assert service[0].login('bob',PASSWORD+'new','x')

def test_session_expiry_logout_and_rate_limit(service):
    token,csrf=login(service,'alice');store=service[0]
    assert call(service,'/api/auth/logout',token,{},csrf)[0]==200
    assert call(service,'/api/state',token)[0]==401
    token,csrf=login(service,'bob')
    with store.connect() as db:db.execute('UPDATE sessions SET expires=0 WHERE user_id=?',(service[5],))
    assert call(service,'/api/state',token)[0]==401
    for _ in range(12):
        with pytest.raises(ValueError,match='incorrectos'):store.login('unknown','wrong','rate-test')
    with pytest.raises(ValueError,match='Demasiados'):store.login('unknown','wrong','rate-test')
    with store.connect() as db:
        row=db.execute('SELECT password FROM users WHERE username=?',('admin',)).fetchone()
        assert PASSWORD not in row['password']

def test_shared_lab_excludes_other_users_and_stop_is_local(service):
    registry=Workspaces(service[1],service[0]);a=registry.for_id(service[4]);b=registry.for_id(service[5])
    a.operations.jobs.append({'id':'active','action':'audit','status':'running','run_key':None})
    assert b.operations.snapshot()['busy'] is True
    assert b.operations.snapshot()['jobs']==[]
    with pytest.raises(ValueError,match='activa'):b.operations.start('empresa_restore')
    with pytest.raises(ValueError,match='No hay'):b.operations.stop()

def test_discovery_reservation_blocks_audits_across_admins_and_releases_after_failure(service):
    registry=Workspaces(service[1],service[0]);a=registry.for_id(service[3]);b=registry.for_id(service[4])
    with pytest.raises(OSError):
        with a.operations.reserve():
            assert b.state()['busy'] is True
            with pytest.raises(ValueError,match='activa'):b.operations.start('empresa_restore')
            with pytest.raises(ValueError,match='activa'):
                with b.operations.reserve():pytest.fail('Two simultaneous network operations')
            raise OSError('Synthetic scan failure')
    assert a.operations.snapshot()['busy'] is False
    assert b.operations.snapshot()['busy'] is False

def test_company_cannot_start_or_change_any_audit_control(service):
    token,csrf=login(service,'alice')
    for path in ('/api/audit','/api/stop','/api/lab/personal/check','/api/lab/personal/discover','/api/lab/empresa/restore','/api/lab/suite/down','/api/web-session','/api/evaluation-reference'):
        assert call(service,path,token,{},csrf)[0]==403

def test_session_csrf_is_not_shared_between_users(service):
    a,ac=login(service,'alice');b,bc=login(service,'bob')
    assert ac!=bc
    assert call(service,'/api/auth/logout',a,{},bc)[0]==403
    assert call(service,'/api/state',a)[0]==200


def test_audit_output_and_identity_survive_a_server_restart(service):
    store,base,_,admin,alice,bob=service
    registry=Workspaces(base,store)
    panel=registry.for_id(alice)
    captured=[]

    class Process:
        pid=os.getpid()
        def wait(self, timeout=None):return 0

    def fake_process(command,**kwargs):
        output=Path(command[command.index('--output')+1])
        captured.append(output)
        fixture_run(output,'generated-audit')
        return Process()

    panel.operations.popen=fake_process
    job={'id':'test-launch','action':'audit','name':'Alice audit',
         'created_at':'2026-11-07T00:00:00Z','status':'queued','run_key':None,
         'options':{'scope':'empresa','architecture':'single'}}
    panel.operations._run(job)
    assert job['status']=='complete'
    assert captured==[store.directory/'workspaces'/alice/'runs'/'panel'/'test-launch']
    token,_=login(service,'alice')
    restarted_store=IdentityStore(store.directory)
    assert restarted_store.session(token)['id']==alice
    restarted=Workspaces(base,restarted_store)
    assert [r['name'] for r in restarted.for_id(alice).state()['runs']]==['Alice audit']
    assert restarted.for_id(bob).state()['runs']==[]
    assert restarted.for_id(admin).state()['runs']==[]


def test_protected_export_keeps_job_name_and_date_when_published(service):
    key = finished_run(service[1].root, 'panel/job/runs/audit')
    folder = service[1].root / key
    (folder.parent / 'panel_job.json').rename(folder.parent.parent / 'panel_job.json')
    admin, csrf = login(service, 'admin')
    alice, _ = login(service, 'alice')
    bob, _ = login(service, 'bob')
    assert published_runs(service, admin)[0]['name'] == 'Informe de empresa'
    assert call(service, '/api/admin/publish', admin, {'key': key, 'user': service[4]}, csrf)[0] == 201
    published = published_runs(service, alice)[0]
    assert published['name'] == 'Informe de empresa'
    metadata = json.loads((service[0].directory / 'workspaces' / service[4] / 'runs' / published['key']).parent.joinpath('panel_job.json').read_text())
    assert metadata == {'name': 'Informe de empresa', 'created_at': '2026-11-08T00:00:00Z'}
    assert published_runs(service, bob) == []


def test_job_metadata_never_reads_above_a_workspace_named_runs(tmp_path):
    root = tmp_path / 'runs'
    panel = Panel(root)
    write_json(tmp_path / 'panel_job.json', {'name': 'Outside this workspace'})
    assert panel.job_metadata(root / 'audit') == {}
