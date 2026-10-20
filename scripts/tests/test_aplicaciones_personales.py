import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
import pytest

pytestmark = pytest.mark.usefixtures("healthy_kernel")
from unittest.mock import patch
from contextlib import contextmanager

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from aplicaciones_personales import (configure_applications, save_session, load_session, read_sessions, ApplicationTask,
    execute_application, adjudicate_application, classify, corroborated_checks, PROFILE)
from laboratorio_personal import configuration, run
from dualstack_panel import validate_options, Panel, make_server
from auditoria.contracts import Target
from auditoria.store import RunStore

SESSION='SYNTHETIC_TEST_SESSION_DO_NOT_EXPORT'

class Server(BaseHTTPRequestHandler):
    protected=False
    seen=[]
    def handle(self):
        try:super().handle()
        except (ConnectionResetError,BrokenPipeError):pass
    def log_message(self,*args):pass
    def do_GET(self):
        type(self).seen.append((self.path,self.headers.get('Authorization')))
        auth=self.headers.get('Authorization')=='Bearer '+SESSION
        code=403;body=b'Access denied'
        if self.path=='/own' and auth:code=200;body=b'OWN_DOCUMENT_CANARY_2026'
        elif self.path=='/foreign' and auth:
            if not self.protected:code=200;body=b'FOREIGN_DOCUMENT_CANARY_2026'
        elif self.path=='/download?file=../internal/canary.txt' and auth:
            if not self.protected:code=200;body=b'INTERNAL_FILE_CANARY_2026'
        elif self.path=='/admin' and auth:
            if self.server.server_address[0]=='::1' and not self.protected:code=200;body=b'ADMIN_RESOURCE_CANARY_2026'
        elif self.path=='/redirect':
            self.send_response(302);self.send_header('Location','http://8.8.8.8/');self.end_headers();return
        elif self.path=='/ambiguous':code=200;body=b'Login page without a marker'
        self.send_response(code);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


@contextmanager
def server_pair(protected=False):
    handler=type('FixtureServer',(Server,),{'protected':protected,'seen':[]})
    v4=ThreadingHTTPServer(('127.0.0.1',0),handler)
    class V6(ThreadingHTTPServer):address_family=socket.AF_INET6
    try:v6=V6(('::1',v4.server_port),handler)
    except OSError:
        v4.server_close();raise
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in [v4,v6]]
    for t in threads:t.start()
    try:yield v4.server_port,handler
    finally:
        for s in [v4,v6]:s.shutdown();s.server_close()
        for t in threads:t.join()


def app_config(port=8080):
    return {'name':'Aplicación desconocida de prueba','ipv4':'127.0.0.1','ipv6':'::1','port':port,'scheme':'http',
        'session':'cuenta-prueba','scope_confirmed':True,'own_path':'/own','own_marker':'OWN_DOCUMENT_CANARY_2026',
        'foreign_path':'/foreign','foreign_marker':'FOREIGN_DOCUMENT_CANARY_2026',
        'download_path':'/download?file=../internal/canary.txt','download_marker':'INTERNAL_FILE_CANARY_2026',
        'admin_path':'/admin','admin_marker':'ADMIN_RESOURCE_CANARY_2026'}


def net_config(port=8080):return configuration({'ipv4':'127.0.0.1','ipv6':'::1','ports':[port],'interface':'lo'})


class ApplicationTests(unittest.TestCase):
    def test_configuration_requires_scope_ports_distinct_markers_and_declared_permissions(self):
        app=app_config();self.assertEqual(configure_applications([app],net_config()),[app])
        for change in [{'ipv4':'8.8.8.8'},{'ipv6':'fd00::2'},{'port':8000},{'scope_confirmed':False},
                       {'own_path':'http://8.8.8.8/'},{'own_path':'//8.8.8.8/'},{'own_path':'/x\r\nHost:x'},
                       {'foreign_marker':app['own_marker']},{'foreign_path':'/own'},{'download_path':'/secret'},
                       {'foreign_path':'/x?echo='+app['foreign_marker']},{'session':'../secret'}, {'password':'secret'}]:
            with self.subTest(change=change),self.assertRaises(ValueError):configure_applications([{**app,**change}],net_config())
        with self.assertRaises(ValueError):configure_applications([app]*17,net_config())
        with self.assertRaises(ValueError):configure_applications([app,app],net_config())
        options={'name':'Test','authorization':'LAB-PROPIO','scope':'personal','personal':net_config(),'applications':[app]}
        self.assertEqual(validate_options(options)['applications'],[app])
        with self.assertRaises(ValueError):validate_options({**options,'scope':'v2','personal':None})

    def test_sessions_are_private_and_never_in_public_options(self):
        with tempfile.TemporaryDirectory() as td,patch('aplicaciones_personales.SESSION_FILE',Path(td)/'sessions.json'):
            path=Path(td)/'sessions.json'
            save_session({'name':'cuenta-prueba','header':'Authorization','value':'Bearer '+SESSION})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(load_session('cuenta-prueba'),{'Authorization':'Bearer '+SESSION})
            with self.assertRaises(ValueError):save_session({'name':'x','header':'Host','value':'8.8.8.8'})
            with self.assertRaises(ValueError):save_session({'name':'x','header':'Cookie','value':'x\r\nInjected:y'})
            path.chmod(0o644)
            with self.assertRaises(ValueError):read_sessions()

    def test_session_endpoint_checks_csrf_and_does_not_publish_secret(self):
        import urllib.request
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as td:
            panel=Panel(Path(td)/'runs');server=make_server(panel,0)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url=f'http://127.0.0.1:{server.server_port}'
            def send(csrf):
                body=json.dumps({'name':'cuenta-prueba','header':'Authorization','value':'Bearer '+SESSION}).encode()
                return urllib.request.urlopen(urllib.request.Request(url+'/api/web-session',data=body,
                    headers={'Content-Type':'application/json','Origin':url,'X-CSRF-Token':csrf}),timeout=3)
            try:
                with patch('aplicaciones_personales.SESSION_FILE',Path(td)/'private.json'),patch('laboratorio_suite.activity',return_value={}),patch('aceptar_laboratorios.public_status',return_value={}):
                    with self.assertRaises(HTTPError) as denied:send('wrong')
                    self.assertEqual(denied.exception.code,403);denied.exception.close()
                    with send(panel.csrf) as response:result=json.load(response)
                    self.assertEqual(result['name'],'cuenta-prueba')
                    self.assertNotIn(SESSION,json.dumps(result))
                    self.assertNotIn(SESSION,json.dumps(panel.state()))
                    self.assertEqual((Path(td)/'private.json').stat().st_mode & 0o777,0o600)
            finally:server.shutdown();server.server_close();thread.join()

    def test_web_task_is_blocked_when_inventory_does_not_recognize_http(self):
        from auditoria.contracts import TaskResult,Service
        def inventory(task,store):
            return TaskResult(task_id=task.task_id,status='completed_no_findings',services=[Service(port=8080,protocol='tcp',state='open',name='ssh')])
        with tempfile.TemporaryDirectory() as td:
            options={'personal':net_config(),'architecture':'multiagent','tokens':0,'ia':'none','authorization':'LAB-PROPIO','applications':[app_config()],'creds':False}
            with patch('aplicaciones_personales.load_session',return_value={}),patch('laboratorio_personal.execute_task',side_effect=inventory),patch('aplicaciones_personales.execute_application') as web:
                self.assertEqual(run(options,Path(td)),3);web.assert_not_called()
            directory=next(Path(td).iterdir());report=json.loads((directory/'report.json').read_text())
            self.assertEqual(report['findings'],[])
            self.assertEqual(report['tasks'][-1]['reason_code'],'web_inventory_or_service_unavailable')
            self.assertTrue(all(c['web_state']=='incomplete' for c in report['coverage']))

    def execute(self,app,directory):
        target=Target(asset_id='external_app',address=app['ipv4'] or app['ipv6'],interface='lo',ports=[app['port']])
        task=ApplicationTask(task_id='application_test',target=target,application_index=0)
        store=RunStore(directory,'application_test')
        try:
            with patch('aplicaciones_personales.load_session',return_value={'Authorization':'Bearer '+SESSION}):
                result=execute_application(task,app,store,time.monotonic()+60)
            findings,validation=adjudicate_application(directory,task,result,app)
        finally:store.close()
        return task,result,findings,validation

    def test_real_dualstack_http_confirms_three_classes_and_preserves_no_secret_or_body(self):
        with server_pair() as (port,handler),tempfile.TemporaryDirectory() as td:
            directory=Path(td)/'evidence';app=app_config(port)
            task,result,findings,validation=self.execute(app,directory)
            self.assertEqual(result.status.value,'completed')
            self.assertEqual({f['condition'] for f in findings},{'object_authorization','file_boundary','ipv6_authorization_gap'})
            self.assertEqual(len(findings),5)
            self.assertTrue(validation['independent_confirmation'])
            self.assertEqual(len(handler.seen),20)
            for path in directory.rglob('*'):
                if path.is_file():
                    self.assertNotIn(SESSION.encode(),path.read_bytes())
                    self.assertNotIn(b'OWN_DOCUMENT_CANARY_2026',path.read_bytes())
            evidence=directory/result.evidence_ref;evidence.write_text('{}')
            self.assertEqual(adjudicate_application(directory,task,result,app)[0],[])

    def test_protected_controls_have_no_findings_and_ambiguous_200_is_incomplete(self):
        with server_pair(protected=True) as (port,_),tempfile.TemporaryDirectory() as td:
            task,result,findings,validation=self.execute(app_config(port),Path(td)/'protected')
            self.assertEqual(findings,[]);self.assertEqual(result.status.value,'completed')
            self.assertTrue(all(s=='not_detected' for s in validation['checks'].values()))
            app={**app_config(port),'foreign_path':'/ambiguous'}
            _,result,findings,validation=self.execute(app,Path(td)/'ambiguous')
            self.assertEqual(result.status.value,'failed');self.assertEqual(findings,[])
            self.assertEqual(validation['checks']['object_authorization'],'incomplete')

    def test_redirects_are_not_followed_and_deadline_stops_network_requests(self):
        with server_pair() as (port,handler),tempfile.TemporaryDirectory() as td:
            app={**app_config(port),'foreign_path':'/redirect'}
            _,result,findings,validation=self.execute(app,Path(td)/'redirect')
            self.assertEqual(validation['checks']['object_authorization'],'incomplete')
            self.assertFalse(any(f['condition']=='object_authorization' for f in findings))
            before=len(handler.seen)
            task=ApplicationTask(task_id='deadline',target=Target(asset_id='app',address='127.0.0.1',interface='lo',ports=[port]),application_index=0)
            store=RunStore(Path(td)/'deadline','deadline')
            try:
                with patch('aplicaciones_personales.load_session',return_value={}):result=execute_application(task,app,store,time.monotonic()-1)
            finally:store.close()
            self.assertEqual(len(handler.seen),before);self.assertEqual(result.status.value,'failed')

    def test_confirmation_must_match_the_same_family_and_direction(self):
        app=app_config()
        own={'status':200,'matches':{'own':True}};denied={'status':403,'matches':{}}
        foreign={'status':200,'matches':{'foreign':True}};admin={'status':200,'matches':{'admin':True}}
        a={'ipv4':{'own':own,'anonymous':denied,'foreign':foreign,'admin':denied},'ipv6':{'own':own,'anonymous':denied,'foreign':denied,'admin':admin}}
        b=copy.deepcopy(a);b['ipv4']['foreign']=denied;b['ipv6']['foreign']=foreign
        b['ipv4']['admin']=admin;b['ipv6']['admin']=denied
        checks,_=corroborated_checks(app,a,b)
        self.assertEqual(checks['object_authorization'],'incomplete')
        self.assertEqual(checks['ipv6_authorization_gap'],'incomplete')

    def test_application_changes_invalidate_precheck_signature_and_ai_context_hides_inputs(self):
        from dualstack_panel import personal_options_signature
        from auditoria.scheduler import Scheduler
        from laboratorio_personal import InventoryTask
        opts={'personal':net_config(),'applications':[app_config()]}
        changed=copy.deepcopy(opts);changed['applications'][0]['foreign_path']='/different'
        self.assertNotEqual(personal_options_signature(opts),personal_options_signature(changed))
        target=Target(asset_id='app',address='127.0.0.1',interface='lo',ports=[8080])
        inventory=InventoryTask(task_id='inventory',agent_type='ipv4_services',target=target)
        web=ApplicationTask(task_id='web',target=target,application_index=0,dependencies=['inventory'])
        scheduler=object.__new__(Scheduler);scheduler.aliases={};scheduler.asset_aliases={};scheduler.architecture='single'
        captured=[]
        def choose(choices,context,role):captured.append(json.dumps(context));return choices[0]
        scheduler.decide=choose
        self.assertIn(scheduler.select([inventory,web],[],[inventory,web]),[inventory,web])
        self.assertNotIn(SESSION,''.join(captured));self.assertNotIn(app_config()['own_marker'],''.join(captured))
        self.assertNotIn('127.0.0.1',''.join(captured))

    def test_whole_runner_real_nmap_and_web_without_api_in_both_architectures(self):
        for architecture in ['single','multiagent']:
            with self.subTest(architecture=architecture),server_pair() as (port,_),tempfile.TemporaryDirectory() as td:
                options={'personal':net_config(port),'architecture':architecture,'tokens':0,'ia':'none','authorization':'LAB-PROPIO',
                         'applications':[app_config(port)],'creds':False}
                with patch('aplicaciones_personales.load_session',return_value={'Authorization':'Bearer '+SESSION}),patch('auditoria.openai_provider.OpenAIScheduler') as api:
                    self.assertEqual(run(options,Path(td)),0);api.assert_not_called()
                directory=next(Path(td).iterdir());report=json.loads((directory/'report.json').read_text())
                self.assertEqual(len(report['inventory']),2);self.assertEqual(len(report['tasks']),3)
                self.assertEqual(len(report['findings']),5)
                self.assertTrue(all(c['web_state']=='confirmed' for c in report['coverage']))
                detail=Panel(Path(td)).detail(directory.name)
                self.assertFalse(detail['brief']['is_inventory']);self.assertTrue(detail['brief']['has_web'])
                self.assertEqual(len(detail['brief']['cards']),5)
                self.assertTrue(any(line['kind']=='HTTP' for line in detail['console']['lines']))
                for audience in ['technical','executive']:
                    html=Panel(Path(td)).environment.get_template('report.html').render(**detail,audience=audience)
                    self.assertIn('Hallazgos confirmados',html);self.assertNotIn('No se evaluaron vulnerabilidades.',html)
                    self.assertNotIn(SESSION,html)
