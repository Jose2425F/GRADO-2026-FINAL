import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import pytest

pytestmark = pytest.mark.usefixtures("healthy_kernel")
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import laboratorio_personal as P
import puertos_personales as A
from auditoria.contracts import TaskResult
from auditoria.store import RunStore
from dualstack_panel import validate_options,Panel
from aplicaciones_personales import configure_applications
from scripts.tests.authorization_fixture import personal_authorization, scope_options


def xml_ports(task,ports):
    rows=''.join(f'<port protocol="tcp" portid="{p}"><state state="open"/></port>' for p in ports)
    return (f'<nmaprun><scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>'
        f'<host><status state="up"/><address addr="{task.target.address}" addrtype="ipv{P.ip_address(task.target.address).version}"/>'
        f'<ports>{rows}<extraports state="closed" count="{65535-len(ports)}"/></ports></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>').encode()


def xml_services(task,closed=()):
    names={2222:'ssh',15432:'postgresql',31337:'redis',8085:'http'}
    rows=''.join(f'<port protocol="tcp" portid="{p}"><state state="{"closed" if p in closed else "open"}"/>'
        f'<service name="{names.get(p,"unknown")}"/></port>' for p in task.target.ports)
    return f'<nmaprun><host><address addr="{task.target.address}" addrtype="ipv{P.ip_address(task.target.address).version}"/><ports>{rows}</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'.encode()


class AutomaticPortsTests(unittest.TestCase):
    def config(self,**values):return P.configuration({'ipv4':'192.0.2.10','interface':'eth0',**values})
    def task(self,**values):
        config=self.config(**values)
        family,address=P.scope_hosts(config)[0]
        return P.InventoryTask(task_id='automatic_test',agent_type=family+'_services',action_profile=A.PROFILE,target=P.target_for(family,address,config,'eth0'))
    def test_automatic_is_canonical_without_manual_ports_and_rejects_ambiguous_or_public_input(self):
        config=self.config();self.assertEqual(config['port_mode'],'auto');self.assertEqual(config['ports'],[])
        self.assertEqual(P.configuration(config),config)
        options=validate_options({'scope':'personal','personal':{'ipv4':'192.0.2.10'},'authorization':'LAB-PROPIO'})
        self.assertEqual(options['personal']['port_mode'],'auto')
        for values in [{'ipv4':'8.8.8.8'},{'ipv6':'fd00::/64'},{'port_mode':'auto','ports':[22]},
                       {'port_mode':'auto','ports':'22'},{'port_mode':True},{'port_mode':[]},
                       {'port_mode':'arbitrary'},{'interface':'eth0;id'}]:
            with self.subTest(values=values),self.assertRaises(ValueError):self.config(**values)
        self.assertNotIn('port_mode',self.config(ports=[22])) # réplicas históricas explícitas
    def test_cidr_liveness_keeps_routes_and_internal_probes_without_manual_ports(self):
        config=self.config(ipv4='192.0.2.0/30');targets=[P.target_for(f,a,config,'eth0') for f,a in P.scope_hosts(config)]
        xml=b'<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>'
        with tempfile.TemporaryDirectory() as root:
            store=RunStore(Path(root)/'run','host-discovery')
            try:
                with personal_authorization(scope_options(config)) as authorization,patch.object(P,'resolve_targets',side_effect=[[t] for t in targets]) as routes,patch.object(P.subprocess,'run',return_value=subprocess.CompletedProcess([],0,xml,b'')) as runner:
                    states=P.discover_targets(targets,config,store,time.monotonic()+240,authorization=authorization)
                self.assertTrue(all(call.args[0]['port_mode']=='auto' for call in routes.call_args_list))
                self.assertIn('-PS21,22,80,443,5432,8080',runner.call_args.args[0])
                self.assertEqual(states,{'192.0.2.1':'up','192.0.2.2':'down'})
                self.assertFalse(runner.call_args.kwargs.get('shell',False))
            finally:store.close()
    def test_evaluator_accepts_automatic_tcp_scope_without_manual_port_list(self):
        from referencia_laboratorio import evaluate_reference
        request={'bank':'personal','personal':self.config()}
        record={'name':'Referencia de prueba','cases':[{'address':'192.0.2.10','port':31337,'condition':'ssh_default_credential','expected':'present'}]}
        with tempfile.TemporaryDirectory() as root:
            value=evaluate_reference(Path(root),request,[],{},record,{'sha256':'b'*64})
            self.assertEqual(value['FN'],1);self.assertEqual(value['TP'],0)
            record['cases'][0]['address']='192.0.2.11'
            with self.assertRaises(ValueError):evaluate_reference(Path(root),request,[],{},record,{'sha256':'b'*64})

    def test_command_is_closed_finite_tcp_connect_without_nse_or_shell(self):
        for task in [self.task(),self.task(ipv4='',ipv6='fd00::10')]:
            command=A.automatic_command(task)
            self.assertIn('--unprivileged',command);self.assertIn('-sT',command);self.assertIn('-Pn',command)
            self.assertEqual(command[command.index('-p')+1],'1-65535')
            self.assertNotIn('-sV',command);self.assertNotIn('--script',command);self.assertNotIn('-sU',command)
        task=self.task();task.target.ports=[22]
        with self.assertRaises(ValueError):A.automatic_command(task)
    def test_full_range_accounting_rejects_partial_timedout_duplicate_and_wrong_target_xml(self):
        task=self.task();raw=xml_ports(task,[2222,15432,31337]);self.assertEqual(A.parse_open_ports(raw,task),[2222,15432,31337])
        bad=[raw.replace(b'65532',b'65531'),raw.replace(b'<host>',b'<host timedout="true">'),
             raw.replace(b'<status state="up"/>',b'<status state="down"/>'),raw.replace(b'192.0.2.10',b'8.8.8.8'),raw.replace(b'exit="success"',b'exit="error"'),
             xml_ports(task,[2222,2222]),raw.replace(b'protocol="tcp" portid=',b'protocol="udp" portid='),
             raw.replace(b'portid="2222"',b'portid="0"')]
        for value in bad:
            with self.subTest(value=value[:40]),self.assertRaises(ValueError):A.parse_open_ports(value,task)
        self.assertEqual(A.parse_open_ports(xml_ports(task,[]),task),[])
    def test_execute_revalidates_route_and_timeout_is_not_an_empty_success(self):
        task=self.task()
        with tempfile.TemporaryDirectory() as root:
            store=RunStore(Path(root)/'run','route-test')
            try:
                with personal_authorization(scope_options(self.config())) as authorization,patch.object(P,'resolve_targets',return_value=[]) as routes:
                    with self.assertRaises(ValueError):A.execute_open_task(task,store,time.monotonic()+100,runner=lambda *a,**k:self.fail('No tool before route'),authorization=authorization)
                def timeout(command,**kwargs):
                    self.assertFalse(kwargs.get('shell',False));self.assertLessEqual(kwargs['timeout'],65)
                    raise subprocess.TimeoutExpired(command,kwargs['timeout'],output=xml_ports(task,[]))
                with personal_authorization(scope_options(self.config())) as authorization,patch.object(P,'resolve_targets',return_value=[task.target]):result=A.execute_open_task(task,store,time.monotonic()+100,runner=timeout,authorization=authorization)
                self.assertEqual(result.status,'failed');self.assertFalse(result.observations['scan_complete']);self.assertEqual(result.services,[])
            finally:store.close()
    def execute_run(self,root,*,ports=(2222,15432,31337),architecture='multiagent',hosts=1,sweep=False,applications=None,closed=(),tamper=False,ia='none'):
        options=validate_options({'scope':'personal','personal':{'ipv4':','.join('192.0.2.'+str(10+i) for i in range(hosts)),'interface':'eth0'},
            'authorization':'LAB-PROPIO','architecture':architecture,'creds':sweep,'applications':applications or [],'ia':ia,'expert_mode':ia=='openai'})
        active=0;maximum=0;lock=threading.Lock();commands=[]
        original=P.execute_task;original_open=A.execute_open_task
        def route(config,**kwargs):
            config=P.configuration(config);return [P.target_for(f,a,config,'eth0') for f,a in P.scope_hosts(config)]
        def enter():
            nonlocal active,maximum
            with lock:active+=1;maximum=max(maximum,active)
            time.sleep(.015)
        def leave():
            nonlocal active
            with lock:active-=1
        def discover(task,store,deadline,**kwargs):
            enter()
            try:
                result=original_open(task,store,deadline,runner=lambda command,**kwargs:subprocess.CompletedProcess(command,0,xml_ports(task,ports),b''),authorization=kwargs.get('authorization'))
                commands.append(result.command)
                if tamper:(store.root/result.evidence_ref).write_bytes(b'<altered/>')
                return result
            finally:leave()
        def service(task,store,**kwargs):
            enter()
            try:
                result=original(task,store,runner=lambda command,**kwargs:subprocess.CompletedProcess(command,0,xml_services(task,closed),b''),authorization=kwargs.get('authorization'))
                commands.append(result.command);return result
            finally:leave()
        with personal_authorization(options),patch.object(P,'resolve_targets',side_effect=route),patch.object(P,'discover_targets',side_effect=lambda targets,*args,**kwargs:{t.address:'up' for t in targets}),\
             patch.object(A,'execute_open_task',side_effect=discover),patch.object(P,'execute_task',side_effect=service),\
             patch.object(P,'credential_sweep',return_value=[]) as credentials,patch('aplicaciones_personales.load_session',return_value={}),\
             patch('aplicaciones_personales.execute_application') as web:
            code=P.run(options,Path(root))
        directory=next(Path(root).iterdir());report=json.loads((directory/'report.json').read_text());plan=json.loads((directory/'plan.json').read_text())
        return code,report,plan,maximum,commands,directory,credentials,web
    def test_admin_receives_only_open_ports_and_dispatches_recognition_then_compatible_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,maximum,commands,directory,credentials,_=self.execute_run(root,sweep=True)
            self.assertEqual(code,0);self.assertEqual(len(plan),2)
            detail=next(t for t in plan if t['action_profile']==P.PROFILE)
            self.assertEqual(detail['target']['ports'],[2222,15432,31337]);self.assertNotIn(80,detail['target']['ports'])
            self.assertEqual(credentials.call_args.kwargs['services_by_address'],{'192.0.2.10':{2222:'ssh',15432:'postgres'}})
            self.assertEqual(len(report['inventory']),1);self.assertEqual(report['inventory'][0]['scan_status'],'completed_no_findings')
            events=__import__('panel_observabilidad').event_rows(directory/'events.sqlite3',directory)
            handoff=next(e for e in events if e[3]=='open_ports_reported');self.assertEqual(handoff[5]['open_ports'],[2222,15432,31337])
            value=Panel(Path(root)).detail(directory.name);self.assertEqual(value['brief']['service_count'],3)
            self.assertTrue(any(line['kind']=='ADMINISTRADOR' for line in value['console']['lines']))
    def test_more_than_32_open_ports_are_chunked_without_silent_truncation(self):
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,*_=self.execute_run(root,ports=tuple(range(10000,10070)))
            chunks=[t['target']['ports'] for t in plan if t['action_profile']==P.PROFILE]
            self.assertEqual(code,0);self.assertEqual([len(c) for c in chunks],[32,32,6]);self.assertEqual(sum(chunks,[]),list(range(10000,10070)))
            self.assertEqual(len(report['inventory']),1);self.assertEqual(len(report['inventory'][0]['services']),70)
    def test_no_open_ports_creates_no_fingerprint_or_credential_tasks(self):
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,_,commands,_,credentials,_=self.execute_run(root,ports=(),sweep=True)
            self.assertEqual(code,0);self.assertEqual(len(plan),1);self.assertEqual(len(commands),1)
            self.assertEqual(report['inventory'][0]['ports'],[]);self.assertEqual(credentials.call_args.args[0],[])
    def test_evidence_tampering_and_service_task_limit_never_dispatch_unverified_ports(self):
        for tamper,limit in [(True,256),(False,0)]:
            with tempfile.TemporaryDirectory() as root,patch.object(A,'MAX_SERVICE_TASKS',limit):
                code,report,plan,_,commands,_,credentials,_=self.execute_run(root,tamper=tamper,sweep=True)
                self.assertEqual(code,3);self.assertEqual(len(plan),1);self.assertEqual(len(commands),1)
                self.assertEqual(report['inventory'][0]['scan_status'],'incomplete');self.assertEqual(credentials.call_args.args[0],[])
    def test_closed_after_discovery_does_not_trigger_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,_,_,_,credentials,_=self.execute_run(root,ports=(2222,),closed=(2222,),sweep=True)
            self.assertEqual(code,0);self.assertEqual(credentials.call_args.args[0],[])
            self.assertEqual(report['inventory'][0]['services'],[])
    def test_concurrency_and_runtime_budget_are_preserved(self):
        for architecture,expected in [('single',1),('multiagent',2)]:
            with tempfile.TemporaryDirectory() as root:
                code,_,_,maximum,*_=self.execute_run(root,architecture=architecture,hosts=2)
                self.assertEqual(code,0);self.assertEqual(maximum,expected)
        with tempfile.TemporaryDirectory() as root,patch.object(P,'RUNTIME_SECONDS',69):
            code,report,_,maximum,commands,_,credentials,_=self.execute_run(root,sweep=True)
            self.assertEqual(code,3);self.assertEqual(maximum,0);self.assertEqual(commands,[])
            self.assertTrue(all(t['status']=='cancelled' for t in report['tasks']))
    def test_real_scheduler_accepts_new_tasks_with_a_simulated_provider_and_shared_budget(self):
        from types import SimpleNamespace
        from scripts.tests.test_panel_expertos import FakeTransport
        class Transport(FakeTransport):
            def post(self,endpoint,body,*,timeout):
                properties=body['text']['format']['schema']['properties']
                if endpoint=='responses' and 'choice' in properties:
                    self.calls.append((endpoint,body,timeout))
                    return {'model':'gpt-6.1-sol','status':'completed','id':'simulated-choice',
                        'output':[{'type':'message','content':[{'type':'output_text','text':json.dumps({'choice':properties['choice']['enum'][0]})}]}],
                        'usage':{'input_tokens':100,'output_tokens':80,'total_tokens':180}}
                return super().post(endpoint,body,timeout=timeout)
        transport=Transport();config=SimpleNamespace(model='gpt-6.1-sol',api_key='fake-key',reasoning_effort='low',max_output_tokens=2048)
        with tempfile.TemporaryDirectory() as root,patch('auditoria.openai_provider.load_openai_config',return_value=config),\
             patch('auditoria.openai_provider.OpenAIConfig.from_environment',return_value=config),\
             patch('auditoria.openai_provider.OpenAITransport',return_value=transport),\
             patch('llm_especialistas.TracedOpenAITransport',return_value=transport):
            code,report,plan,*_=self.execute_run(root,hosts=2,ia='openai')
            self.assertEqual(code,0);self.assertTrue(report['llm']['usage_complete']);self.assertEqual(report['llm']['fallbacks'],0)
            self.assertTrue(all(c['status']=='accepted' for c in report['llm']['calls']))
            self.assertTrue(report['llm']['specialist_reviews']);self.assertLessEqual(report['llm']['known_tokens'],6000)
            self.assertEqual(len([t for t in plan if t['action_profile']==P.PROFILE]),2)
    def test_automatic_kpi_catalog_is_independent_of_worker_completion_order(self):
        from panel_metricas import scope_signature
        request={'bank':'personal','personal':self.config()}
        plan=[{'task_id':'a','target':{'address':'192.0.2.1','ports':[]},'action_profile':A.PROFILE},
              {'task_id':'b','target':{'address':'192.0.2.2','ports':[]},'action_profile':A.PROFILE},
              {'task_id':'c','target':{'address':'192.0.2.1','ports':[2222]},'action_profile':P.PROFILE},
              {'task_id':'d','target':{'address':'192.0.2.2','ports':[15432]},'action_profile':P.PROFILE}]
        reordered=plan[:2]+list(reversed(plan[2:]))
        self.assertEqual(scope_signature(request,plan),scope_signature(request,reordered))
        changed=[dict(t) for t in reordered];changed[-1]['target']={'address':'192.0.2.1','ports':[22]}
        self.assertNotEqual(scope_signature(request,plan),scope_signature(request,changed))

    def test_configured_web_endpoint_is_not_probed_without_matching_open_http_service(self):
        app={'name':'Test','ipv4':'192.0.2.10','ipv6':'','port':8085,'session':'test-session','scope_confirmed':True,
             'own_path':'/own','own_marker':'OWN_MARKER_123','foreign_path':'/foreign','foreign_marker':'FOREIGN_MARKER_123'}
        self.assertEqual(configure_applications([app],self.config())[0]['port'],8085)
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,_,_,_,_,web=self.execute_run(root,ports=(31337,),applications=[app])
            web.assert_not_called();self.assertEqual(code,3)
            self.assertTrue(any(t.get('reason_code')=='web_inventory_or_service_unavailable' for t in report['tasks']))
        with tempfile.TemporaryDirectory() as root:
            code,report,plan,_,_,_,_,web=self.execute_run(root,ports=(8085,),applications=[app])
            web.assert_called_once()
            self.assertEqual(web.call_args.args[0].target.ports,[8085])
            self.assertEqual(len(web.call_args.args[0].dependencies),2)
            self.assertEqual(code,3) # el cliente simulado no aporta evidencia web, nunca inventar hallazgos

if __name__=='__main__':unittest.main()
