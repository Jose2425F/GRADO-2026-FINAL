import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime", "healthy_kernel")
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from laboratorio_personal import (configuration, resolve_targets, scope_hosts, target_for, discover_targets,
                                 parse_discovery, execute_task, InventoryTask, command_for, parse_inventory, run,
                                 supported_services, coverage_for)
from dualstack_panel import validate_options, Panel, make_server
from auditoria.contracts import Target, TaskResult, Service
from auditoria.store import RunStore
from scripts.tests.authorization_fixture import personal_authorization, scope_options


class PersonalLabTests(unittest.TestCase):
    def test_ipv4_start_end_ranges_are_bounded_and_private(self):
        config={**self.config(),'ipv4':'192.168.56.10 - 192.168.56.80','ipv6':''}
        normalized=configuration(config)
        self.assertEqual(normalized['ipv4'],'192.168.56.10-192.168.56.80')
        self.assertEqual(len(scope_hosts(normalized)),71)
        self.assertEqual(len(scope_hosts({**config,'ipv4':'192.168.56.0-192.168.56.255'})),256)
        for value in ['192.168.56.80-192.168.56.10','192.168.56.0-192.168.57.0','8.8.8.1-8.8.8.2',
                      '192.168.255.254-192.169.0.1','192.168.56.1-192.168.56.2,192.168.56.3']:
            with self.subTest(value=value),self.assertRaises(ValueError):configuration({**config,'ipv4':value})
        with self.assertRaises(ValueError):configuration({**config,'ipv6':'fd00::1-fd00::2'})

    def test_service_profiles_follow_observed_names_even_on_unusual_ports(self):
        services=[Service(port=2222,protocol='tcp',state='open',name='ssh'),
                  Service(port=15432,protocol='tcp',state='open',name='postgresql'),
                  Service(port=8085,protocol='tcp',state='open',name='http'),
                  Service(port=22,protocol='tcp',state='open',name='telnet'),
                  Service(port=443,protocol='tcp',state='open',name='https')]
        self.assertEqual(supported_services(services),{2222:'ssh',15432:'postgres',8085:'http-get'})

    def test_host_coverage_never_equates_unsupported_or_missing_tests_with_no_findings(self):
        config=configuration({**self.config(),'ipv6':''})
        target=target_for('ipv4',config['ipv4'],config,'eth0')
        task=InventoryTask(task_id='coverage_inventory',agent_type='ipv4_services',target=target)
        inventory=TaskResult(task_id=task.task_id,status='completed_no_findings',services=[Service(port=80,protocol='tcp',state='open',name='http')])
        value=coverage_for([target],[task],[inventory],[],{target.address:'up'},True)[0]
        self.assertEqual(value['credentials_state'],'incomplete')
        self.assertEqual(value['application_checks'],'requires_application_adapter')
        value=coverage_for([target],[],[],[],{target.address:'down'},True)[0]
        self.assertEqual(value['credentials_state'],'not_evaluated')
        self.assertEqual(value['inventory_state'],'down')
        value=coverage_for([target],[task],[inventory],[],{target.address:'up'},False)[0]
        self.assertEqual(value['credentials_state'],'not_requested')

    def test_start_end_range_discovers_before_scanning_only_live_hosts(self):
        config={**self.config(),'ipv4':'192.168.56.10-192.168.56.12','ipv6':''}
        with self.run_mocked(config,['192.168.56.11']) as (code,report,plan,worker,directory):
            self.assertEqual(code,0);self.assertEqual(worker.call_count,1)
            self.assertEqual([t['target']['address'] for t in plan],['192.168.56.11'])
            self.assertEqual(len(report['inventory']),3)
            self.assertEqual(len(report['coverage']),3)
            detail=Panel(directory.parent).detail(directory.name)
            self.assertEqual(len(detail['brief']['coverage']),3)
            self.assertTrue(all('coverage' in i for i in detail['brief']['inventory']))
    def config(self):
        return {'ipv4':'192.168.56.20','ipv6':'fd00:56::20','ports':'80,8080','interface':'eth0'}

    def task(self,ipv6=False):
        return InventoryTask(task_id='personal_test_1',agent_type='ipv6_services' if ipv6 else 'ipv4_services',
            target=Target(asset_id='objetivo',address='fd00:56::20' if ipv6 else '192.168.56.20',interface='eth0',ports=[80,8080]))

    def test_scope_rejects_urls_public_hosts_and_command_injection(self):
        for extra in [{'ipv4':'8.8.8.8'},{'ipv4':'192.168.56.20;whoami'},{'ipv4':'http://192.168.56.20'},
                      {'ipv4':'192.168.56.0/23'},{'ipv6':'ff02::1'},{'ports':'1-65535'},
                      {'ports':'80,80'},{'ports':[True]},{'interface':'eth0;id'},{'command':'whoami'}]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):configuration({**self.config(),**extra})
        self.assertEqual(configuration(self.config())['ports'],[80,8080])

    def test_cidr_and_lists_are_bounded_canonical_and_idempotent(self):
        config=configuration({**self.config(),'ipv4':'192.168.56.0/24','ipv6':''})
        hosts=scope_hosts(config)
        self.assertEqual(len(hosts),254)
        self.assertEqual(hosts[0],('ipv4','192.168.56.1'))
        self.assertEqual(hosts[-1],('ipv4','192.168.56.254'))
        self.assertEqual(configuration(config),config)
        config=configuration({**self.config(),'ipv4':'192.168.56.20, 192.168.56.21,192.168.56.20',
                              'ipv6':'fd00:56::20,fd00:56::21'})
        self.assertEqual(len(scope_hosts(config)),4)
        for prefix,count in [('192.168.56.0/31',2),('192.168.56.20/32',1)]:
            self.assertEqual(len(scope_hosts({**self.config(),'ipv4':prefix,'ipv6':''})),count)

    def test_scope_rejects_public_cidr_mixed_lists_and_ipv6_prefixes(self):
        for extra in [{'ipv4':'8.8.8.0/24'},{'ipv4':'192.168.56.20,8.8.8.8'},
                      {'ipv4':'192.168.56.20/24'},{'ipv4':'192.168.56.0/24,192.168.57.1'},
                      {'ipv6':'fd00:56::/64'},{'ipv6':'2001:db8::/128'},{'ipv6':'fd00::1,2606:4700::1111'},
                      {'ipv6':'fd00::1,'},{'ipv6':'fe80::1%eth0'}]:
            with self.subTest(extra=extra),self.assertRaises(ValueError):configuration({**self.config(),**extra})

    def test_host_limit_is_shared_between_both_families(self):
        base={**self.config(),'ipv4':'192.168.56.0/24','ipv6':'fd00::1,fd00::2'}
        self.assertEqual(len(scope_hosts(base)),256)
        with self.assertRaises(ValueError):configuration({**base,'ipv6':'fd00::1,fd00::2,fd00::3'})
        with self.assertRaises(ValueError):configuration({**self.config(),'ipv4':'10.0.0.0/8'})
        addresses=','.join('fd00::'+format(i,'x') for i in range(1,258))
        with self.assertRaises(ValueError):configuration({**self.config(),'ipv4':'','ipv6':addresses})
        self.assertEqual(len(scope_hosts({**self.config(),'ipv4':'','ipv6':','.join('fd00::'+format(i,'x') for i in range(1,257))})),256)

    def test_routes_must_be_direct_and_match_the_selected_interface(self):
        direct=subprocess.CompletedProcess([],0,stdout=json.dumps([{'dev':'eth0'}]))
        with patch('laboratorio_personal.shutil.which',return_value='/usr/bin/nmap'),patch('laboratorio_personal.subprocess.run',return_value=direct):
            targets=resolve_targets(self.config())
        self.assertEqual([t.address for t in targets],['192.168.56.20','fd00:56::20'])
        via=subprocess.CompletedProcess([],0,stdout=json.dumps([{'dev':'eth0','gateway':'192.168.56.1'}]))
        with patch('laboratorio_personal.shutil.which',return_value='/usr/bin/nmap'),patch('laboratorio_personal.subprocess.run',return_value=via):
            with self.assertRaises(ValueError):resolve_targets(self.config())
        with patch('laboratorio_personal.shutil.which',return_value='/usr/bin/nmap'),patch('laboratorio_personal.subprocess.run',return_value=direct):
            with self.assertRaises(ValueError):resolve_targets({**self.config(),'interface':'eth1'})

    def test_precheck_checks_every_host_without_discovery_or_model(self):
        config={**self.config(),'ipv4':'192.168.56.0/29','ipv6':'fd00::1,fd00::2'}
        direct=subprocess.CompletedProcess([],0,stdout=json.dumps([{'dev':'eth0'}]))
        with patch('laboratorio_personal.shutil.which',return_value='/usr/bin/nmap'),patch('laboratorio_personal.subprocess.run',return_value=direct) as runner:
            targets=resolve_targets(config)
        self.assertEqual(len(targets),8)
        self.assertEqual(len({t.asset_id for t in targets}),8)
        self.assertTrue(all(c.args[0][0]=='ip' for c in runner.call_args_list))
        self.assertEqual(runner.call_count,8)

    def discovery_xml(self,up):
        hosts=''.join(f'<host><status state="up"/><address addr="{address}" addrtype="ipv4"/></host>' for address in up)
        return f'<nmaprun>{hosts}<runstats><finished exit="success"/></runstats></nmaprun>'.encode()

    def test_discovery_only_accepts_authorized_completed_results(self):
        config=configuration({**self.config(),'ipv4':'192.168.56.0/30','ipv6':''})
        targets=[target_for(f,a,config,'eth0') for f,a in scope_hosts(config)]
        self.assertEqual(parse_discovery(self.discovery_xml(['192.168.56.1']),targets),
                         {'192.168.56.1':'up','192.168.56.2':'down'})
        for raw in [self.discovery_xml(['8.8.8.8']),self.discovery_xml(['192.168.56.1']*2),
                    self.discovery_xml([]).replace(b'exit="success"',b'exit="error"')]:
            with self.assertRaises(ValueError):parse_discovery(raw,targets)

    def test_discovery_revalidates_routes_and_keeps_finite_command_and_evidence(self):
        import time
        config=configuration({**self.config(),'ipv4':'192.168.56.0/30','ipv6':''})
        targets=[target_for(f,a,config,'eth0') for f,a in scope_hosts(config)]
        with tempfile.TemporaryDirectory() as temp:
            store=RunStore(Path(temp)/'run','discovery_test')
            try:
                with personal_authorization(scope_options(config)) as authorization,patch('laboratorio_personal.resolve_targets',side_effect=[[t] for t in targets]) as routes,patch('laboratorio_personal.subprocess.run',return_value=subprocess.CompletedProcess([],0,self.discovery_xml(['192.168.56.1']),b'')) as runner:
                    states=discover_targets(targets,config,store,time.monotonic()+240,authorization=authorization)
                self.assertEqual(routes.call_count,2)
                command=runner.call_args.args[0]
                self.assertIn('--unprivileged',command);self.assertIn('-sn',command);self.assertIn('-n',command)
                self.assertIn('-PS80,8080',command)
                self.assertEqual(command[-2:],['192.168.56.1','192.168.56.2'])
                self.assertNotIn('-Pn',command);self.assertNotIn('--script',command)
                self.assertFalse(runner.call_args.kwargs.get('shell',False))
                self.assertLessEqual(runner.call_args.kwargs['timeout'],60)
                self.assertEqual(states['192.168.56.2'],'down')
                self.assertTrue((store.root/'evidence/discovery_0.xml').is_file())
            finally:store.close()

    def test_execute_task_still_revalidates_each_literal_host(self):
        config=configuration({**self.config(),'ipv6':''})
        target=target_for('ipv4',config['ipv4'],config,'eth0')
        task=InventoryTask(task_id='personal_execute',agent_type='ipv4_services',target=target)
        with tempfile.TemporaryDirectory() as temp:
            store=RunStore(Path(temp)/'run','execute_test')
            try:
                with personal_authorization(scope_options(config)) as authorization,patch('laboratorio_personal.resolve_targets',return_value=[target]) as route:
                    result=execute_task(task,store,runner=lambda *a,**k:subprocess.CompletedProcess(a,0,self.xml(),b''),authorization=authorization)
                self.assertEqual(route.call_args.args[0]['ipv4'],target.address)
                self.assertEqual(result.status,'completed_no_findings')
                with personal_authorization(scope_options(config)) as authorization,patch('laboratorio_personal.resolve_targets',return_value=[]),self.assertRaises(ValueError):execute_task(task,store,authorization=authorization)
            finally:store.close()

    def run_mocked(self,config,up,*,architecture='multiagent',executor=None):
        import contextlib
        @contextlib.contextmanager
        def context():
            with tempfile.TemporaryDirectory() as temp:
                options=validate_options({'name':'Mi red','authorization':'LAB-PROPIO','scope':'personal','personal':config,'architecture':architecture})
                def process(command,**kwargs):
                    if command[0]=='ip':return subprocess.CompletedProcess(command,0,json.dumps([{'dev':'eth0'}]))
                    self.assertIn('-sn',command)
                    return subprocess.CompletedProcess(command,0,self.discovery_xml(up),b'')
                def execute(task,store,**kwargs):
                    return TaskResult(task_id=task.task_id,status='completed_no_findings')
                with personal_authorization(options),patch('laboratorio_personal.shutil.which',return_value='/usr/bin/nmap'),patch('laboratorio_personal.subprocess.run',side_effect=process),patch('laboratorio_personal.execute_task',side_effect=executor or execute) as worker:
                    code=run(options,Path(temp))
                directory=next(Path(temp).glob('*/report.json')).parent
                yield code,json.loads((directory/'report.json').read_text()),json.loads((directory/'plan.json').read_text()),worker,directory
        return context()

    def test_each_live_host_produces_one_task_and_down_hosts_only_inventory(self):
        config={**self.config(),'ipv4':'192.168.56.0/29','ipv6':'fd00::1,fd00::2'}
        with self.run_mocked(config,['192.168.56.1','192.168.56.4']) as (code,report,plan,worker,directory):
            self.assertEqual(code,0)
            self.assertEqual(worker.call_count,4) # dos descubiertos y dos IPv6 explícitos
            self.assertEqual(len(plan),4);self.assertEqual(len(report['tasks']),4)
            self.assertEqual(len(report['inventory']),8)
            self.assertEqual(sum(i['host_state']=='down' for i in report['inventory']),4)
            self.assertEqual({t['target']['address'] for t in plan},{'192.168.56.1','192.168.56.4','fd00::1','fd00::2'})
            self.assertTrue(all(i['task_id'] is None and not i['ports'] for i in report['inventory'] if i['host_state']=='down'))
            self.assertEqual(report['findings'],[]);self.assertEqual(report['llm']['known_tokens'],0)
            self.assertEqual(json.loads((directory/'manifest.json').read_text())['execution_concurrency'],2)

    def test_all_down_is_preserved_and_visible_in_panel_without_fake_tasks(self):
        config={**self.config(),'ipv4':'192.168.56.0/30','ipv6':''}
        with self.run_mocked(config,[]) as (code,report,plan,worker,directory):
            self.assertEqual(code,0);self.assertEqual(plan,[]);worker.assert_not_called()
            self.assertEqual([i['host_state'] for i in report['inventory']],['down','down'])
            panel=Panel(directory.parent)
            state=panel.state()
            self.assertEqual(len(state['runs']),1)
            detail=panel.detail(state['runs'][0]['key'])
            self.assertEqual(len(detail['brief']['inventory']),2)
            self.assertIn('2 hosts down',detail['brief']['summary'])

    def test_explicit_lists_skip_discovery_and_runtime_exhaustion_cancels_hosts(self):
        config={**self.config(),'ipv4':'192.168.56.1,192.168.56.2','ipv6':''}
        with self.run_mocked(config,[],architecture='single') as (code,report,plan,worker,directory):
            self.assertEqual(code,0);self.assertEqual(worker.call_count,2)
            self.assertEqual(json.loads((directory/'manifest.json').read_text())['execution_concurrency'],1)
        with patch('laboratorio_personal.RUNTIME_SECONDS',69):
            with self.run_mocked(config,[]) as (code,report,plan,worker,directory):
                self.assertEqual(code,3);worker.assert_not_called()
                self.assertTrue(all(t['status']=='cancelled' for t in report['tasks']))

    def test_failed_discovery_does_not_report_down_or_launch_port_scans(self):
        config={**self.config(),'ipv4':'192.168.56.0/30','ipv6':''}
        with patch('laboratorio_personal.parse_discovery',side_effect=ValueError('truncated')):
            with self.run_mocked(config,[]) as (code,report,plan,worker,directory):
                self.assertEqual(code,3);worker.assert_not_called()
                self.assertTrue(all(i['host_state']=='unknown' for i in report['inventory']))
                self.assertTrue(all(t['status']=='blocked' for t in report['tasks']))

    def test_actual_concurrency_remains_one_or_two_workers(self):
        import threading
        import time
        config={**self.config(),'ipv4':'192.168.56.1,192.168.56.2,192.168.56.3,192.168.56.4','ipv6':''}
        for architecture,limit in [('single',1),('multiagent',2)]:
            counts={'active':0,'peak':0};lock=threading.Lock()
            def execute(task,store,**kwargs):
                with lock:
                    counts['active']+=1;counts['peak']=max(counts['active'],counts['peak'])
                time.sleep(.02)
                with lock:counts['active']-=1
                return TaskResult(task_id=task.task_id,status='completed_no_findings')
            with self.subTest(architecture=architecture),self.run_mocked(config,[],architecture=architecture,executor=execute) as (code,report,plan,worker,directory):
                self.assertEqual(code,0);self.assertEqual(counts['peak'],limit)

    def test_http_accepts_full_ipv6_list_beyond_old_body_limit(self):
        import threading
        from urllib.request import Request,urlopen
        from unittest.mock import Mock
        addresses=','.join(f'2001:0db8:0000:0000:0000:0000:0000:{i:04x}' for i in range(1,257))
        payload={'name':'Lista IPv6','authorization':'LAB-PROPIO','scope':'personal',
                 'personal':{**self.config(),'ipv4':'','ipv6':addresses}}
        body=json.dumps(payload).encode()
        self.assertGreater(len(body),8192)
        with tempfile.TemporaryDirectory() as temp:
            operations=Mock()
            operations.start.side_effect=lambda action,options:{'id':'test','status':'queued','count':len(scope_hosts(validate_options(options)['personal']))}
            panel=Panel(Path(temp),operations=operations);server=make_server(panel,0)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            origin=f'http://127.0.0.1:{server.server_port}'
            try:
                request=Request(origin+'/api/lab/personal/check',data=body,
                    headers={'Content-Type':'application/json','Origin':origin,'X-CSRF-Token':panel.csrf})
                with urlopen(request) as response:
                    self.assertEqual(response.status,202)
                    self.assertEqual(json.load(response)['job']['count'],256)
            finally:
                server.shutdown();server.server_close();thread.join(timeout=2)

    def test_commands_bind_only_the_exact_address_ports_and_family(self):
        v4=command_for(self.task());v6=command_for(self.task(True))
        self.assertNotIn('-6',v4);self.assertIn('-6',v6)
        self.assertEqual(v6[-1],'fd00:56::20')
        self.assertEqual(v6[v6.index('-p')+1],'80,8080')
        for forbidden in ['--script','-A','-sC','-sU']:
            self.assertNotIn(forbidden,v6)

    def xml(self,address='192.168.56.20',port=80):
        return f'<nmaprun><host><address addr="{address}" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state state="open"/><service name="http" product="Servidor de prueba" version="1"/></port><extraports state="closed" count="1"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'.encode()

    def test_inventory_requires_exact_target_and_ports_and_never_fabricates_cve(self):
        services,states=parse_inventory(self.xml(),self.task())
        self.assertEqual(services[0].port,80)
        self.assertEqual(states,[{'port':80,'state':'open'},{'port':8080,'state':'closed'}])
        with self.assertRaises(ValueError):parse_inventory(self.xml(address='192.168.56.21'),self.task())
        with self.assertRaises(ValueError):parse_inventory(self.xml(port=22),self.task())
        with self.assertRaises(ValueError):parse_inventory(self.xml().replace(b'exit="success"',b'exit="error"'),self.task())

    def test_v2_and_personal_scope_are_not_interchangeable(self):
        options={'name':'Mi laboratorio','authorization':'LAB-PROPIO','scope':'personal','personal':self.config()}
        self.assertEqual(validate_options(options)['personal']['ports'],[80,8080])
        self.assertEqual(validate_options(validate_options(options)),validate_options(options))
        with self.assertRaises(ValueError):validate_options({**options,'ia':'openai','tokens':0})
        with self.assertRaises(ValueError):validate_options({**options,'mode':'dry_run'})
        with self.assertRaises(ValueError):validate_options({**options,'scope':'v2'})
        with self.assertRaises(ValueError):validate_options({**options,'scope':[]})

    def test_preflight_failure_is_preserved_as_blocked_not_as_success(self):
        with tempfile.TemporaryDirectory() as temp:
            options=validate_options({'name':'Mi laboratorio','authorization':'LAB-PROPIO','scope':'personal','personal':self.config()})
            with personal_authorization(options),patch('laboratorio_personal.resolve_targets',side_effect=ValueError('Sin ruta')):
                self.assertEqual(run(options,Path(temp)),3)
            report=json.loads(next(Path(temp).glob('*/report.json')).read_text())
            self.assertEqual(report['status'],'partial')
            self.assertEqual(len(report['tasks']),2)
            self.assertTrue(all(t['status']=='blocked' for t in report['tasks']))
            self.assertEqual(report['findings'],[])
            self.assertEqual(report['llm']['known_tokens'],0)


if __name__=='__main__':unittest.main()
