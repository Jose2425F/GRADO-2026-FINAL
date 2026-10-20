import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dualstack_panel import Panel
from panel_informe import report_view, execution_progress
from panel_observabilidad import inspect_run
from auditoria.store import RunStore


class FocusedReportTests(unittest.TestCase):
    def fixture(self):
        run={'name':'Cliente <script>','key':'fixture','id':'test','mode':'live','architecture':'multiagent',
             'status_name':'Finalizada','started_display':'17/10/2026','total':3,
             'llm':{'known_tokens':0,'usage_complete':True}}
        brief={'summary':'Resumen','final':True,'is_inventory':True,'cards':[],'affected':0,'assets':3,
               'checked':3,'issues':[],'tasks':[{'id':str(i),'profile':'nmap_tcp_services_personal_v1','status':'completed_no_findings'} for i in range(3)],
               'inventory':[{'address':'192.0.2.1','asset':'A','host_state':'up','ports':[{'port':22,'state':'open'},{'port':80,'state':'closed'}],
                             'services':[{'port':22,'name':'ssh','product':'OpenSSH','version':'9'}]},
                            {'address':'192.0.2.2','asset':'B','host_state':'down','ports':[],'services':[]},
                            {'address':'192.0.2.3','asset':'C','host_state':'up','ports':[{'port':80,'state':'closed'}],'services':[]}],
               'coverage':[{'address':'192.0.2.1','inventory_state':'completed','credentials_state':'not_requested',
                            'web_checks':{'object_authorization':'not_configured'}}]}
        return run,brief
    def html(self,run,brief,assistance,audience):
        with tempfile.TemporaryDirectory() as root:
            env=Panel(Path(root)).environment
            return env.get_template('report.html').render(run=run,brief=brief,technical=[],assistance=assistance,
                report_view=report_view(run,brief,[],assistance),audience=audience)
    def test_executive_selects_exposure_without_inactive_hosts_or_modules(self):
        run,brief=self.fixture();before=copy.deepcopy(brief)
        html=self.html(run,brief,{'reviews':[{'status':'unavailable','role':'network'}]},'executive')
        self.assertIn('192.0.2.1',html);self.assertNotIn('192.0.2.2',html);self.assertNotIn('192.0.2.3',html)
        self.assertNotIn('Sin IA',html);self.assertNotIn('Pendiente de configuración',html)
        self.assertNotIn('not_requested',html);self.assertNotIn('Revisión no realizada',html)
        self.assertNotIn('tcp: closed',html);self.assertNotIn('Análisis asistido por IA',html)
        self.assertIn('&lt;script&gt;',html);self.assertEqual(brief,before)
    def test_technical_preserves_diagnostic_appendix_without_default_expansion(self):
        run,brief=self.fixture();html=self.html(run,brief,{},'technical')
        main,appendix=html.split('<details id="technical-appendix"',1)
        self.assertNotIn('192.0.2.2',main);self.assertIn('192.0.2.2',appendix)
        self.assertIn('80/tcp: closed',appendix);self.assertIn('Incluir anexo técnico',html)
        self.assertNotIn(' open>',appendix.split('<summary>',1)[0]);self.assertIn('Herramientas y trazabilidad técnica',appendix)
    def test_reports_keep_real_incidents_and_only_accepted_llm_interpretations(self):
        run,brief=self.fixture();brief['issues']=[{'id':'failed','asset_name':'Equipo A','label':'SSH','status_name':'Fallida','reason':'timeout'}]
        brief['tasks'].append({'id':'failed','profile':'hydra_ssh_single_v1','status':'failed'});run['total']=4
        reviews={'reviews':[{'status':'accepted','role':'network','interpretation':'Servicio SSH observado <script>',
                            'next_step':'Restringir su acceso y verificar.','limitation':'Solo puerto 22.'},
                           {'status':'unavailable','role':'credentials','interpretation':'DO-NOT-SHOW'}]}
        for audience in ['technical','executive']:
            html=self.html(run,brief,reviews,audience)
            self.assertIn('1 operaciones con incidencias',html);self.assertIn('Análisis asistido por IA',html)
            self.assertIn('Servicio SSH observado &lt;script&gt;',html);self.assertNotIn('DO-NOT-SHOW',html)
    def test_actions_group_same_condition_but_keep_affected_targets(self):
        run,brief=self.fixture();brief.update(is_inventory=False,affected=2)
        card={'title':'Acceso SSH','condition':'ssh_default_credential','fix':'Rotar y comprobar.',
              'impact':'Acceso indebido.','severity':'high','address':'192.0.2.1'}
        brief['cards']=[card,{**card,'condition':'ftp_default_credential','title':'Acceso FTP','address':'192.0.2.3'}]
        view=report_view(run,brief,[],{})
        self.assertEqual(len(view['priorities']),1);self.assertEqual(view['priorities'][0]['count'],2)
        self.assertEqual(view['priorities'][0]['targets'],['192.0.2.1','192.0.2.3'])
        self.assertIn('2 hallazgos confirmados',view['headline'])
    def test_console_projects_xml_service_results_only_when_evidence_hash_matches(self):
        with tempfile.TemporaryDirectory() as root:
            directory=Path(root)/'run';store=RunStore(directory,'xml-test')
            ref,digest=store.evidence('scan','xml',b'<nmaprun/>')
            store.event('controller','task_admitted',task_id='scan')
            store.event('controller','task_terminal',task_id='scan',payload={'status':'completed_no_findings'})
            store.close()
            task={'task_id':'scan','action_profile':'nmap_tcp_services_personal_v1','target':{'asset_id':'A','address':'192.0.2.1','ports':[22]}}
            report={'tasks':[{'task_id':'scan','evidence_ref':ref,'evidence_sha256':digest,
                              'services':[{'port':22,'state':'open','name':'ssh'}]}]}
            def read(p):return p.read_bytes() if p.is_file() else None
            run={'mode':'live','tasks':[]}
            lines=inspect_run(directory,Path(root),run,report,[task],read)['console']['lines']
            self.assertTrue(any(r['kind']=='SERVICIO' and '22 abierto' in r['text'] for r in lines))
            (directory/ref).write_bytes(b'<tampered/>')
            lines=inspect_run(directory,Path(root),run,report,[task],read)['console']['lines']
            self.assertFalse(any(r['kind']=='SERVICIO' for r in lines))
            self.assertTrue(any(r['level']=='error' and r['kind']=='VALIDACIÓN' for r in lines))

    def test_discovery_console_reconstructs_known_command_and_rejects_injection(self):
        with tempfile.TemporaryDirectory() as root:
            directory=Path(root)/'run';store=RunStore(directory,'console-test')
            (directory/'request.json').write_text(json.dumps({'personal':{'ipv4':'192.0.2.0/30','ports':[22],'interface':'eth0'}}))
            command=['nmap','--unprivileged','-n','-sn','-PS22','--max-retries','1','--host-timeout','15s','-e','eth0','-oX','-','192.0.2.1','192.0.2.2']
            store.event('controller','discovery_started',payload={'command':command,'host_count':2})
            store.event('controller','discovery_finished',payload={'states':{'192.0.2.1':'up','192.0.2.2':'down'}})
            store.event('controller','discovery_started',payload={'command':command+['--script=secret-injected']})
            store.event('llm','request_started',payload={'phase':'specialist_review'})
            store.close()
            def read(p):return p.read_bytes() if p.is_file() else None
            result=inspect_run(directory,Path(root),{'mode':'live','tasks':[]},{},[],read)
            text=json.dumps(result)
            self.assertIn('Buscando respuesta en 2',text);self.assertIn('1 con respuesta; 1 sin respuesta',text)
            self.assertNotIn('secret-injected',text)
            commands=[r for r in result['console']['lines'] if r['kind']=='COMANDO'];self.assertEqual(len(commands),1)
            self.assertTrue(any(r['tool']=='Revisor LLM' for r in result['console']['lines']))


    def test_dynamic_progress_distinguishes_closed_valid_and_failed_operations(self):
        tasks=[]
        for profile,count in [('nmap_tcp_open_ports_personal_v1',7),('nmap_tcp_services_personal_v1',7),('hydra_http_get_single_v1',44)]:
            tasks += [{'id':str(len(tasks)+i),'profile':profile,'status':'completed_no_findings'} for i in range(count)]
        for task in tasks[-6:]:task['status']='failed'
        brief={'tasks':tasks,'automatic_ports':True}
        before=copy.deepcopy(brief)
        progress=execution_progress({'total':58},brief)
        self.assertEqual((progress['closed'],progress['successful'],progress['issues'],progress['remaining'],progress['percent']),(58,52,6,0,100))
        self.assertEqual([s['total'] for s in progress['stages']],[7,7,44])
        self.assertTrue(progress['dynamic']);self.assertIn('no es una vulnerabilidad',progress['explanation'])
        tasks.append({'id':'new','profile':'hydra_ssh_single_v1','status':'pending'})
        running=execution_progress({'total':59},brief)
        self.assertEqual((running['closed'],running['total'],running['remaining']),(58,59,1))
        self.assertLess(running['percent'],100);self.assertEqual(before['tasks'][-1]['status'],'failed')

    def test_incidents_are_grouped_with_exact_endpoints_and_do_not_erase_findings(self):
        run,brief=self.fixture();brief.update(is_inventory=False,affected=1)
        brief['cards']=[{'task_id':'good','address':'192.0.2.1','title':'Acceso HTTP confirmado','condition':'http_get_default_credential',
            'fix':'Rotar.','impact':'Acceso indebido.','severity':'high'}]
        brief['issues']=[{'id':'bad'+str(i),'address':'192.0.2.1','profile':'hydra_http_get_single_v1','label':'HTTP Basic',
            'reason':'credential_evidence_not_validated','status':'failed'} for i in range(2)]
        plan=[{'task_id':key,'action_profile':'hydra_http_get_single_v1','target':{'ports':[8080]}} for key in ['good','bad0','bad1']]
        before=copy.deepcopy(brief)
        view=report_view(run,brief,[],{},plan)
        self.assertEqual(view['findings'][0]['ports'],[8080])
        self.assertEqual(view['incident_groups'][0]['count'],2)
        self.assertEqual(view['incident_groups'][0]['ports'],[8080])
        self.assertIn('no confirma',view['incident_groups'][0]['meaning'])
        self.assertEqual(view['hosts'][0]['conclusion'],'Hallazgo confirmado · revisión pendiente')
        self.assertEqual(view['priorities'][0]['endpoints'][0]['ports'],[8080])
        self.assertIn('rechazada',view['priorities'][0]['verification']);self.assertEqual(brief,before)

    def test_pending_skipped_and_web_stages_are_not_reported_as_successes(self):
        tasks=[{'profile':'http_application_personal_v1','status':s} for s in ['skipped','running','blocked','completed']]
        view=execution_progress({'total':4},{'tasks':tasks})
        self.assertEqual((view['closed'],view['successful'],view['issues'],view['skipped'],view['remaining']),(3,1,1,1,1))
        self.assertEqual(view['stages'][0]['key'],'applications')

    def test_report_uses_authentication_port_and_does_not_label_icmp_as_tcp(self):
        run,brief=self.fixture();brief.update(is_inventory=False,affected=1)
        card={'task_id':'cred','address':'192.0.2.1','title':'Acceso SSH','condition':'ssh_default_credential','fix':'Rotar.','impact':'Acceso.','severity':'high'}
        brief['cards']=[card,{**card,'task_id':'nd','condition':'neighbor_override'}]
        plan=[{'task_id':'cred','action_profile':'hydra_ssh_single_v1','target':{'ports':[21,22]}},
              {'task_id':'nd','action_profile':'ipv6_na_neighbor_v2','target':{'ports':[53000]}}]
        view=report_view(run,brief,[],{},plan,[{'task_id':'cred','authentication':{'port':22}}])
        self.assertEqual(view['findings'][0]['ports'],[22]);self.assertEqual(view['findings'][1]['ports'],[])

    def test_integrated_bank_matrix_includes_instrumented_non_tcp_controls(self):
        run,brief=self.fixture();run['bank']='empresa'
        brief['tasks'] += [{'id':'nd','address':'fd00::20','agent':'ipv6_ndp','profile':'ipv6_na_neighbor_v2','status':'completed_no_findings'},
                           {'id':'app','address':'192.0.2.4','agent':'application_access','profile':'http_application_dualstack_v2','status':'completed_no_findings'}]
        view=report_view(run,brief,[],{})
        rows={h['address']:h for h in view['hosts']}
        self.assertEqual(len(rows),3);self.assertEqual(rows['fd00::20']['services'],[])
        self.assertIn('IPv6',rows['fd00::20']['activity']);self.assertIn('dual-stack',rows['192.0.2.4']['activity'])
        self.assertNotIn('192.0.2.2',rows)

if __name__=='__main__':unittest.main()
