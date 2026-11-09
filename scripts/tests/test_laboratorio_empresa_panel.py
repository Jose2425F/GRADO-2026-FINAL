from scripts.tests.authorization_fixture import personal_authorization, scope_options
"""Regresiones sin tráfico ni API: controlador NovaFlow, credenciales y reportes."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import threading
import time
import unittest
import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime", "healthy_kernel", "simulated_bank_restoration")
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import laboratorio_empresa as company
import laboratorio_personal as personal
from dualstack_panel import validate_options,Panel,Operations
from auditoria.contracts import TaskResult,Authentication,Service
from auditoria.store import RunStore


class FakeScheduler:
    instances=[]
    def __init__(self,store,**kwargs):
        self.config=SimpleNamespace(model='modelo-simulado');self.options=kwargs;self.calls=[]
        self.instances.append(self)
    def select(self,ready,previous,tasks):
        self.calls.append({'status':'accepted','total_tokens':3});return ready[0]
    def summary(self):
        return {'status':'accepted','model':self.config.model,'known_tokens':3*len(self.calls),
                'budget':self.options['budget'],'usage_complete':True,'calls':self.calls,'fallbacks':0}
    def close(self):pass


class EmpresaPanelTests(unittest.TestCase):
    def options(self,**extra):
        return validate_options({'name':'PRUEBA CONTROLADA','authorization':'LAB-PROPIO','scope':'empresa',**extra})

    def execute(self,options,worker=None,validation=None,preflight=None):
        with tempfile.TemporaryDirectory() as temp:
            FakeScheduler.instances=[]
            def default(task,store):return TaskResult(task_id=task.task_id,status='completed_no_findings')
            with patch.object(company.lab,'load_auditor_environment'),patch.object(company.lab,'preflight',side_effect=preflight or (lambda root:{})),patch.object(company.agent,'run_task',side_effect=worker or default),patch.object(company,'validation_for',side_effect=validation or (lambda *args:({'state':'observed'},[]))),patch('auditoria.openai_provider.load_openai_config'),patch('auditoria.openai_provider.OpenAIScheduler',FakeScheduler):
                code=company.run_panel(options,Path(temp))
            root=next(Path(temp).glob('*/report.json')).parent
            return code,json.loads((root/'report.json').read_text()),json.loads((root/'request.json').read_text()),json.loads((root/'manifest.json').read_text())

    def test_same_32_tasks_serial_or_parallel_with_protocol_and_asset_isolation(self):
        for architecture,limit in [('single',1),('multiagent',2)]:
            active=[];peak=0;lock=threading.Lock()
            first_pair_started=threading.Event()
            def worker(task,store):
                nonlocal peak
                with lock:
                    self.assertNotIn(task.target.asset_id,[t.target.asset_id for t in active])
                    if task.agent_type in {'ipv6_ndp','ipv6_fragmentation'}:
                        self.assertFalse(any(t.agent_type in {'ipv6_ndp','ipv6_fragmentation'} for t in active))
                    first_worker=peak==0
                    active.append(task);peak=max(peak,len(active))
                    if len(active)==2:first_pair_started.set()
                if limit==2 and first_worker:
                    self.assertTrue(first_pair_started.wait(timeout=5),
                                    'No se despacharon dos tareas independientes')
                time.sleep(.003)
                with lock:active.remove(task)
                return TaskResult(task_id=task.task_id,status='completed_no_findings')
            with self.subTest(architecture=architecture):
                code,report,request,manifest=self.execute(self.options(architecture=architecture),worker)
                self.assertEqual(code,0);self.assertEqual(len(report['tasks']),32)
                self.assertEqual(peak,limit);self.assertEqual(manifest['execution_concurrency'],peak)
                self.assertEqual(report['llm']['status'],'disabled')
                self.assertEqual(request['token_budget'],0)

    def test_api_choice_and_token_budget_are_honored_using_fake_provider(self):
        code,report,request,manifest=self.execute(self.options(ia='openai',tokens=6000))
        self.assertEqual(code,0);self.assertEqual(request['llm_mode'],'scheduler')
        self.assertEqual(request['token_budget'],6000)
        self.assertEqual(report['llm']['model'],'modelo-simulado')
        self.assertGreater(report['llm']['known_tokens'],0)
        self.assertEqual(FakeScheduler.instances[0].options['budget'],6000)

    def test_preflight_failure_preserves_all_tasks_and_never_initializes_provider(self):
        def denied(root):raise company.LabError('not ready')
        code,report,request,manifest=self.execute(self.options(ia='openai'),preflight=denied)
        self.assertEqual(code,3);self.assertEqual(len(report['tasks']),32)
        self.assertTrue(all(t['status']=='blocked' for t in report['tasks']))
        self.assertEqual(FakeScheduler.instances,[])
        self.assertEqual(report['llm']['status'],'not_started')

    def test_invalid_evidence_is_a_failure_and_findings_are_deduplicated(self):
        def invalid(root,task,result):return {'state':'indeterminate'},[]
        code,report,*_=self.execute(self.options(),validation=invalid)
        self.assertEqual(code,3)
        self.assertTrue(any(t['reason_code']=='evidence_not_validated' for t in report['tasks']))
        def detected(root,task,result):
            findings=[{'asset_id':task.target.asset_id,'defect_key':'untrusted_router_advertisement','state':'verified'}] if task.target.asset_id=='receiver_a' and task.action_profile in {'ipv6_ra_route_v2','ipv6_ra_mtu_v2'} else []
            return {'state':'observed'},findings
        code,report,*_=self.execute(self.options(),validation=detected)
        self.assertEqual(code,0);self.assertEqual(len(report['findings']),1)

    def test_nmap_xml_is_validated_as_xml_with_exact_target(self):
        req=company.agent.request('LAB-PROPIO',llm=False)
        task=next(t for t in company.agent.build_plan(req) if t.action_profile=='nmap_tcp_services_v1')
        with tempfile.TemporaryDirectory() as temp:
            store=RunStore(Path(temp)/'run','xml_test')
            try:
                raw=f'<nmaprun><host><address addr="{task.target.address}" addrtype="ipv4"/><ports/></host><runstats><finished exit="success"/></runstats></nmaprun>'.encode()
                ref,digest=store.evidence(task.task_id,'xml',raw)
                result=TaskResult(task_id=task.task_id,status='completed_no_findings',evidence_ref=ref,evidence_sha256=digest)
                record,findings=company.validation_for(store.root,task,result)
                self.assertEqual(record['state'],'observed');self.assertEqual(findings,[])
                (store.root/ref).write_bytes(b'altered')
                record,_=company.validation_for(store.root,task,result)
                self.assertFalse(record['evidence_integrity']['valid'])
            finally:store.close()

    def test_empresa_requires_its_own_readiness_not_v2_readiness(self):
        with tempfile.TemporaryDirectory() as temp,patch('laboratorio_suite.activity',return_value={}),patch('aceptar_laboratorios.public_status',return_value={}):
            operations=Operations(Path(temp));operations.lab['status']='ready'
            with self.assertRaisesRegex(ValueError,'Comprueba el banco NovaFlow'):
                operations.start('audit',self.options())

    def test_failed_dependency_blocks_following_ipv6_profiles(self):
        admitted=[]
        def worker(task,store):
            admitted.append(task)
            return TaskResult(task_id=task.task_id,status='failed' if task.target.asset_id=='receiver_a' else 'completed_no_findings',reason_code='controlled_failure' if task.target.asset_id=='receiver_a' else None)
        code,report,*_=self.execute(self.options(),worker=worker)
        self.assertEqual(code,3)
        self.assertEqual([t.action_profile for t in admitted if t.target.asset_id=='receiver_a'],['ipv6_slaac_v2'])
        self.assertEqual(sum(t['status']=='blocked' for t in report['tasks']),8)

    def test_runtime_budget_preserves_unstarted_tasks_as_cancelled(self):
        request=company.agent.request('LAB-PROPIO',llm=False).model_copy(update={'max_runtime_seconds':200})
        with patch.object(company.agent,'request',return_value=request):
            code,report,*_=self.execute(self.options())
        self.assertEqual(code,3)
        self.assertEqual(len(report['tasks']),32)
        self.assertTrue(all(t['status']=='cancelled' for t in report['tasks']))


class CredentialsPresentationTests(unittest.TestCase):
    def run_credential(self,accepted=False,failed=False,cap=80):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);store=RunStore(root/'run','credentials_test');self.addCleanup(store.close)
        config=personal.configuration({'ipv4':'192.168.56.20','ports':'22','interface':'eth0'})
        target=personal.target_for('ipv4',config['ipv4'],config,'eth0')
        tasks=[];results=[];validations=[]
        def hydra(task,profile,store,**kwargs):
            outcome='accepted' if accepted else 'rejected'
            if failed:return TaskResult(task_id=task.task_id,status='failed',reason_code='timeout')
            refs=[]
            for tool,name in [('hydra',task.task_id),('paramiko',task.task_id+'_confirmation')]:
                refs.append(store.evidence(name,'json',json.dumps({'tool':tool,'target':target.address,'port':22,'credential_ref':profile.ref,'service':'ssh','outcome':outcome}).encode()))
            return TaskResult(task_id=task.task_id,status='completed' if accepted else 'completed_no_findings',
                authentication=Authentication(credential_ref=profile.ref,service='ssh',port=22,outcome=outcome),
                evidence_ref=refs[0][0],evidence_sha256=refs[0][1],diagnostic_ref=refs[1][0],diagnostic_sha256=refs[1][1])
        with personal_authorization(scope_options(config,credentials=True)) as authorization,patch.dict(os.environ,{personal.SWEEP_ENV:'previous-value'}),patch.object(personal,'MAX_SWEEP_ATTEMPTS',cap),patch('auditoria.agentes.agente_ipv4_credenciales.run_hydra',side_effect=hydra):
            findings=personal.credential_sweep([target],{target.address:[22]},store,time.monotonic()+240,tasks=tasks,results=results,validations=validations,authorization=authorization)
            self.assertEqual(os.environ[personal.SWEEP_ENV],'previous-value')
        return store,tasks,results,validations,findings

    def test_positive_credentials_have_evidence_and_independent_validation(self):
        store,tasks,results,validation,findings=self.run_credential(accepted=True)
        self.assertEqual(len(findings),1);self.assertTrue(validation[0]['independent_confirmation'])
        self.assertEqual(len(tasks),len(results));self.assertEqual(len(tasks),1)
        self.assertTrue((store.root/findings[0]['confirmation_ref']).is_file())

    def test_timeouts_and_attempt_limit_are_recorded_as_incomplete(self):
        store,tasks,results,validation,findings=self.run_credential(failed=True,cap=1)
        self.assertEqual(findings,[]);self.assertEqual([r.status for r in results],['failed','cancelled'])
        self.assertEqual(results[-1].reason_code,'attempt_budget_exhausted')
        self.assertEqual(len(json.loads((store.root/'plan.json').read_text())),len(results))

    def test_mixed_report_shows_credential_finding_in_both_audiences(self):
        store,tasks,results,validation,findings=self.run_credential(accepted=True)
        request={'audit_id':'credentials_test','bank':'personal','personal':{'ipv4':'192.168.56.20','ports':[22],'interface':'eth0'}}
        (store.root/'request.json').write_text(json.dumps(request))
        (store.root/'manifest.json').write_text(json.dumps({'mode':'live'}))
        (store.root/'report.json').write_text(json.dumps({'status':'complete','purpose':'service_inventory_with_default_credentials',
            'findings':findings,'tasks':[r.model_dump(mode='json') for r in results],'validation':validation}))
        panel=Panel(store.root.parent);detail=panel.detail('run')
        self.assertFalse(detail['brief']['is_inventory']);self.assertTrue(detail['brief']['has_credentials'])
        self.assertEqual(len(detail['brief']['cards']),1)
        for audience in ['technical','executive']:
            html=panel.environment.get_template('report.html').render(**detail,audience=audience)
            self.assertNotIn('No se evaluaron vulnerabilidades.',html)
            self.assertIn('credencial',html.lower())


if __name__=='__main__':unittest.main()
