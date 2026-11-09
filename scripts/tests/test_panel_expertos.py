from scripts.tests.authorization_fixture import personal_authorization
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import time
import unittest
import pytest

pytestmark = pytest.mark.usefixtures("healthy_kernel")
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from llm_especialistas import ExpertScheduler,context_for
from laboratorio_personal import InventoryTask
from aplicaciones_personales import ApplicationTask
from auditoria.contracts import Target,TaskResult
from auditoria.store import RunStore
from dualstack_panel import validate_options
from panel_metricas import compare_runs,operation_metrics


class FakeTransport:
    def __init__(self,missing=False,invalid=False):self.calls=[];self.missing=missing;self.invalid=invalid
    def post(self,endpoint,body,timeout):
        self.calls.append((endpoint,body,timeout))
        if endpoint.endswith('input_tokens'):return {'input_tokens':100}
        choice=body['text']['format']['schema']['properties']['evidence_tasks']['items']['enum'][0]
        value={'interpretation':'Se revisaron las observaciones disponibles.','next_step':'Repetir el control con evidencia tras corregir.','limitation':'La revisión se limita a las tareas registradas.','evidence_tasks':['t999' if self.invalid else choice],'prioritized_actions':[]}
        return {'model':'gpt-6.1-sol','status':'completed','id':'fake-response','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(value)}]}],
                'usage':None if self.missing else {'input_tokens':100,'output_tokens':80,'total_tokens':180}}


class ExpertsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=RunStore(Path(self.temp.name)/'run','expert-test')
        self.extra_stores=[]
        self.config=SimpleNamespace(model='gpt-6.1-sol',api_key='fake-key',reasoning_effort='low',max_output_tokens=2048)
        self.target=Target(asset_id='sensitive_name',address='192.168.56.10',interface='eth0',ports=[8080])
        self.tasks=[InventoryTask(task_id='real-task-name',agent_type='ipv4_services',target=self.target),ApplicationTask(task_id='web-task',target=self.target,application_index=0)]
        self.results=[TaskResult(task_id=t.task_id,status='completed') for t in self.tasks]
    def tearDown(self):
        for store in self.extra_stores:store.close()
        self.store.close();self.temp.cleanup()
    def scheduler(self,architecture='multiagent',budget=6000,transport=None):
        store=RunStore(Path(self.temp.name)/('scheduler_'+str(len(self.extra_stores))),'expert-test')
        self.extra_stores.append(store)
        with patch('auditoria.openai_provider.OpenAIConfig.from_environment',return_value=self.config):
            scheduler=ExpertScheduler(store,architecture=architecture,budget=budget,deadline=time.monotonic()+60)
        scheduler.transport=transport or FakeTransport();return scheduler

    def test_real_specialist_contract_shared_budget_and_sanitized_context(self):
        scheduler=self.scheduler();findings=[{'task_id':'web-task','condition':'object_authorization','state':'verified','address':'192.168.56.10','secret':'DO_NOT_SEND'}];before=copy.deepcopy(findings)
        scheduler.review(self.tasks,self.results,findings)
        self.assertEqual([r['role'] for r in scheduler.reviews],['applications','network'])
        self.assertTrue(all(r['status']=='accepted' for r in scheduler.reviews))
        summary=scheduler.summary();self.assertEqual(summary['known_tokens'],360);self.assertEqual(summary['budget'],6000)
        self.assertEqual(summary['planning_budget'],3600);self.assertEqual(summary['review_budget'],2400)
        self.assertEqual(findings,before)
        for endpoint,body,timeout in scheduler.transport.calls:
            self.assertNotIn('192.168.56.10',body['input']);self.assertNotIn('DO_NOT_SEND',body['input']);self.assertNotIn('sensitive_name',body['input'])
            if endpoint=='responses':self.assertLessEqual(body['max_output_tokens'],2048);self.assertFalse(body['store'])
            self.assertLessEqual(timeout,60)

    def test_review_wait_is_longer_than_old_limit_and_bounded_by_deadline(self):
        scheduler=self.scheduler('single');scheduler.review(self.tasks,self.results,[])
        generation=[t for e,_,t in scheduler.transport.calls if e=='responses'][0]
        self.assertGreater(generation,15);self.assertLessEqual(generation,60)
        scheduler=self.scheduler('single');scheduler.deadline=time.monotonic()+4
        scheduler.review(self.tasks,self.results,[])
        self.assertTrue(all(0<t<=4 for _,_,t in scheduler.transport.calls))

    def test_larger_budget_is_shared_equally_by_architecture_and_does_not_force_spend(self):
        for architecture in ['single','multiagent']:
            scheduler=self.scheduler(architecture,budget=60000)
            scheduler.review(self.tasks,self.results,[])
            summary=scheduler.summary()
            self.assertEqual(summary['budget'],60000)
            self.assertEqual(summary['planning_budget'],36000);self.assertEqual(summary['review_budget'],24000)
            self.assertLess(summary['known_tokens'],1000)
            self.assertTrue(all(b['max_output_tokens']==2048 for e,b,_ in scheduler.transport.calls if e=='responses'))

    def test_planning_that_previously_exhausted_its_share_can_now_call_api(self):
        class Planning:
            def __init__(self):self.generations=0
            def post(self,endpoint,body,timeout):
                if endpoint.endswith('input_tokens'):return {'input_tokens':831}
                self.generations+=1
                return {'status':'completed','model':'gpt-6.1-sol','id':'fake',
                    'usage':{'input_tokens':831,'output_tokens':70,'total_tokens':901},
                    'output':[{'type':'message','content':[{'type':'output_text','text':'{"choice":"t000"}'}]}]}
        for budget,sent in [(20000,0),(60000,1)]:
            transport=Planning();scheduler=self.scheduler('single',budget=budget,transport=transport)
            scheduler.used=11198
            self.assertEqual(scheduler.decide(['t000','t001'],{},'single_agent'),'t000')
            self.assertEqual(transport.generations,sent)
            self.assertEqual(scheduler.calls[-1]['status'],'accepted' if sent else 'fallback')

    def test_schema_expresses_validator_limits_and_binds_action_to_same_asset(self):
        scheduler=self.scheduler('single',budget=60000);scheduler.review(self.tasks,self.results,[])
        body=next(b for e,b,_ in scheduler.transport.calls if e=='responses')
        schema=body['text']['format']['schema']['properties']
        self.assertEqual(schema['interpretation']['maxLength'],600)
        self.assertEqual(schema['evidence_tasks']['maxItems'],24)
        actions=schema['prioritized_actions'];self.assertEqual(actions['maxItems'],3)
        context=context_for(self.tasks,self.results,[],'generalist')
        for item in actions['items']['anyOf']:
            properties=item['properties'];asset=properties['asset']['enum'][0]
            self.assertEqual(properties['why']['maxLength'],250)
            self.assertEqual(properties['evidence_tasks']['maxItems'],8)
            self.assertTrue(all(context['task_assets'][ref]==asset for ref in properties['evidence_tasks']['items']['enum']))

    def test_rejected_text_records_specific_safe_reason_and_usage_without_raw_response(self):
        class LongText(FakeTransport):
            def post(self,endpoint,body,timeout):
                response=super().post(endpoint,body,timeout)
                if endpoint=='responses':
                    data=json.loads(response['output'][0]['content'][0]['text']);data['interpretation']='PRIVATE_RESPONSE_'+'x'*650
                    response['output'][0]['content'][0]['text']=json.dumps(data)
                return response
        scheduler=self.scheduler('single',budget=60000,transport=LongText())
        scheduler.review(self.tasks,self.results,[])
        self.assertEqual(scheduler.calls[0]['reason'],'invalid_review_text')
        self.assertGreater(scheduler.calls[0]['review_shape']['text_lengths']['interpretation'],600)
        self.assertEqual(len(scheduler.calls[0]['response_sha256']),64)
        self.assertTrue(scheduler.summary()['usage_complete']);self.assertEqual(scheduler.used,180)
        self.assertNotIn('PRIVATE_RESPONSE',json.dumps(scheduler.summary()))

    def test_untrusted_service_strings_never_enter_the_llm_context(self):
        from auditoria.contracts import Service
        self.results[0]=self.results[0].model_copy(update={'services':[Service(port=8080,protocol='tcp',state='open',name='ssh'),Service(port=8080,protocol='tcp',state='open',name='UNTRUSTED_INSTRUCTIONS_DO_NOT_SEND')]})
        value=context_for(self.tasks,self.results,[],'network')
        self.assertEqual(value['service_observations'],{'ssh':1,'other':1})
        self.assertNotIn('UNTRUSTED',json.dumps(value))

    def test_specific_facts_keep_authentication_separate_from_confirmed_findings(self):
        from auditoria.contracts import Authentication,Service
        result=self.results[0].model_copy(update={
            'services':[Service(port=5432,protocol='tcp',state='open',name='postgresql')],
            'authentication':Authentication(credential_ref='PRIVATE_REF',service='postgres',port=5432,outcome='accepted'),
            'observations':{'application_checks':{'object_authorization':'incomplete','UNTRUSTED':'PRIVATE_SECRET'}}})
        context=context_for(self.tasks,[result],[],'network')
        self.assertEqual(context['task_facts'][0]['open_services'],[{'tcp_port':5432,'service':'postgresql'}])
        self.assertEqual(context['task_facts'][0]['tool_authentication'],'accepted')
        self.assertEqual(context['task_facts'][0]['confirmed_conditions'],[])
        self.assertEqual(context['task_facts'][0]['web_observations'],{'object_authorization':'incomplete'})
        self.assertNotIn('PRIVATE',json.dumps(context));self.assertNotIn('192.168.56.10',json.dumps(context))

    def test_single_agent_reviews_once_without_pretending_multiple_specialists(self):
        scheduler=self.scheduler('single');scheduler.review(self.tasks,self.results,[])
        self.assertEqual(len(scheduler.reviews),1);self.assertEqual(scheduler.reviews[0]['role'],'generalist')
        self.assertEqual(scheduler.used,180)

    def test_budget_and_deadline_skip_without_generation_or_fake_acceptance(self):
        scheduler=self.scheduler(budget=256);scheduler.review(self.tasks,self.results,[])
        self.assertFalse(scheduler.transport.calls);self.assertEqual(scheduler.summary()['status'],'not_started')
        self.assertTrue(all(r['reason']=='review_budget_exhausted' for r in scheduler.reviews))
        scheduler=self.scheduler();scheduler.deadline=time.monotonic()-1;scheduler.review(self.tasks,self.results,[])
        self.assertFalse(scheduler.transport.calls)

    def test_unknown_usage_blocks_later_generations_and_invalid_refs_keep_usage(self):
        transport=FakeTransport(missing=True);scheduler=self.scheduler(transport=transport);scheduler.review(self.tasks,self.results,[])
        self.assertFalse(scheduler.summary()['usage_complete']);self.assertEqual(sum(e=='responses' for e,_,_ in transport.calls),1)
        self.assertTrue(all(r['status']=='unavailable' for r in scheduler.reviews))
        scheduler=self.scheduler(transport=FakeTransport(invalid=True));scheduler.review(self.tasks,self.results,[])
        self.assertEqual(scheduler.used,360);self.assertEqual(scheduler.fallbacks,2)
        self.assertTrue(all(r['status']=='unavailable' for r in scheduler.reviews))

    def test_personal_controller_runs_expert_review_with_simulated_provider(self):
        from laboratorio_personal import run
        options={'personal':{'ipv4':'192.168.56.10','ipv6':'','ports':[8080],'interface':'eth0'},
                 'architecture':'multiagent','tokens':6000,'ia':'openai','authorization':'LAB-PROPIO','expert_mode':True}
        transport=FakeTransport()
        def inventory(task,store,**kwargs):return TaskResult(task_id=task.task_id,status='completed_no_findings')
        with tempfile.TemporaryDirectory() as td,personal_authorization(options),patch('auditoria.openai_provider.load_openai_config',return_value=self.config),patch('auditoria.openai_provider.OpenAIConfig.from_environment',return_value=self.config),patch('auditoria.openai_provider.OpenAITransport',return_value=transport),patch('llm_especialistas.TracedOpenAITransport',return_value=transport),patch('laboratorio_personal.resolve_targets',return_value=[self.target]),patch('laboratorio_personal.execute_task',side_effect=inventory):
            self.assertEqual(run(options,Path(td)),0)
            directory=next(Path(td).iterdir());report=json.loads((directory/'report.json').read_text())
            self.assertEqual(report['llm']['known_tokens'],180);self.assertEqual(report['llm']['budget'],6000)
            self.assertTrue(report['llm']['expert_mode']);self.assertEqual(report['findings'],[])
            self.assertEqual(len(report['llm']['specialist_reviews']),1)
            self.assertIn('expert_review_seconds',report['metrics'])

    def test_mode_validation_does_not_expand_frozen_bank(self):
        opts={'name':'Test','authorization':'LAB-PROPIO','scope':'personal','personal':{'ipv4':'192.168.56.10','ports':'8080','interface':'eth0'},'ia':'openai','tokens':6000,'expert_mode':True}
        self.assertTrue(validate_options(opts)['expert_mode'])
        for extra in [{'ia':'none'},{'scope':'v2','personal':None},{'expert_mode':'yes'}]:
            with self.assertRaises(ValueError):validate_options({**opts,**extra})


def comparison_fixture(architecture,seconds,tokens,tp=4,truth=True):
    target={'address':'192.168.56.10','asset_id':'host','ports':[22],'interface':'eth0'}
    result={'run':{'architecture':architecture,'mode':'live','bank':'personal','status':'complete','seconds':seconds,
                   'total':1,'tasks':[{'status':'completed'}],'llm':{'usage_complete':True,'fallbacks':0,'known_tokens':tokens,'model':'gpt-6.1-sol'}},
            'request':{'bank':'personal','personal':{'ipv4':'192.168.56.10','ports':[22]},'token_budget':6000},
            'plan':[{'task_id':'a','target':target,'action_profile':'nmap_tcp_services_personal_v1','dependencies':[]}],
            'manifest':{'adapter_sha256':'a'*64},'report':{'mode':'live'},
            'evaluation':{'ground_truth_sha256':'b'*64,'TP':tp,'FN':8-tp,'FP':0,'TN':8,'evidence_valid':True} if truth else {}}
    return result


class MetricTests(unittest.TestCase):
    def test_formulas_use_true_positives_and_preserve_zero_or_negative_improvement(self):
        a,b=comparison_fixture('single',100,1000),comparison_fixture('multiagent',70,500)
        value=compare_runs(a,b);self.assertTrue(value['eligible']);self.assertFalse(value['formal_study'])
        self.assertEqual(value['TRTO_percent'],30);self.assertEqual(value['IDE_percent'],0);self.assertEqual(value['ETV_ratio'],2)
        b['run']['seconds']=110;self.assertEqual(compare_runs(a,b)['TRTO_percent'],-10)
    def test_unknown_truth_never_uses_finding_count_as_detection(self):
        a,b=comparison_fixture('single',100,1000,truth=False),comparison_fixture('multiagent',70,500,truth=False)
        b['report']['findings']=[{}]*40
        value=compare_runs(a,b);self.assertEqual(value['TRTO_percent'],30);self.assertIsNone(value['IDE_percent']);self.assertIsNone(value['ETV_ratio'])

    def test_api_usage_is_distinguished_from_local_budget_fallback_and_rejected_review(self):
        a,b=comparison_fixture('single',100,13666),comparison_fixture('multiagent',110,17527)
        a['run']['llm']['fallbacks']=10
        a['report']['llm']={'calls':[
            *[{'status':'accepted','generation_sent':True} for _ in range(14)],
            *[{'status':'fallback','reason':'token_budget_exhausted'} for _ in range(9)],
            {'phase':'specialist_review','status':'fallback','reason':'invalid_specialist_response','generation_sent':True}]}
        value=compare_runs(a,b);self.assertFalse(value['eligible'])
        diagnostic=value['assistance'][0]
        self.assertEqual(diagnostic['api_generations'],15);self.assertEqual(diagnostic['planning_accepted'],14)
        self.assertEqual(diagnostic['reviews_accepted'],0)
        self.assertEqual({r['code']:r['count'] for r in diagnostic['incidents']},{'token_budget_exhausted':9,'invalid_specialist_response':1})
        self.assertIn('presupuesto de planificación',value['reasons'][0])
        self.assertIn('validador de respuestas',value['reasons'][0])
        self.assertIsNone(value['TRTO_percent']);self.assertIsNone(value['ETV_ratio'])

    def test_historical_fallback_without_call_detail_does_not_invent_api_use(self):
        a,b=comparison_fixture('single',100,1000),comparison_fixture('multiagent',70,500)
        a['run']['llm']['fallbacks']=1
        value=compare_runs(a,b);self.assertFalse(value['eligible'])
        self.assertIsNone(value['assistance'][0]['api_generations'])
        self.assertEqual(value['assistance'][0]['incidents'][0]['code'],'other')

    def test_untrusted_failure_text_is_not_copied_into_comparison(self):
        a,b=comparison_fixture('single',100,1000),comparison_fixture('multiagent',70,500)
        a['run']['llm']['fallbacks']=1
        a['report']['llm']={'calls':[{'status':'fallback','reason':'PRIVATE_PROVIDER_BODY_DO_NOT_PUBLISH'}]}
        value=compare_runs(a,b)
        self.assertNotIn('PRIVATE_PROVIDER_BODY',json.dumps(value))
        self.assertEqual(value['assistance'][0]['incidents'][0]['code'],'other')
    def test_comparison_rejects_scope_versions_budget_backups_and_partial_runs(self):
        a,b=comparison_fixture('single',100,1000),comparison_fixture('multiagent',70,500)
        for path,value in [(('run','status'),'partial'),(('run','llm','fallbacks'),1),(('run','llm','usage_complete'),False),
                           (('request','token_budget'),12000),(('manifest','adapter_sha256'),'c'*64),(('request','expert_mode'),True)]:
            changed=copy.deepcopy(b);node=changed
            for key in path[:-1]:node=node[key]
            node[path[-1]]=value
            self.assertFalse(compare_runs(a,changed)['eligible'])
    def test_comparison_endpoint_is_read_only_and_rejects_unavailable_paths(self):
        import threading
        from urllib.request import urlopen
        from urllib.error import HTTPError
        from dualstack_panel import Panel,make_server
        from auditoria.store import write_json
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name,architecture,seconds,tokens in [('a','single',100,1000),('b','multiagent',70,500)]:
                data=comparison_fixture(architecture,seconds,tokens,truth=False)
                store=RunStore(root/name,name);task=data['plan'][0];task.update(agent_type='ipv4_services',protocol='tcp',timeout_seconds=60)
                write_json(store.root/'request.json',{**data['request'],'architecture':architecture,'audit_id':name})
                write_json(store.root/'manifest.json',{**data['manifest'],'mode':'live'})
                write_json(store.root/'plan.json',[task])
                write_json(store.root/'report.json',{'status':'complete','mode':'live','tasks':[{'task_id':'a','status':'completed'}],
                    'llm':{**data['run']['llm'],'status':'accepted','budget':6000,'calls':[]},'metrics':{'elapsed_seconds':seconds}})
                store.event('controller','request_accepted');store.event('controller','task_admitted',task_id='a');store.event('controller','task_terminal',task_id='a',payload={'status':'completed'});store.close()
            panel=Panel(root);server=make_server(panel,0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                url=f'http://127.0.0.1:{server.server_port}'
                with urlopen(url+'/api/compare?single=a&multi=b',timeout=5) as response:value=json.load(response)
                self.assertTrue(value['eligible']);self.assertEqual(value['TRTO_percent'],30);self.assertIsNone(value['IDE_percent'])
                with self.assertRaises(HTTPError) as denied:urlopen(url+'/api/compare?single=../private&multi=b',timeout=5)
                self.assertEqual(denied.exception.code,404);denied.exception.close()
                self.assertEqual(panel.operations.snapshot()['jobs'],[])
            finally:server.shutdown();server.server_close();thread.join()

    def test_inventory_completion_is_not_vulnerability_coverage(self):
        run=comparison_fixture('single',100,0)['run']
        metrics=operation_metrics(run,{'inventory':[{'scan_status':'completed'},{'scan_status':'not_scanned'}]})
        self.assertEqual(metrics['completion_percent'],100);self.assertEqual(metrics['inventory_percent'],50)
        self.assertIsNone(metrics['detection_coverage'])
