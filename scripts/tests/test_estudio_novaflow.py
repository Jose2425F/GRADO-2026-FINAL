"""Análisis y salvaguardas del conductor: sin Docker, escaneos ni API."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.estudio import orders, paired_metrics, analyze, public_status, settle_reservation, budget_available, budget_totals
from auditoria.dashboard import process_identity
from laboratorio_empresa import run_panel


def prior_fixture(driver,pilot,labroot,monitor,operational_stop=False):
    name='estudio_novaflow_20261017T170000';folder=pilot/'corridas/kpi_novaflow'/name
    folder.mkdir(parents=True)
    model={'model':'gpt-6.1-sol','reasoning_effort':'low','max_output_tokens':2048}
    driver.save(folder/'protocol.json',{'id':name,'code_identity':{'auditor_and_extensions':'old'},
        'images':{'host':'sha256:fixed'},'ground_truth_sha256':driver.digest(labroot/'ground_truth.json'),
        'model':model,'run_reserve_usd':.2,'tokens_per_run':20000,
        'pilot_order':[{'block':n,'order':['multiagent','single']} for n in range(1,4 if operational_stop else 2)]})
    rows=[]
    schedule=[(n,arm,.005,.005) for n in range(1,4) for arm in ['multiagent','single']] if operational_stop else [(1,'multiagent',.05913,.05913),(1,'single',None,.02456)]
    for block,arm,cost,lower in schedule:
        run=folder/'pilot'/f'block_{block:02d}_{arm}'/'original';run.mkdir(parents=True)
        llm={'usage_complete':cost is not None,'cost_estimate_usd':cost,'known_cost_estimate_usd':lower}
        driver.save(run/'report.json',{'llm':llm})
        rows.append({'phase':'pilot','block':block,'architecture':arm,'run_key':run.relative_to(pilot/'corridas').as_posix(),
            'status':'complete','usage_complete':cost is not None,'cost_usd':cost})
    driver.save(folder/'attempts.json',rows)
    state={'id':name,'status':'stopped','phase':'pilot','formal_runs':0,'pilot_runs':2,
        'known_cost_usd':.05913,'held_usd':.2,'budget_usd':20,'message':'Detenido: unknown_usage_or_cost; reserva retenida'}
    if operational_stop:state.update(pilot_runs=6,known_cost_usd=.03,held_usd=0,
        prior_budget_commitment_usd=.25913,prior_known_cost_usd=.08369,prior_unknown_reserved_usd=.17544,
        message='Detenido: pilot_not_operational; revisar antes de congelar la muestra')
    driver.save(folder/'state.json',state);driver.save(monitor,state)
    return folder


class StudyTests(unittest.TestCase):
    def row(self,arm='single',**extra):
        return {'phase':'formal','block':1,'architecture':arm,'status':'complete','tasks_valid':32,
                'elapsed_seconds':100 if arm=='single' else 80,'TP':10,'FP':0,'FN':3,'TN':11,
                'usage_complete':True,'known_tokens':1000 if arm=='single' else 800,
                'evidence_valid':True,'fallbacks':0,'api_calls':1,'accepted_reviews':1 if arm=='single' else 5,
                'ground_truth_sha256':'a'*64,'context_sha256':'b'*64,'study_id':'fixture','reported_models':['gpt-6.1-sol'],
                'review_roles':[{'role':role,'status':'accepted'} for role in (['generalist'] if arm=='single' else ['network','credentials','applications','ipv6','fragmentation'])],**extra}

    def test_order_balanced_reproducible_with_both_arms(self):
        sequence=orders(30,20261018)
        self.assertEqual(sequence,orders(30,20261018));self.assertEqual(len(sequence),30)
        self.assertEqual(sum(b['order'][0]=='single' for b in sequence),15)
        self.assertTrue(all(set(b['order'])=={'single','multiagent'} for b in sequence))

    def test_favorable_equal_and_unfavorable_metrics_are_not_filtered(self):
        good=paired_metrics(self.row(),self.row('multiagent'))
        self.assertAlmostEqual(good['TRTO_percent'],20);self.assertEqual(good['IDE_percent'],0)
        self.assertAlmostEqual(good['ETV_ratio'],1.25)
        bad=paired_metrics(self.row(),self.row('multiagent',elapsed_seconds=120,known_tokens=1500,TP=8,FN=5))
        self.assertLess(bad['TRTO_percent'],0);self.assertLess(bad['IDE_percent'],0);self.assertLess(bad['ETV_ratio'],1)

    def test_failed_runs_remain_for_detection_and_not_fast_time(self):
        result=paired_metrics(self.row(),self.row('multiagent',status='partial',elapsed_seconds=1,TP=0,FN=13))
        self.assertNotIn('TRTO_percent',result);self.assertEqual(result['IDE_percent'],-100)
        self.assertNotIn('ETV_ratio',result)

    def test_fallback_or_rejected_review_is_not_an_eligible_llm_comparison(self):
        for changes in [{'fallbacks':1},{'api_calls':0},{'evidence_valid':False},
                        {'accepted_reviews':0},{'review_roles':[{'status':'rejected'}]*5}]:
            result=paired_metrics(self.row(),self.row('multiagent',**changes))
            self.assertFalse(result['eligible_llm_pair'])
            self.assertNotIn('TRTO_percent',result);self.assertNotIn('ETV_ratio',result)
            self.assertEqual(result['IDE_percent'],0)
            self.assertTrue(result['exclusion_reasons']['multiagent'])

    def test_different_model_reference_or_context_cannot_be_paired(self):
        for changes in [{'reported_models':['another-model']},{'ground_truth_sha256':'c'*64},
                        {'context_sha256':'d'*64},{'context_sha256':None},{'architecture':'single'},{'study_id':'another-study'}]:
            result=paired_metrics(self.row(),self.row('multiagent',**changes))
            self.assertFalse(result['eligible_llm_pair']);self.assertTrue(result['context_errors'])
            self.assertNotIn('TRTO_percent',result);self.assertNotIn('IDE_percent',result);self.assertNotIn('ETV_ratio',result)
        from ejecutar_estudio_novaflow import comparison_context
        self.assertNotEqual(comparison_context({'code_identity':{'driver':'old'}}),comparison_context({'code_identity':{'driver':'new'}}))
        self.assertNotEqual(comparison_context({'code_identity':{},'environment':{'logical_cpus':4}}),comparison_context({'code_identity':{},'environment':{'logical_cpus':7}}))

    def test_pilot_excluded_and_block_is_the_sample_unit(self):
        rows=[self.row(),self.row('multiagent'),self.row(phase='pilot')]
        result=analyze(rows,'formal')
        self.assertEqual(result['runs_started'],2);self.assertEqual(result['pairs_observed'],1)
        self.assertEqual(result['metrics']['IDE_percent']['n'],1)
        self.assertNotIn('mean_ci95_percentile_bootstrap',result['metrics']['IDE_percent'])
        with self.assertRaisesRegex(ValueError,'duplicate_audit_slot'):analyze([self.row(),self.row()],'formal')

    def test_unknown_usage_retains_reservation_and_known_cost_releases_it(self):
        state={'held_usd':.2,'known_cost_usd':0}
        self.assertFalse(settle_reservation(state,{'usage_complete':False,'known_tokens':1000,'cost_usd':None}))
        self.assertEqual(state['held_usd'],.2)
        self.assertTrue(settle_reservation(state,{'usage_complete':True,'known_tokens':1000,'cost_usd':.005}))
        self.assertEqual(state,{'held_usd':0.,'known_cost_usd':.005})
        for data in [{'cost_usd':float('nan'),'known_tokens':1000},{'cost_usd':.3,'known_tokens':1000},{'cost_usd':.01,'known_tokens':20001}]:
            self.assertFalse(settle_reservation(state,{'usage_complete':True,**data}))

    def test_zero_tp_and_missing_timing_have_no_fabricated_ratios(self):
        result=paired_metrics(self.row(TP=0,FN=13,elapsed_seconds=None),self.row('multiagent'))
        self.assertNotIn('IDE_percent',result);self.assertNotIn('ETV_ratio',result);self.assertNotIn('TRTO_percent',result)

    def test_prior_budget_and_unknown_cost_are_not_forgotten_or_double_counted(self):
        state={'budget_usd':20,'prior_known_cost_usd':.08369,'prior_budget_commitment_usd':.25913,
               'known_cost_usd':.01,'held_usd':.20}
        total=budget_totals(state,[{'usage_complete':False,'known_cost_lower_bound_usd':.02}])
        self.assertAlmostEqual(total['known_cost_total_usd'],.11369)
        self.assertAlmostEqual(total['budget_committed_usd'],.46913)
        self.assertAlmostEqual(total['unknown_reserved_total_usd'],.35544)
        self.assertTrue(budget_available(state))
        self.assertFalse(budget_available({**state,'known_cost_usd':19.5}))
        self.assertFalse(budget_available({**state,'prior_budget_commitment_usd':float('nan')}))

    def test_monitor_checks_process_identity_and_does_not_publish_private_data(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'monitor.json'
            data={'id':'test','pid':os.getpid(),'identity':process_identity(os.getpid()),'status':'pilot','api_key':'DO-NOT-PUBLISH'}
            path.write_text(json.dumps(data));result=public_status(path)
            self.assertTrue(result['active']);self.assertNotIn('api_key',result)
            data['identity']='stale';path.write_text(json.dumps(data));result=public_status(path)
            self.assertFalse(result['active']);self.assertEqual(result['status'],'interrupted')

    def test_invalid_study_context_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp,patch('laboratorio_empresa.lab.preflight') as preflight:
            with self.assertRaises(ValueError):run_panel({},Path(temp),study_context={'phase':'formal'})
            preflight.assert_not_called();self.assertEqual(list(Path(temp).iterdir()),[])

class DriverIntegrationTests(unittest.TestCase):
    def simulate(self, unknown=False, resume=False, new_version=False, formal_pairs=30):
        import ejecutar_estudio_novaflow as driver
        from types import SimpleNamespace
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            root=Path(temp);pilot=root/'piloto_kali/prototipo';labroot=pilot/'.lab-empresa';labroot.mkdir(parents=True)
            (labroot/'ground_truth.json').write_text(json.dumps({'entries':[{'present':True}]*13}))
            monitor=pilot/'.lab/monitor.json'
            for name,value in [('ROOT',root),('PILOT',pilot),('labroot',labroot),('MONITOR',monitor)]:stack.enter_context(patch.object(driver,name,value))
            stack.enter_context(patch.object(driver,'check_kernel'))
            stack.enter_context(patch('auditoria.dashboard.collect_state',return_value={'runs':[]}))
            stack.enter_context(patch.object(driver,'code_identity',return_value={'code':'fixed'}))
            stack.enter_context(patch.object(driver,'image_identity',return_value={'host':'sha256:fixed'}))
            stack.enter_context(patch.object(driver,'ensure_identity'))
            restoring=stack.enter_context(patch.object(driver,'restore'))
            if resume:
                from urllib.error import URLError
                restoring.side_effect=[None,URLError('fixture_startup')]
            stack.enter_context(patch.object(driver.lab,'preflight',return_value={}))
            stack.enter_context(patch.object(driver,'load_openai_config',return_value=SimpleNamespace(model='gpt-6.1-sol',reasoning_effort='low',max_output_tokens=2048)))
            old=None
            if new_version:
                old=prior_fixture(driver,pilot,labroot,monitor,operational_stop=new_version=='operational')
                preserved={p:p.read_bytes() for p in old.rglob('*') if p.is_file()}
            stack.enter_context(patch('sys.argv',['driver','--ejecutar','--solo-piloto','--parejas-formales',str(formal_pairs),*(['--nueva-version'] if new_version else [])]))
            def fake_child(command,log,timeout):
                slot=Path(command[-1]);spec=json.loads((slot/'slot.json').read_text());paid=spec['membership']['phase']!='acceptance'
                run=slot/'fake-run';run.mkdir()
                ev={'acceptance_passed':True,'tasks_valid':32,'evidence_valid':True,'TP':13,'FP':0,'FN':0,'TN':11,
                    'ground_truth_sha256':driver.digest(labroot/'ground_truth.json')}
                (run/'evaluation.json').write_text(json.dumps(ev))
                llm={'known_tokens':1000 if paid else 0,'usage_complete':not (paid and unknown),'fallbacks':0,
                     'cost_estimate_usd':None if paid and unknown else .005 if paid else 0.,
                     'known_cost_estimate_usd':.002 if paid and unknown else .005 if paid else 0.,
                     'specialist_reviews':[{'role':role,'status':'accepted'} for role in (['generalist'] if spec['options']['architecture']=='single' else ['network','credentials','applications','ipv6','fragmentation'])] if paid else [],
                     'calls':[{'generation_sent':True}] if paid else [],'configuration':{'reported_models':['gpt-6.1-sol']} if paid else {}}
                (run/'report.json').write_text(json.dumps({'status':'complete','llm':llm,'metrics':{'execution_seconds':5}}))
                (slot/'timing.json').write_text(json.dumps({'elapsed_seconds':7}))
                return 0
            run=stack.enter_context(patch.object(driver,'guarded',side_effect=fake_child))
            result=driver.main();state=json.loads(monitor.read_text());folder=pilot/'corridas/kpi_novaflow'/state['id']
            if new_version:
                for p,original in preserved.items():self.assertEqual(p.read_bytes(),original)
                receipt=json.loads((folder/'predecessor_receipt.json').read_text())
                self.assertEqual(receipt['id'],old.name)
                self.assertEqual(receipt['files'],{p.relative_to(old).as_posix():driver.digest(p) for p in preserved})
            if resume:
                self.assertEqual(state['status'],'stopped');self.assertEqual(state['pilot_runs'],1)
                original=(folder/'protocol.json').read_bytes();first=json.loads((folder/'attempts.json').read_text())[0]
                restoring.side_effect=None
                stack.enter_context(patch('sys.argv',['driver','--ejecutar','--continuar','--solo-piloto']))
                result=driver.main();state=json.loads(monitor.read_text())
                self.assertEqual((folder/'protocol.json').read_bytes(),original)
                self.assertEqual(json.loads((folder/'attempts.json').read_text())[0],first)
                self.assertTrue(list(folder.glob('protocol-continuation-*.json')))
            attempts=json.loads((folder/'attempts.json').read_text())
            return result,state,attempts,restoring.call_count,run.call_count

    def test_complete_pilot_excludes_acceptance_and_does_not_start_formal(self):
        code,state,attempts,restores,children=self.simulate()
        self.assertEqual(code,0);self.assertEqual(state['status'],'pilot_complete')
        self.assertEqual(state['pilot_runs'],6);self.assertEqual(state['formal_runs'],0)
        self.assertEqual(restores,6);self.assertEqual(children,7)
        self.assertEqual(len(attempts),6);self.assertTrue(all(r['phase']=='pilot' for r in attempts))
        self.assertAlmostEqual(state['known_cost_usd'],.03);self.assertEqual(state['held_usd'],0.)

    def test_unknown_usage_stops_after_first_paid_attempt_and_preserves_it(self):
        code,state,attempts,restores,children=self.simulate(unknown=True)
        self.assertEqual(code,3);self.assertEqual(state['status'],'stopped')
        self.assertEqual(state['pilot_runs'],1);self.assertEqual(state['formal_runs'],0)
        self.assertEqual(len(attempts),1);self.assertFalse(attempts[0]['usage_complete'])
        self.assertEqual(state['held_usd'],.6);self.assertEqual(state['known_cost_usd'],0)
        self.assertEqual(restores,1);self.assertEqual(children,2)

    def test_formal_size_is_fixed_before_pilot_and_does_not_count_acceptance(self):
        code,state,attempts,restores,children=self.simulate(formal_pairs=15)
        self.assertEqual(code,0);self.assertEqual(state['pairs_planned'],15);self.assertEqual(state['runs_planned'],30)
        self.assertEqual(state['pilot_runs'],6);self.assertEqual(state['formal_runs'],0)
        self.assertTrue(all(r['phase']=='pilot' for r in attempts));self.assertEqual(children,7)

    def test_continue_preserves_first_attempt_and_budget_without_repeating_acceptance(self):
        code,state,attempts,restores,children=self.simulate(resume=True)
        self.assertEqual(code,0);self.assertEqual(state['pilot_runs'],6);self.assertEqual(state['formal_runs'],0)
        self.assertEqual(len(attempts),6);self.assertEqual(children,7);self.assertEqual(restores,7)
        self.assertAlmostEqual(state['known_cost_usd'],.03)

    def test_new_version_preserves_old_files_and_carries_cost_in_same_budget(self):
        code,state,attempts,restores,children=self.simulate(new_version=True)
        self.assertEqual(code,0);self.assertEqual(len(attempts),6)
        self.assertEqual(state['predecessor_id'],'estudio_novaflow_20261017T170000')
        self.assertAlmostEqual(state['prior_budget_commitment_usd'],.25913)
        self.assertAlmostEqual(state['prior_known_cost_usd'],.08369)
        self.assertAlmostEqual(state['prior_unknown_reserved_usd'],.17544)
        self.assertAlmostEqual(state['budget_committed_usd'],.28913)
        self.assertAlmostEqual(state['known_cost_total_usd'],.11369)
        self.assertEqual(children,7);self.assertEqual(restores,6)

    def test_new_failure_keeps_prior_and_current_unknown_reservations(self):
        code,state,attempts,restores,children=self.simulate(new_version=True,unknown=True)
        self.assertEqual(code,3);self.assertEqual(len(attempts),1)
        self.assertAlmostEqual(state['held_usd'],.6)
        self.assertAlmostEqual(state['budget_committed_usd'],.85913)
        self.assertAlmostEqual(state['known_cost_total_usd'],.08569)
        self.assertEqual(children,2)

    def test_new_version_after_non_operational_pilot_carries_all_previous_cohorts(self):
        code,state,attempts,_,_=self.simulate(new_version='operational')
        self.assertEqual(code,0);self.assertEqual(len(attempts),6)
        self.assertAlmostEqual(state['prior_budget_commitment_usd'],.28913)
        self.assertAlmostEqual(state['prior_known_cost_usd'],.11369)
        self.assertAlmostEqual(state['prior_unknown_reserved_usd'],.17544)
        self.assertAlmostEqual(state['budget_committed_usd'],.31913)

    def test_pilot_gate_requires_no_fallback_and_all_reviews_before_formal(self):
        import ejecutar_estudio_novaflow as driver
        rows=[{'phase':'pilot','block':block,'architecture':arm,'status':'complete','tasks_valid':32,
               'usage_complete':True,'fallbacks':0,'api_calls':2,'known_tokens':1000,'evidence_valid':True,
               'ground_truth_sha256':'a'*64,'context_sha256':'b'*64,'study_id':'fixture','reported_models':['gpt-6.1-sol'],
               'accepted_reviews':1 if arm=='single' else 5,
               'review_roles':[{'role':role,'status':'accepted'} for role in (['generalist'] if arm=='single' else ['network','credentials','applications','ipv6','fragmentation'])]}
              for block in range(1,4) for arm in ['single','multiagent']]
        self.assertTrue(driver.pilot_operational(rows))
        for extra in [{'fallbacks':1},{'usage_complete':False},{'accepted_reviews':0},{'tasks_valid':31},
                      {'api_calls':0},{'known_tokens':0},{'evidence_valid':False},{'review_roles':[]},
                      {'phase':'formal'},{'block':2},{'review_roles':[{'role':'network','status':'accepted'}]*5},
                      {'context_sha256':'c'*64},{'reported_models':['another-model']}]:
            self.assertFalse(driver.pilot_operational([{**rows[0],**extra},*rows[1:]]))
        self.assertEqual(driver.TOKEN_LIMIT,60000);self.assertEqual(driver.RUN_RESERVE,.6)

    def test_new_image_version_is_explicit_preserves_reference_and_records_transition(self):
        import ejecutar_estudio_novaflow as driver
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            pilot=Path(temp)/'pilot';labroot=pilot/'.lab-empresa';labroot.mkdir(parents=True)
            (labroot/'ground_truth.json').write_text('{}');monitor=pilot/'monitor.json'
            with patch.object(driver,'PILOT',pilot),patch.object(driver,'labroot',labroot),patch.object(driver,'MONITOR',monitor),patch.object(driver,'image_identity',return_value={'host':'sha256:new'}),patch.object(driver,'code_identity',return_value={'auditor_and_extensions':'new'}),patch.object(driver,'load_openai_config',return_value=SimpleNamespace(model='gpt-6.1-sol',reasoning_effort='low',max_output_tokens=2048)):
                folder=prior_fixture(driver,pilot,labroot,monitor)
                preserved={p:p.read_bytes() for p in folder.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError,'Banco o referencia'):driver.load_predecessor()
                carry,receipt=driver.load_predecessor(new_images=True)
                self.assertAlmostEqual(carry['prior_budget_commitment_usd'],.25913)
                self.assertTrue(receipt['image_transition']['changed'])
                self.assertTrue(receipt['image_transition']['acceptance_required'])
                self.assertFalse(receipt['image_transition']['pool_with_predecessor'])
                self.assertEqual(receipt['image_transition']['previous'],{'host':'sha256:fixed'})
                self.assertEqual(receipt['image_transition']['current'],{'host':'sha256:new'})
                self.assertTrue(all(p.read_bytes()==original for p,original in preserved.items()))
                with patch.object(driver,'image_identity',return_value={'host':'sha256:fixed'}):
                    with self.assertRaisesRegex(ValueError,'No hay imágenes nuevas'):driver.load_predecessor(new_images=True)
                (labroot/'ground_truth.json').write_text('{"changed":true}')
                with self.assertRaisesRegex(ValueError,'Referencia diferente'):driver.load_predecessor(new_images=True)

    def test_new_version_rejects_changed_ledger_and_uncorrected_source(self):
        import ejecutar_estudio_novaflow as driver
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            pilot=Path(temp)/'pilot';labroot=pilot/'.lab-empresa';labroot.mkdir(parents=True)
            (labroot/'ground_truth.json').write_text('{}');monitor=pilot/'monitor.json'
            with patch.object(driver,'PILOT',pilot),patch.object(driver,'labroot',labroot),patch.object(driver,'MONITOR',monitor),patch.object(driver,'image_identity',return_value={'host':'sha256:fixed'}),patch.object(driver,'code_identity',return_value={'auditor_and_extensions':'new'}),patch.object(driver,'load_openai_config',return_value=SimpleNamespace(model='gpt-6.1-sol',reasoning_effort='low',max_output_tokens=2048)):
                prior_fixture(driver,pilot,labroot,monitor)
                carry,_=driver.load_predecessor();self.assertAlmostEqual(carry['prior_budget_commitment_usd'],.25913)
                with patch.object(driver,'code_identity',return_value={'auditor_and_extensions':'old'}):
                    with self.assertRaisesRegex(ValueError,'No cambió'):driver.load_predecessor()
                old=json.loads(monitor.read_text())
                for extra in [{'held_usd':0},{'known_cost_usd':0},{'formal_runs':1},{'status':'pilot'},{'prior_budget_commitment_usd':19.9}]:
                    driver.save(monitor,{**old,**extra})
                    with self.assertRaises(ValueError):driver.load_predecessor()


class ReadinessTests(unittest.TestCase):
    def test_transient_http_startup_is_waited_without_rerunning_an_audit(self):
        import ejecutar_estudio_novaflow as driver
        from urllib.error import URLError
        with patch.object(driver,'check_kernel'),patch.object(driver.time,'sleep') as sleep,patch.object(driver.lab,'preflight',side_effect=[URLError('fixture'),URLError('fixture'),{'ready':True}]) as preflight:
            self.assertEqual(driver.wait_preflight(Path('/fixture'),attempts=3),{'ready':True})
            self.assertEqual(preflight.call_count,3);self.assertEqual(sleep.call_count,2)

    def test_invalid_scope_is_fatal_and_readiness_attempts_are_bounded(self):
        import ejecutar_estudio_novaflow as driver
        from urllib.error import URLError
        with patch.object(driver,'check_kernel'),patch.object(driver.time,'sleep'),patch.object(driver.lab,'preflight',side_effect=driver.lab.LabError('invalid scope')) as preflight:
            with self.assertRaises(driver.lab.LabError):driver.wait_preflight(Path('/fixture'))
            self.assertEqual(preflight.call_count,1)
        with patch.object(driver,'check_kernel'),patch.object(driver.time,'sleep'),patch.object(driver.lab,'preflight',side_effect=URLError('fixture')) as preflight:
            with self.assertRaisesRegex(ValueError,'readiness_transport_unavailable'):driver.wait_preflight(Path('/fixture'),attempts=2)
            self.assertEqual(preflight.call_count,2)

    def test_http_authorization_error_is_not_retried_as_startup(self):
        import ejecutar_estudio_novaflow as driver
        from urllib.error import HTTPError
        with patch.object(driver,'check_kernel'),patch.object(driver.time,'sleep') as sleep,patch.object(driver.lab,'preflight',side_effect=HTTPError('http://fixture',401,'denied',None,None)) as preflight:
            with self.assertRaises(HTTPError):driver.wait_preflight(Path('/fixture'))
            self.assertEqual(preflight.call_count,1);sleep.assert_not_called()

    def test_unknown_budget_or_active_study_cannot_be_continued(self):
        import ejecutar_estudio_novaflow as driver
        with tempfile.TemporaryDirectory() as temp:
            monitor=Path(temp)/'monitor.json'
            with patch.object(driver,'MONITOR',monitor):
                for extra in [{'status':'pilot'},{'held_usd':.2},{'formal_runs':1}]:
                    monitor.write_text(json.dumps({'id':'estudio_novaflow_20261017T171746','status':'stopped','phase':'pilot','formal_runs':0,'held_usd':0,'message':'Detenido: URLError',**extra}))
                    with self.assertRaises(ValueError):driver.load_continuation()
