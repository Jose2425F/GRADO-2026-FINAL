import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[2]/'piloto_kali/prototipo/src')]
from tesis.interrupciones import recover_usage,additional_study_minimum


class InterruptedUsageTests(unittest.TestCase):
    def fixture(self,root,events):
        directory=root/'attempt';directory.mkdir()
        with closing(sqlite3.connect(directory/'events.sqlite3')) as c:
            c.execute('create table events(event_id text,component text,kind text,payload_json text,monotonic_ns integer)')
            for i,(kind,payload) in enumerate(events):c.execute('insert into events values(?,?,?,?,?)',(str(i),'llm',kind,json.dumps(payload),i))
            c.commit()
        return directory

    def call(self,**extra):
        return {'generation_sent':True,'response_id':'recorded-response','input_tokens':100,'provider_output_tokens':20,
                'total_tokens':120,'cached_tokens':0,'cache_write_tokens':0,**extra}

    def test_closed_usage_recovers_minimum_without_marking_total_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root,[('decision',self.call()),('api_request_started',{'client_request_id':'pending'})])
            value=recover_usage(root)
            self.assertEqual(value['known_tokens'],120);self.assertAlmostEqual(value['known_cost_lower_bound_usd'],.0004)
            self.assertEqual(value['pending_transport_requests'],1)
            self.assertFalse(value['usage_complete']);self.assertIsNone(value['cost_usd'])

    def test_duplicate_response_and_unknown_usage_are_not_double_counted_or_zero_total(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root,[('decision',self.call()),('decision',self.call()),('decision',{'generation_sent':True,'response_id':'unknown'})])
            value=recover_usage(root)
            self.assertEqual(value['known_tokens'],120);self.assertEqual(value['api_calls'],2)
            self.assertEqual(value['generations_without_usage'],1);self.assertFalse(value['usage_complete'])

    def test_invalid_counters_do_not_produce_negative_cost_or_fabricated_tokens(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root,[('decision',self.call(cached_tokens=101))])
            value=recover_usage(root);self.assertEqual(value['known_tokens'],0)
            self.assertEqual(value['generations_without_usage'],1);self.assertIsNone(value['cost_usd'])

    def test_driver_uses_recovery_when_final_report_is_missing(self):
        import ejecutar_estudio_novaflow as driver
        with tempfile.TemporaryDirectory() as temp:
            pilot=Path(temp);slot=pilot/'corridas/study/pilot';slot.mkdir(parents=True)
            self.fixture(slot,[('decision',self.call())])
            with patch.object(driver,'PILOT',pilot):record=driver.summarize(slot,{'architecture':'multiagent'},130)
            self.assertEqual(record['status'],'interrupted');self.assertEqual(record['known_tokens'],120)
            self.assertEqual(record['run_key'],'study/pilot/attempt');self.assertFalse(record['usage_complete'])

    def test_public_minimum_adds_only_missing_cost_and_never_releases_reservation(self):
        from tesis.estudio import public_status
        with tempfile.TemporaryDirectory() as temp:
            pilot=Path(temp);name='estudio_novaflow_20261017T201343'
            study=pilot/'corridas/kpi_novaflow'/name;slot=study/'pilot/block_01_multiagent';slot.mkdir(parents=True)
            self.fixture(slot,[('decision',self.call())])
            (study/'attempts.json').write_text(json.dumps([{'status':'interrupted','phase':'pilot','block':1,'architecture':'multiagent','known_cost_lower_bound_usd':.0001}]))
            monitor=pilot/'.lab/monitor.json';monitor.parent.mkdir()
            monitor.write_text(json.dumps({'id':name,'status':'stopped','message':'Detenido: interrupted_attempt_preserved; kernel_failure',
                'known_cost_total_usd':1.0001,'budget_committed_usd':1.6,'held_usd':.6}))
            before=monitor.read_bytes();value=public_status(monitor)
            self.assertAlmostEqual(value['known_cost_total_usd'],1.0004)
            self.assertAlmostEqual(value['unknown_reserved_total_usd'],.5996)
            self.assertEqual(value['held_usd'],.6);self.assertEqual(before,monitor.read_bytes())
            self.assertEqual(additional_study_minimum('../escape',pilot/'corridas'),{})
            rows=json.loads((study/'attempts.json').read_text())
            (study/'attempts.json').write_text(json.dumps(rows+rows))
            self.assertEqual(additional_study_minimum(name,pilot/'corridas'),{})

    def test_explicit_new_version_inherits_interrupted_reserve_and_recovered_minimum(self):
        import ejecutar_estudio_novaflow as driver
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            pilot=Path(temp);labroot=pilot/'.lab-empresa';labroot.mkdir();(labroot/'ground_truth.json').write_text('{}')
            name='estudio_novaflow_20261017T201343';study=pilot/'corridas/kpi_novaflow'/name
            slot=study/'pilot/block_01_multiagent';slot.mkdir(parents=True);self.fixture(slot,[('decision',self.call())])
            protocol={'code_identity':{'auditor_and_extensions':'old'},'images':{'host':'fixed'},
                'ground_truth_sha256':driver.digest(labroot/'ground_truth.json'),
                'model':{'model':'gpt-6.1-sol','reasoning_effort':'low','max_output_tokens':2048},
                'pricing':{**driver.PRICING,'verified_on':'2026-10-17'},'run_reserve_usd':.6,'pilot_order':[{'block':1,'order':['multiagent','single']}]}
            driver.save(study/'protocol.json',protocol)
            driver.save(study/'attempts.json',[{'phase':'pilot','block':1,'architecture':'multiagent','status':'interrupted','usage_complete':False,'cost_usd':None}])
            monitor=pilot/'.lab/monitor.json';driver.save(monitor,{'id':name,'status':'stopped','phase':'pilot','formal_runs':0,'pilot_runs':1,
                'message':'Detenido: interrupted_attempt_preserved; kernel_failure','known_cost_usd':0.,'held_usd':.6,'budget_usd':20})
            before=monitor.read_bytes()
            with patch.object(driver,'PILOT',pilot),patch.object(driver,'MONITOR',monitor),patch.object(driver,'labroot',labroot),patch.object(driver,'image_identity',return_value={'host':'fixed'}),patch.object(driver,'code_identity',return_value={'auditor_and_extensions':'new'}),patch.object(driver,'load_openai_config',return_value=SimpleNamespace(**protocol['model'])):
                carry,receipt=driver.load_predecessor()
            self.assertEqual(carry['prior_budget_commitment_usd'],.6)
            self.assertAlmostEqual(carry['prior_known_cost_usd'],.0004)
            self.assertAlmostEqual(carry['prior_unknown_reserved_usd'],.5996)
            self.assertEqual(receipt['interrupted_usage_recovery'][0]['known_tokens'],120)
            self.assertEqual(before,monitor.read_bytes())
