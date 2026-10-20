import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.workspace import archive_runs, archives, archive_root, restore_archive
from tesis.candidatos import correlate
from tesis.llm_contexto import context_for,validate_actions
from tesis.presentacion import actions_for_view
from laboratorio_personal import InventoryTask
from auditoria.contracts import Target,TaskResult


class ArchiveTests(unittest.TestCase):
    def test_archive_preserves_bytes_and_restore_refuses_nonempty_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'corridas';root.mkdir();(root/'evidence.bin').write_bytes(b'original')
            with patch('tesis.workspace.collect_state',return_value={'runs':[]}):receipt=archive_runs(root)
            self.assertEqual(list(root.iterdir()),[]);saved=archive_root(root,receipt['id'])
            self.assertEqual(hashlib.sha256((saved/'evidence.bin').read_bytes()).hexdigest(),receipt['sha256']['evidence.bin'])
            self.assertEqual(archives(root)[0]['files_count'],1)
            (root/'keep').write_text('no overwrite')
            with self.assertRaises(ValueError):restore_archive(root,receipt['id'])
            (root/'keep').unlink();restore_archive(root,receipt['id']);self.assertEqual((root/'evidence.bin').read_bytes(),b'original')
    def test_running_audit_and_symlinks_are_rejected_without_moving(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'corridas';root.mkdir();(root/'keep').write_text('original')
            with patch('tesis.workspace.collect_state',return_value={'runs':[{'status':'running'}]}),self.assertRaises(ValueError):archive_runs(root)
            self.assertTrue((root/'keep').is_file())
            (root/'link').symlink_to(root/'keep')
            with patch('tesis.workspace.collect_state',return_value={'runs':[]}),self.assertRaises(ValueError):archive_runs(root)
    def test_archive_identifier_cannot_escape_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            for identifier in ['../corridas','archivo_2026/../../','file','archivo_2026Z']:
                with self.assertRaises(ValueError):archive_root(Path(tmp)/'corridas',identifier)


class CandidateTests(unittest.TestCase):
    def service(self,version,product='OpenSSH'):
        return {'port':22,'state':'open','product':product,'version':version}
    def test_candidate_is_not_a_finding_and_keeps_backport_caveat(self):
        value=correlate([self.service('9.2p1 Debian 2+deb12u10')])[0]
        self.assertEqual(value['state'],'candidate');self.assertIn('backport',value['limitation']);self.assertEqual(value['cve'],'CVE-2024-6387')
        self.assertNotIn('verified',value.values());self.assertNotIn('severity',value)
    def test_affected_and_fixed_boundaries_are_distinguished(self):
        for version in ['8.4p1','9.8p1','10.0p1','unknown']:self.assertEqual(correlate([self.service(version)]),[])
        self.assertEqual(len(correlate([self.service('8.5p1')])),1)
        self.assertEqual(len(correlate([self.service('15.4','PostgreSQL DB')])),1)
        self.assertEqual(correlate([self.service('15.5','PostgreSQL DB')]),[])
        self.assertEqual(correlate([self.service('15','PostgreSQL DB')]),[])
        self.assertEqual(correlate([{**self.service('9.2p1'),'state':'closed'}]),[])
        self.assertEqual(correlate([{**self.service('9.2p1'),'port':True}]),[])


class ActionTests(unittest.TestCase):
    def fixture(self):
        tasks=[InventoryTask(task_id='PRIVATE_'+str(i),agent_type='ipv4_services',target=Target(asset_id='PRIVATE_ASSET_'+str(i),address='192.0.2.'+str(i+1),interface='eth0',ports=[22])) for i in range(2)]
        results=[TaskResult(task_id=t.task_id,status='completed_no_findings') for t in tasks]
        return tasks,context_for(tasks,results,[],'network')
    def test_context_groups_assets_without_addresses_or_private_ids(self):
        _,context=self.fixture();text=json.dumps(context)
        self.assertEqual(context['assets_total'],2);self.assertNotIn('192.0.2.',text);self.assertNotIn('PRIVATE',text)
        self.assertEqual(context['task_assets'],{'t000':'a000','t001':'a001'})
    def test_action_cannot_cite_a_different_asset_or_request_a_new_operation(self):
        tasks,context=self.fixture();action={'asset':'a000','action':'restrict_service','why':'Revisar exposición.','verification':'Repetir el perfil autorizado.','evidence_tasks':['t000']}
        self.assertEqual(validate_actions([action],context),[action])
        for bad in [{**action,'evidence_tasks':['t001']},{**action,'action':'execute_shell'},{**action,'asset':'a999'}]:
            with self.assertRaises(ValueError):validate_actions([bad],context)
        plan=[t.model_dump(mode='json') for t in tasks]
        public=actions_for_view({'prioritized_actions':[action]},plan)
        self.assertEqual(public[0]['addresses'],['192.0.2.1'])
        self.assertEqual(actions_for_view({'prioritized_actions':[{**action,'evidence_tasks':['t001']}]},plan),[])


class EvaluatorTests(unittest.TestCase):
    def fixture(self,tmp):
        from auditoria import empresa_agent
        tasks=[t for t in empresa_agent.build_plan(empresa_agent.request('LAB-PROPIO',tokens=0,llm=False)) if t.action_profile.startswith('hydra_')][:2]
        directory=Path(tmp)/'run';directory.mkdir()
        (directory/'plan.json').write_text(json.dumps([t.model_dump(mode='json') for t in tasks]))
        (directory/'report.json').write_text(json.dumps({'tasks':[TaskResult(task_id=t.task_id,status='completed_no_findings').model_dump(mode='json') for t in tasks]}))
        from tesis.evaluacion import conditions_for
        entries=[{'asset_id':t.target.asset_id,'defect_key':next(iter(conditions_for(t))),'present':i==0} for i,t in enumerate(tasks)]
        truth=Path(tmp)/'truth.json';truth.write_text(json.dumps({'bank':'docker-empresa-1.0','entries':entries}))
        return directory,truth,tasks,entries
    def test_detection_is_grounded_in_reserved_reference_and_valid_checks(self):
        from tesis.evaluacion import score
        with tempfile.TemporaryDirectory() as tmp:
            directory,truth,tasks,entries=self.fixture(tmp)
            def validate(root,task,result):
                found=[{'asset_id':entries[0]['asset_id'],'defect_key':entries[0]['defect_key']}] if task.task_id==tasks[0].task_id else []
                return {'independent_confirmation':True,'evidence_integrity':{'valid':True}},found
            with patch('laboratorio_empresa.validation_for',side_effect=validate):value=score(directory,truth)
            self.assertEqual((value['TP'],value['FP'],value['FN'],value['TN']),(1,0,0,1));self.assertTrue(value['acceptance_passed'])
    def test_missing_evidence_does_not_become_a_negative_control(self):
        from tesis.evaluacion import score
        with tempfile.TemporaryDirectory() as tmp:
            directory,truth,_,_=self.fixture(tmp)
            with patch('laboratorio_empresa.validation_for',return_value=({'independent_confirmation':False,'evidence_integrity':{'valid':False}},[])):value=score(directory,truth)
            self.assertEqual(value['TP'],0);self.assertEqual(value['FN'],1);self.assertEqual(value['TN'],0)
            self.assertEqual(value['unknown_negative_controls'],1);self.assertFalse(value['evidence_valid']);self.assertFalse(value['acceptance_passed'])
    def test_unselected_positive_stays_false_negative_and_acceptance_is_not_relaxed(self):
        from tesis.evaluacion import score
        with tempfile.TemporaryDirectory() as tmp:
            directory,truth,tasks,entries=self.fixture(tmp)
            report=json.loads((directory/'report.json').read_text())
            report['tasks'][0].update(status='skipped',reason_code='task_budget_not_selected')
            (directory/'report.json').write_text(json.dumps(report))
            with patch('laboratorio_empresa.validation_for',return_value=({'independent_confirmation':True,'evidence_integrity':{'valid':True}},[])):
                value=score(directory,truth)
            self.assertEqual((value['TP'],value['FN'],value['TN']),(0,1,1))
            self.assertEqual(value['intentional_budget_omissions'],1)
            self.assertTrue(value['evidence_valid']);self.assertFalse(value['acceptance_passed'])

class WorkspaceHTTPTests(unittest.TestCase):
    def test_static_assets_and_state_are_local_and_archive_path_is_guarded(self):
        import threading,urllib.request,urllib.error
        from dualstack_panel import Panel,make_server
        with tempfile.TemporaryDirectory() as tmp:
            panel=Panel(Path(tmp)/'corridas');server=make_server(panel,0)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                for path in ['/workspace.js','/novaflow.css','/brand/wordmark.webp']:
                    with urllib.request.urlopen(base+path) as response:
                        self.assertEqual(response.status,200);self.assertGreater(len(response.read()),100)
                        self.assertIn("default-src 'self'",response.headers['Content-Security-Policy'])
                with urllib.request.urlopen(base+'/api/state') as response:value=json.load(response)
                self.assertEqual(value['thesis']['active_runs'],0);self.assertNotIn('api_key',json.dumps(value))
                for path in ['/archive?id=../corridas','/report?archive=../corridas&key=x','/brand/../../.lab/openai.json']:
                    with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(base+path)
                    self.assertEqual(caught.exception.code,404)
            finally:server.shutdown();server.server_close();thread.join()

if __name__=='__main__':unittest.main()
