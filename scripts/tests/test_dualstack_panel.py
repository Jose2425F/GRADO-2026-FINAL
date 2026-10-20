import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dualstack_panel import Operations, Panel, command_for, friendly_error, make_server, validate_options
from auditoria.dashboard import process_identity
from auditoria.store import RunStore, write_json
from panel_observabilidad import recorded_command


class FakeOperations:
    def __init__(self):
        self.calls = []

    def snapshot(self):
        return {"jobs": [], "busy": False, "lab": {"status": "ready", "message": "Laboratorio de prueba", "checked_at": None}}

    def start(self, action, options=None):
        if action == "audit":
            options = validate_options(options)
        self.calls.append((action, options))
        return {"id": "fake-job", "action": action, "status": "queued"}

    def stop(self):
        self.calls.append(("stop", None))
        return {"status": "stopping"}


class PanelTests(unittest.TestCase):
    def test_acceptance_and_close_original_endpoints_are_explicit_controls(self):
        for path,action in [('/api/lab/acceptance-all','acceptance_all'),('/api/lab/empresa/down','empresa_down')]:
            with self.post(path,{}) as response:
                self.assertEqual(response.status,202)
            self.assertEqual(self.operations.calls[-1],(action,{} if action=='acceptance_all' else None))
            with self.assertRaises(HTTPError):self.post(path,{},csrf=False)

    def test_public_detection_budget_counts_omissions_without_raw_manifest_or_commands(self):
        self.fixture()
        write_json(self.store.root/'manifest.json',{'detection_budget':{'applied':True,'catalogue_size':32,
            'task_limit':19,'executed_tasks':19,'private_secret':'DO_NOT_EXPOSE','admitted_task_ids':['private-id']}})
        report={}
        report['tasks']=[{'task_id':'private-id','status':'skipped','reason_code':'task_budget_not_selected',
                         'command':['DO_NOT_EXPOSE']}]
        write_json(self.store.root/'report.json',report)
        detail=self.panel.detail('fixture')
        self.assertEqual(detail['detection_budget'],{'applied':True,'catalogue_size':32,'task_limit':19,
            'executed_tasks':19,'not_selected_tasks':1})
        self.assertNotIn('DO_NOT_EXPOSE',json.dumps(detail))
        self.assertNotIn('manifest',detail);self.assertNotIn('report',detail)

    def test_manual_export_has_fifty_positions_without_private_payloads(self):
        import csv,io,zipfile
        rows=list(csv.DictReader(io.StringIO(urlopen(self.url+'/api/manual/export?format=csv').read().decode())))
        self.assertEqual(len(rows),50)
        self.assertTrue(all(row['status']=='not_started' for row in rows))
        self.assertTrue(all(row['input_tokens']=='' and row['TP']=='' for row in rows))
        archive=urlopen(self.url+'/api/manual/export?format=zip').read()
        with zipfile.ZipFile(io.BytesIO(archive)) as exported:
            self.assertIn('manifest.json',exported.namelist())
            self.assertIn('protocol.json',exported.namelist())
            self.assertFalse(any('evidence' in name or 'openai.json' in name for name in exported.namelist()))
        with self.assertRaises(HTTPError):urlopen(self.url+'/api/manual/export?format=invalid')

    def test_interrupted_api_trace_is_not_disabled(self):
        self.fixture(terminal=False)
        write_json(self.store.root / 'request.json', {'bank':'v2','llm_mode':'scheduler','token_budget':6000})
        write_json(self.store.root / 'runtime.json', {'status':'running','pid':999999999,'identity':'absent'})
        self.store.event('llm','decision',payload={'status':'sent','generation_sent':True,'total_tokens':None})
        run = self.panel.state()['runs'][0]
        self.assertEqual(run['status'], 'interrupted')
        self.assertEqual(run['llm']['status'], 'interrupted')
        self.assertFalse(run['llm']['usage_complete'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.operations = FakeOperations()
        self.panel = Panel(self.root, operations=self.operations)
        self.server = make_server(self.panel, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.store = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.store:
            self.store.close()
        self.temp.cleanup()

    def post(self, path, body, *, csrf=True, origin=True):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = self.panel.csrf
        if origin:
            headers["Origin"] = self.url
        return urlopen(Request(self.url + path, data=json.dumps(body).encode(), headers=headers))

    def fixture(self, *, terminal=True, report=False):
        # Fixture sintético: no depende de corridas ni sesiones privadas.
        from auditoria import v2_agent
        from auditoria.contracts import TaskResult
        request = v2_agent.request('UNIT-TEST', llm=False)
        model = next(t for t in v2_agent.build_plan(request) if t.target.asset_id == 'app_a')
        task = model.model_dump(mode='json')
        self.store = RunStore(self.root / "fixture", request.audit_id)
        write_json(self.store.root / "request.json", {"audit_id": request.audit_id, "bank": "v2"})
        write_json(self.store.root / "manifest.json", {"mode": "live"})
        write_json(self.store.root / "runtime.json", {"status": "running", "pid": os.getpid(), "identity": process_identity(os.getpid())})
        write_json(self.store.root / "plan.json", [task])
        self.store.event("controller", "task_admitted", task_id=task["task_id"], payload={"password": "DO-NOT-SERVE"})
        def facts(family, channel):
            nonce = f'unit-{channel}-{family}'
            records = [
                {'path': '/objects/own', 'status': 200, 'body': {'kind': 'document', 'owner': 'viewer', 'marker': 'unit-own'}},
                {'path': '/objects/other', 'status': 200, 'body': {'kind': 'document', 'owner': 'other', 'marker': 'unit-other'}},
                {'path': '/download?name=unit-internal', 'status': 200, 'body': {'kind': 'internal_configuration', 'marker': 'unit-file'}},
                {'path': '/admin', 'status': 200 if family == 'ipv6' else 403,
                 'body': {'kind': 'admin_configuration'} if family == 'ipv6' else {'error': 'role_denied'}},
            ]
            return {'nonce': nonce, 'own_marker_sha256': hashlib.sha256(b'unit-own').hexdigest(), 'records': records,
                    'server_trace': [{'path': row['path'], 'status': row['status'], 'nonce': nonce} for row in records]}
        data = {'asset_id': model.target.asset_id, 'target': model.target.address, 'profile': model.action_profile,
                'families': {family: facts(family, 'primary') for family in ('ipv4', 'ipv6')}}
        confirmation = {**data, 'channel': 'independent_http_client',
                        'families': {family: facts(family, 'confirmation') for family in ('ipv4', 'ipv6')}}
        er, eh = self.store.evidence(task['task_id'] + '_state', 'json', json.dumps(data).encode())
        cr, ch = self.store.evidence(task['task_id'] + '_confirmation', 'json', json.dumps(confirmation).encode())
        result = TaskResult(task_id=task['task_id'], status='completed', evidence_ref=er, evidence_sha256=eh,
                            diagnostic_ref=cr, diagnostic_sha256=ch, observations={'bank': 'v2', 'restored': True})
        if terminal:
            self.store.event("orchestration", "task_terminal", task_id=task["task_id"], payload={"status": "completed"})
        if report:
            original = {'audit_id': request.audit_id, 'architecture': 'multiagent', 'status': 'complete',
                        'tasks': [result.model_dump(mode='json')],
                        'findings': v2_agent.adjudicate(self.store.root, model, result),
                        'llm': {"known_tokens": 0, "usage_complete": True, "status": "disabled", "budget": 0}}
            write_json(self.store.root / "report.json", original)
            write_json(self.root / "panel_job.json", {"name": "<script>alert('XSS')</script>"})
        self.panel.cached_at = 0
        return task

    def test_scope_budget_and_no_shell_commands(self):
        good = {"name": "Prueba", "authorization": "LAB-PROPIO", "ia": "openai", "tokens": 6000}
        normalized = validate_options(good)
        command = command_for(normalized, self.root / "output")
        self.assertIn("--openai", command)
        self.assertIn("6000", command)
        for extra in ({"scope": "internet"}, {"targets": ["8.8.8.8"]}, {"tokens": 20001}, {"tokens": True}, {"architecture": "free"}):
            with self.assertRaises(ValueError):
                validate_options({**good, **extra})
        simulation = validate_options({**good, "mode": "dry_run"})
        self.assertEqual(simulation["tokens"], 0)
        self.assertIn("--sin-ia", command_for(simulation, self.root))
        self.assertNotIn("--ejecutar", command_for(simulation, self.root))

    def test_novaflow_accepts_larger_budget_without_expanding_other_banks(self):
        good={'name':'NovaFlow','authorization':'LAB-PROPIO','ia':'openai','scope':'empresa','expert_mode':True}
        self.assertEqual(validate_options(good)['tokens'],60000)
        for tokens in [20000,40000,60000,80000]:self.assertEqual(validate_options({**good,'tokens':tokens})['tokens'],tokens)
        for tokens in [80001,True,-1]:
            with self.assertRaises(ValueError):validate_options({**good,'tokens':tokens})
        with self.assertRaises(ValueError):validate_options({**good,'scope':'v2','tokens':60000,'expert_mode':False})
        with self.assertRaises(ValueError):validate_options({**good,'scope':'personal','personal':{'ipv4':'192.168.56.10','ports':'22','interface':'eth0'},'tokens':60000})

    def test_console_projects_evidence_without_prompts_or_bodies(self):
        self.fixture(report=True)
        self.store.event('llm','request_started',payload={'prompt':'PRIVATE-PROMPT','api_key':'PRIVATE-KEY'})
        detail = self.panel.detail('fixture')
        lines = detail['console']['lines']
        self.assertTrue(any(line['kind']=='HTTP' and 'HTTP 200' in line['text'] for line in lines))
        self.assertTrue(any(line['kind']=='IA' for line in lines))
        public = json.dumps(detail)
        for secret in ['PRIVATE-PROMPT','PRIVATE-KEY','DO-NOT-SERVE','Authorization:','Bearer ']:
            self.assertNotIn(secret, public)
        self.assertTrue(detail['technical'][0]['hash_matches'])

    def test_console_rejects_changed_evidence_and_does_not_invent_http(self):
        task = self.fixture(report=True)
        path = self.store.root/'evidence'/f"{task['task_id']}_state.json"
        data=json.loads(path.read_text());data['not_in_original']=True;write_json(path,data)
        detail=self.panel.detail('fixture')
        self.assertFalse(any(line['kind']=='HTTP' for line in detail['console']['lines']))
        self.assertFalse(detail['technical'][0]['hash_matches'])

    def test_console_dry_run_does_not_claim_tool_execution(self):
        self.fixture()
        write_json(self.store.root/'manifest.json',{'mode':'dry_run'})
        detail=self.panel.detail('fixture')
        self.assertFalse(any(line['kind'] in {'PERFIL','HTTP','PAQUETES','COMANDO'} for line in detail['console']['lines']))

    def test_two_reports_share_findings_but_target_distinct_readers(self):
        self.fixture(report=True)
        technical=urlopen(self.url+'/report?key=fixture&audience=technical').read().decode()
        executive=urlopen(self.url+'/report?key=fixture&audience=executive').read().decode()
        self.assertIn('INFORME TÉCNICO',technical)
        self.assertIn('Herramientas y trazabilidad técnica',technical)
        self.assertIn('evidence/',technical)
        self.assertIn('INFORME EJECUTIVO',executive)
        self.assertIn('Decisiones y acciones recomendadas',executive)
        self.assertNotIn('evidence/',executive)
        self.assertNotIn('Herramientas y trazabilidad técnica',executive)
        self.assertNotIn('Sin IA registrada',executive)
        self.assertNotIn('Revisión no realizada',executive)
        with self.assertRaises(HTTPError):
            urlopen(self.url+'/report?key=fixture&audience=arbitrary')

    def test_recorded_hydra_command_redacts_user_and_private_files(self):
        task={'action_profile':'hydra_ssh_single_v1','target':{'address':'192.168.59.11','ports':[22]}}
        command=['hydra','-l','PRIVATE-USER','-P','/PRIVATE-PASSWORDS','-o','/PRIVATE-RESULT','-b','json','-t','1','-f','-I','-4','-w','5','-s','22','192.168.59.11','ssh']
        public=recorded_command(command,task)
        self.assertIn('hydra',public)
        self.assertNotIn('PRIVATE-',public)
        self.assertEqual(recorded_command(command+['arbitrary'],task),'')
        self.assertEqual(recorded_command(['sh','-c','PRIVATE-COMMAND'],task),'')

    def test_control_requires_origin_and_csrf(self):
        for kwargs in ({"csrf": False}, {"origin": False}):
            with self.assertRaises(HTTPError) as caught:
                self.post("/api/lab/restore", {}, **kwargs)
            self.assertEqual(caught.exception.code, 403)
        self.assertEqual(self.operations.calls, [])
        with self.assertRaises(HTTPError) as caught:
            self.post("/api/audit", {"authorization": "LAB-PROPIO", "tokens": 999999})
        self.assertEqual(caught.exception.code, 400)
        self.assertEqual(self.operations.calls, [])
        self.assertEqual(self.post("/api/lab/check", {}).status, 202)
        self.assertEqual(self.operations.calls[0][0], "check")

    def test_host_and_arbitrary_files_are_rejected(self):
        write_json(self.root / "private.json", {"key": "DO-NOT-SERVE"})
        for path in ("/.env", "/private.json", "/download?key=../outside&kind=pdf", "/api/run?key=../outside"):
            with self.assertRaises(HTTPError) as caught:
                urlopen(self.url + path)
            self.assertEqual(caught.exception.code, 404)
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.url + "/api/state", headers={"Host": "external.invalid"}))
        self.assertEqual(caught.exception.code, 403)

    def test_preliminary_findings_are_distinct_and_do_not_write(self):
        self.fixture()
        db = self.store.root / "events.sqlite3"
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        detail = self.panel.detail("fixture")
        self.assertFalse(detail["brief"]["final"])
        self.assertEqual(len(detail["brief"]["cards"]), 3)
        self.assertTrue(all(card["preliminary"] for card in detail["brief"]["cards"]))
        self.assertEqual(before, hashlib.sha256(db.read_bytes()).hexdigest())
        self.assertNotIn("DO-NOT-SERVE", json.dumps(detail))
        self.assertIn("Un usuario puede consultar", detail["brief"]["cards"][0]["title"])
        self.assertEqual(detail["brief"]["report_tokens"], 0)

    def test_unfinished_task_does_not_publish_findings(self):
        self.fixture(terminal=False)
        self.assertEqual(self.panel.detail("fixture")["brief"]["cards"], [])

    def test_interrupted_run_does_not_promise_a_future_final_report(self):
        self.fixture()
        write_json(self.store.root / "request.json", {"audit_id": self.store.audit_id, "bank": "v2", "token_budget": 6000})
        write_json(self.store.root / "runtime.json", {"status": "running", "pid": os.getpid(), "identity": "expired"})
        self.panel.cached_at = 0
        detail = self.panel.detail("fixture")
        self.assertEqual(detail["run"]["status"], "interrupted")
        self.assertFalse(detail["brief"]["final"])
        self.assertIn("se interrumpió antes", detail["brief"]["summary"])
        self.assertFalse(detail["run"]["llm"]["usage_complete"])

    def test_invalid_or_symlinked_evidence_does_not_publish(self):
        task = self.fixture()
        file = self.store.root / "evidence" / f"{task['task_id']}_confirmation.json"
        file.write_text('{"invalid":true}')
        self.assertEqual(self.panel.detail("fixture")["brief"]["cards"], [])
        file.unlink()
        outside = self.root.parent / (self.root.name + "-external.json")
        outside.write_text("{}"); file.symlink_to(outside)
        try:
            self.assertEqual(self.panel.detail("fixture")["brief"]["cards"], [])
        finally:
            outside.unlink()

    def test_final_client_report_is_readable_and_escaped(self):
        self.fixture(report=True)
        detail = self.panel.detail("fixture")
        self.assertTrue(detail["brief"]["final"])
        self.assertFalse(any(card["preliminary"] for card in detail["brief"]["cards"]))
        response = urlopen(self.url + "/report?" + urlencode({"key": "fixture"}))
        html = response.read().decode()
        self.assertIn("Cómo corregirlo", html)
        self.assertIn("Anexo · cobertura, diagnóstico y evidencia completa", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("DO-NOT-SERVE", html)
        response = urlopen(self.url + "/report?" + urlencode({"key": "fixture", "download": "1"}))
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_partial_report_retains_incidents(self):
        self.fixture(report=True)
        path = self.store.root / "report.json"
        report = json.loads(path.read_text())
        report["status"] = "partial"; report["tasks"][0]["status"] = "failed"
        write_json(path, report); self.panel.cached_at = 0
        detail = self.panel.detail("fixture")
        self.assertEqual(len(detail["brief"]["issues"]), 1)
        self.assertIn("cobertura debe revisarse", detail["brief"]["summary"])

    def test_busy_operations_cannot_overlap_or_restore(self):
        operations = Operations(self.root)
        operations.jobs.append({"id":"busy", "action":"audit", "status":"stopping", "run_key":"fixture"})
        self.assertTrue(operations.snapshot()["busy"])
        for action in ("check", "restore", "audit"):
            with self.assertRaises(ValueError):
                operations.start(action, {"authorization": "LAB-PROPIO"})

    def test_kernel_failure_overrides_ready_without_changing_recorded_lab_check(self):
        operations = Operations(self.root)
        operations.lab.update(status='ready', message='Contenedores listos')
        with patch('dualstack_panel.kernel_warning', return_value='Reinicia Kali: fallo de kernel'):
            snapshot = operations.snapshot()
        self.assertEqual(snapshot['lab']['status'], 'error')
        self.assertIn('Reinicia Kali', snapshot['lab']['message'])
        self.assertTrue(snapshot['execution_guard']['blocked'])
        self.assertEqual(snapshot['execution_guard']['reason'], 'kernel_fault')
        self.assertIn('Reinicia Kali', snapshot['execution_guard']['message'])
        self.assertEqual(snapshot['empresa_lab']['status'], 'error')
        self.assertEqual(snapshot['personal_lab']['status'], 'error')
        self.assertEqual(operations.lab['status'], 'ready')
        with patch('dualstack_panel.kernel_warning', return_value=None):
            restored = operations.snapshot()
            self.assertEqual(restored['lab']['status'], 'ready')
            self.assertEqual(restored['execution_guard'], {'blocked':False, 'reason':None, 'message':''})

    def test_provider_output_is_not_exposed(self):
        self.assertNotIn("SECRET-MARKER", friendly_error("OPENAI SECRET-MARKER traceback"))
        self.assertNotIn("SECRET-MARKER", friendly_error("unknown SECRET-MARKER"))


if __name__ == "__main__":
    unittest.main()
