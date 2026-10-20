"""Escenarios separados, sin Docker ni API en estas pruebas."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.laboratorios import Context,catalog
from dualstack_panel import validate_options,command_for


class ScenarioTests(unittest.TestCase):
    def test_suite_http_fixture_challenges_invalid_credentials_and_accepts_valid_ones(self):
        import io,runpy
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            ctx=Context('comercial',state_root=Path(temp));ctx.prepare()
            with patch.dict('os.environ',{'LAB_HTTP_PASSWORD':'fixture-only-password'}):
                module=runpy.run_path(str(ctx.state/'http_target.py'))
            for header,expected in [('Basic incorrect',401),('Basic '+module['EXPECTED'],200)]:
                handler=object.__new__(module['Handler']);handler.path='/manager/html'
                handler.headers={'Authorization':header};handler.wfile=io.BytesIO()
                handler.send_response=Mock();handler.send_header=Mock();handler.end_headers=Mock()
                handler.do_GET();handler.send_response.assert_called_once_with(expected)
                if expected==401:self.assertIn('WWW-Authenticate',[call.args[0] for call in handler.send_header.call_args_list])

    def test_readiness_waits_only_for_wrapped_legacy_transport(self):
        from auditoria.lab import LabError
        from laboratorio_suite import ready
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            state=Path(temp);(state/'prepared.json').write_text('{"images": {}}')
            transport=LabError('no se pudo contactar la consola legada NovaFlow')
            transport.__cause__=ConnectionRefusedError()
            ctx=SimpleNamespace(state=state,preflight=__import__('unittest.mock',fromlist=['Mock']).Mock(side_effect=[transport,{'ready':True}]))
            with patch('laboratorio_suite.kernel_ok'),patch('laboratorio_suite.images',return_value={}),patch('laboratorio_suite.time.sleep') as sleep:
                self.assertEqual(ready(ctx),{'ready':True});sleep.assert_called_once_with(1)
                ctx.preflight.side_effect=LabError('contenedores ajenos o faltantes')
                with self.assertRaises(LabError):ready(ctx)
                self.assertEqual(sleep.call_count,1)

    def test_four_distinct_catalogs_with_closed_targets_and_real_configuration_changes(self):
        addresses=[];truths=[]
        with tempfile.TemporaryDirectory() as temp:
            for entry in catalog():
                ctx=Context(entry['id'],state_root=Path(temp));ctx.prepare()
                req=ctx.agent.request('LAB-PROPIO',tokens=60000)
                ctx.agent.authorize_empresa(req,ctx.policy())
                self.assertEqual(len(ctx.agent.build_plan(req)),entry['tasks'])
                target_ips={t.address for t in req.targets};self.assertTrue(all(not target_ips.intersection(a) for a in addresses));addresses.append(target_ips)
                self.assertLessEqual(len(req.targets),16)
                data=json.loads(ctx.lab.COMPOSE.read_text());truth=json.loads((ctx.state/'ground_truth.json').read_text());truths.append((sum(e['present'] for e in truth['entries']),len(truth['entries'])))
                self.assertTrue(all(n['internal'] for n in data['networks'].values()))
                self.assertTrue(all(not s.get('ports') and not s.get('privileged') and 'build' not in s for s in data['services'].values()))
                actual_names={s['container_name'] for s in data['services'].values()}
                self.assertEqual(actual_names,{name for _,_,members in ctx.lab.NETWORKS.values() for name in members})
                self.assertEqual(len(actual_names),entry['containers'])
                self.assertEqual((ctx.state/'lab.env').stat().st_mode&0o777,0o600)
                self.assertEqual(data['services']['receiver-a']['environment']['LAB_GUARDED'],'1' if entry['id']=='reforzado' else '0')
                self.assertNotIn('nova-sender',(ctx.state/'protocol/sender.py').read_text())
            self.assertEqual(truths,[(9,15),(9,19),(11,24),(4,27)])

    def test_foreign_targets_and_unknown_scenarios_rejected(self):
        with self.assertRaises(ValueError):Context('../empresa')
        with self.assertRaises(ValueError):validate_options({'authorization':'LAB-PROPIO','scope':'v2','scenario':'sucursal'})
        for entry in catalog():
            c=Context(entry['id']);task=c.agent.build_plan(c.agent.request('LAB-PROPIO',llm=False))[0]
            other=Context('comercial' if entry['id']=='sucursal' else 'sucursal')
            with self.assertRaises(Exception):other.agent.run_task(task,None)
            opts=validate_options({'authorization':'LAB-PROPIO','scope':'empresa','scenario':entry['id'],'ia':'openai','tokens':60000,'expert_mode':True})
            self.assertIn('laboratorio_suite.py',' '.join(command_for(opts,Path('/tmp/safe'))))

    def test_reference_tampering_is_rejected_before_network_requests(self):
        with tempfile.TemporaryDirectory() as temp:
            c=Context('sucursal',state_root=Path(temp));c.prepare()
            (c.state/'ground_truth.json').write_text('{}')
            with patch.object(c.lab,'preflight') as preflight:
                with self.assertRaisesRegex(ValueError,'Cambió'):c.preflight()
                preflight.assert_not_called()
