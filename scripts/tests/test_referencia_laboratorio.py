import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from referencia_laboratorio import save_reference,load_reference,list_references,evaluate_reference
from dualstack_panel import Panel,make_server,validate_options
from aplicaciones_personales import ApplicationTask,execute_application,adjudicate_application
from auditoria.contracts import Target
from auditoria.store import RunStore
from scripts.tests.authorization_fixture import personal_authorization, scope_options
from scripts.tests.test_aplicaciones_personales import server_pair,app_config,net_config,SESSION


class ReferenceTests(unittest.TestCase):
    def case(self,**extra):return {'address':'192.168.56.20','port':8080,'condition':'object_authorization','expected':'present',**extra}
    def test_registry_is_private_versioned_bounded_and_rejects_public_or_invalid_cases(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'refs';first=save_reference({'name':'Laboratorio A','cases':[self.case()]},root)
            second=save_reference({'name':'Laboratorio A','cases':[self.case(expected='absent')]},root)
            self.assertNotEqual(first['id'],second['id']);self.assertNotEqual(first['sha256'],second['sha256'])
            self.assertEqual((root/(first['id']+'.json')).stat().st_mode & 0o777,0o600)
            self.assertEqual(len(list_references(root)),2);self.assertNotIn('address',json.dumps(list_references(root)))
            self.assertEqual(load_reference(first['id'],root)[0]['cases'][0]['expected'],'present')
            for case in [self.case(address='8.8.8.8'),self.case(address='192.168.56.0/24'),self.case(condition=[]),self.case(expected='unknown'),self.case(port=True)]:
                with self.assertRaises(ValueError):save_reference({'name':'Bad','cases':[case]},root)
            with self.assertRaises(ValueError):save_reference({'name':'Duplicado','cases':[self.case(),self.case()]},root)
            with self.assertRaises(ValueError):load_reference('../openai',root)
            with self.assertRaises(ValueError):save_reference({'name':'Exceso','cases':[self.case()]*129},root)

    def test_reference_endpoint_requires_csrf_and_never_adds_labels_to_audit_options(self):
        with tempfile.TemporaryDirectory() as td,patch('referencia_laboratorio.ROOT',Path(td)/'private'),patch('laboratorio_suite.activity',return_value={}),patch('aceptar_laboratorios.public_status',return_value={}):
            panel=Panel(Path(td)/'runs');server=make_server(panel,0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url=f'http://127.0.0.1:{server.server_port}'
            def send(csrf):
                body=json.dumps({'name':'Verdad independiente','cases':[self.case()]}).encode()
                return urlopen(Request(url+'/api/evaluation-reference',data=body,headers={'Content-Type':'application/json','Origin':url,'X-CSRF-Token':csrf}),timeout=5)
            try:
                with self.assertRaises(HTTPError) as denied:send('wrong')
                self.assertEqual(denied.exception.code,403);denied.exception.close()
                with send(panel.csrf) as response:value=json.load(response)
                self.assertEqual(value['reference']['cases'],1)
                state=panel.state();self.assertEqual(len(state['evaluation_references']),1)
                self.assertNotIn('object_authorization',json.dumps(state['evaluation_references']))
                self.assertEqual(panel.operations.snapshot()['jobs'],[])
                with self.assertRaises(ValueError):validate_options({'name':'A','authorization':'LAB','evaluation_reference':value['reference']['id']})
            finally:server.shutdown();server.server_close();thread.join()

    def test_offline_readjudication_counts_cases_and_never_trusts_edited_findings(self):
        with server_pair() as (port,_),tempfile.TemporaryDirectory() as td:
            root=Path(td);app=app_config(port);config=net_config(port)
            task=ApplicationTask(task_id='web',target=Target(asset_id='app',address='127.0.0.1',interface='lo',ports=[port]),application_index=0)
            store=RunStore(root/'run','reference-test')
            try:
                with personal_authorization(scope_options(config,applications=[app])) as authorization,patch('aplicaciones_personales.load_session',return_value={'Authorization':'Bearer '+SESSION}):result=execute_application(task,app,store,time.monotonic()+60,authorization=authorization)
            finally:store.close()
            plan=[task.model_dump(mode='json')];request={'bank':'personal','personal':config,'applications':[app]};report={'tasks':[result.model_dump(mode='json')],'findings':[{'state':'verified','condition':'ssh_default_credential','address':'127.0.0.1'}]}
            original=copy.deepcopy(request);cases=[]
            for address in ['127.0.0.1','::1']:
                for condition in ['object_authorization','file_boundary']:cases.append(self.case(address=address,port=port,condition=condition))
            cases.extend([self.case(address='::1',port=port,condition='ipv6_authorization_gap'),self.case(address='127.0.0.1',port=port,condition='ipv6_authorization_gap',expected='absent')])
            meta=save_reference({'name':'Referencia controlada','cases':cases},root/'refs');record,_=load_reference(meta['id'],root/'refs')
            with patch('aplicaciones_personales.fetch') as network:
                value=evaluate_reference(root/'run',request,plan,report,record,meta);network.assert_not_called()
            self.assertEqual((value['TP'],value['FP'],value['FN'],value['TN']),(5,0,0,1));self.assertEqual(request,original)
            self.assertEqual(value['unscored_findings'],0)
            (root/'run'/result.evidence_ref).write_text('{}')
            value=evaluate_reference(root/'run',request,plan,report,record,meta)
            self.assertFalse(value['evidence_valid']);self.assertEqual(value['TP'],0);self.assertEqual(value['FN'],5);self.assertEqual(value['TN'],0);self.assertEqual(value['unknown_negative_controls'],1)
            bad={**record,'cases':[self.case(address='192.168.56.99',port=port)]}
            with self.assertRaises(ValueError):evaluate_reference(root/'run',request,plan,report,bad,meta)
            with self.assertRaises(ValueError):evaluate_reference(root/'run',{**request,'bank':'v2'},plan,report,record,meta)
