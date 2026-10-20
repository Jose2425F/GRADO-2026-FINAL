"""Transporte simulado: IDs, timeout de conexión/lectura y cero reintentos o secretos."""
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.transporte_api import TracedOpenAITransport, request_id
from auditoria.openai_provider import ProviderError


class Response(io.BytesIO):
    headers={'x-request-id':'req_test'}


class TimeoutResponse(Response):
    def read(self,*args):raise TimeoutError('SECRET-BODY')


class TransportTests(unittest.TestCase):
    def transport(self,response=None,error=None):
        self.events=[]
        store=SimpleNamespace(event=lambda actor,name,*,payload:self.events.append((name,payload)))
        transport=TracedOpenAITransport(SimpleNamespace(api_key='SECRET-KEY'),store)
        transport.opener=Mock()
        transport.opener.open.side_effect=error
        transport.opener.open.return_value=response or Response(b'{"ok":true}')
        return transport,transport.opener

    def test_success_has_unique_client_id_and_safe_server_id_without_payload(self):
        transport,opener=self.transport()
        self.assertEqual(transport.post('responses',{'input':'SECRET-PROMPT'},timeout=60),{'ok':True})
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_header('X-client-request-id'),transport.last_trace['client_request_id'])
        self.assertEqual(transport.last_trace['server_request_id'],'req_test')
        self.assertEqual(transport.last_trace['status'],'received')
        self.assertEqual(opener.open.call_count,1)
        self.assertNotIn('SECRET',json.dumps(self.events))
        self.assertIs(transport.opener,opener)

    def test_timeouts_in_connection_and_body_are_identified_without_retries(self):
        for response,error in [(None,URLError(TimeoutError('SECRET'))),(TimeoutResponse(b'{}'),None)]:
            transport,opener=self.transport(response,error)
            with self.assertRaises(ProviderError) as failure:transport.post('responses',{},timeout=60)
            self.assertEqual(failure.exception.reason,'provider_timeout')
            self.assertEqual(opener.open.call_count,1)
            self.assertEqual(transport.last_trace['failure_kind'],'timeout')
            self.assertIs(transport.opener,opener)
            self.assertNotIn('SECRET',json.dumps(self.events))

    def test_http_failure_retains_core_reason_and_request_id_without_error_body(self):
        error=HTTPError('https://api.openai.com/v1/responses',429,'SECRET',{'x-request-id':'req_http'},io.BytesIO(b'{"error":{"code":"insufficient_quota","message":"SECRET"}}'))
        transport,opener=self.transport(error=error)
        with self.assertRaises(ProviderError) as failure:transport.post('responses',{},timeout=60)
        self.assertEqual(failure.exception.reason,'insufficient_quota')
        self.assertEqual(transport.last_trace['server_request_id'],'req_http')
        self.assertEqual(opener.open.call_count,1)
        self.assertNotIn('SECRET',json.dumps(self.events))

    def test_unknown_network_failure_is_not_falsely_classified_as_timeout(self):
        transport,opener=self.transport(error=URLError('SECRET'))
        with self.assertRaises(ProviderError) as failure:transport.post('responses',{},timeout=60)
        self.assertEqual(failure.exception.reason,'provider_connection_failed')
        self.assertEqual(opener.open.call_count,1)
        for unsafe in ['bad\nheader','x'*513,'é']:
            self.assertIsNone(request_id({'x-request-id':unsafe}))
        with self.assertRaises(ValueError):transport.post('unauthorized',{},timeout=60)
        self.assertEqual(opener.open.call_count,1)
