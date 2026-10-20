"""Trazabilidad sin secretos ni reintentos; conserva el transporte TLS del núcleo."""
from __future__ import annotations

import ssl
import time
from urllib.error import HTTPError, URLError
from uuid import uuid4

from auditoria.openai_provider import OpenAITransport, ProviderError


def request_id(headers):
    value=headers.get('x-request-id') if headers is not None else None
    return value if isinstance(value,str) and 0<len(value)<=512 and all(33<=ord(c)<=126 for c in value) else None


def failure_kind(exc):
    if isinstance(exc,HTTPError):return 'http'
    reason=exc.reason if isinstance(exc,URLError) else exc
    if isinstance(reason,TimeoutError):return 'timeout'
    if isinstance(reason,ssl.SSLCertVerificationError):return 'tls'
    return 'connection'


class ObservedResponse:
    def __init__(self,response,trace):self.response=response;self.trace=trace
    def __enter__(self):
        self.response.__enter__()
        self.trace['server_request_id']=request_id(getattr(self.response,'headers',None))
        return self
    def __exit__(self,*args):return self.response.__exit__(*args)
    def read(self,*args):
        try:return self.response.read(*args)
        except (URLError,OSError) as exc:
            self.trace['failure_kind']=failure_kind(exc)
            raise


class ObservedOpener:
    def __init__(self,opener,trace):self.opener=opener;self.trace=trace
    def open(self,request,*,timeout):
        request.add_header('X-Client-Request-Id',self.trace['client_request_id'])
        try:return ObservedResponse(self.opener.open(request,timeout=timeout),self.trace)
        except (URLError,OSError) as exc:
            self.trace['failure_kind']=failure_kind(exc)
            if isinstance(exc,HTTPError):self.trace['server_request_id']=request_id(exc.headers)
            raise


class TracedOpenAITransport(OpenAITransport):
    """Uso secuencial por scheduler. Solo publica campos explícitos, nunca headers/cuerpos."""
    def __init__(self,config,store):
        super().__init__(config);self.store=store;self.last_trace={}

    def post(self,endpoint,body,*,timeout):
        if endpoint not in {'responses','responses/input_tokens'}:raise ValueError('Endpoint no autorizado')
        trace={'endpoint':endpoint,'client_request_id':str(uuid4()),'timeout_seconds':timeout,'status':'started'}
        self.last_trace=trace
        self.store.event('llm','api_request_started',payload=dict(trace))
        opener=self.opener;self.opener=ObservedOpener(opener,trace);started=time.monotonic()
        try:
            value=super().post(endpoint,body,timeout=timeout)
            trace['status']='received'
            return value
        except ProviderError as exc:
            trace.update(status='failed',reason='provider_timeout' if trace.get('failure_kind')=='timeout' else exc.reason)
            if trace.get('failure_kind')=='timeout':raise ProviderError(exc.code,'provider_timeout') from None
            raise
        except Exception:
            trace.update(status='failed',reason='transport_response_invalid')
            raise
        finally:
            self.opener=opener
            trace['duration_seconds']=round(time.monotonic()-started,6)
            self.store.event('llm','api_request_finished',payload=dict(trace))
