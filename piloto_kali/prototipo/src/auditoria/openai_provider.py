"""Planificador OpenAI: Responses, decisiones acotadas y uso facturable real."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_FLOOR
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from .scheduler import PROMPT_VERSION, Scheduler
from .decisions import decision_prompt, parse_choice

REASONING_EFFORTS = {"low", "medium", "high", "xhigh", "max"}
PRICING = {
    "input_per_million": 2.0,
    "output_per_million": 10.0,
    "cached_per_million": 0.10,
    "cache_write_per_million": 2.50,
    "currency": "USD",
    "service_tier": "default",
    "source": "https://developers.openai.com/api/docs/models/gpt-6.1-sol",
    "verified_on": "2026-10-18",
}


@dataclass(frozen=True)
class OpenAIConfig:
    model: str
    api_key: str = field(repr=False)
    reasoning_effort: str = "low"
    max_output_tokens: int = 2048

    @classmethod
    def from_environment(cls):
        if os.environ.get("CENTINELA_PROTECTED_RUNTIME") == "1":
            from .secure_runtime import require_protected_runtime
            data = require_protected_runtime().get("provider", {}).get("config", {})
            if (not isinstance(data, dict) or set(data) != {"model", "reasoning_effort", "max_output_tokens"}
                    or data.get("model") != "gpt-6.1-sol"
                    or not isinstance(data.get("reasoning_effort"), str)
                    or data.get("reasoning_effort") not in REASONING_EFFORTS
                    or type(data.get("max_output_tokens")) is not int
                    or not 256 <= data["max_output_tokens"] <= 2048):
                raise ValueError("protected_provider_configuration_unavailable")
            # La llave permanece únicamente en el proceso de salida del operador.
            return cls(data["model"], "", data["reasoning_effort"], data["max_output_tokens"])
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        model = os.environ.get("OPENAI_MODEL", "").strip()
        effort = os.environ.get("OPENAI_REASONING_EFFORT", "low").strip()
        cap = int(os.environ.get("OPENAI_MAX_OUTPUT_TOKENS", "2048"))
        if not key or not model:
            raise ValueError("OPENAI_API_KEY y OPENAI_MODEL deben configurarse explícitamente")
        if model != "gpt-6.1-sol":
            raise ValueError("Este adaptador y sus tarifas se validan para gpt-6.1-sol")
        if effort not in REASONING_EFFORTS or not 256 <= cap <= 4096:
            raise ValueError("Configuración de razonamiento o límite de salida inválida")
        return cls(model, key, effort, cap)


def load_openai_config(root: Path):
    if os.environ.get("CENTINELA_PROTECTED_RUNTIME") == "1":
        return OpenAIConfig.from_environment()
    path = root / "openai.json"
    if path.exists():
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValueError("openai.json debe ser privado, con permisos 0600")
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            raise ValueError("Configuración OpenAI inválida")
        for key, env in [("api_key", "OPENAI_API_KEY"), ("model", "OPENAI_MODEL")]:
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Configuración OpenAI incompleta")
            os.environ.setdefault(env, value.strip())
        for key, env in [
            ("reasoning_effort", "OPENAI_REASONING_EFFORT"),
            ("max_output_tokens", "OPENAI_MAX_OUTPUT_TOKENS"),
        ]:
            if key in data:
                os.environ.setdefault(env, str(data[key]))
    return OpenAIConfig.from_environment()


class ProviderError(Exception):
    def __init__(self, code: int | None, reason: str):
        self.code = code
        self.reason = reason
        # No incluir el cuerpo de error, headers ni claves en mensajes o trazas.
        super().__init__(reason)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class OpenAITransport:
    def __init__(self, config: OpenAIConfig):
        if os.environ.get("CENTINELA_PROTECTED_RUNTIME") == "1":
            raise ValueError("protected_provider_requires_ipc")
        self.config = config
        # Conserva validación de CA y hostname. Nunca acepta certificados sin verificar.
        self.opener = build_opener(
            HTTPSHandler(context=ssl.create_default_context()), NoRedirects()
        )

    def post(self, endpoint: str, body: dict, *, timeout: float) -> dict:
        if endpoint not in {"responses", "responses/input_tokens"}:
            raise ValueError("Endpoint no autorizado")
        request = Request(
            "https://api.openai.com/v1/" + endpoint,
            data=json.dumps(body, ensure_ascii=False).encode(),
            headers={
                "Authorization": "Bearer " + self.config.api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                result = json.load(response)
            if not isinstance(result, dict):
                raise ProviderError(None, "provider_response_invalid")
            return result
        except HTTPError as exc:
            try:
                error = json.loads(exc.read()).get("error", {})
                code = error.get("code")
            except (ValueError, AttributeError):
                code = None
            # Solo códigos conocidos, nunca texto del proveedor que pueda repetir la clave.
            reason = (
                code
                if code
                in {
                    "invalid_api_key",
                    "insufficient_quota",
                    "model_not_found",
                    "organization_spend_limit_exceeded",
                    "project_spend_limit_exceeded",
                    "credit_balance_exhausted",
                    "organization_usage_limit_exceeded",
                    "cyber_policy",
                }
                else "provider_http_error"
            )
            raise ProviderError(exc.code, reason) from None
        except URLError as exc:
            reason = (
                "tls_certificate_untrusted"
                if isinstance(exc.reason, ssl.SSLCertVerificationError)
                else "provider_connection_failed"
            )
            raise ProviderError(None, reason) from None
        except (TimeoutError, OSError):
            raise ProviderError(None, "provider_connection_failed") from None


def valid_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def normalize_usage(response: dict) -> dict | None:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return None
    inp, out, total = (usage.get(k) for k in ["input_tokens", "output_tokens", "total_tokens"])
    inp_details, out_details = (
        usage.get("input_tokens_details") or {},
        usage.get("output_tokens_details") or {},
    )
    if not isinstance(inp_details, dict) or not isinstance(out_details, dict):
        return None
    reasoning = out_details.get("reasoning_tokens", 0)
    cached, writes = inp_details.get("cached_tokens", 0), inp_details.get("cache_write_tokens", 0)
    if not all(valid_int(v) for v in [inp, out, total, reasoning, cached, writes]):
        return None
    if total != inp + out or reasoning > out or cached + writes > inp:
        return None
    return {
        "input_tokens": inp,
        "output_tokens": out - reasoning,
        "provider_output_tokens": out,
        "thought_tokens": reasoning,
        "cached_tokens": cached,
        "cache_write_tokens": writes,
        "total_tokens": total,
    }


def estimated_cost(calls: list[dict], *, complete: bool) -> dict:
    known = 0.0
    measurable = True
    for call in calls:
        if not call.get("generation_sent"):
            continue
        if not all(
            valid_int(call.get(k))
            for k in [
                "input_tokens",
                "provider_output_tokens",
                "cached_tokens",
                "cache_write_tokens",
            ]
        ):
            measurable = False
            continue
        inp, cached, writes = (
            call["input_tokens"],
            call["cached_tokens"],
            call["cache_write_tokens"],
        )
        known += (
            (inp - cached - writes) * PRICING["input_per_million"]
            + cached * PRICING["cached_per_million"]
            + writes * PRICING["cache_write_per_million"]
            + call["provider_output_tokens"] * PRICING["output_per_million"]
        ) / 1_000_000
    return {
        "pricing": PRICING.copy(),
        "known_cost_estimate_usd": round(known, 8),
        "cost_estimate_usd": round(known, 8) if complete and measurable else None,
        "cost_note": "Estimación a tarifa estándar de gpt-6.1-sol, con caché y razonamiento; no sustituye la factura.",
    }


class OpenAIScheduler(Scheduler):
    def __init__(self, store, *, architecture: str, budget: int, deadline: float):
        self.config = OpenAIConfig.from_environment()
        if os.environ.get("CENTINELA_PROTECTED_RUNTIME") == "1":
            from .provider_proxy import ProviderProxyTransport
            self.transport = ProviderProxyTransport(self.config, store)
        else:
            self.transport = OpenAITransport(self.config)
        self.store, self.architecture, self.budget, self.deadline = (
            store,
            architecture,
            budget,
            deadline,
        )
        self.used, self.complete, self.fallbacks = 0, True, 0
        self.calls, self.aliases, self.asset_aliases = [], {}, {}
        self.provider_blocked = False
        self.max_cost_usd = 2.0

    def affordable_generation(self, inputs, requested_output):
        """Reserva conservadora antes de enviar; incluye razonamiento facturable.

        Standard/default solamente. Se cubre incluso contexto largo y el recargo
        regional del 10 %. Consumo desconocido impide más generaciones.
        """
        if not self.complete or not valid_int(inputs) or not valid_int(requested_output):
            raise RuntimeError('usage_unavailable')
        input_rate=Decimal(str(max(PRICING['input_per_million'],PRICING['cache_write_per_million'])))*Decimal('2.2')
        output_rate=Decimal(str(PRICING['output_per_million']))*Decimal('1.65')
        million=Decimal(1_000_000);spent=Decimal(0)
        for call in self.calls:
            if not call.get('generation_sent'):continue
            if not all(valid_int(call.get(k)) for k in ['input_tokens','provider_output_tokens']):
                raise RuntimeError('usage_unavailable')
            spent+=(Decimal(call['input_tokens'])*input_rate+Decimal(call['provider_output_tokens'])*output_rate)/million
        remaining=Decimal(str(self.max_cost_usd))-spent-Decimal(inputs)*input_rate/million
        affordable=max(0,int((remaining*million/output_rate).to_integral_value(rounding=ROUND_FLOOR)))
        cap=min(requested_output,affordable)
        if cap<256:raise RuntimeError('cost_budget_exhausted')
        reservation=(Decimal(inputs)*input_rate+Decimal(cap)*output_rate)/million
        return cap,float(reservation)

    def close(self):
        pass

    def summary(self):
        return {
            "provider": "openai",
            "status": "accepted" if not self.fallbacks else "fallback",
            "model": self.config.model,
            "prompt_version": PROMPT_VERSION,
            "architecture": self.architecture,
            "budget": self.budget,
            "total_tokens": self.used if self.complete else None,
            "known_tokens": self.used,
            "usage_complete": self.complete,
            "fallbacks": self.fallbacks,
            "provider_retries": 0,
            "cost_limit_usd": self.max_cost_usd,
            "cost_guard": "before_each_generation_conservative_standard_long_context_regional",
            "configuration": {
                "endpoint": "responses",
                "reasoning_effort": self.config.reasoning_effort,
                "max_output_tokens": self.config.max_output_tokens,
                "service_tier": "default",
                "store": False,
                "http_timeout_seconds": 60,
                "automatic_retries": 0,
                "output_contract": "authorized_choice_json_schema",
                "reported_models": sorted({c["response_model"] for c in self.calls if isinstance(c.get("response_model"), str)}),
                "cost_limit_usd": self.max_cost_usd,
            },
            "usage_note": "output_tokens excluye razonamiento; provider_output_tokens lo incluye. total_tokens = input_tokens + provider_output_tokens. Errores sin usage mantienen el uso desconocido y detienen nuevas generaciones.",
            "calls": self.calls,
            **estimated_cost(self.calls, complete=self.complete),
        }

    def decide(self, choices: list[str], context: dict, role: str) -> str:
        budget = getattr(self, 'detection_budget', None)
        if budget is not None:
            names = ('catalogue_size','task_limit','admitted_tasks','remaining_slots')
            public = {name:budget.get(name) for name in names} if isinstance(budget,dict) else {}
            if (not all(valid_int(public.get(name)) for name in names)
                or not public['catalogue_size'] >= public['task_limit'] >= public['admitted_tasks']
                or public['remaining_slots'] != public['task_limit']-public['admitted_tasks']):
                raise ValueError('invalid_detection_budget_context')
            context = {**context, 'detection_budget':public}
        prompt = decision_prompt(choices, context, role)
        text_format = {
            "format": {
                "type": "json_schema",
                "name": "authorized_choice",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"choice": {"type": "string", "enum": choices}},
                    "required": ["choice"],
                    "additionalProperties": False,
                },
            }
        }
        body = {"model": self.config.model, "input": prompt, "text": text_format}
        call = {
            "provider": "openai",
            "role": role,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "request_sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
            "status": "not_sent",
            "input_tokens": None,
            "output_tokens": None,
            "provider_output_tokens": None,
            "thought_tokens": None,
            "total_tokens": None,
        }
        call["prompt_ref"], _ = self.store.evidence(
            f"llm_{len(self.calls):03d}_{role}", "txt", prompt.encode()
        )
        started, sent = time.monotonic(), False
        try:
            if self.provider_blocked:
                raise RuntimeError("provider_unavailable")
            if not self.complete:
                raise RuntimeError("usage_unavailable")
            remaining = self.deadline - time.monotonic()
            if remaining < 2:
                raise RuntimeError("runtime_budget_exhausted")
            count = self.transport.post("responses/input_tokens", body, timeout=min(30, remaining))
            inputs = count.get("input_tokens")
            if not valid_int(inputs):
                raise RuntimeError("input_usage_unavailable")
            call["counted_input_tokens"] = inputs
            cap = min(self.config.max_output_tokens, self.budget - self.used - inputs)
            if cap < 256:
                raise RuntimeError("token_budget_exhausted")
            cap,reservation=self.affordable_generation(inputs,cap)
            call['cost_reservation_usd']=reservation
            remaining = self.deadline - time.monotonic()
            if remaining < 1:
                raise RuntimeError("runtime_budget_exhausted")
            call["max_output_tokens"] = cap
            call["generation_sent"], sent = True, True
            self.store.event("llm", "request_started", payload={"role": role, "provider": "openai",
                "cost_reservation_usd":reservation,"cost_limit_usd":self.max_cost_usd,
                "input_tokens_reserved":inputs,"max_output_tokens":cap})
            response = self.transport.post(
                "responses",
                {
                    **body,
                    "max_output_tokens": cap,
                    "reasoning": {"effort": self.config.reasoning_effort},
                    "store": False,
                    "service_tier": "default",
                },
                timeout=min(60, remaining),
            )
            usage = normalize_usage(response)
            if usage:
                call.update(usage)
                self.used += usage["total_tokens"]
            else:
                self.complete = False
                raise RuntimeError("usage_unavailable")
            call["response_id"] = response.get("id")
            call["response_model"] = response.get("model") if isinstance(response.get("model"), str) else None
            call["response_status"] = response.get("status")
            call["service_tier"] = response.get("service_tier")
            if self.used > self.budget:
                self.provider_blocked = True
                raise RuntimeError("reported_budget_exceeded")
            if response.get("status") != "completed":
                raise RuntimeError("response_incomplete")
            if any(
                item.get("type") == "refusal"
                for message in response.get("output", [])
                if message.get("type") == "message"
                for item in message.get("content", [])
            ):
                raise ProviderError(None, "provider_refusal")
            output = "".join(
                item.get("text", "")
                for message in response.get("output", [])
                if message.get("type") == "message"
                for item in message.get("content", [])
                if item.get("type") == "output_text"
            )
            choice = parse_choice(output, choices)
            call.update(status="accepted", choice=choice)
            return choice
        except (ProviderError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            if sent and call["total_tokens"] is None:
                self.complete = False
            self.fallbacks += 1
            if isinstance(exc, ProviderError):
                reason = exc.reason
                self.provider_blocked = True
            else:
                reason = str(exc) if isinstance(exc, RuntimeError) else "provider_response_invalid"
            call.update(
                status="fallback", reason=reason, provider_http_status=getattr(exc, "code", None)
            )
            return choices[0]
        finally:
            call["duration_seconds"] = round(time.monotonic() - started, 6)
            self.calls.append(call)
            self.store.event("llm", "decision", payload=call)
