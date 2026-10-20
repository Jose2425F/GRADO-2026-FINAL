import json
import time

import pytest

from auditoria.openai_provider import (
    OpenAIConfig,
    OpenAIScheduler,
    ProviderError,
    load_openai_config,
    normalize_usage,
)


class Store:
    def evidence(self, task_id, extension, data):
        assert b"private-key" not in data
        return "evidence/" + task_id + ".txt", ""

    def event(self, *args, **kwargs):
        assert "private-key" not in json.dumps(kwargs)


def response(*, choice="b", status="completed", usage=True):
    return {
        "status": status,
        "id": "response-test",
        "model": "gpt-6.1-sol-tested-snapshot",
        "service_tier": "default",
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps({"choice": choice})}],
            }
        ],
        "usage": {
            "input_tokens": 1000,
            "input_tokens_details": {"cached_tokens": 200, "cache_write_tokens": 100},
            "output_tokens": 100,
            "output_tokens_details": {"reasoning_tokens": 80},
            "total_tokens": 1100,
        }
        if usage
        else None,
    }


def scheduler(monkeypatch, answer, *, budget=4000, inputs=1000):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-6.1-sol")
    monkeypatch.setenv("OPENAI_API_KEY", "private-key")
    s = OpenAIScheduler(
        Store(), architecture="single", budget=budget, deadline=time.monotonic() + 60
    )
    calls = []

    def post(endpoint, body, **kwargs):
        calls.append((endpoint, body))
        if endpoint.endswith("input_tokens"):
            return {"input_tokens": inputs}
        if isinstance(answer, Exception):
            raise answer
        return answer

    s.transport.post = post
    return s, calls


def test_reasoning_counted_once_and_cache_writes_priced(monkeypatch):
    s, calls = scheduler(monkeypatch, response())
    assert s.decide(["a", "b"], {}, "single_agent") == "b"
    summary = s.summary()
    assert summary["total_tokens"] == 1100
    assert summary["calls"][0]["response_model"] == "gpt-6.1-sol-tested-snapshot"
    assert summary["configuration"]["reported_models"] == ["gpt-6.1-sol-tested-snapshot"]
    assert summary["calls"][0]["output_tokens"] == 20
    assert summary["calls"][0]["thought_tokens"] == 80
    assert summary["cost_estimate_usd"] == pytest.approx(
        (700 * 2 + 200 * 0.1 + 100 * 2.5 + 100 * 10) / 1e6
    )
    assert calls[1][1]["store"] is False
    assert calls[1][1]["service_tier"] == "default"
    assert "temperature" not in calls[1][1]
    assert calls[0][1]["text"] == calls[1][1]["text"]
    assert calls[1][1]["text"]["format"]["schema"]["properties"]["choice"]["enum"] == ["a", "b"]
    assert "private-key" not in json.dumps(summary)


def test_insufficient_budget_prevents_generation(monkeypatch):
    s, calls = scheduler(monkeypatch, response(), budget=1200)
    assert s.decide(["a", "b"], {}, "single_agent") == "a"
    assert len(calls) == 1 and calls[0][0] == "responses/input_tokens"
    assert s.summary()["cost_estimate_usd"] == 0
    assert s.summary()["status"] == "fallback"


def test_rejected_choice_keeps_usage_and_excludes_formal_ai(monkeypatch):
    s, _ = scheduler(monkeypatch, response(choice="unauthorized"))
    assert s.decide(["a", "b"], {}, "single_agent") == "a"
    assert s.summary()["status"] == "fallback"
    assert s.summary()["total_tokens"] == 1100


def test_unknown_generation_does_not_retry_or_spend_again(monkeypatch):
    s, calls = scheduler(monkeypatch, ProviderError(429, "insufficient_quota"))
    s.decide(["a", "b"], {}, "single_agent")
    s.decide(["a", "b"], {}, "single_agent")
    assert len(calls) == 2
    assert s.summary()["usage_complete"] is False
    assert s.summary()["cost_estimate_usd"] is None
    assert s.calls[0]["provider_http_status"] == 429


def test_incomplete_response_records_billable_reasoning(monkeypatch):
    s, _ = scheduler(monkeypatch, response(status="incomplete"))
    s.decide(["a", "b"], {}, "single_agent")
    assert s.calls[0]["reason"] == "response_incomplete"
    assert s.summary()["total_tokens"] == 1100
    assert s.summary()["cost_estimate_usd"] > 0


def test_invalid_usage_is_not_certified():
    value = response()
    value["usage"]["total_tokens"] = 1101
    assert normalize_usage(value) is None
    value = response()
    value["usage"]["input_tokens_details"]["cache_write_tokens"] = 900
    assert normalize_usage(value) is None


def test_private_config_and_model_gate(tmp_path, monkeypatch):
    path = tmp_path / "openai.json"
    path.write_text(json.dumps({"api_key": "private-key", "model": "gpt-6.1-sol"}))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        load_openai_config(tmp_path)
    path.chmod(0o600)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert load_openai_config(tmp_path).model == "gpt-6.1-sol"
    assert "private-key" not in repr(OpenAIConfig.from_environment())
    monkeypatch.setenv("OPENAI_REASONING_EFFORT", "none")
    with pytest.raises(ValueError):
        OpenAIConfig.from_environment()


def test_openai_is_identified_in_the_experimental_context(tmp_path):
    from auditoria.laboratorio import request_for_lab
    from auditoria.metrics import comparison_context
    from auditoria.store import write_json

    request = request_for_lab("test", openai=True)
    write_json(tmp_path / "request.json", request.model_dump(mode="json"))
    write_json(tmp_path / "manifest.json", {"policy_sha256":"same-policy","tools":{},"lab":{}})
    context = comparison_context(tmp_path)
    assert context["llm_provider"] == "openai"
    assert request.llm_mode == "scheduler"
    assert request.token_budget > 0


def test_http_error_never_exposes_the_provider_error_body():
    from io import BytesIO
    from urllib.error import HTTPError
    from auditoria.openai_provider import OpenAITransport

    transport = OpenAITransport(OpenAIConfig("gpt-6.1-sol", "private-key"))

    def fail(*args, **kwargs):
        raise HTTPError(
            "https://api.openai.com/v1/responses",
            401,
            "Unauthorized",
            {},
            BytesIO(b'{"error":{"code":"invalid_api_key","message":"private-key"}}'),
        )

    transport.opener.open = fail
    with pytest.raises(ProviderError) as caught:
        transport.post("responses", {}, timeout=1)
    assert caught.value.code == 401
    assert str(caught.value) == "invalid_api_key"
    assert "private-key" not in str(caught.value)


def test_refusal_records_usage_and_stops_provider_generations(monkeypatch):
    value = response()
    value["output"][0]["content"] = [{"type": "refusal", "refusal": "private-key"}]
    s, calls = scheduler(monkeypatch, value)
    assert s.decide(["a", "b"], {}, "single_agent") == "a"
    assert s.calls[0]["reason"] == "provider_refusal"
    assert s.summary()["total_tokens"] == 1100
    s.decide(["a", "b"], {}, "single_agent")
    assert len(calls) == 2
    assert "private-key" not in json.dumps(s.summary())


def test_cyber_policy_block_is_not_a_vulnerability_result_or_retried(monkeypatch):
    s, calls = scheduler(monkeypatch, ProviderError(403, "cyber_policy"))
    s.decide(["a", "b"], {}, "single_agent")
    s.decide(["a", "b"], {}, "single_agent")
    assert len(calls) == 2
    assert s.calls[0]["reason"] == "cyber_policy"
    assert s.summary()["status"] == "fallback"
    assert s.summary()["usage_complete"] is False


def test_authorized_choice_with_script_is_not_accepted(monkeypatch):
    value = response()
    value["output"][0]["content"][0]["text"] = '{"choice":"b","script":"print(1)"}'
    s, _ = scheduler(monkeypatch, value)
    assert s.decide(["a", "b"], {}, "single_agent") == "a"
    assert s.calls[0]["status"] == "fallback"
    assert s.summary()["total_tokens"] == 1100
