"""Canal y cuotas del proveedor con HTTP simulado; ninguna llamada API real."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

import pytest

from auditoria import provider_proxy as proxy
from auditoria.tool_worker import WorkerDenied


SECRET = {"api_key": "sk-private-test-never-log-0123456789", "model": proxy.MODEL}


def policy(budget=4096):
    return {"expires_at": time.time() + 300, "limits": proxy.limits_for(budget),
            "config": proxy.public_config(SECRET), "controller_uid": 65531, "controller_gid": 65531,
            "controller_pid": os.getpid(), "controller_start_time": "123",
            "controller_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


def request(endpoint="responses/input_tokens", **changes):
    body = {"model": proxy.MODEL, "input": "Datos sintéticos", "text": {"format": {"type": "json_schema"}}}
    if endpoint == "responses":
        body.update(max_output_tokens=256, reasoning={"effort": "low"}, store=False, service_tier="default")
    body.update(changes)
    return {"endpoint": endpoint, "body": body, "timeout": 10}


class Transport:
    def __init__(self): self.calls = []
    def post(self, endpoint, body, timeout):
        self.calls.append((endpoint, body, timeout))
        if endpoint == "responses/input_tokens": return {"input_tokens": 50}, "req-safe"
        return {"status": "completed", "usage": {"input_tokens": 50, "output_tokens": 10, "total_tokens": 60},
                "output": []}, "req-safe"


def test_quote_is_bound_to_exact_prompt_and_generation_is_not_replayed():
    transport = Transport(); session = proxy.ProviderSession(policy(), transport)
    session.process(request())
    with pytest.raises(proxy.ProxyDenied, match="quote_required"):
        session.process(request("responses", input="Otro prompt"))
    response = session.process(request("responses"))
    assert response["response"]["status"] == "completed"
    assert session.known_tokens == session.used_tokens == 60
    with pytest.raises(proxy.ProxyDenied, match="quote_required"):
        session.process(request("responses"))
    assert len(transport.calls) == 2


@pytest.mark.parametrize("change", [
    {"endpoint": "https://other.invalid/responses"}, {"endpoint": "files"},
    {"endpoint": ["responses"]}, {"timeout": 61}, {"timeout": True}, {"timeout": float("inf")},
    {"extra": "Authorization"},
])
def test_request_contract_denies_before_https(change):
    transport = Transport(); session = proxy.ProviderSession(policy(), transport)
    message = {**request(), **change}
    with pytest.raises(proxy.ProxyDenied): session.process(message)
    assert transport.calls == []


@pytest.mark.parametrize("change", [
    {"model": "arbitrary-model"}, {"input": [{"image_url": "https://other.invalid"}]},
    {"tools": [{"type": "web_search"}]}, {"max_output_tokens": 2049},
    {"store": True}, {"service_tier": "priority"}, {"reasoning": {"effort": "max"}},
])
def test_generation_has_no_user_tools_urls_or_unbounded_output(change):
    transport = Transport(); session = proxy.ProviderSession(policy(), transport)
    session.process(request())
    with pytest.raises(proxy.ProxyDenied): session.process(request("responses", **change))
    assert len(transport.calls) == 1


def test_payload_request_count_and_expiry_are_bounded():
    transport = Transport(); p = policy(); p["limits"]["max_requests"] = 1
    session = proxy.ProviderSession(p, transport); session.process(request())
    with pytest.raises(proxy.ProxyDenied, match="request_quota"): session.process(request())
    p = policy(); p["limits"]["max_request_bytes"] = 1024
    with pytest.raises(proxy.ProxyDenied, match="message_limit"):
        proxy.ProviderSession(p, transport).process(request(input="x" * 1025))
    p["expires_at"] = time.time() - 1
    with pytest.raises(proxy.ProxyDenied, match="session_closed"):
        proxy.ProviderSession(p, transport).process(request())


def test_token_reservation_is_atomic_while_https_requests_overlap():
    entered, release = threading.Event(), threading.Event()
    class Blocked(Transport):
        def post(self, endpoint, body, timeout):
            if endpoint == "responses":
                entered.set(); assert release.wait(2)
            return super().post(endpoint, body, timeout)
    transport = Blocked(); session = proxy.ProviderSession(policy(512), transport)
    session.process(request()); session.process(request())
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(session.process, request("responses")); assert entered.wait(2)
        try:
            with pytest.raises(proxy.ProxyDenied, match="token_or_cost_quota"):
                session.process(request("responses"))
        finally: release.set()
        first.result(timeout=2)
    assert session.generations == 1 and session.known_tokens == 60


def test_two_generations_can_run_concurrently_with_separate_quotes():
    barrier = threading.Barrier(2)
    class Concurrent(Transport):
        def post(self, endpoint, body, timeout):
            if endpoint == "responses": barrier.wait(timeout=2)
            return super().post(endpoint, body, timeout)
    session = proxy.ProviderSession(policy(), Concurrent())
    session.process(request()); session.process(request())
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(session.process, request("responses")) for _ in range(2)]
        assert all(f.result(timeout=3)["response"]["status"] == "completed" for f in futures)
    assert session.generations == 2 and session.known_tokens == session.used_tokens == 120


@pytest.mark.parametrize("usage", [{}, {"input_tokens": 51, "output_tokens": 10, "total_tokens": 61},
    {"input_tokens": 50, "output_tokens": 257, "total_tokens": 307}])
def test_lost_or_excess_usage_closes_session_without_retry(usage):
    class Unknown(Transport):
        def post(self, endpoint, body, timeout):
            if endpoint == "responses": return {"usage": usage}, None
            return super().post(endpoint, body, timeout)
    transport = Unknown(); session = proxy.ProviderSession(policy(), transport)
    session.process(request())
    with pytest.raises(proxy.ProxyDenied, match="provider_request_failed"): session.process(request("responses"))
    assert session.used_tokens == 306 and session.blocked
    with pytest.raises(proxy.ProxyDenied, match="session_closed"): session.process(request())


def test_upstream_exception_never_exposes_secret_body_or_traceback():
    class Broken(Transport):
        def post(self, *args, **kwargs): raise RuntimeError(SECRET["api_key"])
    events = []
    with pytest.raises(proxy.ProxyDenied) as error:
        proxy.ProviderSession(policy(), Broken()).process(request(), lambda event, **fields: events.append((event, fields)))
    assert SECRET["api_key"] not in str(error.value) + json.dumps(events)


def test_https_destination_tls_and_error_redaction(monkeypatch):
    calls = []
    class Response:
        status = 200
        def read(self, size): return b'{"input_tokens":50}'
        def getheader(self, name): return "req-safe"
    class Connection:
        def __init__(self, host, port, **kwargs):
            assert host == "api.openai.com" and port == 443
            assert isinstance(kwargs["context"], ssl.SSLContext)
            assert kwargs["context"].check_hostname and kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        def request(self, method, path, **kwargs): calls.append((method, path, kwargs))
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.invalid")
    monkeypatch.setattr(proxy.http.client, "HTTPSConnection", Connection)
    transport = proxy.FixedOpenAIHTTPS(SECRET)
    assert transport.post("responses/input_tokens", request()["body"], 10)[0] == {"input_tokens": 50}
    assert calls[0][0:2] == ("POST", "/v1/responses/input_tokens")
    assert calls[0][2]["headers"]["Authorization"] == "Bearer " + SECRET["api_key"]
    Response.status = 302
    with pytest.raises(proxy.ProxyDenied, match="http_error"): transport.post("responses", {}, 10)
    Response.status = 401
    with pytest.raises(proxy.ProxyDenied, match="authentication_failed"): transport.post("responses", {}, 10)


def test_http_child_deadline_really_terminates_process_without_network(monkeypatch):
    original = proxy.subprocess.Popen
    spawned = []
    def harmless_child(command, **kwargs):
        assert command[:3] == [proxy.sys.executable, "-I", "-B"]
        assert kwargs["close_fds"] is True
        assert all(SECRET["api_key"] not in str(value) for value in [command, kwargs])
        child = original([proxy.sys.executable, "-I", "-B", "-c", "import time;time.sleep(10)"], **kwargs)
        spawned.append(child)
        return child
    monkeypatch.setattr(proxy.subprocess, "Popen", harmless_child)
    started = time.monotonic()
    with pytest.raises(proxy.ProxyDenied, match="request_timeout"):
        proxy.BoundedOpenAIHTTPS(SECRET).post("responses/input_tokens", request()["body"], .2)
    assert time.monotonic() - started < 3
    assert len(spawned) == 1 and spawned[0].poll() is not None


def test_provider_policy_pins_role_boot_identity_limits_and_has_no_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy, "_protected_path", lambda path: Path(path))
    value = {**policy(), "version": 1, "role": "provider", "worker_uid": proxy.PROVIDER_UID,
             "worker_gid": proxy.PROVIDER_UID, "proxy_netns": 123}
    path = tmp_path / "provider-policy.json"
    path.write_text(json.dumps(value))
    assert proxy.load_policy(path) == value
    assert SECRET["api_key"] not in path.read_text()
    for change in [{"version": True}, {"worker_uid": 65531}, {"worker_gid": 65531},
                   {"controller_boot_id": "other-boot"}, {"controller_start_time": 123},
                   {"expires_at": float("inf")}, {"secret": SECRET["api_key"]}]:
        path.write_text(json.dumps({**value, **change}))
        with pytest.raises(proxy.ProxyDenied): proxy.load_policy(path)


def test_oversized_framing_is_rejected_before_body_read():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", proxy.MAX_REQUEST + 1))
        with pytest.raises(proxy.ProxyDenied, match="message_limit"): proxy.receive(right, proxy.MAX_REQUEST)


@pytest.mark.parametrize("payload", [b'{"v":NaN}', b'{"v":Infinity}', b'{"v":-Infinity}',
    b'{"v":1,"v":2}', b'{"outer":{"v":1,"v":2}}'])
def test_ipc_nonfinite_constants_and_duplicate_keys_are_rejected(payload):
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", len(payload)) + payload)
        with pytest.raises(proxy.ProxyDenied, match="message_invalid"):
            proxy.receive(right, proxy.MAX_REQUEST)


def test_ipc_depth_checked_before_decoder_and_valid_next_message_survives(monkeypatch):
    payload = b'{"v":' + b'[' * 64 + b'0' + b']' * 64 + b'}'
    original = proxy.json.loads
    def must_not_decode(*args, **kwargs):raise AssertionError("decoder must not receive deep input")
    monkeypatch.setattr(proxy.json, "loads", must_not_decode)
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", len(payload)) + payload)
        with pytest.raises(proxy.ProxyDenied, match="depth_limit"):
            proxy.receive(right, proxy.MAX_REQUEST)
        monkeypatch.setattr(proxy.json, "loads", original)
        value = {"escaped": '\\"' + '[]{}' * 80, "valid": {"v": 1}}
        proxy.send(left, value)
        assert proxy.receive(right, proxy.MAX_REQUEST) == value


def test_actual_unix_peer_with_wrong_uid_is_denied_before_reading_prompt():
    left, right = socket.socketpair(); session = proxy.ProviderSession(policy(), Transport())
    with left, right:
        with pytest.raises(WorkerDenied): proxy.connection_request(policy(), session, right, lambda *a, **k: None)
    assert session.calls == 0


def test_peer_revalidated_after_prompt_before_upstream(monkeypatch):
    left, right = socket.socketpair(); calls = []
    def authorize(*args):
        calls.append(args)
        if len(calls) == 2: raise WorkerDenied("controller_identity_invalid")
    monkeypatch.setattr(proxy, "_peer_allowed", authorize)
    session = proxy.ProviderSession(policy(), Transport())
    with left, right:
        proxy.send(left, request())
        with pytest.raises(WorkerDenied): proxy.connection_request(policy(), session, right, lambda *a, **k: None)
    assert len(calls) == 2 and session.calls == 0


def test_protected_config_ignores_environment_key_and_private_file(monkeypatch, tmp_path):
    from auditoria import openai_provider, secure_runtime
    monkeypatch.setenv("CENTINELA_PROTECTED_RUNTIME", "1")
    monkeypatch.setenv("OPENAI_API_KEY", SECRET["api_key"])
    monkeypatch.setattr(secure_runtime, "require_protected_runtime", lambda: {"provider": {"config": proxy.public_config(SECRET)}})
    (tmp_path / "openai.json").write_text("This must never be parsed")
    config = openai_provider.load_openai_config(tmp_path)
    assert config.api_key == "" and config.model == proxy.MODEL
    with pytest.raises(ValueError, match="requires_ipc"): openai_provider.OpenAITransport(config)
    monkeypatch.setattr(secure_runtime, "require_protected_runtime", lambda: {})
    with pytest.raises(ValueError, match="unavailable"): openai_provider.load_openai_config(tmp_path)


def test_protected_scheduler_and_expert_keep_ipc_transport(monkeypatch):
    from auditoria import openai_provider, secure_runtime
    from llm_especialistas import ExpertScheduler
    monkeypatch.setenv("CENTINELA_PROTECTED_RUNTIME", "1")
    monkeypatch.setattr(secure_runtime, "require_protected_runtime", lambda: {"provider": {"config": proxy.public_config(SECRET)}})
    for kind in [openai_provider.OpenAIScheduler, ExpertScheduler]:
        value = kind(None, architecture="multiagent", budget=6000, deadline=time.monotonic() + 60)
        assert isinstance(value.transport, proxy.ProviderProxyTransport) and value.config.api_key == ""


def test_trace_is_not_shared_between_threads():
    transport = proxy.ProviderProxyTransport(None); transport.last_trace = {"main": True}
    def worker():
        assert transport.last_trace == {}
        transport.last_trace = {"worker": True}
        return transport.last_trace
    with ThreadPoolExecutor(1) as pool: assert pool.submit(worker).result() == {"worker": True}
    assert transport.last_trace == {"main": True}
