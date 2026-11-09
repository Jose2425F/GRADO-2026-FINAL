"""Salida OpenAI por un proceso distinto; el controlador no recibe la llave.

El operador prepara política, socket y descriptores. El servidor sólo acepta
el proceso fijado de la corrida y los dos POST usados por los planificadores.
No recibe destinos, cabeceras, archivos, comandos ni credenciales del cliente.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from .tool_worker import identity, unprivileged, _audit_log, _endpoint, _peer_allowed, _protected_path

PROVIDER_UID = 65530
MODEL = "gpt-6.1-sol"
MAX_REQUEST = 1_000_000
MAX_RESPONSE = 2_000_000
MAX_REQUESTS = 128
ENDPOINTS = {"responses/input_tokens", "responses"}
EFFORTS = {"low", "medium", "high", "xhigh", "max"}


class ProxyDenied(RuntimeError):
    """Sólo códigos constantes; nunca cuerpos o mensajes del proveedor."""


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def public_config(secret):
    if (not isinstance(secret, dict) or set(secret) - {"api_key", "model", "reasoning_effort", "max_output_tokens"}
            or not isinstance(secret.get("api_key"), str)
            or not re.fullmatch(r"[!-~]{20,512}", secret["api_key"])
            or secret.get("model") != MODEL
            or not isinstance(secret.get("reasoning_effort", "low"), str)
            or secret.get("reasoning_effort", "low") not in EFFORTS
            or not _integer(secret.get("max_output_tokens", 2048), 256, 2048)):
        raise ProxyDenied("provider_configuration_invalid")
    return {"model": MODEL, "reasoning_effort": secret.get("reasoning_effort", "low"),
            "max_output_tokens": secret.get("max_output_tokens", 2048)}


def limits_for(budget):
    if not _integer(budget, 256, 60_000):
        raise ProxyDenied("provider_budget_invalid")
    return {"token_budget": budget, "max_requests": MAX_REQUESTS, "max_request_bytes": MAX_REQUEST,
            "max_response_bytes": MAX_RESPONSE, "request_timeout_seconds": 60,
            "max_cost_usd": 2.0}


def _validate_limits(value):
    if (not isinstance(value, dict) or set(value) != set(limits_for(256))
            or not _integer(value.get("token_budget"), 256, 60_000)
            or not _integer(value.get("max_requests"), 1, MAX_REQUESTS)
            or not _integer(value.get("max_request_bytes"), 1024, MAX_REQUEST)
            or not _integer(value.get("max_response_bytes"), 1024, MAX_RESPONSE)
            or not _integer(value.get("request_timeout_seconds"), 1, 60)
            or isinstance(value.get("max_cost_usd"), bool)
            or not isinstance(value.get("max_cost_usd"), (int, float))
            or not math.isfinite(value["max_cost_usd"]) or not 0 < value["max_cost_usd"] <= 2):
        raise ProxyDenied("provider_limits_invalid")


def _raw(value):
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise ProxyDenied("provider_message_invalid") from None


def _json_loads(raw):
    # Limita la profundidad antes del decodificador C. Los corchetes dentro
    # de cadenas y sus escapes no cuentan como estructura JSON.
    data = raw.encode() if isinstance(raw, str) else raw
    depth = 0
    quoted = escaped = False
    for character in data:
        if quoted:
            if escaped:escaped = False
            elif character == 92:escaped = True
            elif character == 34:quoted = False
        elif character == 34:quoted = True
        elif character in (91, 123):
            depth += 1
            if depth > 64:raise ProxyDenied("provider_message_depth_limit")
        elif character in (93, 125):
            depth -= 1
            if depth < 0:raise ProxyDenied("provider_message_invalid")
    def constant(_value):
        raise ProxyDenied("provider_message_invalid")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:raise ProxyDenied("provider_message_invalid")
            result[key] = value
        return result
    try:
        return json.loads(data, parse_constant=constant, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise ProxyDenied("provider_message_invalid") from None


def _exact(connection, size):
    chunks = []
    while size:
        part = connection.recv(min(size, 65536))
        if not part:
            raise ProxyDenied("provider_message_incomplete")
        size -= len(part); chunks.append(part)
    return b"".join(chunks)


def receive(connection, maximum):
    size = struct.unpack("!I", _exact(connection, 4))[0]
    if not 0 < size <= maximum:
        raise ProxyDenied("provider_message_limit")
    value = _json_loads(_exact(connection, size))
    if not isinstance(value, dict):
        raise ProxyDenied("provider_message_invalid")
    return value


def send(connection, value, maximum=MAX_RESPONSE):
    raw = _raw(value)
    if len(raw) > maximum:
        raise ProxyDenied("provider_message_limit")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def load_policy(path):
    path = _protected_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
        raise ProxyDenied("provider_policy_invalid")
    data = _json_loads(path.read_bytes())
    required = {"version", "role", "worker_uid", "worker_gid", "controller_uid", "controller_gid",
                "controller_pid", "controller_start_time", "controller_boot_id", "proxy_netns",
                "expires_at", "config", "limits"}
    if (not isinstance(data, dict) or set(data) != required or type(data.get("version")) is not int or data["version"] != 1
            or data.get("role") != "provider" or data.get("worker_uid") != PROVIDER_UID
            or data.get("worker_gid") != PROVIDER_UID
            or data.get("controller_uid") != 65531 or data.get("controller_gid") != 65531
            or not _integer(data.get("controller_pid"), 1, 2**31 - 1)
            or not isinstance(data.get("controller_start_time"), str) or not data["controller_start_time"].isdigit()
            or data.get("controller_boot_id") != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            or not _integer(data.get("proxy_netns"), 1, 2**64 - 1)
            or isinstance(data.get("expires_at"), bool)
            or not isinstance(data.get("expires_at"), (int, float))
            or not math.isfinite(data["expires_at"]) or not time.time() < data["expires_at"] <= time.time() + 3000):
        raise ProxyDenied("provider_policy_invalid")
    config = data.get("config")
    if (not isinstance(config, dict) or set(config) != {"model", "reasoning_effort", "max_output_tokens"}
            or config["model"] != MODEL or not isinstance(config["reasoning_effort"], str)
            or config["reasoning_effort"] not in EFFORTS
            or not _integer(config["max_output_tokens"], 256, 2048)):
        raise ProxyDenied("provider_policy_invalid")
    _validate_limits(data["limits"])
    return data


class FixedOpenAIHTTPS:
    """Un único host HTTPS, sin redirecciones, proxies de entorno ni URL externa."""
    def __init__(self, secret):
        public_config(secret)
        self._key = secret["api_key"]

    def post(self, endpoint, body, timeout):
        if not isinstance(endpoint, str) or endpoint not in ENDPOINTS:
            raise ProxyDenied("provider_endpoint_denied")
        connection = http.client.HTTPSConnection("api.openai.com", 443,
            timeout=timeout, context=ssl.create_default_context())
        try:
            connection.request("POST", "/v1/" + endpoint, body=_raw(body), headers={
                "Authorization": "Bearer " + self._key, "Content-Type": "application/json"})
            response = connection.getresponse()
            # http.client no sigue Location. No se persisten cabeceras ni errores.
            if response.status != 200:
                if response.status == 401: raise ProxyDenied("provider_authentication_failed")
                if response.status == 429: raise ProxyDenied("provider_rate_limited")
                raise ProxyDenied("provider_http_error")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE or self._key.encode() in raw:
                raise ProxyDenied("provider_response_limit_or_secret")
            result = _json_loads(raw)
            if not isinstance(result, dict) or self._key.encode() in _raw(result):
                raise ProxyDenied("provider_response_invalid")
            request_id = response.getheader("x-request-id")
            if (not isinstance(request_id, str) or not 0 < len(request_id) <= 512 or self._key in request_id
                    or any(not 33 <= ord(c) <= 126 for c in request_id)):
                request_id = None
            return result, request_id
        except ProxyDenied:
            raise
        except (OSError, ValueError, http.client.HTTPException, RecursionError):
            raise ProxyDenied("provider_transport_unavailable") from None
        finally:
            connection.close()


class BoundedOpenAIHTTPS:
    """Plazo de pared aun durante DNS/TLS o una respuesta entregada lentamente.

    El hijo hereda UID, grupos, capacidades y namespace del proxy. Sólo recibe
    esta petición por stdin; no hereda sockets de roles ni la escucha IPC.
    """
    def __init__(self, secret):
        public_config(secret)
        self._secret = dict(secret)

    def post(self, endpoint, body, timeout):
        if (not isinstance(endpoint, str) or endpoint not in ENDPOINTS
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 60):
            raise ProxyDenied("provider_request_invalid")
        code = ("import sys;sys.path.insert(0," + repr(str(Path(__file__).resolve().parents[1]))
                + ");from auditoria.provider_proxy import _https_child;_https_child()")
        message = _raw({"secret": self._secret, "endpoint": endpoint, "body": body, "timeout": timeout})
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", code],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        try:
            output, _ = process.communicate(message, timeout=timeout)
            if process.returncode != 0 or len(output) > MAX_RESPONSE + 4096:
                raise ProxyDenied("provider_transport_unavailable")
            value = _json_loads(output)
            if (not isinstance(value, dict) or set(value) != {"response", "server_request_id"}
                    or not isinstance(value["response"], dict)):
                raise ProxyDenied("provider_response_invalid")
            return value["response"], value["server_request_id"]
        except subprocess.TimeoutExpired:
            raise ProxyDenied("provider_request_timeout") from None
        except (OSError, ValueError, RecursionError):
            raise ProxyDenied("provider_transport_unavailable") from None
        finally:
            if process.poll() is None:process.kill()
            process.wait()


def _https_child():
    """Entrada interna sin argumentos ni salida de diagnóstico sensible."""
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 8193)
        if len(raw) > MAX_REQUEST + 8192:raise ProxyDenied("provider_message_limit")
        value = _json_loads(raw)
        if not isinstance(value, dict) or set(value) != {"secret", "endpoint", "body", "timeout"}:
            raise ProxyDenied("provider_request_invalid")
        result, request_id = FixedOpenAIHTTPS(value["secret"]).post(value["endpoint"], value["body"], value["timeout"])
        sys.stdout.buffer.write(_raw({"response": result, "server_request_id": request_id}))
    except Exception:
        raise SystemExit(1) from None


class ProviderSession:
    def __init__(self, policy, transport):
        _validate_limits(policy["limits"])
        self.policy, self.transport = policy, transport
        self.calls = self.generations = self.used_tokens = self.known_tokens = 0
        self.cost_reserved = 0.0
        self.blocked = False
        self.quotes = {}
        self.lock = threading.Lock()

    def process(self, message, record=lambda *args, **kwargs: None):
        limits, config = self.policy["limits"], self.policy["config"]
        if not isinstance(message, dict) or set(message) != {"endpoint", "body", "timeout"}:
            raise ProxyDenied("provider_request_invalid")
        endpoint, body, timeout = message["endpoint"], message["body"], message["timeout"]
        if not isinstance(endpoint, str) or endpoint not in ENDPOINTS:
            raise ProxyDenied("provider_endpoint_denied")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= limits["request_timeout_seconds"]):
            raise ProxyDenied("provider_timeout_invalid")
        if (not isinstance(body, dict) or body.get("model") != config["model"]
                or not isinstance(body.get("input"), str) or not isinstance(body.get("text"), dict)):
            raise ProxyDenied("provider_body_invalid")
        common = {"model", "input", "text"}
        if endpoint == "responses/input_tokens":
            if set(body) != common:
                raise ProxyDenied("provider_body_invalid")
            quote_body = body
        else:
            if (set(body) != common | {"max_output_tokens", "reasoning", "store", "service_tier"}
                    or not _integer(body.get("max_output_tokens"), 256, config["max_output_tokens"])
                    or body.get("reasoning") != {"effort": config["reasoning_effort"]}
                    or body.get("store") is not False or body.get("service_tier") != "default"):
                raise ProxyDenied("provider_body_invalid")
            quote_body = {key: body[key] for key in common}
        if len(_raw(body)) > limits["max_request_bytes"]:
            raise ProxyDenied("provider_message_limit")
        key = hashlib.sha256(json.dumps(quote_body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        reservation = 0
        with self.lock:
            if self.blocked or time.time() >= self.policy["expires_at"]:
                raise ProxyDenied("provider_session_closed")
            if self.calls >= limits["max_requests"]:
                raise ProxyDenied("provider_request_quota_exhausted")
            if endpoint == "responses":
                quotes = self.quotes.get(key, [])
                if not quotes:
                    raise ProxyDenied("provider_input_quote_required")
                inputs = quotes.pop(0)
                if not quotes:self.quotes.pop(key, None)
                reservation = inputs + body["max_output_tokens"]
                cost = (inputs * 5.5 + body["max_output_tokens"] * 16.5) / 1_000_000
                if self.used_tokens + reservation > limits["token_budget"] or self.cost_reserved + cost > limits["max_cost_usd"]:
                    raise ProxyDenied("provider_token_or_cost_quota_exhausted")
                # Una respuesta perdida puede haber sido facturada: no se reintenta.
                self.used_tokens += reservation; self.cost_reserved += cost
                self.generations += 1
            self.calls += 1
            record("provider_request_started", endpoint=endpoint, requests=self.calls,
                   generations=self.generations, tokens_reserved=reservation)
        try:
            response, request_id = self.transport.post(endpoint, body,
                timeout=min(float(timeout), self.policy["expires_at"] - time.time()))
            if len(_raw(response)) > limits["max_response_bytes"]:
                raise ProxyDenied("provider_response_limit")
            with self.lock:
                if endpoint == "responses/input_tokens":
                    inputs = response.get("input_tokens")
                    if not _integer(inputs, 0, limits["token_budget"]):
                        raise ProxyDenied("provider_input_usage_invalid")
                    self.quotes.setdefault(key, []).append(inputs)
                else:
                    usage = response.get("usage", {})
                    actual_in, actual_out = usage.get("input_tokens"), usage.get("output_tokens")
                    if (not _integer(actual_in, 0, inputs) or not _integer(actual_out, 0, body["max_output_tokens"])
                            or usage.get("total_tokens") != actual_in + actual_out):
                        raise ProxyDenied("provider_usage_unavailable_or_exceeded")
                    self.used_tokens -= reservation - actual_in - actual_out
                    self.known_tokens += actual_in + actual_out
                record("provider_request_completed", endpoint=endpoint, requests=self.calls,
                       generations=self.generations, known_tokens=self.known_tokens)
            return {"response": response, "server_request_id": request_id}
        except Exception:
            with self.lock:
                self.blocked = True
                record("provider_request_failed", endpoint=endpoint, requests=self.calls,
                       generations=self.generations, reason="provider_request_failed")
            raise ProxyDenied("provider_request_failed") from None


def connection_request(policy, session, connection, record):
    """Autentica antes de leer el prompt y antes de reservar una salida."""
    pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    _peer_allowed(policy, pid, uid, gid)
    message = receive(connection, policy["limits"]["max_request_bytes"] + 4096)
    _peer_allowed(policy, pid, uid, gid)
    return session.process(message, record)


def serve(policy_path, listen_fd, secret_fd, audit_log):
    policy = load_policy(policy_path)
    own = identity()
    if not unprivileged(own, PROVIDER_UID) or own["netns"] != policy["proxy_netns"]:
        raise ProxyDenied("provider_identity_invalid")
    if not stat.S_ISFIFO(os.fstat(secret_fd).st_mode):
        raise ProxyDenied("provider_secret_channel_invalid")
    try:
        raw = os.read(secret_fd, 4097)
        if len(raw) > 4096:
            raise ProxyDenied("provider_configuration_invalid")
        secret = _json_loads(raw)
    finally:
        os.close(secret_fd)
    if public_config(secret) != policy["config"]:
        raise ProxyDenied("provider_configuration_invalid")
    session = ProviderSession(policy, BoundedOpenAIHTTPS(secret))
    del secret, raw
    os.umask(0o077)
    server = socket.socket(fileno=listen_fd)
    if server.family != socket.AF_UNIX or server.type != socket.SOCK_STREAM or not server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
        raise ProxyDenied("provider_listener_invalid")
    _endpoint(server.getsockname())
    server.listen(4); server.settimeout(0.5)
    slots = threading.BoundedSemaphore(8)
    with _audit_log(audit_log) as log, ThreadPoolExecutor(max_workers=4, thread_name_prefix="provider") as pool:
        log_lock = threading.Lock()
        def record(event, **fields):
            with log_lock:
                log.write(json.dumps({"time": time.time(), "role": "provider", "event": event, **fields}, sort_keys=True) + "\n")
        def handle(connection):
            try:
                with connection:
                    connection.settimeout(65)
                    try:
                        result = connection_request(policy, session, connection, record)
                        send(connection, {"ok": True, **result}, MAX_RESPONSE + 4096)
                    except Exception:
                        record("provider_request_rejected", reason="provider_request_denied")
                        try:
                            send(connection, {"ok": False, "error": "provider_request_denied"})
                        except (OSError, ProxyDenied):
                            pass
            finally:
                slots.release()
        record("worker_started", identity=own)
        connections = 0
        while time.time() < policy["expires_at"] and connections < MAX_REQUESTS * 2:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            connections += 1
            if slots.acquire(blocking=False):
                pool.submit(handle, connection)
            else:
                connection.close()


class ProviderProxyTransport:
    protected_proxy = True

    def __init__(self, config, store=None):
        self.config, self.store = config, store
        self._thread = threading.local()

    @property
    def last_trace(self):
        if not hasattr(self._thread, "trace"):self._thread.trace = {}
        return self._thread.trace

    @last_trace.setter
    def last_trace(self, value):
        self._thread.trace = value

    def post(self, endpoint, body, *, timeout):
        from .openai_provider import ProviderError
        from .secure_runtime import require_protected_runtime
        self.last_trace = {}
        try:
            runtime = require_protected_runtime()
            provider = runtime.get("provider", {})
            if endpoint not in ENDPOINTS or provider.get("config", {}).get("model") != self.config.model:
                raise ProxyDenied("provider_configuration_invalid")
            if provider.get("uid") != PROVIDER_UID or provider.get("gid") != PROVIDER_UID:
                raise ProxyDenied("provider_identity_invalid")
            _validate_limits(provider["limits"])
            request = {"endpoint": endpoint, "body": body, "timeout": timeout}
            if len(_raw(body)) > provider["limits"]["max_request_bytes"]:
                raise ProxyDenied("provider_message_limit")
            self.last_trace = {"endpoint": endpoint, "client_request_id": str(uuid4()),
                               "timeout_seconds": timeout, "status": "started", "transport": "protected-provider-ipc-1"}
            if self.store is not None:
                self.store.event("llm", "api_request_started", payload=dict(self.last_trace))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(65)
                connection.connect(_endpoint(provider["socket"]))
                pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                peer = identity(pid, namespace=False)
                principal = provider["principal"]
                if (uid != PROVIDER_UID or gid != PROVIDER_UID or pid != principal["pid"]
                        or peer["start_time"] != principal["start_time"] or not unprivileged(peer, uid, gid)
                        or principal["boot_id"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()):
                    raise ProxyDenied("provider_identity_invalid")
                send(connection, request, MAX_REQUEST + 4096)
                result = receive(connection, MAX_RESPONSE + 4096)
            if result.get("ok") is not True or not isinstance(result.get("response"), dict):
                raise ProxyDenied("provider_request_denied")
            self.last_trace.update(status="received", server_request_id=result.get("server_request_id"))
            return result["response"]
        except Exception:
            self.last_trace.update(status="failed", reason="protected_provider_unavailable")
            raise ProviderError(None, "protected_provider_unavailable") from None
        finally:
            if self.store is not None and self.last_trace:
                self.store.event("llm", "api_request_finished", payload=dict(self.last_trace))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--listen-fd", required=True, type=int)
    parser.add_argument("--secret-fd", required=True, type=int)
    parser.add_argument("--audit-log", required=True, type=Path)
    args = parser.parse_args()
    try:
        serve(args.policy, args.listen_fd, args.secret_fd, args.audit_log)
    except Exception:
        raise SystemExit("provider_startup_rejected") from None


if __name__ == "__main__":
    main()
