"""Panel de observación local: eventos reales, sin ejecutar acciones del laboratorio."""

from __future__ import annotations

import json
import math
import sqlite3
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlsplit

from jinja2 import Environment, select_autoescape
from .agentes import AGENT_NAMES

ARTIFACTS = {"report.html", "report.pdf", "report.json", "evaluation.json", "runs.csv"}


def read_json(path: Path, root: Path, default=None):
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def number(value):
    return (
        value
        if isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value)
        else None
    )


def process_identity(pid: int) -> str | None:
    """Identifica la instancia del proceso, incluso si Linux reutiliza su PID."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return None
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + stat[19]
    except (OSError, IndexError):
        return None


def event_rows(path: Path, root: Path) -> list[dict]:
    if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
        return []
    try:
        with sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2
        ) as connection:
            connection.row_factory = sqlite3.Row
            records = connection.execute(
                "SELECT task_id,component,kind,timestamp,payload_json FROM events ORDER BY monotonic_ns"
            ).fetchall()
        rows = []
        for record in records:
            try:
                payload = json.loads(record["payload_json"])
                if not isinstance(payload, dict):
                    continue
                rows.append({**dict(record), "payload": payload})
            except ValueError:
                continue
        return rows
    except (OSError, sqlite3.Error):
        return []


def collect_run(directory: Path, root: Path) -> dict:
    report = read_json(directory / "report.json", root, {})
    request = read_json(directory / "request.json", root, {})
    manifest = read_json(directory / "manifest.json", root, {})
    runtime = read_json(directory / "runtime.json", root, {})
    plan = read_json(directory / "plan.json", root, [])
    if not all(isinstance(v, dict) for v in [report, request, manifest, runtime]) or not isinstance(
        plan, list
    ):
        raise ValueError("corrida con estructura inválida")
    events = event_rows(directory / "events.sqlite3", root)
    terminal = {e["task_id"]: e["payload"] for e in events if e["kind"] == "task_terminal"}
    admitted = {e["task_id"] for e in events if e["kind"] == "task_admitted"}
    results = {
        t["task_id"]: t for t in report.get("tasks", []) if isinstance(t, dict) and "task_id" in t
    }
    alive = (
        runtime.get("status") == "running"
        and isinstance(runtime.get("pid"), int)
        and bool(runtime.get("identity"))
        and process_identity(runtime["pid"]) == runtime["identity"]
    )
    status = report.get("status") or ("running" if alive else "interrupted")
    tasks = []
    for task in plan:
        if not isinstance(task, dict) or "task_id" not in task:
            continue
        task_id = task["task_id"]
        result = results.get(task_id) or terminal.get(task_id, {})
        state = result.get("status") or ("running" if alive and task_id in admitted else "pending")
        tasks.append(
            {
                "id": task_id,
                "agent": task.get("agent_type", ""),
                "profile": task.get("action_profile", ""),
                "case": task.get("case_id"),
                "asset": task.get("target", {}).get("asset_id", ""),
                "address": task.get("target", {}).get("address", ""),
                "status": state,
                "reason": result.get("reason_code"),
            }
        )
    # Los informes históricos también pueden existir sin plan.json.
    if not tasks:
        tasks = [
            {
                "id": t["task_id"],
                "agent": t.get("agent_name", ""),
                "profile": "",
                "asset": "",
                "address": "",
                "status": t.get("status", "pending"),
                "reason": t.get("reason_code"),
            }
            for t in results.values()
        ]
    finished = sum(t["status"] not in {"running", "pending"} for t in tasks)
    decisions = [
        e["payload"] for e in events if e["kind"] == "decision" and e["component"] == "llm"
    ]
    llm = report.get("llm", {})
    known_tokens = llm.get("known_tokens")
    if number(known_tokens) is None:
        known_tokens = sum(number(d.get("total_tokens")) or 0 for d in decisions)
    usage_complete = (
        llm.get("usage_complete")
        if report
        else not any(d.get("generation_sent") and d.get("total_tokens") is None for d in decisions)
    )
    started_at = events[0]["timestamp"] if events else runtime.get("started_at")
    elapsed = number(report.get("metrics", {}).get("elapsed_seconds"))
    if elapsed is None and started_at:
        try:
            end = (
                datetime.now(timezone.utc)
                if alive
                else datetime.fromisoformat(
                    runtime.get("ended_at") or (events[-1]["timestamp"] if events else started_at)
                )
            )
            elapsed = max(0, (end - datetime.fromisoformat(started_at)).total_seconds())
        except (ValueError, TypeError):
            pass
    public_events = []
    for event in events[-60:][::-1]:
        payload = event["payload"]
        # Lista explícita: nunca devolver comandos, contraseñas, prompts ni evidencia cruda.
        public_events.append(
            {
                "time": event["timestamp"],
                "kind": event["kind"],
                "component": event["component"],
                "task": event["task_id"],
                "status": payload.get("status"),
                "reason": payload.get("reason_code") or payload.get("reason"),
                "tokens": number(payload.get("total_tokens")),
                "http": number(payload.get("provider_http_status")),
            }
        )
    evaluation = read_json(directory / "evaluation.json", root, {})
    if not isinstance(evaluation, dict):
        evaluation = {}
    artifacts = {
        name: (directory / name).relative_to(root).as_posix()
        for name in ARTIFACTS
        if (directory / name).is_file() and not (directory / name).is_symlink()
    }
    agents = []
    for role in dict.fromkeys(t["agent"] for t in tasks):
        subset = [t for t in tasks if t["agent"] == role]
        agents.append(
            {
                "id": role,
                "name": AGENT_NAMES.get(role, role),
                "total": len(subset),
                "finished": sum(t["status"] not in {"running", "pending"} for t in subset),
                "active": sum(t["status"] == "running" for t in subset),
                "failed": sum(t["status"] in {"failed", "blocked", "cancelled"} for t in subset),
            }
        )
    return {
        "key": directory.relative_to(root).as_posix(),
        "id": report.get("audit_id") or request.get("audit_id") or directory.name,
        "status": status,
        "architecture": report.get("architecture") or request.get("architecture", "multiagent"),
        "mode": report.get("mode") or manifest.get("mode", "dry_run"),
        "started_at": started_at,
        "seconds": elapsed,
        "total": len(tasks),
        "finished": finished,
        "progress": round(finished / len(tasks) * 100) if tasks else 0,
        "tasks": tasks,
        "agents": agents,
        "events": public_events,
        "findings": len(report.get("findings", [])) if report else None,
        "llm": {
            "model": llm.get("model")
            or manifest.get("llm_model")
            or next(
                (e["payload"].get("model") for e in reversed(events) if e["kind"] == "llm_ready"),
                None,
            ),
            "status": llm.get("status")
            or (
                "fallback"
                if any(e["kind"] == "llm_fallback" for e in events)
                or any(d.get("status") == "fallback" for d in decisions)
                else "active"
                if decisions and alive
                else "disabled"
            ),
            "known_tokens": known_tokens,
            "usage_complete": usage_complete,
            "calls": len(llm.get("calls", decisions)),
            "fallbacks": llm.get(
                "fallbacks", sum(d.get("status") == "fallback" for d in decisions)
            ),
            "cost": number(llm.get("cost_estimate_usd")),
            "budget": llm.get("budget") or request.get("token_budget", 0),
        },
        "evaluation": {k: number(evaluation.get(k)) for k in ["TP", "FP", "FN", "TN"]},
        "artifacts": artifacts,
    }


def collect_state(root: Path) -> dict:
    root = root.resolve()
    directories = {}
    for name in ["events.sqlite3", "report.json"]:
        for path in root.rglob(name):
            if ".lab" in path.relative_to(root).parts or not path.resolve().is_relative_to(root):
                continue
            try:
                directories[path.parent] = max(
                    directories.get(path.parent, 0), path.stat().st_mtime
                )
            except OSError:
                continue
    runs = []
    for directory in sorted(directories, key=directories.get, reverse=True)[:100]:
        try:
            runs.append(collect_run(directory, root))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            continue
    runs.sort(key=lambda r: (r["status"] == "running", r["started_at"] or ""), reverse=True)
    experiments = []
    for path in root.rglob("evaluation.json"):
        value = read_json(path, root, {})
        if not isinstance(value, dict) or not isinstance(value.get("analysis"), dict):
            continue
        design = read_json(path.parent / "design.json", root, {})
        experiments.append(
            {
                "id": path.parent.name,
                "key": path.parent.relative_to(root).as_posix(),
                "runs_started": number(value.get("runs_started")),
                "runs_planned": number(value.get("runs_planned")),
                "pairs_eligible": number(value.get("pairs_eligible")),
                "pairs_planned": number(value.get("pairs_planned")),
                "complete": value.get("formal_cohort_complete") is True,
                "pilot": value.get("pilot") is True,
                "created_at": design.get("created_at", "") if isinstance(design, dict) else "",
                "analysis": {
                    k: {
                        "mean": number(value["analysis"].get(k, {}).get("mean")),
                        "n": number(value["analysis"].get(k, {}).get("n_defined")),
                    }
                    for k in ["TRTO_percent", "IDE_percent", "ETV_ratio"]
                },
                "artifact": path.relative_to(root).as_posix(),
            }
        )
    experiments.sort(key=lambda e: e["id"], reverse=True)
    return {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "experiments": experiments,
        "run_limit": 100,
    }


def render_dashboard(state: dict, *, live: bool) -> str:
    environment = Environment(autoescape=select_autoescape(["html"]))
    template = files("auditoria").joinpath("templates/dashboard.html.j2").read_text()
    return environment.from_string(template).render(state=state, live=live)


def build_dashboard(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "index.html"
    path.write_text(render_dashboard(collect_state(root), live=False), encoding="utf-8")
    return path


def make_server(root: Path, port: int = 8765) -> ThreadingHTTPServer:
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = {"time": 0, "state": None}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, body: bytes, content_type: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionError:
                # El navegador puede cancelar una consulta al cambiar de página.
                pass

        def do_GET(self):
            # Rechaza Hosts externos: el panel solo escucha en loopback.
            if self.headers.get("Host") not in {
                f"127.0.0.1:{self.server.server_port}",
                f"localhost:{self.server.server_port}",
            }:
                self.send(b"Host no permitido", "text/plain; charset=utf-8", 403)
                return
            path = unquote(urlsplit(self.path).path)
            if path in {"/", "/api/state"}:
                if time.monotonic() - cache["time"] > 1 or cache["state"] is None:
                    cache["state"] = collect_state(root)
                    cache["time"] = time.monotonic()
                if path == "/":
                    self.send(
                        render_dashboard(cache["state"], live=True).encode(),
                        "text/html; charset=utf-8",
                    )
                else:
                    self.send(
                        json.dumps(cache["state"], ensure_ascii=False, allow_nan=False).encode(),
                        "application/json; charset=utf-8",
                    )
            elif path.startswith("/artifacts/"):
                candidate = root / path.removeprefix("/artifacts/")
                if (
                    candidate.name not in ARTIFACTS
                    or not candidate.resolve().is_relative_to(root)
                    or candidate.is_symlink()
                    or not candidate.is_file()
                ):
                    self.send(b"Archivo no disponible", "text/plain; charset=utf-8", 404)
                    return
                types = {
                    ".html": "text/html; charset=utf-8",
                    ".json": "application/json; charset=utf-8",
                    ".pdf": "application/pdf",
                    ".csv": "text/csv; charset=utf-8",
                }
                self.send(candidate.read_bytes(), types[candidate.suffix])
            else:
                self.send(b"No encontrado", "text/plain; charset=utf-8", 404)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
