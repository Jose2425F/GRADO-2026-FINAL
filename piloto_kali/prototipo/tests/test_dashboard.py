import json
import os
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from auditoria.dashboard import build_dashboard, collect_state, make_server, process_identity
from auditoria.store import RunStore, write_json


def create_run(root):
    store = RunStore(root / "current", "test-audit")
    write_json(
        store.root / "request.json",
        {"audit_id": "test-audit", "architecture": "multiagent", "token_budget": 2000},
    )
    write_json(store.root / "manifest.json", {"mode": "live"})
    write_json(
        store.root / "runtime.json",
        {"status": "running", "pid": os.getpid(), "identity": process_identity(os.getpid())},
    )
    write_json(
        store.root / "plan.json",
        [
            {
                "task_id": "first",
                "agent_type": "ipv4_services",
                "action_profile": "nmap_tcp_services_v1",
                "target": {"asset_id": "asset1", "address": "127.0.0.1"},
            },
            {
                "task_id": "second",
                "agent_type": "ipv4_credentials",
                "action_profile": "hydra_ssh_single_v1",
                "target": {"asset_id": "asset1", "address": "127.0.0.1"},
            },
        ],
    )
    store.event("controller", "request_accepted")
    store.event(
        "controller",
        "task_admitted",
        task_id="first",
        payload={"password": "PRIVATE-MARKER", "command": "secret command"},
    )
    return store


def test_running_progress_is_read_from_committed_events(tmp_path):
    store = create_run(tmp_path)
    try:
        initial = collect_state(tmp_path)["runs"][0]
        assert initial["status"] == "running"
        assert initial["progress"] == 0
        assert initial["tasks"][0]["status"] == "running"
        assert "PRIVATE-MARKER" not in json.dumps(initial)
        store.event(
            "orchestration",
            "task_terminal",
            task_id="first",
            payload={"status": "completed_no_findings"},
        )
        store.event("llm", "decision", payload={"status": "accepted", "total_tokens": 100})
        store.event(
            "llm",
            "decision",
            payload={"status": "fallback", "generation_sent": True, "total_tokens": None},
        )
        updated = collect_state(tmp_path)["runs"][0]
        assert updated["progress"] == 50
        assert updated["llm"]["known_tokens"] == 100
        assert updated["llm"]["usage_complete"] is False
        assert updated["llm"]["fallbacks"] == 1
        assert updated["findings"] is None
        write_json(
            store.root / "runtime.json",
            {"status": "running", "pid": os.getpid(), "identity": "another-instance"},
        )
        assert collect_state(tmp_path)["runs"][0]["status"] == "interrupted"
    finally:
        store.close()


def test_completed_report_and_partial_experiment_are_not_promoted(tmp_path):
    store = create_run(tmp_path)
    try:
        write_json(
            store.root / "report.json",
            {
                "audit_id": "</script><script>alert(1)</script>",
                "status": "complete",
                "mode": "live",
                "tasks": [
                    {"task_id": "first", "status": "completed_no_findings"},
                    {"task_id": "second", "status": "completed"},
                ],
                "findings": [{}],
                "llm": {"known_tokens": 12, "usage_complete": True, "status": "accepted"},
                "metrics": {"elapsed_seconds": 2},
            },
        )
        study = tmp_path / "study"
        study.mkdir()
        write_json(
            study / "evaluation.json",
            {
                "runs_started": 30,
                "runs_planned": 30,
                "pairs_eligible": 10,
                "pairs_planned": 15,
                "formal_cohort_complete": False,
                "analysis": {"IDE_percent": {"mean": 0, "n_defined": 10}},
            },
        )
        state = collect_state(tmp_path)
        assert state["runs"][0]["progress"] == 100
        assert state["runs"][0]["findings"] == 1
        assert state["experiments"][0]["complete"] is False
        assert state["experiments"][0]["analysis"]["IDE_percent"]["mean"] == 0
        html = build_dashboard(tmp_path).read_text()
        assert "<script>alert(1)</script>" not in html
        assert "\\u003c/script\\u003e" in html
    finally:
        store.close()


def test_local_http_only_serves_public_artifacts(tmp_path):
    store = create_run(tmp_path)
    store.close()
    write_json(tmp_path / "current" / "report.json", {"status": "complete", "tasks": []})
    write_json(tmp_path / "current" / "policy.json", {"password": "DO-NOT-SERVE"})
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    write_json(outside / "report.json", {"password": "DO-NOT-SERVE"})
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    server = make_server(tmp_path, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        assert urlopen(url + "/").status == 200
        state = json.load(urlopen(url + "/api/state"))
        assert "DO-NOT-SERVE" not in json.dumps(state)
        assert urlopen(url + "/artifacts/current/report.json").status == 200
        for path in [
            "/artifacts/current/policy.json",
            "/artifacts/linked/report.json",
            "/artifacts/../" + outside.name + "/report.json",
            "/.lab/openai.json",
            "/artifacts/current/events.sqlite3",
        ]:
            with pytest.raises(HTTPError) as caught:
                urlopen(url + path)
            assert caught.value.code == 404
        with pytest.raises(HTTPError) as caught:
            urlopen(Request(url + "/api/state", headers={"Host": "external.invalid"}))
        assert caught.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_empty_directory_has_a_usable_dashboard(tmp_path):
    assert collect_state(tmp_path)["runs"] == []
    html = build_dashboard(tmp_path).read_text()
    assert "Centro de operaciones" in html
    assert "Vista guardada" in html
