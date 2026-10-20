import json

import pytest
from typer.testing import CliRunner

from auditoria.cli import app
from auditoria.contracts import LabPolicy, TaskResult, TaskStatus, Authentication
from auditoria.laboratorio import prepare, request_for_lab
from auditoria.policy import authorize_request, PolicyError
from auditoria.agentes.agente_administrador import build_graph
from auditoria.store import RunStore
from auditoria.findings import confirm_findings
from auditoria.validation import validate_results
from auditoria.metrics import kpis, truth_keys, summarize_experiment, bootstrap_ci


def bank(tmp_path):
    root = tmp_path / "lab"
    prepare(root)
    policy = LabPolicy.model_validate_json((root / "policy.json").read_text())
    return root, policy, request_for_lab("test-lab")


def test_mixed_family_policy_and_plan_do_not_dispatch_ipv4_to_ipv6(tmp_path):
    root, policy, request = bank(tmp_path)
    authorize_request(request, policy)
    store = RunStore(tmp_path / "run", request.audit_id)
    try:
        state = build_graph(store, live=False).invoke({"request": request, "policy": policy})
    finally:
        store.close()
    assert len(state["tasks"]) == 22
    assert sum(t.case_id is not None for t in state["tasks"]) == 8
    assert all(":" in t.target.address for t in state["tasks"] if t.case_id)
    assert all(
        ":" not in t.target.address for t in state["tasks"] if t.action_profile.startswith("hydra")
    )
    assert (store.root / "report.pdf").read_bytes().startswith(b"%PDF-")
    assert state["report"]["metrics"]["elapsed_seconds"] > 0
    assert state["report"]["findings"] == []


def test_control_secret_permissions_and_idempotence(tmp_path):
    root, policy, request = bank(tmp_path)
    previous = (root / "lab.env").read_bytes()
    prepare(root)
    assert (root / "lab.env").read_bytes() == previous
    assert (root / "lab.env").stat().st_mode & 0o777 == 0o600
    assert previous.decode().split("=")[1].strip() not in (root / "policy.json").read_text()
    positive, negative = truth_keys(json.loads((root / "ground_truth.json").read_text()))
    assert len(positive) == len(negative) == 4


def test_mixed_request_cannot_expand_scope_or_credential_attempts(tmp_path):
    _, policy, request = bank(tmp_path)
    target = request.targets[-1].model_copy(update={"interface": "eth0"})
    with pytest.raises(PolicyError):
        authorize_request(request.model_copy(update={"targets": [target]}), policy)
    with pytest.raises(PolicyError):
        authorize_request(request.model_copy(update={"max_attempts": 2}), policy)


def make_auth_evidence(store, task, profile, confirmed=True):
    data = {
        "target": task.target.address,
        "port": profile.port,
        "credential_ref": profile.ref,
        "outcome": "accepted",
    }
    ref, digest = store.evidence(
        task.task_id, "json", json.dumps({**data, "tool": "hydra"}).encode()
    )
    diag, diag_hash = store.evidence(
        task.task_id + "_confirmation",
        "json",
        json.dumps(
            {**data, "tool": "paramiko", "outcome": "accepted" if confirmed else "rejected"}
        ).encode(),
    )
    return TaskResult(
        task_id=task.task_id,
        status=TaskStatus.COMPLETED,
        authentication=Authentication(
            credential_ref=profile.ref,
            service=profile.service,
            port=profile.port,
            outcome="accepted",
        ),
        evidence_ref=ref,
        evidence_sha256=digest,
        diagnostic_ref=diag,
        diagnostic_sha256=diag_hash,
    )


@pytest.mark.parametrize(
    "confirmed,tampered,expected", [(True, False, 1), (False, False, 0), (True, True, 0)]
)
def test_verified_auth_requires_independent_matching_intact_evidence(
    tmp_path, confirmed, tampered, expected
):
    from auditoria.contracts import Task

    _, policy, request = bank(tmp_path)
    profile = next(p for p in policy.credential_profiles if p.ref == "ssh_lab")
    target = request.targets[0].model_copy(
        update={"credential_ref": profile.ref, "credential_refs": []}
    )
    task = Task(
        task_id="ssh",
        agent_type="ipv4_credentials",
        target=target,
        protocol="tcp",
        action_profile="hydra_ssh_single_v1",
        timeout_seconds=20,
    )
    store = RunStore(tmp_path / "run", "test")
    try:
        result = make_auth_evidence(store, task, profile, confirmed)
        if tampered:
            (store.root / result.diagnostic_ref).write_text("changed")
        validation = validate_results(store.root, [task], [result])
        findings = confirm_findings(store.root, policy, [task], [result], validation)
        assert len(findings) == expected
    finally:
        store.close()


def test_kpi_formulas_and_zero_denominators():
    result = kpis(
        {"TP": 5, "tokens": 1000, "elapsed_seconds": 100},
        {"TP": 6, "tokens": 1000, "elapsed_seconds": 70},
    )
    assert result["TRTO_percent"] == 30
    assert result["IDE_percent"] == 20
    assert result["ETV_ratio"] == pytest.approx(1.2)
    assert all(result["met"].values())
    missing = kpis(
        {"TP": 0, "tokens": None, "elapsed_seconds": 0},
        {"TP": 0, "tokens": 0, "elapsed_seconds": None},
    )
    assert all(missing[k] is None for k in ["TRTO_percent", "IDE_percent", "ETV_ratio"])


def test_ground_truth_rejects_duplicate_or_nonboolean_labels():
    entry = {"asset_id": "a", "defect_key": "ssh", "present": True}
    with pytest.raises(ValueError):
        truth_keys({"entries": [entry, entry]})
    with pytest.raises(ValueError):
        truth_keys({"entries": [{**entry, "present": "false"}]})


def test_interrupted_runs_remain_false_negatives_without_faster_kpi(tmp_path):
    root, _, _ = bank(tmp_path)
    experiment = tmp_path / "experiment"
    experiment.mkdir()
    (experiment / "attempts.json").write_text(
        json.dumps(
            [
                {
                    "block": 1,
                    "order": 1,
                    "architecture": "single",
                    "status": "started",
                    "run_path": None,
                }
            ]
        )
    )
    summary = summarize_experiment(experiment, root / "ground_truth.json")
    assert summary["runs_started"] == 1
    assert summary["runs"][0]["FN"] == 4
    assert summary["pairs_eligible"] == 0
    assert summary["analysis"]["TRTO_percent"]["mean"] is None
    assert (experiment / "runs.csv").exists()


def test_bootstrap_seed_and_small_sample():
    assert bootstrap_ci([1], seed=3) is None
    assert bootstrap_ci([1, 3, 7], seed=3) == bootstrap_ci([1, 3, 7], seed=3)


def test_demo_simulation_never_requires_docker_or_sends_auth(tmp_path, monkeypatch):
    from contextlib import nullcontext

    root, _, _ = bank(tmp_path)
    monkeypatch.setattr("auditoria.cli.operation_lock", nullcontext)
    monkeypatch.setattr(
        "auditoria.laboratorio.preflight", lambda **kwargs: pytest.fail("dry-run Docker")
    )
    result = CliRunner().invoke(
        app,
        [
            "demo",
            "--config",
            str(root),
            "--salida",
            str(tmp_path / "runs"),
            "--autorizacion",
            "test-lab",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(next((tmp_path / "runs").glob("*/report.json")).read_text())
    assert report["mode"] == "dry_run"
    assert report["findings"] == []


def test_hydra_only_fixed_http_path_and_single_guess(tmp_path):
    from auditoria.agentes.agente_ipv4_credenciales import hydra_command
    from auditoria.contracts import Task

    _, policy, request = bank(tmp_path)
    profile = next(p for p in policy.credential_profiles if p.ref == "tomcat_lab")
    task = Task(
        task_id="http",
        agent_type="ipv4_credentials",
        target=request.targets[1],
        protocol="tcp",
        action_profile="hydra_http_get_single_v1",
        timeout_seconds=20,
    )
    cmd = hydra_command(task, profile, "private-password-file", "private-result-file")
    assert cmd[-2:] == ["http-get", "/manager/html"]
    assert cmd[cmd.index("-t") + 1] == "1"
    assert "lab2026" not in cmd


def test_multi_dispatches_independent_assets_in_parallel_but_single_serial(tmp_path, monkeypatch):
    import threading
    import time
    from auditoria.contracts import Category

    _, policy, request = bank(tmp_path)
    request = request.model_copy(
        update={
            "categories": [Category.IPV4_SERVICES],
            "case_ids": [],
            "targets": [t.model_copy(update={"credential_refs": []}) for t in request.targets[:2]],
        }
    )
    active = peak = 0
    lock = threading.Lock()

    def fake_scan(task, store, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        store.event("test", "concurrent_write", task_id=task.task_id)
        time.sleep(0.05)
        with lock:
            active -= 1
        ref, digest = store.evidence(task.task_id, "xml", b"<nmaprun/>")
        return TaskResult(
            task_id=task.task_id,
            status=TaskStatus.COMPLETED_NO_FINDINGS,
            evidence_ref=ref,
            evidence_sha256=digest,
        )

    monkeypatch.setattr("auditoria.agentes.agente_administrador.run_nmap", fake_scan)
    for architecture, expected in [("multiagent", 2), ("single", 1)]:
        peak = 0
        store = RunStore(tmp_path / architecture, "concurrency")
        try:
            state = build_graph(store, live=True).invoke(
                {
                    "request": request.model_copy(update={"architecture": architecture}),
                    "policy": policy,
                }
            )
            assert state["report"]["status"] == "complete"
            assert peak == expected
            assert (
                store.connection.execute(
                    "SELECT count(*) FROM events WHERE kind='concurrent_write'"
                ).fetchone()[0]
                == 2
            )
        finally:
            store.close()


def test_ambiguous_http_response_never_reaches_hydra(tmp_path, monkeypatch):
    from auditoria.contracts import Task
    from auditoria.agentes.agente_ipv4_credenciales import run_hydra

    _, policy, request = bank(tmp_path)
    profile = next(p for p in policy.credential_profiles if p.ref == "tomcat_lab")
    task = Task(
        task_id="http",
        agent_type="ipv4_credentials",
        target=request.targets[1],
        protocol="tcp",
        action_profile="hydra_http_get_single_v1",
        timeout_seconds=20,
    )
    monkeypatch.setenv("LAB_PROBE_PASSWORD", "synthetic")
    monkeypatch.setattr(
        "auditoria.agentes.agente_ipv4_credenciales.check_route", lambda *args: None
    )
    monkeypatch.setattr(
        "auditoria.authentication.http_basic_challenge", lambda *args, **kwargs: False
    )
    monkeypatch.setattr(
        "auditoria.agentes.agente_ipv4_credenciales.subprocess.run",
        lambda *args, **kwargs: pytest.fail("403 no demuestra autenticación"),
    )
    store = RunStore(tmp_path / "run", "http")
    try:
        result = run_hydra(task, profile, store, timeout_seconds=20)
    finally:
        store.close()
    assert result.status == TaskStatus.FAILED
    assert result.reason_code == "http_basic_challenge_missing"


def test_reset_preserves_images_for_paired_comparison(tmp_path, monkeypatch):
    from auditoria.laboratorio import compose

    (tmp_path / "lab.env").write_text("LAB_CONTROL_PASSWORD=synthetic-test-only\n")
    calls = []
    monkeypatch.setattr(
        "auditoria.laboratorio.subprocess.run", lambda command, **kwargs: calls.append(command)
    )
    compose(tmp_path, "reset")
    assert len(calls) == 4
    for command in calls[1::2]:
        assert command[-5:] == ["up", "-d", "--no-build", "--pull", "never"]
        assert command[-2:] == ["--pull", "never"]
        assert "--build" not in command


def test_formal_cohort_requires_all_planned_pairs(tmp_path, monkeypatch):
    from auditoria import metrics

    root, _, _ = bank(tmp_path)
    experiment = tmp_path / "experiment"
    experiment.mkdir()
    (experiment / "design.json").write_text(
        json.dumps(
            {
                "pilot": False,
                "blocks": [{"block": 1}, {"block": 2}],
            }
        )
    )
    monkeypatch.setattr(
        metrics, "score_run", lambda path, truth: {"TP": 4, "FP": 0, "FN": 0, "TN": 4}
    )
    monkeypatch.setattr(
        metrics,
        "compare_pair",
        lambda *args: {
            "eligible": True,
            "formal_kpis": {"TRTO_percent": 40, "IDE_percent": 0, "ETV_ratio": 2},
        },
    )
    attempts = []
    for block in [1, 2]:
        for order, arch in enumerate(["single", "multiagent"], 1):
            attempts.append(
                {
                    "block": block,
                    "order": order,
                    "architecture": arch,
                    "status": "complete",
                    "run_path": str(tmp_path / f"{block}_{arch}"),
                }
            )
        (experiment / "attempts.json").write_text(json.dumps(attempts))
        summary = summarize_experiment(experiment, root / "ground_truth.json")
        assert summary["pairs_eligible"] == block
        assert summary["runs_planned"] == 4
        assert summary["formal_cohort_complete"] is (block == 2)
