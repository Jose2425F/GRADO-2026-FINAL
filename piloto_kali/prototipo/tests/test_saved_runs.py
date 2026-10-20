"""Regresiones de integridad y comparación de corridas, sin tráfico de red."""

import hashlib
import json
import pytest
from typer.testing import CliRunner

from auditoria.casos_ipv6 import CASES
from auditoria.cli import app
from auditoria.contracts import Target, Task, TaskResult, TaskStatus
from auditoria.store import write_json
from auditoria.modulo_reportes import save_report
from auditoria.validation import compare_runs, validate_results


def saved_run(root, audit_id, *, case_ids=("GT-13",), asset_id="receptor",
              delivered=False, address="fd57:2026:9:28::20"):
    root.mkdir()
    (root / "evidence").mkdir()
    tasks, results = [], []
    for case_id in case_ids:
        case = CASES[case_id]
        task = Task(
            task_id=f"{audit_id}_{case_id}", case_id=case_id,
            agent_type=case.category.value,
            target=Target(asset_id=asset_id, address=address,
                          interface="br-lab-ipv6", ports=[53000]),
            protocol="ipv6", action_profile=case.action_profile, timeout_seconds=30,
        )
        references = {}
        for name, extension in (("packet", "pcap"), ("diagnostic", "json"),
                                ("control", "pcap")):
            data = f"{case_id}-{name}".encode()
            ref = f"evidence/{case_id}-{name}.{extension}"
            (root / ref).write_bytes(data)
            references[name] = (ref, hashlib.sha256(data).hexdigest())
        result = TaskResult(
            task_id=task.task_id, status=TaskStatus.COMPLETED_NO_FINDINGS,
            evidence_ref=references["packet"][0], evidence_sha256=references["packet"][1],
            diagnostic_ref=references["diagnostic"][0],
            diagnostic_sha256=references["diagnostic"][1],
            observations={
                "packet_observed": True, "route_changed": True,
                "neighbor_changed": True, "dad_failed": True, "changed": True,
                "restored": True, "control_received": True,
                "variant_fragments_observed": True, "variant_udp_delivered": delivered,
                "control_pcap_ref": references["control"][0],
                "control_pcap_sha256": references["control"][1],
            },
        )
        tasks.append(task)
        results.append(result)
    write_json(root / "plan.json", [task.model_dump(mode="json") for task in tasks])
    write_json(root / "report.json", {
        "audit_id": audit_id, "tasks": [r.model_dump(mode="json") for r in results],
    })
    return tasks, results


def test_ipv4_evidence_changed_makes_cli_fail(tmp_path):
    root = tmp_path / "ipv4"
    root.mkdir()
    (root / "evidence").mkdir()
    raw = b"<nmaprun/>"
    ref = "evidence/nmap.xml"
    (root / ref).write_bytes(raw)
    task = Task(task_id="nmap", agent_type="ipv4_services",
                target=Target(asset_id="tomcat", address="192.168.57.13",
                              interface="br-lab-audit", ports=[8080]),
                protocol="tcp", action_profile="nmap_tcp_services_v1", timeout_seconds=30)
    result = TaskResult(task_id="nmap", status=TaskStatus.COMPLETED_NO_FINDINGS,
                        evidence_ref=ref, evidence_sha256=hashlib.sha256(raw).hexdigest())
    write_json(root / "plan.json", [task.model_dump(mode="json")])
    write_json(root / "report.json", {"audit_id": "ipv4", "tasks": [result.model_dump(mode="json")]})
    runner = CliRunner()
    assert runner.invoke(app, ["validar-corrida", str(root)]).exit_code == 0
    (root / ref).write_bytes(b"changed")
    checked = runner.invoke(app, ["validar-corrida", str(root)])
    assert checked.exit_code == 3, checked.output
    assert "evidence_incomplete_or_changed" in checked.output


@pytest.mark.parametrize("case_id", ["GT-13", "GT-14", "GT-15", "GT-16"])
def test_fragment_behavior_reproduced_without_confirming_vulnerability(tmp_path, case_id):
    first, second = tmp_path / "first", tmp_path / "second"
    saved_run(first, "first", case_ids=(case_id,))
    saved_run(second, "second", case_ids=(case_id,))
    records = compare_runs(first, second)
    assert records[0]["state"] == "reproduced"
    assert records[0]["independent_confirmation"] is False


def test_changed_fragment_delivery_is_not_reproduced(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    saved_run(first, "first", delivered=False)
    saved_run(second, "second", delivered=True)
    assert compare_runs(first, second)[0]["state"] == "not_reproduced"


@pytest.mark.parametrize("changes", [
    {"asset_id": "otro_receptor"}, {"address": "fd57:2026:9:28::21"},
])
def test_different_target_is_not_reproduced(tmp_path, changes):
    first, second = tmp_path / "first", tmp_path / "second"
    saved_run(first, "first", case_ids=("GT-12",))
    saved_run(second, "second", case_ids=("GT-12",), **changes)
    records = compare_runs(first, second)
    assert records and all(r["state"] == "not_reproduced" for r in records)


def test_missing_case_is_reported_and_cli_returns_nonzero(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    saved_run(first, "first", case_ids=("GT-09", "GT-12"))
    saved_run(second, "second", case_ids=("GT-09",))
    records = compare_runs(first, second)
    assert {r["case_id"] for r in records} == {"GT-09", "GT-12"}
    checked = CliRunner().invoke(app, ["comparar-corridas", str(first), str(second)])
    assert checked.exit_code == 3, checked.output


@pytest.mark.parametrize("mismatch", ["missing", "unknown", "duplicate"])
def test_result_ids_must_match_plan(tmp_path, mismatch):
    tasks, results = saved_run(tmp_path / "run", "run", case_ids=("GT-12",))
    if mismatch == "missing":
        results = []
    elif mismatch == "unknown":
        results[0] = results[0].model_copy(update={"task_id": "unknown"})
    else:
        results.append(results[0])
    with pytest.raises(ValueError):
        validate_results(tmp_path / "run", tasks, results)


def test_fragment_without_verified_restoration_stays_indeterminate(tmp_path):
    root = tmp_path / "run"
    tasks, results = saved_run(root, "run")
    results[0].observations["restored"] = False
    assert validate_results(root, tasks, results)[0]["state"] == "indeterminate"


def test_same_run_cannot_be_compared_to_itself(tmp_path):
    root = tmp_path / "run"
    saved_run(root, "run")
    with pytest.raises(ValueError):
        compare_runs(root, root)


def test_corrupt_report_is_rejected_cleanly(tmp_path):
    root = tmp_path / "run"
    saved_run(root, "run")
    (root / "report.json").write_text(json.dumps({"audit_id": "run", "tasks": [None]}))
    checked = CliRunner().invoke(app, ["validar-corrida", str(root)])
    assert checked.exit_code == 2, checked.output
    assert "Rechazado:" in checked.output


@pytest.mark.parametrize("artifact", ["packet", "diagnostic", "control"])
def test_changed_fragment_evidence_prevents_reproduction(tmp_path, artifact):
    first, second = tmp_path / "first", tmp_path / "second"
    saved_run(first, "first")
    saved_run(second, "second")
    path = next((second / "evidence").glob(f"GT-13-{artifact}.*"))
    path.write_bytes(b"changed")
    assert compare_runs(first, second)[0]["state"] == "not_reproduced"


def test_multiple_assets_with_same_case_remain_separate(tmp_path):
    roots = [tmp_path / "first", tmp_path / "second"]
    for index, root in enumerate(roots):
        tasks, results = saved_run(root, f"run{index}", case_ids=("GT-12",))
        task = tasks[0].model_copy(update={
            "task_id": f"other{index}",
            "target": tasks[0].target.model_copy(update={"asset_id": "otro_receptor"}),
        })
        result = results[0].model_copy(update={"task_id": task.task_id})
        write_json(root / "plan.json", [t.model_dump(mode="json") for t in [*tasks, task]])
        write_json(root / "report.json", {
            "audit_id": f"run{index}",
            "tasks": [r.model_dump(mode="json") for r in [*results, result]],
        })
    records = compare_runs(*roots)
    assert len(records) == 2
    assert {r["asset_id"] for r in records} == {"receptor", "otro_receptor"}
    assert all(r["state"] == "reproduced" for r in records)


@pytest.mark.parametrize("link", [False, True])
def test_evidence_cannot_escape_run_directory(tmp_path, link):
    root = tmp_path / "run"
    tasks, results = saved_run(root, "run", case_ids=("GT-12",))
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"external")
    if link:
        (root / "evidence" / "link.pcap").symlink_to(outside)
        results[0].evidence_ref = "evidence/link.pcap"
    else:
        results[0].evidence_ref = "../outside.pcap"
    results[0].evidence_sha256 = hashlib.sha256(b"external").hexdigest()
    record = validate_results(root, tasks, results)[0]
    assert record["evidence_integrity"]["valid"] is False
    assert record["state"] == "indeterminate"


def test_html_displays_same_integrity_as_json(tmp_path):
    root = tmp_path / "run"
    tasks, results = saved_run(root, "run", case_ids=("GT-12",))
    report = json.loads((root / "report.json").read_text())
    report.update({"validation": validate_results(root, tasks, results),
                   "llm": {"status": "disabled", "model": None}})
    save_report(root, report)
    html = (root / "report.html").read_text()
    assert "receptor / run_GT-12" in html
    assert "<td>sí</td>" in html
    (root / results[0].evidence_ref).write_bytes(b"changed")
    report["validation"] = validate_results(root, tasks, results)
    save_report(root, report)
    assert "<td>no</td>" in (root / "report.html").read_text()


def test_duplicate_plan_ids_rejected(tmp_path):
    root = tmp_path / "run"
    tasks, results = saved_run(root, "run")
    with pytest.raises(ValueError):
        validate_results(root, [*tasks, tasks[0]], results)
