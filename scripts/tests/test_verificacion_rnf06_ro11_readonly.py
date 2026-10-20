"""Pruebas negativas del cotejo posterior: sin herramientas, API o red."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def load(name):
    path = Path(__file__).parents[1] / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ro11 = load("verificar_ro11_denominadores_ro")
rnf06 = load("verificar_rnf06_privilegios_ro")


def rows_with_partial():
    return [
        {"sequence": 1, "architecture": "single", "recorded": True,
         "status": "partial", "TP": 1, "FN": 9, "seconds": 100},
        {"sequence": 2, "architecture": "single", "recorded": True,
         "status": "complete", "TP": 9, "FN": 1, "seconds": 200},
        {"sequence": 3, "architecture": "multiagent", "recorded": True,
         "status": "complete", "TP": 10, "FN": 0, "seconds": 80},
    ]


def test_ro11_partial_fn_and_time_stay_in_descriptive_denominator():
    result = ro11.aggregate(rows_with_partial())
    assert result["single"]["attempts"] == 2
    assert result["single"]["included_sequences"] == [1, 2]
    assert result["single"]["TP"] == 10
    assert result["single"]["FN"] == 10
    assert result["single"]["recall_percent"] == 50
    assert result["single"]["mean_seconds"] == 150


def test_ro11_rejects_table_that_silently_excludes_partial():
    summary = ro11.aggregate(rows_with_partial())
    table = [["header"], ["Agente único", "1 / 1", "9", "1", "90,0", "200,00"],
             ["Multiagente", "1 / 1", "10", "0", "100,0", "80,00"]]
    ok, comparisons = ro11.compare_table(table, summary)
    assert not ok
    assert not comparisons[0]["matches"]


def test_ro11_accepts_table_with_all_initiated_attempts():
    summary = ro11.aggregate(rows_with_partial())
    table = [["header"], ["Agente único", "1 / 2", "10", "10", "50,0", "150,00"],
             ["Multiagente", "1 / 1", "10", "0", "100,0", "80,00"]]
    assert ro11.compare_table(table, summary)[0]


def test_rnf06_effective_capabilities_zero_is_distinct_from_inheritable():
    assert rnf06.decode_capabilities("0000000000000000") == []
    assert rnf06.decode_capabilities("0000000800000000") == ["CAP_WAKE_ALARM"]
    assert rnf06.decode_capabilities("0000000000003000") == ["CAP_NET_ADMIN", "CAP_NET_RAW"]


def test_rnf06_docker_projection_excludes_secrets_and_never_executes(monkeypatch):
    calls = []
    container = {"name": "/v2-sender", "configured_user": "", "pid": 0,
                 "running": False, "privileged": False, "cap_add": ["CAP_NET_RAW"],
                 "cap_drop": ["ALL"], "readonly_rootfs": True,
                 "security_opt": ["no-new-privileges:true"]}
    def command(arguments, **kwargs):
        calls.append(arguments)
        if arguments[1:3] == ["ps", "-a"]:
            return SimpleNamespace(returncode=0, stdout="v2-sender\nunrelated-private-container\n")
        assert arguments[1:3] == ["container", "inspect"]
        assert arguments[-1] == "v2-sender"
        assert ".Config.Env" not in arguments[4]
        assert ".Args" not in arguments[4]
        return SimpleNamespace(returncode=0, stdout=json.dumps(container) + "\n")
    monkeypatch.setattr(rnf06.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(rnf06.subprocess, "run", command)
    result = rnf06.container_observations()
    assert len(calls) == 2
    observed = result["containers"][0]
    assert observed["effective_process"]["available"] is False
    assert "root" in observed["configured_user_interpretation"]


def test_rnf06_missing_process_does_not_fabricate_effective_capabilities():
    observed = rnf06.process_status(-1)
    assert observed["available"] is False
    assert "CapEff" not in observed


def test_rnf06_recognizes_all_five_current_laboratories_and_separates_legacy():
    for prefix in ("nova", "nf1", "nf2", "nf3", "nf4"):
        for suffix in ("sender", "receiver-a", "app-crm", "portal-ops"):
            assert rnf06.container_scope(prefix + "-" + suffix) == "current_five_laboratories"
    assert rnf06.container_scope("v2-sender") == "legacy_v2"
    for excluded in ("nf5-sender", "nf10-sender", "nf1--sender", "nf1-sender\n", "other-sender"):
        assert rnf06.container_scope(excluded) is None


def test_rnf06_current_banks_reach_read_only_inspect_projection(monkeypatch):
    names = ["nova-sender", "nf1-sender", "nf2-sender", "nf3-sender", "nf4-sender"]
    calls = []
    def command(arguments, **kwargs):
        calls.append(arguments)
        if arguments[1:3] == ["ps", "-a"]:
            return SimpleNamespace(returncode=0, stdout="\n".join([*names, "nf5-sender"]))
        assert arguments[1:3] == ["container", "inspect"]
        assert arguments[5:] == names
        return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps({
            "name": "/" + name, "configured_user": "", "pid": 0,
            "running": False, "privileged": False, "cap_add": ["CAP_NET_RAW"],
            "cap_drop": ["ALL"], "readonly_rootfs": True, "security_opt": []}) for name in names))
    monkeypatch.setattr(rnf06.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(rnf06.subprocess, "run", command)
    observed = rnf06.container_observations()
    assert len(calls) == 2
    assert len(observed["containers"]) == 5
    assert all(item["observation_scope"] == "current_five_laboratories" for item in observed["containers"])


def test_rnf06_process_projection_requires_real_fields_and_excludes_free_text():
    status = {"Uid": "0\t0\t0\t0", "Gid": "0\t0\t0\t0", "CapEff": "0000000000002000",
              "CapPrm": "0000000000002000", "CapBnd": "0000000000002000", "unrelated_private_field": "do not copy"}
    projected = rnf06.projected_process_status(status)
    assert projected["available"]
    assert projected["decoded_capabilities"]["CapEff"] == ["CAP_NET_RAW"]
    assert "unrelated_private_field" not in projected
    del status["CapEff"]
    assert not rnf06.projected_process_status(status)["available"]


def test_rnf06_reuses_15_current_receipts_without_docker_or_secret_fields(tmp_path, monkeypatch):
    folder = tmp_path / "docs/verificacion-postevaluacion"
    folder.mkdir(parents=True)
    process = {"Uid": "0\t0\t0\t0", "Gid": "0\t0\t0\t0", "CapEff": "0000000000002000",
               "CapPrm": "0000000000002000", "CapBnd": "0000000000002000"}
    paths = []
    for lab, prefix in {"original": "nova", "sucursal": "nf1", "comercial": "nf2", "mixto": "nf3", "reforzado": "nf4"}.items():
        for segment, suffix in {"corp": "app-crm", "dc": "sender", "dmz": "portal"}.items():
            name = prefix + "-" + suffix
            receipt = {"schema": "novaflow-real-isolation-segment/1", "execution": "REAL", "lab": lab,
                "segment": segment, "status": "PASS", "representative": {"source": name},
                "privileges": {"pid1": process, "exec_process": process, "exec_uid": 0, "exec_euid": 0, "exec_gid": 0},
                "container_snapshots": {name: {"user": "", "cap_add": ["CAP_NET_RAW"], "cap_drop": ["ALL"],
                    "privileged": False, "running": True, "Env": ["PRIVATE_FIELD=do not copy"]}}}
            path = folder / (lab + "-" + segment + ".json")
            path.write_text(json.dumps(receipt))
            paths.append(path)
    def forbid_command(*args, **kwargs):
        raise AssertionError("No subprocess is authorized when reusing isolation receipts")
    monkeypatch.setattr(rnf06.subprocess, "run", forbid_command)
    result = rnf06.isolation_observations(tmp_path, paths)
    assert result["coverage_complete_15_representatives"]
    assert len(result["representative_processes"]) == 15
    assert len(result["containers"]) == 15
    assert "Env" not in json.dumps(result)
    assert "do not copy" not in json.dumps(result)


def test_rnf06_original_integrado_alias_cannot_double_count_one_bank(tmp_path):
    folder = tmp_path / "docs/verificacion-postevaluacion"
    folder.mkdir(parents=True)
    paths = []
    for lab in ("original", "integrado"):
        data = {"schema": "novaflow-real-isolation-segment/1", "execution": "REAL", "lab": lab,
                "segment": "dc", "status": "PARTIAL", "representative": {"source": "nova-sender"}}
        path = folder / (lab + ".json")
        path.write_text(json.dumps(data))
        paths.append(path)
    with pytest.raises(ValueError, match="duplicate_isolation_segment"):
        rnf06.isolation_observations(tmp_path, paths)
