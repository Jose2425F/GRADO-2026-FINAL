"""RNF-07: pruebas del verificador con credenciales exclusivamente sintéticas."""
import base64
import csv
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesis import verificar_secretos as checker


SYNTHETIC_PASSWORD = "Synthetic-Only-Pass#42"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


@pytest.fixture
def corpus(tmp_path):
    ref = tmp_path / "piloto_kali/prototipo/.lab-empresa"
    ref.mkdir(parents=True)
    env = ref / "lab.env"
    env.write_text("LAB_NOVA_PORTAL=" + SYNTHETIC_PASSWORD + "\nLAB_FIXTURE_SEED=synthetic-public-seed\n")
    write_json(ref / "compose-pinned.json", {"services": {"dummy": {"environment": {
        "LAB_TARGET_PASSWORD": "${LAB_NOVA_PORTAL}", "LAB_TARGET_USER": "synthetic-user"}}}})
    write_json(ref / "policy.json", {"credentials": {}})
    run_id = "panel/synthetic/run_001"
    run = tmp_path / "piloto_kali/prototipo/corridas" / run_id
    prompt = b'Instruction\n{"context":{"task_states":{"completed":1}},"role":"generalist"}'
    (run / "evidence").mkdir(parents=True)
    (run / "evidence/llm_000_synthetic.txt").write_bytes(prompt)
    call = {"prompt_ref": "evidence/llm_000_synthetic.txt", "prompt_sha256": hashlib.sha256(prompt).hexdigest(), "generation_sent": True}
    write_json(run / "report.json", {"llm": {"calls": [call]}})
    for name in ("request.json", "manifest.json", "plan.json"):
        write_json(run / name, {})
    database = sqlite3.connect(run / "events.sqlite3")
    database.execute("CREATE TABLE events (kind TEXT, payload_json TEXT)")
    database.execute("INSERT INTO events VALUES (?,?)", ("decision", json.dumps(call)))
    database.commit()
    database.close()
    rows = [{"run_id": run_id, "fixture_sha256": hashlib.sha256(env.read_bytes()).hexdigest(), "api_generations": 1}]
    write_json(tmp_path / "docs/evaluacion-langgraph/runs.json", rows)
    csv_path = tmp_path / "docs/evaluacion-langgraph/evaluacion-langgraph-corridas.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id"])
        writer.writeheader()
        writer.writerow({"run_id": run_id})
    return tmp_path, run


def test_original_corpus_checked_without_network_commands_or_mutation(corpus, monkeypatch):
    repo, run = corpus
    before = checker.snapshot([path for path in run.rglob("*") if path.is_file()])

    def forbidden(*args, **kwargs):
        raise AssertionError("No network or process execution is permitted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    receipt = checker.verify(repo, expected_runs=1)
    after = checker.snapshot(list(before))
    assert before == after
    assert not list(run.glob("*-wal")) and not list(run.glob("*-journal"))
    assert receipt["result"]["corpus_check_passed"]
    assert not receipt["result"]["rnf07_exhaustively_closed"]
    assert receipt["coverage"]["original_files_scanned"] == 6
    assert receipt["coverage"]["sqlite"]["databases_read_only_immutable"] == 1
    assert receipt["coverage"]["provider_prompts"]["context_present"] == 1
    assert receipt["references"]["run_fixture_hashes_matched_in_memory"] == 1
    assert SYNTHETIC_PASSWORD not in json.dumps(receipt)
    assert hashlib.sha256(SYNTHETIC_PASSWORD.encode()).hexdigest() not in json.dumps(receipt)


@pytest.mark.parametrize("surface", ["prompt", "report", "database", "binary"])
def test_detects_and_preserves_original_leaks_without_receipt_excerpts(corpus, surface):
    repo, run = corpus
    if surface == "prompt":
        path = run / "evidence/llm_000_synthetic.txt"
        path.write_text(path.read_text() + "\n" + SYNTHETIC_PASSWORD)
    elif surface == "report":
        path = run / "report.json"
        value = json.loads(path.read_text())
        value["retained_state"] = {"password": SYNTHETIC_PASSWORD}
        write_json(path, value)
    elif surface == "database":
        path = run / "events.sqlite3"
        connection = sqlite3.connect(path)
        connection.execute("INSERT INTO events VALUES (?,?)", ("retained_state", json.dumps({"password": SYNTHETIC_PASSWORD})))
        connection.commit()
        connection.close()
    else:
        path = run / "evidence/synthetic.pcap"
        path.write_bytes(b"\x00\x01" + SYNTHETIC_PASSWORD.encode())
    before = path.read_bytes()
    receipt = checker.verify(repo, expected_runs=1)
    assert receipt["detection"]["files_with_matches"] == 1
    assert receipt["result"]["status"] == "coincidencias_requieren_revision"
    assert path.read_bytes() == before
    encoded = json.dumps(receipt)
    assert SYNTHETIC_PASSWORD not in encoded
    assert hashlib.sha256(SYNTHETIC_PASSWORD.encode()).hexdigest() not in encoded
    assert all(set(match) == {"path", "artifact_type", "surface", "types", "count"} for match in receipt["detection"]["matches"])


def test_password_representations_and_basic_authorization():
    matcher = checker.Matcher({"Synthetic Päss#42"}, {"dummy"})
    assert matcher.scan_bytes("Synthetic Päss#42".encode())["known_password_plain"] == 1
    assert matcher.scan_bytes("Synthetic Päss#42".encode("utf-16le"))["known_password_utf16"] == 1
    assert matcher.scan_bytes(b"Synthetic%20P%C3%A4ss%2342")["known_password_url_encoded"] == 1
    assert matcher.scan_bytes(json.dumps("Synthetic Päss#42").encode())["known_password_json_escaped"] == 1
    assert matcher.scan_bytes(base64.b64encode(b"dummy:" + "Synthetic Päss#42".encode()))["known_basic_credential_base64"] == 1


def test_decoded_json_and_unknown_sensitive_fields():
    assert checker.sensitive_fields({"password_env": "LAB_NAME", "credential_ref": "opaque", "password": "[REDACTED]"}) == 0
    assert checker.sensitive_fields({"nested": [{"api_key": "synthetic-unknown-value"}]}) == 1
    matcher = checker.Matcher({"synthetic"})
    escaped = '{"value":"\\u0073ynthetic"}'
    assert not matcher.scan_bytes(escaped.encode())
    assert any(matcher.scan_bytes(text.encode()) for obj in checker.json_objects(escaped) for text in checker.text_values(obj))


@pytest.mark.parametrize("defect", ["missing_prompt", "missing_context", "wrong_hash", "event_mismatch", "fixture_mismatch", "csv_mismatch"])
def test_incomplete_coverage_cannot_pass(corpus, defect):
    repo, run = corpus
    if defect == "missing_prompt":
        (run / "evidence/llm_000_synthetic.txt").unlink()
    elif defect == "missing_context":
        (run / "evidence/llm_000_synthetic.txt").write_text("Instruction only")
    elif defect == "wrong_hash":
        report = json.loads((run / "report.json").read_text())
        report["llm"]["calls"][0]["prompt_sha256"] = "0" * 64
        write_json(run / "report.json", report)
    elif defect == "event_mismatch":
        connection = sqlite3.connect(run / "events.sqlite3")
        connection.execute("DELETE FROM events")
        connection.commit()
        connection.close()
    elif defect == "fixture_mismatch":
        inventory_path = repo / "docs/evaluacion-langgraph/runs.json"
        rows = json.loads(inventory_path.read_text())
        rows[0]["fixture_sha256"] = "0" * 64
        write_json(inventory_path, rows)
    else:
        (repo / "docs/evaluacion-langgraph/evaluacion-langgraph-corridas.csv").write_text("run_id\nother_run\n")
    receipt = checker.verify(repo, expected_runs=1)
    assert receipt["issues"]
    assert not receipt["result"]["corpus_check_passed"]
    assert receipt["result"]["status"] == "cobertura_incompleta"


def test_reference_parser_never_executes_shell(tmp_path):
    path = tmp_path / "lab.env"
    path.write_text("export LAB_NOVA_PORTAL='$(touch never_execute)'\nLAB_FIXTURE_SEED=public\n")
    assert checker.parse_env(path)["LAB_NOVA_PORTAL"] == "$(touch never_execute)"
    assert checker.interpolate("${KNOWN}-suffix", {"KNOWN": "synthetic"}) == "synthetic-suffix"
    assert checker.interpolate("${MISSING}", {}) is None
    assert not (tmp_path / "never_execute").exists()


def test_sqlite_reader_rejects_database_writes(corpus, monkeypatch):
    _, run = corpus
    connect = checker.sqlite3.connect
    connections = []

    def captured(database_uri, **kwargs):
        assert "mode=ro&immutable=1" in database_uri and kwargs["uri"] is True
        connection = connect(database_uri, **kwargs)
        connections.append(connection)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("CREATE TABLE must_not_exist (value TEXT)")
        return connection

    monkeypatch.setattr(checker.sqlite3, "connect", captured)
    counts, coverage, issues, decisions = checker.scan_sqlite(run / "events.sqlite3", checker.Matcher({SYNTHETIC_PASSWORD}))
    assert not counts and not issues
    assert coverage["rows"] == 1 and len(decisions) == 1
    assert len(connections) == 1


def test_cli_refuses_to_overwrite_existing_receipt(corpus, monkeypatch):
    repo, _ = corpus
    output = repo / "docs/verificacion-postevaluacion/receipt.json"
    output.parent.mkdir()
    output.write_text("preserved")
    monkeypatch.setattr(sys, "argv", ["verifier", "--repo", str(repo), "--output", str(output)])
    with pytest.raises(SystemExit):
        checker.main()
    assert output.read_text() == "preserved"


def test_cli_writes_only_new_safe_receipt(corpus, monkeypatch, capsys):
    repo, _ = corpus
    output = repo / "docs/verificacion-postevaluacion/receipt.json"
    actual_verify = checker.verify
    monkeypatch.setattr(checker, "verify", lambda root: actual_verify(root, expected_runs=1))
    monkeypatch.setattr(sys, "argv", ["verifier", "--repo", str(repo), "--output", str(output)])
    assert checker.main() == 0
    assert SYNTHETIC_PASSWORD not in output.read_text()
    assert SYNTHETIC_PASSWORD not in capsys.readouterr().out
