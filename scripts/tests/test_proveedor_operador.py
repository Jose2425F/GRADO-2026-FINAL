"""Trabajos cerrados del operador, sin red, Docker ni configuración real."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ejecutar_protegido as operator


def options(**changes):
    return {"name": "Trabajo sintético", "scope": "empresa", "mode": "live", "authorization": "LAB-PROPIO",
            "architecture": "single", "ia": "openai", "tokens": 6000, "creds": False, **changes}


def job(tmp_path, value):
    private = tmp_path / "private"; private.mkdir(exist_ok=True)
    path = private / ("job-" + "a" * 32 + ".json")
    path.write_text(json.dumps(value)); path.chmod(0o600)
    return path


def test_live_job_cannot_choose_other_bank_output_provider_or_command(tmp_path, monkeypatch):
    monkeypatch.setattr(operator, "trusted", lambda path, **kwargs: Path(path))
    path = job(tmp_path, {"options": options()})
    parsed = operator.live_options(tmp_path, "integrado", "single", path)
    assert parsed == options()
    assert operator.live_options(tmp_path, "integrado", "single", job(tmp_path, {"options": options(ia="none", tokens=0)}))["tokens"] == 0
    for value in [{"options": options(output="/etc")}, {"options": options(provider_url="https://other.invalid")},
                  {"options": options(scenario="sucursal")}, {"options": options(architecture="multiagent")},
                  {"options": options(), "argv": ["docker"]}, {"options": options(scope="personal")},
                  {"options": options(tokens=60001)}, {"options": options(manual_context={})}]:
        with pytest.raises((ValueError, operator.OperatorError)):
            operator.live_options(tmp_path, "integrado", "single", job(tmp_path, value))


def test_job_path_mode_and_hardlinks_cannot_cross_private_queue(tmp_path, monkeypatch):
    monkeypatch.setattr(operator, "trusted", lambda path, **kwargs: Path(path))
    path = job(tmp_path, {"options": options()})
    for other in [tmp_path / path.name, path.parent / "openai.json"]:
        other.write_text(path.read_text()); other.chmod(0o600)
        with pytest.raises(operator.OperatorError): operator.live_options(tmp_path, "integrado", "single", other)
    path.chmod(0o644)
    with pytest.raises(operator.OperatorError): operator.live_options(tmp_path, "integrado", "single", path)
    path.chmod(0o600)
    import os
    os.link(path, path.parent / "hardlink")
    with pytest.raises(operator.OperatorError): operator.live_options(tmp_path, "integrado", "single", path)


def test_job_cli_is_only_admitted_for_live_action(monkeypatch):
    monkeypatch.setattr(operator.os, "geteuid", lambda: 0)
    for arguments in [["--action", "audit-live"], ["--action", "audit", "--job", "/var/tmp/job.json"]]:
        monkeypatch.setattr(sys, "argv", ["operator", "--base", "/var/tmp/c113-0123456789ab", "--bank", "integrado", *arguments])
        with pytest.raises(SystemExit) as error: operator.main()
        assert error.value.code == 2


def test_invalid_provider_configuration_never_leaks_content(tmp_path, monkeypatch):
    monkeypatch.setattr(operator, "trusted", lambda path, **kwargs: Path(path))
    folder = tmp_path / "private"; folder.mkdir()
    path = folder / "openai.json"; path.write_text('{"secret":"must-never-appear"}'); path.chmod(0o600)
    with pytest.raises(operator.OperatorError) as error: operator.provider_configuration(tmp_path)
    assert "must-never-appear" not in str(error.value)


def test_provider_receipt_counts_generations_without_headers_or_prompts(tmp_path):
    path = tmp_path / "audit.jsonl"
    events = [{"event": "provider_request_started", "endpoint": "responses/input_tokens"},
              {"event": "provider_request_started", "endpoint": "responses"},
              {"event": "provider_request_completed", "endpoint": "responses", "known_tokens": 12},
              {"event": "provider_request_failed", "endpoint": "responses"}]
    path.write_text("".join(json.dumps(row) + "\n" for row in events))
    assert operator.provider_summary(path) == {"generation_calls": 1, "input_token_calls": 1,
                                               "known_tokens": 12, "usage_complete": False}


def test_cancelled_request_cannot_be_recorded_as_known_zero_usage(tmp_path):
    path = tmp_path / "provider-audit.jsonl"
    assert operator.provider_summary(path)["usage_complete"] is False
    path.write_text(json.dumps({"event": "provider_request_started", "endpoint": "responses"}) + "\n")
    result = operator.provider_summary(path)
    assert result["generation_calls"] == 1 and result["known_tokens"] == 0
    assert result["usage_complete"] is False
