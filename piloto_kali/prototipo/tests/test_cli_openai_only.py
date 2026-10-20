from typer.testing import CliRunner

from auditoria.cli import app
from auditoria.laboratorio import request_for_lab


def test_cli_exposes_only_current_provider_flags():
    runner = CliRunner()
    for command in ["demo", "experimento", "piloto-ipv6"]:
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, result.output
        assert "--openai" in result.output
        assert "--gemini" not in result.output
    assert "--sin-ia" in runner.invoke(app, ["experimento", "--help"]).output


def test_lab_request_distinguishes_openai_from_disabled_without_old_provider():
    enabled = request_for_lab("LAB-PROPIO", openai=True)
    disabled = request_for_lab("LAB-PROPIO")
    assert enabled.llm_provider == disabled.llm_provider == "openai"
    assert enabled.llm_mode == "scheduler" and enabled.token_budget > 0
    assert disabled.llm_mode == "disabled" and disabled.token_budget == 0
