"""Entradas públicas sin descriptor: rechazo antes de herramientas, rutas o API."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import laboratorio_empresa as company
import laboratorio_personal as personal
import puertos_personales as automatic
import descubrimiento_red as discovery
from auditoria import cli
from auditoria.secure_runtime import ProtectedRuntimeError
from dualstack_panel import validate_options
from authorization_fixture import personal_authorization


def test_company_without_protected_runtime_records_rejection(tmp_path,monkeypatch):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    options=validate_options({'scope':'empresa','authorization':'LAB-PROPIO','ia':'none'})
    with (patch.object(company.lab,'preflight') as preflight,
          patch.object(company.lab,'load_auditor_environment') as secret,
          patch.object(company.agent,'run_task') as tool,
          patch('auditoria.openai_provider.load_openai_config') as provider):
        assert company.run_panel(options,tmp_path)==3
    for operation in [preflight,secret,tool,provider]:operation.assert_not_called()
    report=json.loads(next(tmp_path.glob('*/report.json')).read_text())
    assert report['reason_code']=='protected_runtime_required'
    assert report['tasks']==report['findings']==[]
    assert report['llm']['known_tokens']==0


@pytest.mark.parametrize('entry',[personal.run,automatic.run_automatic])
def test_personal_valid_asset_authorization_still_needs_protected_roles(tmp_path,monkeypatch,entry):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    options=validate_options({'scope':'personal','authorization':'LAB-PROPIO','ia':'none',
                             'personal':{'ipv4':'127.0.0.1','interface':'lo','ports':[22]}})
    with (personal_authorization(options),patch.object(personal,'resolve_targets') as routes,
          patch.object(personal,'execute_task') as tool,patch.object(personal.subprocess,'run') as process):
        with pytest.raises(ProtectedRuntimeError):entry(options,tmp_path/'results')
    routes.assert_not_called();tool.assert_not_called();process.assert_not_called()
    assert not (tmp_path/'results').exists()


def test_demo_rejects_before_preflight_or_reading_provider_key(tmp_path,monkeypatch):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    with (patch('auditoria.laboratorio.preflight') as preflight,
          patch('auditoria.openai_provider.load_openai_config') as provider):
        with pytest.raises(ProtectedRuntimeError):
            cli.execute_demo(tmp_path,tmp_path/'out','LAB-PROPIO','single',True,True,0,openai=True)
    preflight.assert_not_called();provider.assert_not_called()


def test_v2_rejects_before_preflight_or_reading_provider_key(tmp_path,monkeypatch):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    with (patch('auditoria.lab_v2.preflight') as preflight,
          patch('auditoria.openai_provider.load_openai_config') as provider):
        with pytest.raises(ProtectedRuntimeError):
            cli.execute_v2(tmp_path,tmp_path,tmp_path/'out','LAB-PROPIO','single',live=True,llm=True)
    preflight.assert_not_called();provider.assert_not_called()


@pytest.mark.parametrize('entry,bank_module',[
    (cli.experimento,'auditoria.laboratorio'),
    (cli.experimento_v2,'auditoria.lab_v2'),
])
def test_experiments_reject_before_provider_reset_preflight_or_output(tmp_path,monkeypatch,entry,bank_module):
    monkeypatch.delenv('CENTINELA_RUNTIME_DESCRIPTOR',raising=False)
    with (patch(bank_module+'.compose') as reset,
          patch(bank_module+'.preflight') as preflight,
          patch('auditoria.openai_provider.load_openai_config') as provider):
        with pytest.raises(ProtectedRuntimeError):
            entry.__wrapped__(autorizacion='LAB-PROPIO',salida=tmp_path/'experiment')
    reset.assert_not_called();preflight.assert_not_called();provider.assert_not_called()
    assert not (tmp_path/'experiment').exists()
