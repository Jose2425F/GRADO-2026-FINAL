"""El bloqueo por kernel permanece activo fuera de la fixture de entorno sano."""
import json
from pathlib import Path
from unittest.mock import patch
import sys

import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import laboratorio_empresa as company
import laboratorio_personal as personal
from dualstack_panel import validate_options
from scripts.tests.authorization_fixture import personal_authorization


@pytest.mark.parametrize('taint', [1 << 7, 1 << 14, (1 << 7) | (1 << 14)])
@pytest.mark.parametrize('bank', ['empresa', 'personal'])
def test_kernel_failure_stops_before_routes_tools_or_provider(tmp_path, monkeypatch, taint, bank):
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        return str(taint) if path == Path('/proc/sys/kernel/tainted') else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read_text)
    if bank == 'empresa':
        options = validate_options({'name': 'Prueba de bloqueo', 'authorization': 'LAB-PROPIO',
                                    'scope': 'empresa', 'ia': 'openai'})
        with patch.object(company.lab, 'preflight') as preflight, \
             patch.object(company.agent, 'run_task') as tool, \
             patch('auditoria.openai_provider.OpenAIScheduler') as provider:
            code = company.run_panel(options, tmp_path)
            preflight.assert_not_called()
            tool.assert_not_called()
            provider.assert_not_called()
    else:
        options = {'personal': personal.configuration({'ipv4': '192.0.2.10', 'ports': '22', 'interface': 'eth0'}),
                   'architecture': 'single', 'tokens': 6000, 'ia': 'openai', 'authorization': 'LAB-PROPIO', 'creds': False}
        with personal_authorization(options),patch.object(personal, 'resolve_targets') as routes, \
             patch.object(personal, 'execute_task') as tool, \
             patch('auditoria.openai_provider.OpenAIScheduler') as provider:
            code = personal.run(options, tmp_path)
            routes.assert_not_called()
            tool.assert_not_called()
            provider.assert_not_called()
    assert code == 3
    report = json.loads(next(tmp_path.glob('*/report.json')).read_text())
    assert report['findings'] == []
    assert report['tasks']
    assert all(task['status'] == 'blocked' for task in report['tasks'])
