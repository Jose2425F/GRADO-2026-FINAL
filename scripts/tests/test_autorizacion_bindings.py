"""Un guard válido no permite ampliar el alcance en los argumentos del adaptador."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import time
from unittest.mock import Mock

import pytest

import aplicaciones_personales as W
import laboratorio_personal as P
import puertos_personales as A
from autorizacion_personal import AuthorizationError, AuthorizationGuard, issue_authorization


@pytest.fixture
def binding(tmp_path):
    now = datetime.now(timezone.utc)
    raw_app = {'name': 'Recurso autorizado', 'ipv4': '192.168.56.10', 'port': 80,
               'session': 'sesion-aprobada', 'scope_confirmed': True,
               'own_path': '/documentos/10', 'own_marker': 'RECURSO-PROPIO-CANARIO',
               'foreign_path': '/documentos/11', 'foreign_marker': 'RECURSO-AJENO-CANARIO'}
    options = {'scope': 'personal', 'authorization': 'ACTA-RO02-01',
               'personal': {'ipv4': '192.168.56.10,192.168.56.11', 'ipv6': 'fd00::10',
                            'ports': [80], 'interface': 'eth0'},
               'creds': False, 'applications': [raw_app]}
    registry = tmp_path / 'operador' / 'authorizations.json'
    issue_authorization(registry, options['authorization'], options,
                        'responsable', 'acta-local', (now + timedelta(hours=1)).isoformat(), now=now)
    guard = AuthorizationGuard(options, registry_path=registry, now=now)
    config = P.configuration(options['personal'])
    app = W.configure_applications([raw_app], config)[0]
    return SimpleNamespace(guard=guard, config=config, app=app)


def test_discovery_cannot_replace_approved_probe_ports(binding, monkeypatch):
    targets = [P.target_for('ipv4', '192.168.56.10', binding.config)]
    changed = {**binding.config, 'ports': [443]}
    # Un rango activa las sondas de descubrimiento; también altera el alcance.
    changed['ipv4'] = '192.168.56.10-192.168.56.11'
    run = Mock(side_effect=AssertionError('No debe emitirse una sonda'))
    routes = Mock(side_effect=AssertionError('No debe consultarse la ruta del alcance ampliado'))
    monkeypatch.setattr(P.subprocess, 'run', run)
    monkeypatch.setattr(P, 'resolve_targets', routes)
    store = Mock()
    with pytest.raises(AuthorizationError):
        P.discover_targets(targets, changed, store, time.monotonic()+20,
                           authorization=binding.guard)
    run.assert_not_called()
    routes.assert_not_called()
    store.event.assert_not_called()


def test_manual_grant_cannot_be_reused_for_a_full_port_scan(binding, monkeypatch):
    target = P.target_for('ipv4', '192.168.56.10', binding.config).model_copy(update={'ports': []})
    task = P.InventoryTask(task_id='puertos-todos', agent_type='ipv4_services',
                           target=target, action_profile=A.PROFILE)
    run = Mock(side_effect=AssertionError('No debe iniciarse Nmap'))
    routes = Mock(side_effect=AssertionError('No debe comprobarse una tarea sin permiso'))
    monkeypatch.setattr(P, 'resolve_targets', routes)
    with pytest.raises(AuthorizationError):
        A.execute_open_task(task, Mock(), time.monotonic()+20, runner=run,
                            authorization=binding.guard)
    run.assert_not_called()
    routes.assert_not_called()


@pytest.mark.parametrize('channel', ['urllib', 'httpclient'])
@pytest.mark.parametrize('address,path', [
    ('192.168.56.10', '/otro-recurso-no-aprobado'),
    # Esta segunda dirección sí pertenece al permiso de inventario, pero no al
    # endpoint web aprobado. Un permiso de red no amplía el permiso de aplicación.
    ('192.168.56.11', '/documentos/10'),
])
def test_web_probe_requires_both_the_approved_endpoint_and_exact_path(
        binding, monkeypatch, channel, address, path):
    routes = Mock(side_effect=AssertionError('No debe comprobarse una ruta web no autorizada'))
    opener = Mock(side_effect=AssertionError('No debe abrirse la URL'))
    client = Mock(side_effect=AssertionError('No debe abrirse la conexión HTTP'))
    monkeypatch.setattr(P, 'resolve_targets', routes)
    monkeypatch.setattr(W, 'build_opener', opener)
    monkeypatch.setattr(W.http.client, 'HTTPConnection', client)
    monkeypatch.setattr(W.http.client, 'HTTPSConnection', client)
    with pytest.raises(AuthorizationError):
        W.fetch(address, binding.app, path, {}, channel, time.monotonic()+20,
                'eth0', authorization=binding.guard)
    routes.assert_not_called()
    opener.assert_not_called()
    client.assert_not_called()
