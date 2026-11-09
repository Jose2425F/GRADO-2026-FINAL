"""El permiso se decide con un registro privado, no con una IP ni un texto libre."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from autorizacion_personal import (AuthorizationError, AuthorizationGuard,
    authorized_options, issue_authorization, revoke_authorization)


NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)


def options(**changes):
    value = {'scope': 'personal', 'authorization': 'LAB-VALIDADO-01',
             'personal': {'ipv4': '192.168.56.10', 'ipv6': 'fd00::10',
                          'ports': [22, 80], 'interface': 'eth0'},
             'creds': False, 'applications': []}
    value.update(changes)
    return value


def app(**changes):
    value = {'name': 'Aplicación propia', 'ipv4': '192.168.56.10', 'port': 80,
             'session': 'recurso-propio', 'scope_confirmed': True,
             'own_path': '/documentos/10', 'own_marker': 'PROPIO-MARCADOR',
             'foreign_path': '/documentos/11', 'foreign_marker': 'AJENO-MARCADOR'}
    value.update(changes)
    return value


@pytest.fixture
def registry(tmp_path):
    return tmp_path / 'operador' / 'authorizations.json'


def issue(registry, value=None, reference='LAB-VALIDADO-01', **kwargs):
    return issue_authorization(registry, reference, value or options(),
        'responsable-del-laboratorio', 'acta-20261109-01',
        (NOW + timedelta(hours=2)).isoformat(), now=kwargs.pop('now', NOW), **kwargs)


def load(registry):
    return json.loads(registry.read_text())


def edit(registry, callback):
    data = load(registry)
    callback(data)
    registry.write_text(json.dumps(data))


def denied(code, function):
    with pytest.raises(AuthorizationError) as error:
        function()
    assert error.value.reason_code == code


def test_authorized_ipv4_and_ipv6_are_bound_to_operator_scope(registry):
    receipt = issue(registry)
    guard = AuthorizationGuard(options(), registry_path=registry, now=NOW)
    target = lambda address: SimpleNamespace(address=address, interface='eth0', ports=[80])
    assert guard.check_targets([target('192.168.56.10'), target('fd00::10')]) == receipt
    assert set(receipt) == {'reference', 'approved_by', 'evidence_ref', 'issued_at',
                            'expires_at', 'scope_sha256', 'grant_sha256'}
    assert len(receipt['scope_sha256']) == len(receipt['grant_sha256']) == 64
    assert 'scope' not in receipt and 'personal' not in receipt
    assert registry.stat().st_mode & 0o777 == 0o600
    assert registry.parent.stat().st_mode & 0o777 == 0o700


def test_private_ip_and_free_authorization_text_do_not_create_a_permission(registry):
    denied('authorization_registry_missing', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))
    assert not registry.exists()
    issue(registry, reference='OTRA-REFERENCIA')
    denied('authorization_not_registered', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


@pytest.mark.parametrize('change', [
    {'personal': {'ipv4': '192.168.56.11', 'ipv6': 'fd00::10', 'ports': [22, 80], 'interface': 'eth0'}},
    {'personal': {'ipv4': '192.168.56.10', 'ipv6': 'fd00::10', 'ports': [22, 443], 'interface': 'eth0'}},
    {'personal': {'ipv4': '192.168.56.10', 'ipv6': 'fd00::10', 'ports': [22, 80], 'interface': 'eth1'}},
    {'creds': True}, {'applications': [app()]},
])
def test_a_registered_reference_does_not_authorize_a_different_scope(registry, change):
    issue(registry)
    denied('authorization_scope_mismatch', lambda: AuthorizationGuard(
        options(**change), registry_path=registry, now=NOW))


def test_an_automatic_interface_is_not_a_stable_authorization(registry):
    value = options()
    value['personal']['interface'] = 'auto'
    denied('authorization_interface_required', lambda: issue(registry, value))
    assert not registry.exists()


@pytest.mark.parametrize('address,interface,ports,code', [
    ('192.168.56.99', 'eth0', [80], 'authorization_target_denied'),
    ('fd00::99', 'eth0', [80], 'authorization_target_denied'),
    ('192.168.56.10', 'eth1', [80], 'authorization_target_denied'),
    ('192.168.56.10', 'eth0', [443], 'authorization_ports_denied'),
    ('192.168.56.10', 'eth0', [], 'authorization_ports_denied'),
    ('192.168.56.10', 'eth0', [True], 'authorization_ports_denied'),
    ('example.test', 'eth0', [80], 'authorization_target_denied'),
])
def test_each_dispatched_target_is_checked_again(registry, address, interface, ports, code):
    issue(registry)
    guard = AuthorizationGuard(options(), registry_path=registry, now=NOW)
    denied(code, lambda: guard.check_targets([{
        'address': address, 'interface': interface, 'ports': ports}]))


def test_automatic_ports_require_an_explicit_grant_of_that_mode(registry):
    value = options(personal={'ipv4': '192.168.56.10', 'ipv6': '',
                             'ports': [], 'interface': 'eth0', 'port_mode': 'auto'})
    issue(registry, value)
    guard = AuthorizationGuard(value, registry_path=registry, now=NOW)
    assert guard.check_targets([{'address': '192.168.56.10', 'interface': 'eth0', 'ports': [443]}])
    denied('authorization_ports_denied', lambda: guard.check_targets([
        {'address': '192.168.56.10', 'interface': 'eth0', 'ports': [65536]}]))


def test_expiry_and_revocation_take_effect_after_preflight(registry):
    clock = [NOW]
    issue(registry)
    guard = AuthorizationGuard(options(), registry_path=registry, now=lambda: clock[0])
    clock[0] = NOW + timedelta(hours=2)
    denied('authorization_expired', guard.verify)
    clock[0] = NOW
    revoke_authorization(registry, 'LAB-VALIDADO-01', now=NOW)
    denied('authorization_revoked', guard.verify)
    denied('authorization_revoked', lambda: authorized_options(
        'LAB-VALIDADO-01', registry_path=registry, now=NOW))
    assert load(registry)['authorizations'][0]['revoked'] is True


def test_future_and_expired_records_are_rejected(registry):
    issue(registry, now=NOW + timedelta(hours=1))
    denied('authorization_not_yet_valid', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))
    denied('authorization_expired', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW + timedelta(hours=2)))


def test_operator_modification_requires_a_fresh_preflight(registry):
    issue(registry)
    guard = AuthorizationGuard(options(), registry_path=registry, now=NOW)
    edit(registry, lambda data: data['authorizations'][0].update(evidence_ref='acta-cambiada'))
    denied('authorization_changed', guard.verify)
    assert AuthorizationGuard(options(), registry_path=registry, now=NOW).verify()['evidence_ref'] == 'acta-cambiada'


def test_duplicate_references_are_rejected_and_cannot_shadow_a_record(registry):
    issue(registry)
    denied('authorization_reference_duplicate', lambda: issue(registry))
    edit(registry, lambda data: data['authorizations'].append(deepcopy(data['authorizations'][0])))
    denied('authorization_reference_duplicate', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


def test_duplicate_json_keys_and_unknown_fields_are_rejected(registry):
    issue(registry)
    data = registry.read_text()
    registry.write_text(data.replace('"version":1', '"version":1,"version":1'))
    denied('authorization_registry_invalid', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))
    registry.write_text(data)
    edit(registry, lambda value: value['authorizations'][0].update(untrusted='field'))
    denied('authorization_registry_invalid', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


@pytest.mark.parametrize('field', ['issued_at', 'expires_at'])
def test_dates_without_timezone_are_rejected(registry, field):
    issue(registry)
    edit(registry, lambda data: data['authorizations'][0].update({field: '2026-11-09T12:00:00'}))
    denied('authorization_time_invalid', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


def test_permissions_of_file_and_immediate_parent_are_required(registry):
    issue(registry)
    registry.chmod(0o640)
    denied('authorization_registry_unsafe', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))
    registry.chmod(0o600)
    registry.parent.chmod(0o750)
    denied('authorization_registry_unsafe', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


def test_writable_ancestor_is_rejected_even_with_a_private_leaf(tmp_path):
    ancestor = tmp_path / 'shared'
    ancestor.mkdir(mode=0o770)
    denied('authorization_registry_unsafe', lambda: issue(ancestor / 'private' / 'grants.json'))


def test_symbolic_and_hard_links_are_rejected(registry, tmp_path):
    issue(registry)
    saved = registry.with_name('saved.json')
    registry.rename(saved)
    registry.symlink_to(saved)
    denied('authorization_registry_unsafe', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))
    denied('authorization_registry_unsafe', lambda: issue(registry, reference='OTRO-PERMISO'))
    registry.unlink()
    os.link(saved, registry)
    denied('authorization_registry_unsafe', lambda: AuthorizationGuard(
        options(), registry_path=registry, now=NOW))


def test_symbolic_parent_is_rejected(registry, tmp_path):
    issue(registry)
    link = tmp_path / 'alias'
    link.symlink_to(registry.parent, target_is_directory=True)
    denied('authorization_registry_unsafe', lambda: AuthorizationGuard(
        options(), registry_path=link / registry.name, now=NOW))


def test_request_cannot_select_a_different_registry(registry, monkeypatch, tmp_path):
    issue(registry)
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE', str(tmp_path / 'missing' / 'file.json'))
    denied('authorization_scope_invalid', lambda: AuthorizationGuard(
        options(registry_path=str(registry)), now=NOW))
    denied('authorization_registry_missing', lambda: AuthorizationGuard(options(), now=NOW))


def test_registered_options_are_recovered_without_exposing_other_grants(registry, monkeypatch):
    receipt = issue(registry)
    issue(registry, reference='LAB-OTRO-02')
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE', str(registry))
    value = authorized_options('LAB-VALIDADO-01', now=NOW)
    assert value == {key: options()[key] for key in ['authorization', 'personal', 'creds', 'applications']}
    value['personal']['ports'].append(443)
    assert AuthorizationGuard(options(), now=NOW).verify() == receipt
    assert 'LAB-OTRO-02' not in json.dumps(authorized_options('LAB-VALIDADO-01', now=NOW))


def test_service_data_directory_and_explicit_server_override(registry, monkeypatch, tmp_path):
    receipt = issue(registry)
    monkeypatch.delenv('CENTINELA_AUTHORIZATIONS_FILE', raising=False)
    monkeypatch.setenv('CENTINELA_DATA_DIR', str(registry.parent))
    assert AuthorizationGuard(options(), now=NOW).verify() == receipt
    override = tmp_path / 'override' / 'authorizations.json'
    issue(override, reference='LAB-SERVIDOR-02')
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE', str(override))
    denied('authorization_not_registered', lambda: AuthorizationGuard(options(), now=NOW))
    assert authorized_options('LAB-SERVIDOR-02', now=NOW)['authorization'] == 'LAB-SERVIDOR-02'


def test_features_and_exact_web_paths_are_part_of_the_grant(registry):
    value = options(creds=True, applications=[app()])
    issue(registry, value)
    guard = AuthorizationGuard(value, registry_path=registry, now=NOW)
    for name in ['inventory', 'credentials', 'applications']:
        assert guard.require_feature(name)
    assert guard.check_application(app())
    denied('authorization_application_denied', lambda: guard.check_application(app(foreign_path='/documentos/12')))
    denied('authorization_feature_denied', lambda: guard.require_feature('arbitrary-command'))
    other = registry.with_name('other.json')
    issue(other)
    guard = AuthorizationGuard(options(), registry_path=other, now=NOW)
    denied('authorization_feature_denied', lambda: guard.require_feature('credentials'))
    denied('authorization_feature_denied', lambda: guard.require_feature('applications'))


def test_parallel_operator_issuance_does_not_lose_records(registry):
    def create(index):
        return issue(registry, reference=f'LAB-PARALELO-{index}')
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(create, range(8)))
    assert len(receipts) == len(load(registry)['authorizations']) == 8
    assert len({receipt['reference'] for receipt in receipts}) == 8
