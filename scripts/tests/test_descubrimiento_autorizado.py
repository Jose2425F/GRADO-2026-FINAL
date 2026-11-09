"""Comprobaciones sin tráfico del alcance registrado en el descubrimiento por IP."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime")

import autorizacion_personal as A
import descubrimiento_red as D
import laboratorio_personal as P


def xml_hosts(addresses):
    hosts = ''.join('<host><status state="up"/><address addr="' + address +
                    '" addrtype="ipv4"/></host>' for address in addresses)
    return ('<nmaprun>' + hosts + '<runstats><finished exit="success"/></runstats></nmaprun>').encode()


@pytest.fixture
def permit(tmp_path, monkeypatch):
    directory = tmp_path / 'private'
    directory.mkdir(mode=0o700)
    path = directory / 'authorizations.json'
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE', str(path))
    calls = []

    def build(ipv4='192.0.2.10', ipv6='fd00::10', interface='eth0', automatic=False):
        raw = {'ipv4': ipv4, 'ipv6': ipv6, 'interface': interface}
        raw.update({'port_mode': 'auto'} if automatic else {'ports': [80, 443]})
        config = P.configuration(raw)
        options = {'authorization': 'LAB-EXPLICITO', 'personal': config, 'creds': False, 'applications': []}
        A.issue_authorization(path, options['authorization'], options, 'operador de prueba',
                              'permiso ficticio del laboratorio de pruebas',
                              (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        targets = [P.target_for(family, address, config) for family, address in P.scope_hosts(config)]
        def resolve(selected, **kwargs):
            return [P.target_for(family, address, selected) for family, address in P.scope_hosts(selected)]
        monkeypatch.setattr(P, 'resolve_targets', Mock(side_effect=resolve))
        monkeypatch.setattr(D.shutil, 'which', lambda name: '/usr/bin/' + name)
        monkeypatch.setattr(D, '_addresses', lambda name: [])
        monkeypatch.setattr(D, '_neighbors', lambda name: {t.address: '02:00:00:00:00:01' for t in targets})

        def run(command, timeout):
            calls.append(command)
            assert 0 < timeout <= 60
            if command[0] == 'nmap':
                return SimpleNamespace(returncode=0, stdout=xml_hosts([t.address for t in targets if ':' not in t.address]))
            assert command[0] == 'ping'
            return SimpleNamespace(returncode=0, stdout=('64 bytes from ' + command[-1] + ': icmp_seq=1\n').encode())
        monkeypatch.setattr(D, '_run', run)
        return options, targets, calls, run, path
    return build


def test_missing_reference_emits_no_commands(monkeypatch):
    runner = Mock()
    monkeypatch.setattr(D, '_run', runner)
    for reference in [None, '', '   ']:
        with pytest.raises(ValueError, match='autorización'):
            D.discover('eth0', reference)
    runner.assert_not_called()


def test_unknown_reference_emits_no_commands(tmp_path, monkeypatch):
    runner = Mock()
    monkeypatch.setattr(D, '_run', runner)
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE', str(tmp_path / 'absent' / 'registry.json'))
    with pytest.raises(A.AuthorizationError):
        D.discover('eth0', 'SIN-PERMISO')
    runner.assert_not_called()


def test_only_registered_addresses_are_probed_and_returned(permit):
    options, targets, calls, _, _ = permit()
    result = D.discover('eth0', options['authorization'])
    assert result['discovery_scope'] == 'registered_assets_only'
    assert result['hosts'] == [{'mac': '02:00:00:00:00:01', 'ipv4': ['192.0.2.10'], 'ipv6': ['fd00::10']}]
    assert result['segments'] == {'name': 'eth0', 'ipv4': ['192.0.2.10'], 'ipv6': ['fd00::10']}
    assert result['authorization']['reference'] == options['authorization']
    nmap = calls[0]
    assert nmap[-1] == '192.0.2.10'
    assert '-PS80,443' in nmap
    assert '--max-retries' in nmap
    assert all('/' not in argument for argument in nmap)
    assert calls[1] == ['ping', '-6', '-c', '1', '-W', '1', '-I', 'eth0', 'fd00::10']
    assert not any('ff02' in argument.lower() for command in calls for argument in command)


def test_authorized_ipv4_range_is_expanded_into_literals(permit):
    options, targets, calls, _, _ = permit('192.0.2.10-192.0.2.11', '')
    result = D.discover('eth0', options['authorization'])
    assert calls[0][-2:] == ['192.0.2.10', '192.0.2.11']
    assert all('-' not in argument for argument in calls[0][-2:])
    assert result['hosts'][0]['ipv4'] == ['192.0.2.10', '192.0.2.11']


def test_automatic_scope_uses_bounded_discovery_probe_ports(permit):
    options, _, calls, _, _ = permit('192.0.2.10', '', automatic=True)
    D.discover('eth0', options['authorization'])
    assert '-PS' + ','.join(map(str, D.PROBES)) in calls[0]


def test_interface_mismatch_denied_before_routes_or_probes(permit):
    options, _, calls, _, _ = permit()
    with pytest.raises(ValueError, match='interfaz'):
        D.discover('eth1', options['authorization'])
    P.resolve_targets.assert_not_called()
    assert calls == []


def test_unexpected_ipv4_in_xml_is_not_accepted_or_probed(permit, monkeypatch):
    options, _, calls, original, _ = permit()
    def wrong(command, timeout):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=xml_hosts(['192.0.2.10', '192.0.2.99']))
    monkeypatch.setattr(D, '_run', wrong)
    with pytest.raises(ValueError, match='alcance autorizado'):
        D.discover('eth0', options['authorization'])
    assert len(calls) == 1
    assert not any('192.0.2.99' in command for command in calls)


def test_unexpected_ipv6_reply_does_not_expand_authorized_scope(permit, monkeypatch):
    options, _, calls, _, _ = permit('', 'fd00::10')
    def wrong(command, timeout):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=b'64 bytes from fd00::99: icmp_seq=1\n')
    monkeypatch.setattr(D, '_run', wrong)
    with pytest.raises(ValueError, match='origen distinto'):
        D.discover('eth0', options['authorization'])
    assert len(calls) == 1
    assert calls[0][-1] == 'fd00::10'


def test_revocation_after_first_process_prevents_remaining_probes(permit, monkeypatch):
    options, _, calls, original, path = permit()
    def revoke_after_first(command, timeout):
        result = original(command, timeout)
        A.revoke_authorization(path, options['authorization'])
        return result
    monkeypatch.setattr(D, '_run', revoke_after_first)
    with pytest.raises(A.AuthorizationError) as error:
        D.discover('eth0', options['authorization'])
    assert error.value.reason_code == 'authorization_revoked'
    assert len(calls) == 1
    assert calls[0][0] == 'nmap'


def test_neighbors_outside_the_scope_are_not_returned(permit, monkeypatch):
    options, _, calls, _, _ = permit('192.0.2.10', '')
    monkeypatch.setattr(D, '_neighbors', lambda name: {'192.0.2.10': '02:00:00:00:00:01',
                                                     '192.0.2.99': '02:00:00:00:00:99'})
    result = D.discover('eth0', options['authorization'])
    assert result['hosts'] == [{'mac': '02:00:00:00:00:01', 'ipv4': ['192.0.2.10'], 'ipv6': []}]
    assert len(calls) == 1


def test_mac_refresh_only_probes_a_registered_responding_address(permit, monkeypatch):
    options, _, calls, _, _ = permit('192.0.2.10', '')
    reads = iter([{}, {'192.0.2.10': '02:00:00:00:00:01'}])
    monkeypatch.setattr(D, '_neighbors', lambda name: next(reads))
    result = D.discover('eth0', options['authorization'])
    assert [command[0] for command in calls] == ['nmap', 'ping']
    assert calls[1][-1] == '192.0.2.10'
    assert result['hosts'][0]['ipv4'] == ['192.0.2.10']


def test_nmap_failure_cannot_continue_with_ipv6_probes(permit, monkeypatch):
    options, _, calls, _, _ = permit()
    def failed(command, timeout):
        calls.append(command)
        return SimpleNamespace(returncode=1, stdout=b'')
    monkeypatch.setattr(D, '_run', failed)
    with pytest.raises(ValueError, match='no terminó'):
        D.discover('eth0', options['authorization'])
    assert len(calls) == 1


def test_route_change_before_first_probe_is_rejected(permit, monkeypatch):
    options, targets, calls, _, _ = permit('192.0.2.10', '')
    altered = targets[0].model_copy(update={'interface': 'eth1'})
    monkeypatch.setattr(P, 'resolve_targets', Mock(side_effect=[targets, [altered]]))
    with pytest.raises(ValueError, match='ruta del activo cambió'):
        D.discover('eth0', options['authorization'])
    assert calls == []


def test_incomplete_nmap_xml_cannot_be_treated_as_no_hosts(permit, monkeypatch):
    options, _, calls, _, _ = permit('192.0.2.10', '')
    def incomplete(command, timeout):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=b'<nmaprun/>')
    monkeypatch.setattr(D, '_run', incomplete)
    with pytest.raises(ValueError, match='no está completo'):
        D.discover('eth0', options['authorization'])
    assert len(calls) == 1
