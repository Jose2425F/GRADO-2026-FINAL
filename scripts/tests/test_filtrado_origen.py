from copy import deepcopy
import json

import pytest

from tesis.filtrado_origen import (FirewallError,compile_auditor,compile_bridge,
                                  validate_policy,policy_for_bank,endpoints_from_topology)


def policy():
    return {'version':1,'name':'test113','audit_uid':1000,'audit_uids':[1000,65532,65533],
      'nodes':[
        {'name':'controller','role':'controller','interface':'pctl0','audit_interface':'eth0','bridge':'br113',
         'mac':'02:ce:11:03:00:01','ipv4':['198.18.113.10'],'ipv6':['fd00:113::10','fe80::ce:11:3:1']},
        {'name':'target','interface':'ptgt0','bridge':'br113','mac':'02:ce:11:03:00:02',
         'ipv4':['198.18.113.20'],'ipv6':['fd00:113::20','fe80::ce:11:3:2']},
      ],'flows':[{'source':'controller','destination':'target','protocol':'tcp','ports':[18080],
                  'uids':[1000]}]}


def test_bridge_pins_physical_origin_mac_and_ip_before_fdb():
    rules=compile_bridge(policy())
    assert 'table bridge centinela_test113' in rules
    assert 'hook prerouting priority -300' in rules
    assert 'meta ibrname "br113" jump source_guard' in rules
    assert 'iifname "pctl0" ether saddr != 02:ce:11:03:00:01' in rules
    assert 'source_ip_denied' in rules and 'unregistered_port_denied' in rules
    assert 'ip saddr 198.18.113.10 ip daddr 198.18.113.20 tcp dport 18080' in rules
    assert 'ip6 saddr { fd00:113::10, fe80::ce:11:3:1 }' in rules
    assert 'origin_flow_denied' in rules
    assert 'host_input_denied' in rules and 'host_output_denied' in rules
    assert 'flush ruleset' not in rules


def test_auditor_uid_interface_and_default_deny_apply_to_both_families():
    rules=compile_auditor(policy())
    assert 'table inet centinela_test113' in rules
    assert 'meta skuid 1000 ip saddr 198.18.113.10' in rules
    assert 'meta skuid 1000 ip6 saddr' in rules
    assert 'oifname "eth0"' in rules
    assert 'policy drop' in rules
    assert 'auditor_output_denied' in rules and 'routing_denied' in rules
    assert 'icmpv6 type 135 @th,64,128' in rules


def test_tools_can_have_disjoint_uids_per_flow():
    p=policy();p['flows'][0]['uids']=[65532]
    assert 'meta skuid 65532' in compile_auditor(p)
    assert 'meta skuid 1000 ip saddr' not in compile_auditor(p)


@pytest.mark.parametrize('change',[
    lambda p:p.update(name='test; flush ruleset'),
    lambda p:p.update(audit_uid=0),
    lambda p:p.update(audit_uids=[0]),
    lambda p:p.update(audit_uids=[True]),
    lambda p:p['nodes'][0].update(interface='eth0; id'),
    lambda p:p['nodes'][0].update(mac='ff:ff:ff:ff:ff:ff'),
    lambda p:p['nodes'][0].update(ipv4=['198.18.113.0/24']),
    lambda p:p['nodes'][0].update(ipv4=['::1']),
    lambda p:p['nodes'][0].update(ipv6=['fe80::10%eth0']),
    lambda p:p['nodes'][0].update(ipv6=['ff02::1']),
    lambda p:p['nodes'][1].update(interface='pctl0'),
    lambda p:p['nodes'][1].update(bridge='other'),
    lambda p:p['flows'][0].update(uids=[0]),
    lambda p:p['flows'][0].update(ports=[True]),
    lambda p:p['flows'][0].update(ports=[]),
    lambda p:p['flows'][0].update(protocol='all'),
    lambda p:p['flows'][0].update(destination='unknown'),
    lambda p:p['flows'][0].update(sources=['198.18.113.30']),
    lambda p:p['flows'][0].update(destinations=['198.18.113.30']),
    lambda p:p['flows'][0].update(destinations=['ff02::1']),
    lambda p:p['flows'][0].update(types=[134]),
])
def test_invalid_or_expanded_policy_is_rejected(change):
    p=policy();change(p)
    with pytest.raises(FirewallError):validate_policy(p)


def test_raw_ipv6_is_explicit_and_does_not_open_other_networks():
    p=policy();p['nodes'][0]['role']='sender'
    p['nodes'].append({'name':'controller','role':'controller','interface':'pctl1','audit_interface':'eth0',
        'bridge':'br113','mac':'02:ce:11:03:00:04','ipv4':['198.18.113.40'],'ipv6':['fd00:113::40']})
    p['flows']=[{'source':'controller','destination':'target','protocol':'tcp','ports':[8000],'uids':[1000]},
        {'source':p['nodes'][0]['name'],'destination':'target','protocol':'icmpv6','types':[134,136],
         'sources':['fe80::ce:11:3:1'],'destinations':['fd00:113::20','ff02::1']},
        {'source':p['nodes'][0]['name'],'destination':'target','protocol':'ipv6_fragment',
         'sources':['fd00:113::10'],'destinations':['fd00:113::20']}]
    # The original source name must remain unique after adding a controller.
    p['nodes'][0]['name']='sender';p['flows'][1]['source']='sender';p['flows'][2]['source']='sender'
    rules=compile_bridge(p)
    assert 'icmpv6 type { 134, 136 }' in rules
    assert 'frag nexthdr { 17, 60 }' in rules
    assert 'notrack comment "profile_frag_notrack"' in rules
    assert 'ip6 daddr { fd00:113::20, ff02::1 }' in rules


def test_input_is_not_modified_by_compilation():
    p=policy();before=json.dumps(p,sort_keys=True)
    compile_auditor(p);compile_bridge(p)
    assert json.dumps(p,sort_keys=True)==before


def bank_fixture():
    from types import SimpleNamespace
    bank=SimpleNamespace(
        NETWORKS={'net':('br113',{'198.18.113.0/24','fd00:113::/64'},
            {'lab-sender','lab-router','lab-receiver','lab-app','lab-cred'})},
        CREDENTIALS={'cred':{'container':'lab-cred','address':'198.18.113.11','services':[('ssh',22),('http-get',8080)]}},
        APPS={'app':{'container':'lab-app','ipv4':'198.18.113.12','ipv6':'fd00:113::12'}},
        RECEIVERS={'receiver':{'container':'lab-receiver','address':'fd00:113::20','dad':'fd00:113::30'}},
        SLAAC_PREFIX='fd00:113:1::/64',SENDER='fd00:113::10')
    endpoints={}
    for i,(name,last,v6) in enumerate([('sender',10,True),('router',254,True),('receiver',20,True),('app',12,True),('cred',11,False)],1):
        address4=f'198.18.113.{last}';address6=f'fd00:113::{last:x}' if v6 else ''
        # El catálogo usa representaciones decimales en las direcciones de ejemplo.
        if name=='sender':address6=bank.SENDER
        if name=='app':address6=bank.APPS['app']['ipv6']
        if name=='receiver':address6=bank.RECEIVERS['receiver']['address']
        endpoints['lab-'+name]={'interface':'peer'+str(i),'bridge':'br113','mac':f'02:ce:11:03:00:{i:02x}',
            'ipv4':[address4],'ipv6':[address6] if address6 else [],
            'configured_ipv4':address4,'configured_ipv6':address6}
    controllers={'br113':{'interface':'pctl0','audit_interface':'eth0','mac':'02:ce:11:03:00:fa',
        'ipv4':['198.18.113.240'],'ipv6':['fd00:113::f0']}}
    return bank,endpoints,controllers


def test_bank_adapter_derives_only_profiles_and_uid_roles():
    bank,endpoints,controllers=bank_fixture()
    p=policy_for_bank(bank,endpoints,controllers,role_uids={'controller':65531,'nmap':65532,'hydra':65533})
    assert p['audit_uid']==65531
    assert p['audit_uids']==[65531,65532,65533]
    cred=[r for r in p['flows'] if r['destination']=='lab-cred' and r['protocol']=='tcp']
    assert {(tuple(r['ports']),tuple(r['uids'])) for r in cred}=={
        ((22,8080),(65532,)),((22,8080),(65533,)),((8080,),(65531,))}
    assert any(r['protocol']=='ipv6_fragment' for r in p['flows'])
    receiver=next(n for n in p['nodes'] if n['name']=='lab-receiver')
    assert 'fd00:113::30' in receiver['ipv6']
    assert any(a.startswith('fd00:113:1:') for a in receiver['ipv6'])


def test_observed_alias_does_not_amplify_bank_authorization():
    bank,endpoints,controllers=bank_fixture()
    endpoints['lab-app']['ipv4'].append('198.18.113.99')
    with pytest.raises(FirewallError,match='fuera del catálogo'):
        policy_for_bank(bank,endpoints,controllers)


def test_bank_adapter_rejects_wrong_bridge_or_missing_role():
    bank,endpoints,controllers=bank_fixture();endpoints['lab-app']['bridge']='other'
    with pytest.raises(FirewallError):policy_for_bank(bank,endpoints,controllers)
    bank,endpoints,controllers=bank_fixture();controllers.clear()
    with pytest.raises(FirewallError):policy_for_bank(bank,endpoints,controllers)


def topology_fixture():
    return {'schema':'centinela-isolated-topology/1','namespace_links':[{'ifindex':9,'ifname':'veth1','master':'br113'}],
        'networks':[{'name':'net','options':{'com.docker.network.bridge.name':'br113'}}],
        'containers':[{'name':'/lab-app','id':'id-fixture','image':'sha256:fixture','running':True,
            'networks':{'net':{'MacAddress':'02:ce:11:03:00:01','IPAddress':'198.18.113.20','GlobalIPv6Address':'fd00:113::20'}},
            'links':[{'ifname':'eth0','link_index':9,'address':'02:ce:11:03:00:01'}],
            'addresses':[{'ifname':'eth0','addr_info':[{'local':'198.18.113.20'},{'local':'fd00:113::20'}]}]}]}


@pytest.mark.parametrize('schema',['centinela-isolated-topology/1','centinela-isolated-topology/2'])
def test_topology_correlates_effective_peer_and_pinned_docker_identity(schema):
    topology=topology_fixture();topology['schema']=schema
    value=endpoints_from_topology(topology)['lab-app']
    assert value['interface']=='veth1' and value['configured_ipv6']=='fd00:113::20'
    assert value['container_id']=='id-fixture'


@pytest.mark.parametrize('change',[
    lambda t:t['namespace_links'][0].update(master='other'),
    lambda t:t['containers'][0]['links'][0].update(address='02:ce:11:03:00:02'),
    lambda t:t['containers'][0].update(running=False),
])
def test_topology_drift_is_rejected(change):
    value=topology_fixture();change(value)
    with pytest.raises(FirewallError):endpoints_from_topology(value)


def test_auditor_plan_uses_exact_routes_and_dedicated_role_ids():
    from ipaddress import ip_address
    from tesis.red_auditoria import plan_bank
    bank,endpoints,_=bank_fixture()
    topology={'schema':'centinela-isolated-topology/2',
        'networks':[{'name':'net','options':{'com.docker.network.bridge.name':'br113'}}],
        'containers':[],'namespace_links':[]}
    for index,(name,node) in enumerate(endpoints.items(),1):
        topology['namespace_links'].append({'ifindex':index,'ifname':node['interface'],'master':'br113'})
        topology['containers'].append({'name':'/'+name,'id':'id-'+name,'image':'sha256:fixture','running':True,
            'networks':{'net':{'MacAddress':node['mac'],'IPAddress':node['configured_ipv4'],
                               'GlobalIPv6Address':node['configured_ipv6']}},
            'links':[{'ifname':'eth0','address':node['mac'],'link_index':index}],
            'addresses':[{'ifname':'eth0','addr_info':[{'local':ip} for ip in node['ipv4']+node['ipv6']]}]})
    plan=plan_bank(bank,topology,tag='abcdef01')
    assert plan['policy']['audit_uids']==[65531,65532,65533]
    assert plan['controllers']['br113']['ipv4']==['198.18.113.240']
    assert plan['controllers']['br113']['ipv6']==['fd00:113::f0','fe80::f0']
    for route in plan['routes']:
        assert str(ip_address(route['address']))==route['address']
        assert route['interface']=='br113'
        assert route['source'] in ['198.18.113.240','fd00:113::f0','fe80::f0']
    assert '198.18.113.99' not in {r['address'] for r in plan['routes']}
    with pytest.raises(FirewallError):plan_bank(bank,topology,tag='x;id')
