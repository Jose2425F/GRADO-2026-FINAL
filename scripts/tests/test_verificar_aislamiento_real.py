"""Pruebas unitarias sin Docker, sockets ni API. No equivalen a ejecución real."""
from copy import deepcopy
from dataclasses import asdict
import errno
import hashlib
from ipaddress import ip_network
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis import verificar_aislamiento_real as real


def test_plan_is_read_only_and_never_validates_requirement():
    with patch.object(real.subprocess,"run",side_effect=AssertionError("no commands")):
        for lab in real.SCENARIOS:
            plan=real.plan(lab)
            assert plan["status"]=="NOT_EXECUTED"
            assert plan["requirement_status"]=="PARCIAL"
            assert {s["segment"] for s in plan["representatives"]}=={"dmz","corp","dc"}
            assert sum(len(s["families"]) for s in plan["representatives"])==5
            assert plan["api_calls"]==plan["audit_runs"]==0


def test_execution_requires_explicit_authorization_before_any_command():
    with patch.object(real.subprocess,"run",side_effect=AssertionError("no commands")):
        with pytest.raises(ValueError,match="explicit_authorization_required"):
            real.execute("original",authorization="")


def test_target_address_must_match_family():
    with pytest.raises(real.CheckError,match="endpoint_address_unavailable"):
        real.address_of({"networks":{"n":{"IPAddress":"fd00::1"}}},"n",4)


def probe(status="blocked",**kw):
    return {"target_container":"peer","family":4,"address":"192.168.71.13","port":8080,"connect":{"status":status},**kw}


def test_negative_requires_live_positive_endpoint_and_routes():
    p=probe();live={("peer",4,"192.168.71.13",8080)}
    assert real.assess_negatives([p],live,"PASS")[0]["status"]=="PASS"
    assert real.assess_negatives([p],set(),"PASS")[0]["status"]=="PARTIAL"
    assert real.assess_negatives([p],live,"PARTIAL")[0]["status"]=="PARTIAL"


@pytest.mark.parametrize("status",["timeout","refused","error"])
def test_timeout_refusal_and_error_are_inconclusive(status):
    live={("peer",4,"192.168.71.13",8080)}
    assert real.assess_negatives([probe(status)],live,"PASS")[0]["status"]=="PARTIAL"


def test_cross_segment_connect_is_failure_even_without_positive_control():
    assert real.assess_negatives([probe("connected")],set(),"PARTIAL")[0]["status"]=="FAIL"


def route_fixture():
    lab=real.definition("original");spec=next(s for s in real.endpoints(lab) if s["segment"]=="dmz")
    info={"networks":{"nova_dmz":{"IPAddress":"192.168.71.11"}}}
    rules={str(f):[{"family":f,"table":254,"action":1,"flags":0,"src_prefix":0,"dst_prefix":0,"tos":0,"selector_attributes":[],"suppress_prefixlen":4294967295}] for f in (4,6)}
    obs={"network_state":{"status":"available","links":[{"index":2,"name":"eth0","up":True,"lower_up":True}],"addresses":[{"address":"192.168.71.11","interface":2,"tentative":False,"dadfailed":False}],"routes":{"4":[{"dst":"192.168.71.0/24","type":1,"interface":2}],"6":[]},"rules":rules}}
    return obs,spec,lab,info


def test_local_route_active_address_and_plain_rules_pass_observed_scope():
    assert real.check_routes(*route_fixture())["status"]=="PASS"


@pytest.mark.parametrize("route",[
    {"dst":"0.0.0.0/0","type":1,"interface":2},
    {"dst":"192.168.69.0/24","type":1,"interface":2},
    {"dst":"192.168.71.0/24","type":1,"interface":2,"gateway":"192.168.71.1"},
    {"dst":"192.168.71.0/24","type":1,"interface":2,"multipath":True},
])
def test_default_other_segment_gateway_and_multipath_fail(route):
    obs,spec,lab,info=route_fixture();obs["network_state"]["routes"]["4"].append(route)
    assert real.check_routes(obs,spec,lab,info)["status"]=="FAIL"


def test_nonstandard_policy_rule_and_missing_routes_fail():
    obs,spec,lab,info=route_fixture();obs["network_state"]["rules"]["4"][0]["table"]=100
    assert real.check_routes(obs,spec,lab,info)["status"]=="FAIL"
    obs,spec,lab,info=route_fixture();obs["network_state"]["routes"]["4"]=[]
    assert real.check_routes(obs,spec,lab,info)["status"]=="FAIL"


def test_missing_netlink_state_is_partial():
    obs,spec,lab,info=route_fixture();obs["network_state"]={"status":"unavailable"}
    assert real.check_routes(obs,spec,lab,info)["status"]=="PARTIAL"


def test_failed_command_never_exposes_stderr_or_stdout():
    def runner(*args,**kwargs):
        assert kwargs["timeout"]<=15
        assert kwargs["env"]==real.MIN_ENV
        return SimpleNamespace(returncode=1,stdout="SECRET_OUT",stderr="SECRET_ERR")
    with pytest.raises(real.CheckError,match="^command_failed$"):
        real.command(["docker"],runner=runner)


def test_receipt_cannot_overwrite_prior_real_attempt(tmp_path):
    path=tmp_path/"receipt.json";real.write_json(path,{"status":"FAIL"})
    with pytest.raises(FileExistsError):real.write_json(path,{"status":"PASS"})
    assert json.loads(path.read_text())["status"]=="FAIL"


def test_remote_program_only_requests_netlink_dumps_and_no_http():
    compile(real.REMOTE,"<remote>","exec")
    assert 'dump(18,' in real.REMOTE and 'dump(22,' in real.REMOTE
    assert 'dump(26,' in real.REMOTE and 'dump(34,' in real.REMOTE
    assert '.sendall(' not in real.REMOTE and 'http' not in real.REMOTE.lower()
    assert '"/proc/1/status"' in real.REMOTE


@pytest.fixture
def kali_bank():
    lab=real.definition("original")
    infos={};addresses=[]
    for network in lab.networks:
        subnets={ip_network(subnet).version:ip_network(subnet) for subnet in network.subnets}
        addresses.append({"ifname":network.bridge,"flags":["UP","LOWER_UP"],"addr_info":[
            {"local":str(subnet.network_address+1),"family":"inet" if family==4 else "inet6",
             "prefixlen":subnet.prefixlen,"scope":"global"} for family,subnet in subnets.items()]})
        for index,name in enumerate(sorted(network.members),10):
            attachment={"IPAddress":str(subnets[4].network_address+index)}
            if 6 in subnets:attachment["GlobalIPv6Address"]=str(subnets[6].network_address+index)
            infos[name]={"id":"id-"+name,"name":"/"+name,"pid":100+index,"running":True,
                "privileged":False,"network_mode":network.name,"networks":{network.name:attachment}}
    state={"addresses":addresses,"routes":{},"rules":{}}
    return lab,infos,state


def kali_case(bank, segment="corp", family=4):
    lab,infos,state=bank
    spec=next(spec for spec in real.selected_kali_specs(lab) if spec["segment"]==segment)
    target=next(target for target in real.targets(spec,infos) if target["family"]==family)
    source=next(source for source in real.kali_sources(lab,spec,state) if source["family"]==family)
    return lab,infos,spec,target,source


class SocketDouble:
    def __init__(self, events, *, connect_error=None, effective=None, bound=None):
        self.events=events;self.local=None;self.connected=False;self.connect_error=connect_error
        self.effective=effective;self.bound=bound
    def settimeout(self,value):
        assert value==0.65;self.events.append("timeout")
    def bind(self,value):
        self.local=value;self.events.append("bind")
    def getsockname(self):
        self.events.append("getsockname")
        return ((self.effective if self.connected and self.effective else self.bound or self.local[0]),12345)
    def connect(self,value):
        self.events.append("connect");self.connected=True
        if self.connect_error:raise self.connect_error
    def close(self):self.events.append("close")
    def send(self,*args):raise AssertionError("TCP payload is forbidden")
    def sendall(self,*args):raise AssertionError("TCP payload is forbidden")


@pytest.mark.parametrize("family",[4,6])
def test_kali_tcp_binds_real_source_and_rechecks_route_before_connect(kali_bank,family):
    lab,infos,spec,target,source=kali_case(kali_bank,family=family)
    events=[];sock=SocketDouble(events)
    def route(address,selected_family,origin):
        assert (address,selected_family,origin)==(target["address"],family,source["address"])
        events.append("route")
        return {"dev":source["interface"],"prefsrc":origin}
    def factory(selected_family,kind):
        assert selected_family==(real.socket.AF_INET if family==4 else real.socket.AF_INET6)
        assert kind==real.socket.SOCK_STREAM
        events.append("socket");return sock
    row=real.kali_tcp_probe(lab,spec,target,source,infos,route_reader=route,socket_factory=factory)
    assert row["status"]=="PASS" and row["payload_bytes"]==0
    assert row["effective_source_address"]==source["address"]
    assert events==["route","socket","timeout","bind","getsockname","route","connect","getsockname","close"]
    assert sock.local[0]==source["address"] and sock.local[1]==0


@pytest.mark.parametrize("defect",["eth0","gateway","other_bridge","wrong_source","blackhole","multipath"])
def test_kali_unsafe_route_never_constructs_socket(kali_bank,defect):
    lab,infos,spec,target,source=kali_case(kali_bank)
    route={"dev":source["interface"],"prefsrc":source["address"]}
    route.update({"eth0":{"dev":"eth0"},"gateway":{"gateway":"192.168.69.254"},
        "other_bridge":{"dev":"br-nova-dc"},"wrong_source":{"prefsrc":"192.168.69.99"},
        "blackhole":{"type":"blackhole"},"multipath":{"nexthops":[{"dev":"eth0"}]}}[defect])
    def forbidden(*args):raise AssertionError("unsafe route must not create sockets")
    row=real.kali_tcp_probe(lab,spec,target,source,infos,route_reader=lambda *args:route,socket_factory=forbidden)
    assert row["status"]=="NO_VERIFICADO" and not row["connection_attempted"]


def test_kali_route_change_after_bind_prevents_connect(kali_bank):
    lab,infos,spec,target,source=kali_case(kali_bank)
    events=[];sock=SocketDouble(events);routes=iter([{"dev":source["interface"]},{"dev":"eth0"}])
    row=real.kali_tcp_probe(lab,spec,target,source,infos,route_reader=lambda *args:next(routes),socket_factory=lambda *args:sock)
    assert row["reason"]=="route_changed_no_connection" and not row["connection_attempted"]
    assert "bind" in events and "connect" not in events


@pytest.mark.parametrize("when",["bind","after_connect"])
def test_kali_effective_source_mismatch_is_failure(kali_bank,when):
    lab,infos,spec,target,source=kali_case(kali_bank)
    events=[];sock=SocketDouble(events,**{"bound" if when=="bind" else "effective":"192.168.69.99"})
    row=real.kali_tcp_probe(lab,spec,target,source,infos,route_reader=lambda *args:{"dev":source["interface"]},socket_factory=lambda *args:sock)
    assert row["status"]=="FAIL"
    assert ("connect" in events)==(when=="after_connect")


@pytest.mark.parametrize("error",[TimeoutError(),OSError(errno.ECONNREFUSED,"synthetic"),OSError(errno.EHOSTUNREACH,"synthetic")])
def test_kali_timeout_refusal_or_unreachable_never_prove_isolation(kali_bank,error):
    lab,infos,spec,target,source=kali_case(kali_bank)
    sock=SocketDouble([],connect_error=error)
    row=real.kali_tcp_probe(lab,spec,target,source,infos,route_reader=lambda *args:{"dev":source["interface"]},socket_factory=lambda *args:sock)
    assert row["status"]=="NO_VERIFICADO" and row["connection_attempted"]


@pytest.mark.parametrize("defect",["documentation","wrong_port","wrong_container","not_running","family_mismatch","broadcast"])
def test_kali_destination_must_be_exact_controlled_active_endpoint(kali_bank,defect):
    lab,infos,spec,target,source=kali_case(kali_bank)
    if defect=="documentation":target["address"]="192.0.2.1"
    elif defect=="wrong_port":target["port"]=443
    elif defect=="wrong_container":target["target_container"]="unknown"
    elif defect=="not_running":infos[target["target_container"]]["running"]=False
    elif defect=="family_mismatch":target["family"]=6
    else:target["address"]="192.168.69.255"
    with patch.object(real.socket,"socket",side_effect=AssertionError("no sockets")),patch.object(real,"kali_route_get",side_effect=AssertionError("no route query")):
        with pytest.raises(real.CheckError):real.kali_tcp_probe(lab,spec,target,source,infos)


@pytest.mark.parametrize("address,family",[("192.168.70.1",4),("192.168.69.0",4),("192.168.69.255",4),("224.0.0.1",4),("0.0.0.0",4),("fd57:2026:69::1",4)])
def test_kali_source_family_and_usable_bridge_range_are_enforced(kali_bank,address,family):
    lab,infos,spec,target,source=kali_case(kali_bank)
    source.update(address=address,family=family)
    with patch.object(real.socket,"socket",side_effect=AssertionError("no sockets")),patch.object(real,"kali_route_get",side_effect=AssertionError("no route query")):
        with pytest.raises(real.CheckError):real.kali_tcp_probe(lab,spec,target,source,infos)


def test_kali_sources_require_assigned_up_nontentative_addresses(kali_bank):
    lab,infos,state=kali_bank;spec=real.selected_kali_specs(lab,segment="corp")[0]
    assert len(real.kali_sources(lab,spec,state))==2
    assert not real.kali_sources(lab,spec,state,source_address="192.168.69.199")
    link=next(row for row in state["addresses"] if row["ifname"]==spec["interface"])
    link["addr_info"][0]["tentative"]=True
    assert all(source["family"]!=4 for source in real.kali_sources(lab,spec,state))
    link["flags"]=[]
    assert not real.kali_sources(lab,spec,state)


def test_kali_intersegment_negative_has_no_fixed_deny_policy_and_never_connects(kali_bank):
    lab,infos,spec,_,source=kali_case(kali_bank)
    other=real.selected_kali_specs(lab,segment="dc")[0]
    target=next(row for row in real.targets(other,infos) if row["family"]==4)
    with patch.object(real.socket,"socket",side_effect=AssertionError("negative has no authorized connection")):
        row=real.kali_passive_negative(lab,target,source,infos,route_reader=lambda *args:{"dev":other["interface"]})
    assert row["status"]=="NO_VERIFICADO" and not row["connection_attempted"]
    assert row["expected_policy"]=="MATRIZ_L3_INTERSEGMENTOS_NO_FIJADA"


@pytest.mark.parametrize("family",[4,6])
def test_kali_external_lookup_uses_only_passive_documentation_address(kali_bank,family):
    _,_,_,_,source=kali_case(kali_bank,family=family)
    queries=[]
    def route(*args):queries.append(args);return {"dev":"eth0","gateway":"10.0.2.2" if family==4 else "fe80::2"}
    with patch.object(real.socket,"socket",side_effect=AssertionError("no external socket")):
        row=real.kali_passive_external(source,{"output_filter_present":False},route_reader=route)
    assert queries==[(real.DOCUMENTATION_ROUTES[family],family,source["address"])]
    assert row["status"]=="NO_VERIFICADO" and row["potential_egress_outside_audit_bridge"]
    assert not row["connection_attempted"] and row["port"] is None


def test_firewall_json_distinguishes_nat_output_and_empty_docker_user(tmp_path):
    path=tmp_path/"rules.json"
    path.write_text(json.dumps({"nftables":[{"table":{"family":"ip","name":"nat"}},
        {"chain":{"family":"ip","table":"nat","name":"OUTPUT","type":"nat","hook":"output","policy":"accept","handle":4}},
        {"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":51}},
        {"rule":{"family":"ip","table":"nat","chain":"OUTPUT","handle":5,"expr":[{"xt":{"name":"addrtype"}},{"counter":{"packets":0,"bytes":0}}]}}]}))
    before=path.read_bytes()
    with patch.object(real.subprocess,"run",side_effect=AssertionError("no privileged nft")):
        result=real.firewall_snapshot(path)
    assert not result["output_filter_present"] and result["docker_user"][0]["rules"]==0
    assert result["opaque_xt"][0]["handle"]==5 and result["nonzero_counters"]==0
    assert path.read_bytes()==before


@pytest.mark.parametrize("address",["192.0.2.1","192.168.69.255","192.168.69.0","0.0.0.0","224.0.0.1"])
def test_cli_rejects_arbitrary_source_ranges_before_commands(address):
    with patch.object(sys,"argv",["checker","--modo","kali","--lab","original","--origen",address]),patch.object(real,"command",side_effect=AssertionError("no commands")):
        with pytest.raises(SystemExit):real.main()


@pytest.mark.parametrize("option,value",[("--interfaz","br-nova-corp"),("--origen","192.168.69.1"),("--segmento","corp"),("--firewall-json","snapshot.json")])
def test_cli_source_options_require_kali_mode(option,value):
    with patch.object(sys,"argv",["checker",option,value]),patch.object(real,"command",side_effect=AssertionError("no commands")):
        with pytest.raises(SystemExit):real.main()


def test_cli_kali_plan_all_labs_is_read_only(capsys):
    with patch.object(sys,"argv",["checker","--modo","kali","--lab","todos","--segmento","corp"]),patch.object(real,"command",side_effect=AssertionError("no commands")):
        assert real.main()==0
    rows=[json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(rows)==5 and all(row["mode"]=="kali" and row["status"]=="NOT_EXECUTED" for row in rows)
    assert all(len(row["representatives"])==1 and row["representatives"][0]["segment"]=="corp" for row in rows)


def test_configuration_never_publishes_environment_fingerprint(tmp_path):
    compose=tmp_path/"compose.json";env=tmp_path/"lab.env"
    compose.write_text(json.dumps({"services":{"synthetic":{"image":"existing:local"}}}))
    env.write_text("LAB_NOVA_PORTAL=SYNTHETIC_ONLY_PRIVATE_VALUE\n");env.chmod(0o600)
    with patch.object(real,"paths",return_value=(compose,env)),patch.object(real,"ROOT",tmp_path):
        result=real.configuration("original")
    encoded=json.dumps(result)
    assert "env_sha256" not in encoded and real.sha256(env) not in encoded
    assert "SYNTHETIC_ONLY_PRIVATE_VALUE" not in encoded


def test_receipt_integrity_sidecar_and_existing_evidence_preserved(tmp_path):
    path=tmp_path/"new-receipt.json"
    real.write_receipt(path,{"status":"NO_VERIFICADO"})
    sidecar=path.with_suffix(".json.sha256")
    assert sidecar.read_text()==real.sha256(path)+"  "+path.name+"\n"
    before=(path.read_bytes(),sidecar.read_bytes())
    with pytest.raises(FileExistsError):real.write_receipt(path,{"status":"PASS"})
    assert before==(path.read_bytes(),sidecar.read_bytes())


def test_kali_lifecycle_stops_after_failure_and_preserves_existing_data(tmp_path,kali_bank):
    lab,infos,state=kali_bank;compose=tmp_path/"compose.json";env=tmp_path/"lab.env"
    compose.write_text("existing configuration");env.write_text("SYNTHETIC_PRIVATE_ENV\n");env.chmod(0o600)
    historical=tmp_path/"historical-run.json";historical.write_text('{"original":true}')
    before={path:path.read_bytes() for path in (compose,env,historical)};commands=[]
    def command(args,**kwargs):
        commands.append(args)
        if "image" in args:return {"id":"existing-local-image"}
        if "network" in args:return {}
        return ""
    config={"compose":"compose.json","env":"lab.env","compose_sha256":real.sha256(compose),"images":["existing:local"]}
    with patch.object(real,"ROOT",tmp_path),patch.object(real,"paths",return_value=(compose,env)),patch.object(real,"configuration",return_value=config),\
         patch.object(real,"protected_check",return_value={"unchanged":True,"files_checked":50}),\
         patch.object(real,"active_jobs",return_value=[]),patch.object(real,"no_running_containers",return_value=True),\
         patch.object(real,"command",side_effect=command),patch.object(real,"inspect_container",side_effect=lambda name:infos[name]),\
         patch.object(real,"check_network",return_value={"status":"PASS"}),\
         patch.object(real,"verify_kali",side_effect=real.CheckError("synthetic_phase_failure")),\
         patch.object(real.socket,"socket",side_effect=AssertionError("no real sockets")):
        receipt=real.execute("original",authorization="LAB-PROPIO",output_dir=tmp_path/"receipts",run_id="synthetic",mode="kali")
    assert all(path.read_bytes()==data for path,data in before.items())
    assert receipt["status"]=="NO_VERIFICADO" and receipt["configuration_unchanged"]
    assert any(args[-6:]==["up","-d","--no-build","--no-recreate","--pull","never"] for args in commands)
    assert any(args[-3:]==["stop","--timeout","2"] for args in commands)
    assert not any(arg in {"down","build","pull","--force-recreate","--volumes"} for args in commands for arg in args)
    assert len(list((tmp_path/"receipts").glob("*.json")))==4
    assert len(list((tmp_path/"receipts").glob("*.sha256")))==4
    encoded=json.dumps(receipt)
    assert "env_sha256" not in encoded and real.sha256(env) not in encoded and "SYNTHETIC_PRIVATE_ENV" not in encoded


def test_kali_complete_phase_connects_only_five_controlled_positive_endpoints(kali_bank):
    lab,infos,state=kali_bank;specs=real.selected_kali_specs(lab)
    segments={spec["segment"]:{"positive_attempts":[],"negative":[],"reason_codes":[]} for spec in specs}
    receipt={"firewall_snapshot":{"output_filter_present":False},"reason_codes":[]}
    allowed={target["address"]:(spec,target) for spec in specs for target in real.targets(spec,infos)}
    connects=[]
    def route(address,family,source=None):
        if address in real.DOCUMENTATION_ROUTES.values():return {"dev":"eth0","gateway":"synthetic_gateway"}
        spec,target=allowed[address]
        selected=next(row for row in real.kali_sources(lab,spec,state) if row["family"]==family)
        return {"dev":spec["interface"],"prefsrc":source or selected["address"]}
    def factory(*args):
        sock=SocketDouble([]);original=sock.connect
        def connect(destination):connects.append(destination);original(destination)
        sock.connect=connect;return sock
    with patch.object(real,"host_network_state",return_value=state),patch.object(real,"kali_route_get",side_effect=route),\
         patch.object(real,"inspect_container",side_effect=lambda name:infos[name]),patch.object(real.socket,"socket",side_effect=factory):
        real.verify_kali(receipt,lab,specs,infos,{spec["network"]:{"status":"PASS"} for spec in specs},segments)
    assert len(connects)==5 and all(address in allowed and port==allowed[address][1]["port"] for address,port in connects)
    assert all(segment["positive_status"]=="PASS" and segment["status"]=="NO_VERIFICADO" for segment in segments.values())
    assert sum(len(segment["negative"]) for segment in segments.values())==8
    assert sum(len(segment["external_route_inspections"]) for segment in segments.values())==5
    assert all(not row["connection_attempted"] for segment in segments.values() for row in segment["negative"]+segment["external_route_inspections"])
    assert receipt["status"]=="NO_VERIFICADO" and receipt["all_containers_stable_during_verification"]


def test_kali_invalid_network_configuration_prevents_all_tcp(kali_bank):
    lab,infos,state=kali_bank;specs=real.selected_kali_specs(lab)
    segments={spec["segment"]:{"positive_attempts":[],"negative":[],"reason_codes":[]} for spec in specs}
    receipt={"reason_codes":[]}
    networks={spec["network"]:{"status":"FAIL" if spec["segment"]=="dmz" else "PASS"} for spec in specs}
    with patch.object(real,"host_network_state",return_value=state),patch.object(real,"inspect_container",side_effect=lambda name:infos[name]),\
         patch.object(real.socket,"socket",side_effect=AssertionError("invalid bank must not transmit")):
        real.verify_kali(receipt,lab,specs,infos,networks,segments)
    assert all(not segment["positive_attempts"] for segment in segments.values())
    assert receipt["status"]=="NO_VERIFICADO"


def test_kali_explicit_but_unassigned_bridge_source_never_connects(kali_bank):
    lab,infos,state=kali_bank;specs=real.selected_kali_specs(lab,source_address="192.168.69.199")
    segments={spec["segment"]:{"positive_attempts":[],"negative":[],"reason_codes":[]} for spec in specs}
    receipt={"reason_codes":[]}
    with patch.object(real,"host_network_state",return_value=state),patch.object(real,"inspect_container",side_effect=lambda name:infos[name]),\
         patch.object(real.socket,"socket",side_effect=AssertionError("unassigned source must not transmit")):
        real.verify_kali(receipt,lab,specs,infos,{spec["network"]:{"status":"PASS"} for spec in specs},segments,source_address="192.168.69.199")
    assert not segments["corp"]["positive_attempts"]
    assert "active_host_source_unavailable_ipv4" in segments["corp"]["reason_codes"]


def test_actual_panel_process_name_is_blocked_without_recording_commandline(tmp_path):
    process=tmp_path/"999999";process.mkdir()
    (process/"cmdline").write_bytes(b"python3\0/path/dualstack_panel.py\0SYNTHETIC_PRIVATE_ARGUMENT\0")
    result=real.active_jobs(tmp_path)
    assert result==[{"pid":999999,"reason":"audit_or_panel_process_present"}]
    assert "SYNTHETIC_PRIVATE_ARGUMENT" not in json.dumps(result)
