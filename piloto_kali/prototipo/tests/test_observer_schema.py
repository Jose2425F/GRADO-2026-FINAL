import copy
import json

import pytest

from auditoria import lab_empresa, lab_v2
from auditoria.observer_schema import ObserverResponseError, packet_observer, virtual_observer


def packets():
    return {"fragments": [{"source":"fd00::1","destination":"fd00::2","id":1,"offset":0,"more":1}],
            "router_advertisements": [{"source":"fe80::1","destination":"ff02::1","hop_limit":255,
                "router_lifetime":1800,"prefix":"fd00::","prefix_length":64,"autonomous":True,"advertised_mtu":None}],
            "neighbor_advertisements": [{"source":"fd00::1","destination":"fd00::2","target":"fd00::3"}],
            "neighbor_solicitations": [], "udp_deliveries": [{"nonce":"a"*16,"source":"fd00::1","length":32}],
            "mtu_changes":[{"mtu":1500,"observed_at":1.0}]}


@pytest.mark.parametrize("key", ["ground_truth","expected","present","defect_key","error","password"])
def test_reserved_and_unknown_fields_rejected_at_every_packet_depth(key):
    values = packets()
    for section in [None,*[name for name,rows in values.items() if rows]]:
        forged = copy.deepcopy(values)
        target = forged if section is None else forged[section][0]
        target[key] = {"nested":"RESERVED_CANARY"}
        with pytest.raises(ObserverResponseError) as caught:
            packet_observer(forged)
        assert str(caught.value) == "observer_schema_rejected"
        assert "RESERVED_CANARY" not in str(caught.value)


@pytest.mark.parametrize("mutation", [
    lambda v:v["udp_deliveries"][0].update(nonce="ground_truth=secret"),
    lambda v:v["fragments"][0].update(source={"ground_truth":True}),
    lambda v:v["router_advertisements"][0].update(autonomous="true"),
    lambda v:v["mtu_changes"][0].update(observed_at=float("nan")),
    lambda v:v.update(fragments=v["fragments"]*65),
])
def test_scalar_types_values_and_collection_limits_are_closed(mutation):
    value=packets();mutation(value)
    with pytest.raises(ObserverResponseError):packet_observer(value)


@pytest.mark.parametrize("bank", [lab_empresa,lab_v2])
def test_production_bank_rejects_error_bodies_and_unexpected_labels(monkeypatch,bank):
    monkeypatch.setattr(bank,"http_json",lambda *args:(500,{"error":"RESERVED_CANARY"}))
    with pytest.raises(ObserverResponseError,match="observer_http_status_rejected"):
        bank.snapshot({"container":"owned","address":"fd00::1"})
    monkeypatch.setattr(bank,"http_json",lambda *args:(200,{**packets(),"ground_truth":"RESERVED_CANARY"}))
    monkeypatch.setattr(bank,"docker",lambda *args:"1500" if "cat" in args else "[]")
    with pytest.raises(ObserverResponseError,match="observer_schema_rejected"):
        bank.snapshot({"container":"owned","address":"fd00::1"})


def virtual():
    return {"asset_id":"receiver","state":{"addresses":[{"ifindex":1,"ifname":"eth0","addr_info":[
        {"family":"inet6","local":"fd00::2","prefixlen":64,"scope":"global"}]}],
        "routes":[],"neighbors":[],"link":[],"kernel_counters":{name:0 for name in
        ("Ip6ReasmReqds","Ip6ReasmOKs","Ip6ReasmFails","Ip6InHdrErrors","Udp6InDatagrams","Icmp6InErrors")},
        "forwarding":{"ipv4":False,"ipv6":False},"udp_deliveries":[]}}


def test_virtual_observer_validates_all_nested_structures_and_identity():
    value=virtual()
    assert virtual_observer(value,"receiver")["state"]["forwarding"] == {"ipv4":False,"ipv6":False}
    nodes=[value,value["state"],value["state"]["kernel_counters"],value["state"]["forwarding"],
           value["state"]["addresses"][0],value["state"]["addresses"][0]["addr_info"][0]]
    for node in nodes:
        node["ground_truth"]="RESERVED_CANARY"
        with pytest.raises(ObserverResponseError):virtual_observer(value,"receiver")
        del node["ground_truth"]
    with pytest.raises(ObserverResponseError):virtual_observer(value,"other")


def test_valid_packet_schema_preserves_only_observed_facts():
    assert packet_observer(packets()) == packets()
    assert "ground_truth" not in json.dumps(packet_observer(packets()))
