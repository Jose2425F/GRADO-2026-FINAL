"""RNF-08: dobles de Docker, rutas y sockets. Cero red, bancos y API."""
from copy import deepcopy
import errno
import json
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesis import verificar_aislamiento as checker


@pytest.fixture
def lab():
    return checker.Lab("original", (
        checker.Network("nova_dmz", "br-nova-dmz", ("192.168.71.0/24",), ("nova-portal",)),
        checker.Network("nova_corp", "br-nova-corp", ("192.168.69.0/24", "fd57:2026:69::/64"), ("nova-app-crm",)),
        checker.Network("nova_datacenter", "br-nova-dc", ("192.168.70.0/24", "fd57:2026:70::/64"), ("nova-sender",)),
    ), "fd57:2026:70:1::/64")


def blocked_probe():
    return {"routes": {str(f): {"table": {"returncode": 0, "data": []},
            "rules": {"returncode": 0, "data": [{"priority": 0, "table": "local"}]}}
        for f in (4, 6)}, "probes": [{**target,
            "route_get": {"returncode": 2, "reason": "no_route"},
            "connect": {"status": "blocked", "errno": errno.ENETUNREACH}}
        for target in checker.DESTINATIONS]}


class DockerDouble:
    def __init__(self, lab):
        self.calls = []; self.probe = blocked_probe(); self.inspections = {}
        self.networks = {n.name: {"Name": n.name, "Id": "net-" + n.name,
            "Internal": True, "Driver": "bridge", "IPAM": {"Config": [{"Subnet": s} for s in n.subnets]},
            "Options": {"com.docker.network.bridge.name": n.bridge},
            "Containers": {"id-" + c: {"Name": c} for c in n.members}} for n in lab.networks}
        self.containers = {c: {"id": "id-" + c, "name": "/" + c, "pid": 1234,
            "running": True, "privileged": False, "network_mode": n.name,
            "networks": {n.name: {"NetworkID": "net-" + n.name,
                **{"IPAddress" if checker.ip_network(s).version == 4 else "GlobalIPv6Address":
                   str(checker.ip_network(s).network_address + 10) for s in n.subnets}}}}
            for n in lab.networks for c in n.members}
        self.change_on_inspection = None
        self.namespace_defect = None

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        assert kwargs["check"] is False and kwargs["timeout"] <= 20
        assert kwargs["env"] == checker.MIN_ENV
        assert "shell" not in kwargs
        if command[:5] == [*checker.DOCKER, "network", "inspect"]:
            result = [deepcopy(self.networks[command[-1]])]
        elif command[:5] == [*checker.DOCKER, "container", "inspect"]:
            name = command[-1]; self.inspections[name] = self.inspections.get(name, 0) + 1
            result = deepcopy(self.containers[name])
            if self.change_on_inspection == self.inspections[name]: result["pid"] += 1
        else:
            assert "--net" in command and "--" in command and "-I" in command and "-S" in command
            assert command[-2] == checker.PROBE_SCRIPT
            cfg = json.loads(command[-1])
            assert cfg["destinations"] == list(checker.DESTINATIONS)
            result = deepcopy(self.probe)
            result["links"] = {"returncode": 0, "data": [{"ifname": "eth0", "flags": ["UP", "LOWER_UP"], "operstate": "UP"}]}
            result["addresses"] = {"returncode": 0, "data": [{"ifname": "eth0",
                "addr_info": [{"local": a} for a in cfg["expected_addresses"]]}]}
            for subnet in cfg["segment_subnets"]:
                family = str(checker.ip_network(subnet).version)
                if self.namespace_defect != "missing_route" and family in result["routes"] and isinstance(result["routes"][family], dict):
                    result["routes"][family]["table"]["data"].append({"dst": subnet, "dev": "eth0", "scope": "link"})
            if self.namespace_defect == "link_down": result["links"]["data"][0]["flags"] = []
            elif self.namespace_defect == "missing_address": result["addresses"]["data"][0]["addr_info"] = []
            elif self.namespace_defect == "tentative":
                result["addresses"]["data"][0]["addr_info"][0]["tentative"] = True
        return SimpleNamespace(returncode=0, stdout=json.dumps(result))


def run(lab, double, **kwargs):
    return checker.execute(lab, authorization="LAB-PROPIO", runner=double,
        which=lambda n: "/usr/bin/" + n, euid=lambda: 0, **kwargs)


def test_plan_has_no_approval_and_all_destinations_outside_allowed(lab):
    with patch.object(checker.subprocess, "run", side_effect=AssertionError("No commands")):
        result = checker.plan(lab)
    assert result["status"] == "not_executed" and result["requirement_status"] == "PARCIAL"
    assert result["api_calls"] == result["audit_runs"] == result["lab_mutations"] == 0
    assert result["planned_tcp_attempts"] == 12
    assert all(checker.ip_address(d["address"]).version == d["family"] for d in checker.DESTINATIONS)


@pytest.mark.parametrize("scenario", checker.SCENARIOS)
def test_five_bank_definitions_are_read_only_and_have_three_segments(scenario):
    with patch.object(checker.subprocess, "run", side_effect=AssertionError("No Docker")):
        result = checker.plan(checker.definition(scenario))
    assert len(result["networks"]) == 3 and result["status"] == "not_executed"


def test_empty_bank_cannot_pass():
    with pytest.raises(ValueError): checker.plan(checker.Lab("original", (), "fd57:2026:70:1::/64"))


def test_explicit_authorization_required_before_inspection(lab):
    with pytest.raises(ValueError): checker.execute(lab, authorization="")


def test_all_containers_and_both_families_must_be_proven_blocked(lab):
    double = DockerDouble(lab); result = run(lab, double)
    assert result["status"] == "passed" and result["requirement_status"] == "VALIDADO"
    assert len(result["containers"]) == 3
    assert all(len(c["observations"]["probes"]) == 4 for c in result["containers"])
    assert all(c["namespace_control"]["passed"] for c in result["containers"])
    assert len([c for c, _ in double.calls if "--net" in c]) == 3
    assert all(".Config.Env" not in " ".join(c) for c, _ in double.calls)
    assert all(c[:3] == list(checker.DOCKER) for c, _ in double.calls if c[0] == "docker")


@pytest.mark.parametrize("defect", ["external_network", "extra_member", "wrong_subnet", "wrong_bridge"])
def test_all_networks_validated_before_any_tcp_attempt(lab, defect):
    double = DockerDouble(lab); network = double.networks["nova_datacenter"]
    if defect == "external_network": network["Internal"] = False
    elif defect == "extra_member": network["Containers"]["foreign"] = {"Name": "foreign"}
    elif defect == "wrong_subnet": network["IPAM"]["Config"].append({"Subnet": "10.0.0.0/8"})
    else: network["Options"]["com.docker.network.bridge.name"] = "br-foreign"
    result = run(lab, double)
    assert result["status"] == "failed"
    assert not any("--net" in c for c, _ in double.calls)


@pytest.mark.parametrize("defect", ["external_attachment", "host_mode", "privileged", "stopped"])
def test_unsafe_or_stopped_container_cannot_be_probed(lab, defect):
    double = DockerDouble(lab); container = double.containers["nova-sender"]
    if defect == "external_attachment": container["networks"]["bridge"] = {}
    elif defect == "host_mode": container["network_mode"] = "host"
    elif defect == "privileged": container["privileged"] = True
    else: container["running"] = False
    result = run(lab, double)
    assert result["status"] == "failed" and not any("--net" in c for c, _ in double.calls)


@pytest.mark.parametrize("status,expected", [("connected", "failed"), ("refused", "failed"), ("timeout", "partial"), ("error", "partial")])
def test_nonresponse_is_not_accepted_as_isolation(lab, status, expected):
    double = DockerDouble(lab); double.probe["probes"][0]["connect"] = {"status": status}
    result = run(lab, double)
    assert result["status"] == expected and result["requirement_status"] == "PARCIAL"


@pytest.mark.parametrize("family,destination", [(4, "default"), (6, "default"), (4, "10.99.0.0/16"), (6, "2001:db8::/32")])
def test_external_routes_fail_even_when_connections_are_blocked(lab, family, destination):
    double = DockerDouble(lab)
    double.probe["routes"][str(family)]["table"]["data"].append({"dst": destination, "dev": "eth0"})
    assert run(lab, double)["status"] == "failed"


def test_authorized_slaac_and_link_local_routes_are_not_external(lab):
    double = DockerDouble(lab)
    double.probe["routes"]["6"]["table"]["data"] = [{"dst": "fd57:2026:70:1::/64"}, {"dst": "fe80::/64"}]
    assert run(lab, double)["status"] == "passed"


def test_reachable_route_fails_even_if_no_default_route_is_in_snapshot(lab):
    double = DockerDouble(lab); double.probe["probes"][0]["route_get"] = {"returncode": 0, "data": []}
    assert run(lab, double)["status"] == "failed"


@pytest.mark.parametrize("defect", ["missing_family", "duplicate_probe", "ip_error", "invalid_schema"])
def test_incomplete_probe_cannot_pass(lab, defect):
    double = DockerDouble(lab)
    if defect == "missing_family": double.probe["routes"].pop("6")
    elif defect == "duplicate_probe": double.probe["probes"][1] = deepcopy(double.probe["probes"][0])
    elif defect == "ip_error": double.probe["probes"][0]["route_get"]["reason"] = "ip_error"
    else: double.probe["routes"]["4"] = None
    assert run(lab, double)["status"] == "partial"


def test_container_identity_revalidated_during_each_probe(lab):
    double = DockerDouble(lab); double.change_on_inspection = 3
    assert run(lab, double)["status"] == "partial"


def test_unavailable_binary_does_not_invoke_docker(lab):
    with patch.object(checker.subprocess, "run", side_effect=AssertionError("No commands")):
        result = checker.execute(lab, authorization="LAB-PROPIO", which=lambda _: None)
    assert result["status"] == "partial" and result["issues"] == ["required_binary_missing"]


def test_timeout_keeps_verifiable_partial_receipt_without_exception_text(lab):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("sensitive-not-to-be-printed", 15, output="secret")
    result = run(lab, timeout)
    assert result["issues"] == ["command_timeout"] and result["status"] == "partial"
    assert "secret" not in json.dumps(result) and "sensitive" not in json.dumps(result)


def test_global_deadline_stops_before_new_probe(lab):
    values = iter([0, 241])
    double = DockerDouble(lab); result = run(lab, double, clock=lambda: next(values, 241))
    assert result["issues"] == ["global_time_budget_exhausted"]
    assert not any("--net" in c for c, _ in double.calls)


def test_nonroot_probe_uses_noninteractive_sudo_and_fixed_local_daemon(lab):
    double = DockerDouble(lab)
    result = checker.execute(lab, authorization="LAB-PROPIO", runner=double,
        which=lambda n: "/usr/bin/" + n, euid=lambda: 1000)
    assert result["status"] == "passed"
    probes = [c for c, _ in double.calls if "--net" in c]
    assert all(c[:3] == ["/usr/bin/sudo", "-n", "/usr/bin/nsenter"] for c in probes)


def test_container_and_network_ids_must_match_before_any_probe(lab):
    double = DockerDouble(lab)
    double.containers["nova-portal"]["networks"]["nova_dmz"]["NetworkID"] = "unrelated-id"
    result = run(lab, double)
    assert result["status"] == "failed"
    assert not any("--net" in c for c, _ in double.calls)


@pytest.mark.parametrize("defect", ["link_down", "missing_address", "missing_route", "tentative"])
def test_disconnected_or_unconfigured_namespace_never_passes(lab, defect):
    double = DockerDouble(lab); double.namespace_defect = defect
    result = run(lab, double)
    assert result["status"] == "partial"
    assert all(not c["namespace_control"]["passed"] for c in result["containers"])


def test_shared_deadline_caps_initial_probes_and_final_inspections(lab):
    class Clock:
        value = 0.0
        def __call__(self): return self.value
    clock = Clock(); double = DockerDouble(lab); timings = []
    def advancing_runner(command, **kwargs):
        duration = 19 if "--net" in command else 14
        timings.append({"start": clock.value, "timeout": kwargs["timeout"], "probe": "--net" in command})
        clock.value += min(duration, kwargs["timeout"])
        if duration > kwargs["timeout"]: raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return double(command, **kwargs)
    result = run(lab, advancing_runner, clock=clock)
    assert result["status"] == "partial" and result["elapsed_seconds"] <= 240
    assert result["issues"] == ["command_timeout"]
    assert all(t["start"] < 240 and t["start"] + t["timeout"] <= 240 for t in timings)
    assert timings[-1]["timeout"] == 1
    assert len(result["containers"]) == 3  # Agotamiento en la inspección final, nunca PASS.


def test_receipt_is_private_and_never_overwrites_existing_evidence(lab, tmp_path):
    path = tmp_path / "receipt.json"; checker.write_receipt(path, checker.plan(lab))
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError): checker.write_receipt(path, {})
    target = tmp_path / "target"; target.write_text("keep")
    link = tmp_path / "link"; link.symlink_to(target)
    with pytest.raises(ValueError): checker.write_receipt(link, {})
    assert target.read_text() == "keep"


def test_embedded_probe_uses_finite_socket_operations_and_no_shell(capsys):
    def fake_ip(command, **kwargs):
        assert kwargs["timeout"] == 2 and "shell" not in kwargs
        return SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: Network is unreachable") if "get" in command else SimpleNamespace(returncode=0, stdout="[]", stderr="")
    fake_socket = SimpleNamespace(settimeout=lambda timeout: None,
        connect=lambda _: (_ for _ in ()).throw(OSError(errno.ENETUNREACH, "blocked")), close=lambda: None)
    cfg = json.dumps({"ip": "/usr/sbin/ip", "destinations": checker.DESTINATIONS})
    with patch.object(sys, "argv", ["probe", cfg]), patch.object(subprocess, "run", side_effect=fake_ip), patch.object(socket, "socket", return_value=fake_socket):
        exec(compile(checker.PROBE_SCRIPT, "<negative-probe>", "exec"), {})
    result = json.loads(capsys.readouterr().out)
    assert len(result["probes"]) == 4 and all(p["connect"]["status"] == "blocked" for p in result["probes"])
