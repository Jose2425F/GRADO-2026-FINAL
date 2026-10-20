import hashlib
import subprocess

from auditoria.agentes.agente_ipv4_servicios import nmap_command, parse_nmap_xml, run_nmap
from auditoria.contracts import Task, Target
from auditoria.store import RunStore


def test_nmap_command_is_fixed_profile():
    task = Task(task_id="t1", agent_type="ipv4_services", target=Target(
        asset_id="a1", address="192.168.57.13", interface="br-lab-audit", ports=[22, 80]),
        protocol="tcp", action_profile="nmap_tcp_services_v1", timeout_seconds=30)
    command = nmap_command(task)
    assert command[0] == "nmap"
    assert command[-1] == "192.168.57.13"
    assert command[command.index("-p") + 1] == "22,80"
    assert "-oX" in command


def test_xml_open_ports_are_inventory():
    raw = b'<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="closed"/></port></ports></host></nmaprun>'
    services = parse_nmap_xml(raw)
    assert len(services) == 1
    assert services[0].port == 22


def test_live_adapter_saves_nmap_xml_and_hash(tmp_path, monkeypatch):
    task = Task(task_id="t2", agent_type="ipv4_services", target=Target(
        asset_id="a2", address="192.168.57.13", interface="br-lab-audit", ports=[8080]),
        protocol="tcp", action_profile="nmap_tcp_services_v1", timeout_seconds=30)
    raw = (b'<nmaprun><host><ports><port protocol="tcp" portid="8080">'
           b'<state state="open"/><service name="http" product="Apache Tomcat"/>'
           b'</port></ports></host></nmaprun>')
    monkeypatch.setattr("auditoria.agentes.agente_ipv4_servicios.check_route", lambda address, interface: None)
    monkeypatch.setattr("auditoria.agentes.agente_ipv4_servicios.subprocess.run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, raw, b""))
    store = RunStore(tmp_path / "run", "audit1")
    try:
        result = run_nmap(task, store, timeout_seconds=30)
    finally:
        store.close()
    assert result.services[0].port == 8080
    assert result.evidence_sha256 == hashlib.sha256(raw).hexdigest()
    assert (tmp_path / "run" / result.evidence_ref).read_bytes() == raw
