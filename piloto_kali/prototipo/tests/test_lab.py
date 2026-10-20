from contextlib import nullcontext

import pytest

from auditoria.lab import LabError, verify_pilot_lab


def test_pilot_preflight_checks_real_topology(monkeypatch):
    network = {
        "Driver": "bridge", "Internal": True, "EnableIPv6": False, "Id": "network-id",
        "IPAM": {"Config": [{"Subnet": "192.168.57.0/24"}]},
        "Options": {"com.docker.network.bridge.name": "br-lab-audit"},
    }
    container = {
        "State": {"Running": True}, "Image": "sha256:image", "Id": "container-id",
        "NetworkSettings": {
            "Networks": {"lab_auditoria_ipv4": {"IPAddress": "192.168.57.13"}},
            "Ports": {"8080/tcp": None},
        },
    }
    image = {"RepoDigests": ["tomcat@sha256:abcd"]}
    values = {("network", "lab_auditoria_ipv4"): network,
              ("container", "obj-tomcat"): container,
              ("image", "sha256:image"): image}
    monkeypatch.setattr("auditoria.lab._docker_inspect", lambda kind, name: values[(kind, name)])
    monkeypatch.setattr("auditoria.lab.check_route", lambda address, interface: None)
    monkeypatch.setattr("auditoria.lab._container_has_default_route", lambda name: False)
    monkeypatch.setattr("auditoria.lab.socket.create_connection", lambda *args, **kwargs: nullcontext())

    metadata = verify_pilot_lab()
    assert metadata["image_id"] == "sha256:image"
    assert metadata["address"] == "192.168.57.13"

    network["Internal"] = False
    with pytest.raises(LabError, match="puente interno"):
        verify_pilot_lab()


def test_pilot_rejects_extra_network_and_default_route(monkeypatch):
    network = {
        "Driver": "bridge", "Internal": True, "EnableIPv6": False,
        "IPAM": {"Config": [{"Subnet": "192.168.57.0/24"}]},
        "Options": {"com.docker.network.bridge.name": "br-lab-audit"},
    }
    container = {
        "State": {"Running": True}, "Image": "sha256:image",
        "NetworkSettings": {
            "Networks": {"lab_auditoria_ipv4": {"IPAddress": "192.168.57.13"},
                         "bridge": {"IPAddress": "172.17.0.2"}},
            "Ports": {"8080/tcp": None},
        },
    }
    values = {("network", "lab_auditoria_ipv4"): network,
              ("container", "obj-tomcat"): container,
              ("image", "sha256:image"): {"RepoDigests": []}}
    monkeypatch.setattr("auditoria.lab._docker_inspect", lambda kind, name: values[(kind, name)])
    monkeypatch.setattr("auditoria.lab.check_route", lambda address, interface: None)
    monkeypatch.setattr("auditoria.lab.socket.create_connection", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr("auditoria.lab._container_has_default_route", lambda name: False)

    with pytest.raises(LabError, match="solo a la red"):
        verify_pilot_lab()
    del container["NetworkSettings"]["Networks"]["bridge"]
    monkeypatch.setattr("auditoria.lab._container_has_default_route", lambda name: True)
    with pytest.raises(LabError, match="ruta predeterminada"):
        verify_pilot_lab()
