from pathlib import Path

import pytest

from auditoria.lab_virtual import VirtualLabError, load_config, preflight_virtual_lab


BASE = Path(__file__).resolve().parents[1]


def test_virtual_lab_preflight_checks_receiver_isolation(monkeypatch):
    config = load_config(BASE / "config/lab_virtual.example.json")

    def ip_json(*args):
        if args[0] == "link":
            return [{"flags": ["UP"]}]
        if args[0] == "-6":
            return [{"addr_info": [{"local": config.kali_address}]}]
        return [{"dev": config.management_interface}]

    snapshot = {"asset_id": config.asset_id, "state": {
        "addresses": [{"addr_info": [{"local": config.target_address}]}],
        "forwarding": {"ipv4": False, "ipv6": False},
    }}
    monkeypatch.setattr("auditoria.lab_virtual._ip_json", ip_json)
    monkeypatch.setattr("auditoria.lab_virtual.check_route", lambda *args: None)
    monkeypatch.setattr("auditoria.lab_virtual.observer_snapshot", lambda *args: snapshot)
    assert preflight_virtual_lab(config)["forwarding"]["ipv6"] is False

    snapshot["state"]["forwarding"]["ipv6"] = True
    with pytest.raises(VirtualLabError, match="reenvía paquetes"):
        preflight_virtual_lab(config)
