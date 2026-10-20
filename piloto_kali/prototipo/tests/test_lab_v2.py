import hashlib
import http.client
import json
import runpy
import sys
import threading
import urllib.error
import urllib.request
from contextlib import nullcontext
from http.server import ThreadingHTTPServer
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditoria import lab_v2
from auditoria.cli import app
from auditoria.store import RunStore, write_json

DEPLOY = Path(__file__).resolve().parents[2] / "despliegue"


def test_prepare_keeps_fixture_seed_and_deduplicates_conditions(tmp_path):
    lab_v2.prepare(tmp_path)
    original = (tmp_path / "lab.env").read_bytes()
    lab_v2.prepare(tmp_path)
    assert (tmp_path / "lab.env").read_bytes() == original
    assert (tmp_path / "lab.env").stat().st_mode & 0o777 == 0o600
    truth = json.loads((tmp_path / "ground_truth.json").read_text())
    keys = [(e["asset_id"], e["defect_key"]) for e in truth["entries"]]
    assert len(keys) == len(set(keys)) == 18
    assert sum(e["present"] for e in truth["entries"]) == 9
    assert not any("fragment" in key[1] or "slaac" in key[1] for key in keys)
    assert original.decode().split("=")[1].strip() not in json.dumps(truth)


def test_preparation_rejects_public_seed_file(tmp_path):
    (tmp_path / "lab.env").write_text("LAB_FIXTURE_SEED=" + "a" * 48)
    (tmp_path / "lab.env").chmod(0o644)
    with pytest.raises(lab_v2.LabError, match="0600"):
        lab_v2.prepare(tmp_path)


def test_ipv6_null_reject_route_is_not_an_external_route():
    null = "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32 + " ffffffff 00000001 00000000 00200200 lo"
    assert lab_v2.has_ipv6_default_route(null) is False
    actual = null.replace("00200200 lo", "00000003 eth0")
    assert lab_v2.has_ipv6_default_route(actual) is True
    with pytest.raises(lab_v2.LabError):
        lab_v2.has_ipv6_default_route("malformed")


def test_slaac_requires_prefix_and_completed_dad():
    state = {"addresses": [{"addr_info": [
        {"local": "fd57:2026:60::20"},
        {"local": "fd57:2026:60:1::a", "tentative": True},
        {"local": "fd57:2026:60:1::b", "dadfailed": True},
        {"local": "fd57:2026:60:1::c", "dynamic": True},
    ]}]}
    assert lab_v2.slaac_addresses(state) == ["fd57:2026:60:1::c"]


def test_mtu_change_is_correlated_with_probe_even_when_legitimate_ra_restores_it():
    before = {"mtu": 1500}
    after = {"mtu": 1500, "observed_at": 30, "observer": {"mtu_changes": [
        {"mtu": 1280, "observed_at": 21}, {"mtu": 1500, "observed_at": 25},
    ]}}
    assert lab_v2.nd_effect("ra_mtu", before, after, {}, {"started_at": 20}) is True
    assert lab_v2.nd_effect("ra_mtu", before, after, {}, {"started_at": 26}) is False


def test_http_scope_is_checked_before_any_connection(monkeypatch):
    monkeypatch.setattr(lab_v2, "check_route", lambda *args: pytest.fail("out-of-scope route"))
    with pytest.raises(lab_v2.LabError):
        lab_v2.http_json("192.0.2.1", 8088, "/health")
    with pytest.raises(lab_v2.LabError):
        lab_v2.http_json("192.168.59.11", 22, "/health")


@pytest.mark.parametrize("scenario,expected", [
    ("alpha", (True, True)), ("beta", (False, True)),
    ("gamma", (True, False)), ("strict", (False, False)),
])
def test_real_fixture_handler_and_two_clients_verify_access_not_http_200(
    tmp_path, monkeypatch, scenario, expected,
):
    monkeypatch.setenv("LAB_SCENARIO", scenario)
    monkeypatch.setenv("LAB_FIXTURE_SEED", "deterministic-test-fixture")
    monkeypatch.setenv("LAB_FIXTURE_ROOT", str(tmp_path / "fixtures"))
    namespace = runpy.run_path(str(DEPLOY / "robusto/app_target.py"), run_name="fixture_test")
    server = ThreadingHTTPServer(("127.0.0.1", 0), namespace["Handler"])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def transport(address, port, path, *, token=None, nonce=None, data=None, independent=False):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if nonce:
            headers["X-Lab-Nonce"] = nonce
        body = json.dumps(data).encode() if data is not None else None
        if independent:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.request("POST" if body else "GET", path, body=body, headers=headers)
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}{path}", data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    monkeypatch.setattr(lab_v2, "http_json", transport)
    try:
        primary = lab_v2.app_family("fixture")
        confirmation = lab_v2.app_family("fixture", independent=True)
        for result in [primary, confirmation]:
            assert (result["object_authorization"], result["file_boundary"]) == expected
            assert result["admin_access"] is False  # Este servidor de prueba solo usa AF_INET.
            assert any(r["status"] == 200 and r["body"].get("error") == "not_found" for r in result["records"])
            assert "token" not in json.dumps(result)
        assert primary["own_marker_sha256"] == confirmation["own_marker_sha256"]
        reloaded = runpy.run_path(str(DEPLOY / "robusto/app_target.py"), run_name="fixture_repeat")
        assert namespace["OBJECTS"] == reloaded["OBJECTS"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("profile", ["ra_route", "ra_mtu", "dad_na"])
def test_sender_nd_frames_are_limited_to_selected_receiver(monkeypatch, profile):
    pytest.importorskip("scapy")
    from scapy.all import Ether, IPv6, ICMPv6ND_NS
    import scapy.all

    spec = spec_from_file_location("ipv6_sender", DEPLOY / "ipv6_sender.py")
    profiles = module_from_spec(spec)
    spec.loader.exec_module(profiles)
    monkeypatch.setitem(sys.modules, "ipv6_sender", profiles)
    monkeypatch.setattr(profiles, "link_local", lambda: "fe80::57:20ff:fe26:6010")
    sent = []
    monkeypatch.setattr(scapy.all, "sendp", lambda packets, **kwargs: sent.extend(packets))
    monkeypatch.setattr(scapy.all, "sniff", lambda **kwargs: [IPv6() / ICMPv6ND_NS()])
    monkeypatch.setattr(sys, "argv", ["sender.py", profile, "fd57:2026:60::21", "a" * 16])
    runpy.run_path(str(DEPLOY / "v2/sender.py"), run_name="sender_test")
    assert len(sent) == 1
    assert sent[0][Ether].dst == "02:57:20:26:60:21"
    assert sent[0][IPv6].dst == ("ff02::1" if profile == "dad_na" else "fd57:2026:60::21")


def test_certificate_verifier_detects_changed_packet(tmp_path):
    store = RunStore(tmp_path / "run", "cert-test")
    try:
        packet, packet_hash = store.evidence("packet", "pcap", b"original")
        state, state_hash = store.evidence("state", "json", json.dumps({
            "pcap_ref": packet, "pcap_sha256": packet_hash,
        }).encode())
        manifest = {"bank": lab_v2.VERSION}
        write_json(store.root / "manifest.json", manifest)
        write_json(store.root / "certificate.json", {
            "status": "certified", "manifest": manifest,
            "checks": [{"case_id": "case", "evidence_ref": state, "evidence_sha256": state_hash}],
        })
        assert lab_v2.verify_certificate(store.root)["valid"] is True
        (store.root / packet).write_bytes(b"changed")
        assert lab_v2.verify_certificate(store.root)["valid"] is False
    finally:
        store.close()


def test_certification_requires_authorization_before_docker(tmp_path, monkeypatch):
    monkeypatch.setattr("auditoria.cli.operation_lock", nullcontext)
    monkeypatch.setattr(lab_v2, "docker", lambda *args, **kwargs: pytest.fail("no Docker without reference"))
    with pytest.raises(lab_v2.LabError, match="autorización"):
        lab_v2.certificate(tmp_path, tmp_path, "")
    result = CliRunner().invoke(app, ["laboratorio-v2", "certificar", "--config", str(tmp_path)])
    assert result.exit_code == 2


def test_failed_certificate_keeps_exit_code_three(tmp_path, monkeypatch):
    monkeypatch.setattr("auditoria.cli.operation_lock", nullcontext)
    monkeypatch.setattr(lab_v2, "certificate", lambda *args: (
        tmp_path, {"status": "failed", "checks": [], "checks_passed": 0},
    ))
    result = CliRunner().invoke(app, ["laboratorio-v2", "certificar", "--autorizacion", "test"])
    assert result.exit_code == 3
    assert "Estado: failed" in result.output
    assert "Rechazado:" not in result.output


def test_reset_uses_retained_image_references_before_stopping(tmp_path, monkeypatch):
    lab_v2.prepare(tmp_path)
    image_id = "sha256:" + "a" * 64
    images = {name: image_id for _, _, names in lab_v2.NETWORKS.values() for name in names}
    write_json(tmp_path / "images.lock.json", images)
    monkeypatch.setattr(lab_v2, "inspect", lambda kind, tag: {"Id": image_id})
    commands = []
    monkeypatch.setattr(lab_v2.subprocess, "run", lambda command, **kwargs: commands.append(command))
    lab_v2.compose(tmp_path, "reset")
    override = json.loads((tmp_path / "images.compose.json").read_text())
    assert override["services"]["app-a"]["image"] == lab_v2.frozen_image(image_id)
    assert all(str((tmp_path / "images.compose.json").resolve()) in c for c in commands)
    assert commands[0][-2:] == ["down", "--volumes"]
    assert "--pull" in commands[1] and "never" in commands[1]


def test_missing_frozen_image_rejects_reset_before_any_mutation(tmp_path, monkeypatch):
    lab_v2.prepare(tmp_path)
    images = {name: "sha256:" + "b" * 64 for _, _, names in lab_v2.NETWORKS.values() for name in names}
    write_json(tmp_path / "images.lock.json", images)
    monkeypatch.setattr(lab_v2, "inspect", lambda kind, tag: {"Id": "sha256:" + "c" * 64})
    monkeypatch.setattr(lab_v2.subprocess, "run", lambda *a, **k: pytest.fail("must not stop containers"))
    with pytest.raises(lab_v2.LabError, match="congelada"):
        lab_v2.compose(tmp_path, "reset")
    with pytest.raises(lab_v2.LabError, match="ID de imagen"):
        lab_v2.frozen_image("not-an-image")
