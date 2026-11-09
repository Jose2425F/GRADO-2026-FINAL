"""Banco v2: certificación finita, datos ficticios, controles y servicios dual-stack.

Esta certificación pertenece al evaluador; no mide un agente ni consulta un LLM.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import select
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from uuid import uuid4

from .lab import LabError
from .red import check_route
from .store import RunStore, write_json

VERSION = "docker-v2.1"
DEPLOY = Path(__file__).resolve().parents[3] / "despliegue"
COMPOSE = DEPLOY / "docker-compose.v2.yml"
SLAAC_PREFIX = "fd57:2026:60:1::/64"
ROUTER_LL = "fe80::57:20ff:fe26:60fe"
SENDER = "fd57:2026:60::10"
SENDER_MAC = "02:57:20:26:60:10"
APP_CONDITIONS = ("object_authorization", "file_boundary", "ipv6_authorization_gap")
APP_EXPECTED = {"a": (True, True, True), "b": (False, True, True),
                "c": (True, False, False), "d": (False, False, False)}
APPS = {f"app_{key}": {
    "container": f"v2-app-{key}", "ipv4": f"192.168.59.{n}",
    "ipv6": f"fd57:2026:59::{n}",
} for key, n in zip("abcd", range(11, 15))}
RECEIVERS = {
    "receiver_a": {"container": "v2-receiver-a", "address": "fd57:2026:60::20", "dad": "fd57:2026:60::30"},
    "receiver_b": {"container": "v2-receiver-b", "address": "fd57:2026:60::21", "dad": "fd57:2026:60::31"},
}
NETWORKS = {
    "lab_v2_apps": ("br-lab-v2-apps", {"192.168.59.0/24", "fd57:2026:59::/64"},
                    {app["container"] for app in APPS.values()}),
    "lab_v2_protocols": ("br-lab-v2-ndp", {"192.168.60.0/24", "fd57:2026:60::/64"},
                         {"v2-router", "v2-sender", "v2-receiver-a", "v2-receiver-b"}),
}
ADDRESSES = {a for app in APPS.values() for a in [app["ipv4"], app["ipv6"]]}
ADDRESSES.update(r["address"] for r in RECEIVERS.values())
class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())


def docker(*args, timeout=15):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              check=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(f"Docker v2 falló en {args[0]}; revise el estado del banco") from exc


def inspect(kind, name):
    return json.loads(docker(kind, "inspect", name))[0]


def source_hash():
    paths = [COMPOSE, DEPLOY / "robusto/app_target.py", DEPLOY / "ipv6_sender.py", Path(__file__)]
    paths += sorted((DEPLOY / "v2").glob("*"))
    digest = hashlib.sha256()
    for path in paths:
        if path.is_file() and path.suffix not in {".pyc"}:
            digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def has_ipv6_default_route(raw):
    """/proc incluye una ruta de rechazo en lo; no es una salida utilizable."""
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 10:
            raise LabError("tabla IPv6 v2 malformada")
        flags = int(fields[8], 16)
        if fields[:2] == ["0" * 32, "00"] and flags & 1 and not flags & 0x200:
            return True
    return False


def prepare(root):
    root.mkdir(parents=True, exist_ok=True)
    env = root / "lab.env"
    if not env.exists():
        with os.fdopen(os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write("LAB_FIXTURE_SEED=" + secrets.token_hex(24) + "\n")
    if env.is_symlink() or env.stat().st_mode & 0o077:
        raise LabError("lab.env v2 debe ser privado con permisos 0600")
    entries = []
    for asset, values in APPS.items():
        for condition, present in zip(APP_CONDITIONS, APP_EXPECTED[asset[-1]]):
            entries.append({"asset_id": asset, "defect_key": condition, "present": present})
    for asset in RECEIVERS:
        for condition in ["untrusted_router_advertisement", "neighbor_override", "dad_interference"]:
            entries.append({"asset_id": asset, "defect_key": condition, "present": asset == "receiver_a"})
    write_json(root / "ground_truth.json", {
        "bank": VERSION, "entries": entries,
        "scope": "Seis defectos sintéticos de aplicación y tres condiciones de confianza ND; sin duplicación por familia o variante.",
        "excluded": "SLAAC y fragmentación son controles funcionales/conformidad, no defectos positivos.",
    })
    write_json(root / "policy.json", {
        "bank": VERSION, "execution": "predefined_profiles", "apps": APPS,
        "receivers": RECEIVERS, "slaac_prefix": SLAAC_PREFIX,
        "approved_ports": [8088, 8000, 53000], "maximum_packets_per_probe": 3,
        "maximum_runtime_seconds": 600, "no_remote_commands_or_shells": True,
        "nd_security_requirement": "Aceptar anuncios del router legítimo; rechazar modificaciones del emisor de prueba.",
    })


def frozen_image(image_id):
    if not isinstance(image_id, str) or not image_id.startswith("sha256:") or len(image_id) != 71 or any(
        c not in "0123456789abcdef" for c in image_id[7:]
    ):
        raise LabError("ID de imagen v2 inválido")
    return "auditoria-lab-v2-frozen:" + image_id[7:]


def image_override(root, images, *, retain=False):
    members = {name for _, _, names in NETWORKS.values() for name in names}
    if set(images) != members:
        raise LabError("inventario congelado de imágenes v2 incompleto")
    services = {}
    for name, image_id in images.items():
        tag = frozen_image(image_id)
        if retain:
            docker("image", "tag", image_id, tag)
        if inspect("image", tag).get("Id") != image_id:
            raise LabError("imagen congelada v2 ausente o diferente; no se restauró el banco")
        services[name.removeprefix("v2-")] = {"image": tag}
    path = root / "images.compose.json"
    write_json(path, {"services": services})
    return path.resolve()


def compose(root, action):
    if action not in {"up", "reset", "down"}:
        raise ValueError("acción v2 desconocida")
    if not (root / "policy.json").is_file() or not (root / "lab.env").is_file():
        raise LabError("ejecute laboratorio-v2 preparar")
    command = ["docker", "compose", "--env-file", str((root / "lab.env").resolve()), "-f", str(COMPOSE)]
    if action == "reset":
        images = json.loads((root / "images.lock.json").read_text())
        # Validar y conservar referencias antes de detener los contenedores.
        override = image_override(root, images)
        command += ["-f", str(override)]
    try:
        if action == "up":
            subprocess.run(command + ["build", "app-a", "router"], check=True)
        else:
            subprocess.run(command + ["down", "--volumes"], check=True)
        if action != "down":
            subprocess.run(command + ["up", "-d", "--no-build", "--pull", "never", "--force-recreate"], check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError("Compose v2 no completó la operación") from exc


def http_json(address, port, path, *, token=None, nonce=None, data=None, independent=False):
    if address not in ADDRESSES or port not in {8000, 8088}:
        raise LabError("objetivo HTTP fuera del catálogo v2")
    interface = "br-lab-v2-apps" if port == 8088 else "br-lab-v2-ndp"
    check_route(address, interface)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if nonce:
        headers["X-Lab-Nonce"] = nonce
    body = json.dumps(data).encode() if data is not None else None
    method = "POST" if body is not None else "GET"
    if independent:
        connection = http.client.HTTPConnection(address, port, timeout=4)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read(65536))
        finally:
            connection.close()
    host = f"[{address}]" if ip_address(address).version == 6 else address
    request = urllib.request.Request(f"http://{host}:{port}{path}", data=body, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=4) as response:
            return response.status, json.loads(response.read(65536))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read(65536))


def snapshot(receiver):
    from .observer_schema import packet_observer, ObserverResponseError
    name = receiver["container"]
    status, observed = http_json(receiver["address"], 8000, "/state")
    if status != 200:
        raise ObserverResponseError("observer_http_status_rejected")
    return {
        "addresses": json.loads(docker("exec", name, "ip", "-j", "-6", "addr", "show", "dev", "eth0")),
        "routes": json.loads(docker("exec", name, "ip", "-j", "-6", "route", "show")),
        "neighbors": json.loads(docker("exec", name, "ip", "-j", "-6", "neigh", "show")),
        "mtu": int(docker("exec", name, "cat", "/proc/sys/net/ipv6/conf/eth0/mtu").strip()),
        "observer": packet_observer(observed),
        "observed_at": time.monotonic(),
    }


def slaac_addresses(state):
    return [a["local"] for iface in state["addresses"] for a in iface.get("addr_info", [])
            if ip_address(a["local"]) in ip_network(SLAAC_PREFIX)
            and a.get("dynamic") is True
            and not a.get("tentative") and not a.get("dadfailed")]


def wait_receiver(receiver, seconds=45):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            state = snapshot(receiver)
            advertisements = state["observer"]["router_advertisements"]
            if slaac_addresses(state) and state["mtu"] == 1500 and not any(
                r.get("dst") == "default" for r in state["routes"]
            ) and any(r.get("source") == ROUTER_LL and r.get("autonomous") is True
                      and r.get("prefix_length") == 64 and r.get("hop_limit") == 255
                      and r.get("prefix") == "fd57:2026:60:1::" for r in advertisements):
                return state
        except (LabError, OSError, ValueError):
            pass
        time.sleep(0.25)
    raise LabError("receptor v2 sin SLAAC, anuncio legítimo o estado inicial correcto")


def preflight(root, *, freeze=False, allow_refreeze=False):
    policy_bytes = (root / "policy.json").read_bytes()
    if json.loads(policy_bytes).get("bank") != VERSION:
        raise LabError("configuración de otro banco")
    env_path = root / "lab.env"
    if env_path.is_symlink() or env_path.stat().st_mode & 0o077:
        raise LabError("lab.env v2 debe ser privado con permisos 0600")
    env_text = env_path.read_text().strip()
    seed = env_text.removeprefix("LAB_FIXTURE_SEED=")
    if not env_text.startswith("LAB_FIXTURE_SEED=") or len(seed) != 48 or any(c not in "0123456789abcdef" for c in seed):
        raise LabError("semilla de fixtures inválida")
    targets = []
    images = {}
    for network_name, (bridge, subnets, members) in NETWORKS.items():
        network = inspect("network", network_name)
        if network.get("Internal") is not True or network.get("EnableIPv6") is not True:
            raise LabError("red v2 sin aislamiento o IPv6")
        if network.get("Driver") != "bridge" or network.get("Options", {}).get("com.docker.network.bridge.name") != bridge:
            raise LabError("puente v2 inesperado")
        if {c["Subnet"] for c in network["IPAM"]["Config"]} != subnets:
            raise LabError("subredes v2 inesperadas")
        if {c["Name"] for c in network.get("Containers", {}).values()} != members:
            raise LabError("contenedores ajenos o faltantes en el banco v2")
        for name in sorted(members):
            container = inspect("container", name)
            host = container["HostConfig"]
            environment = dict(e.split("=", 1) for e in container["Config"].get("Env", []) if "=" in e)
            if name.startswith("v2-app-") and (
                environment.get("LAB_FIXTURE_SEED") != seed
                or environment.get("LAB_SCENARIO") != {"a": "alpha", "b": "beta", "c": "gamma", "d": "strict"}[name[-1]]
            ):
                raise LabError("configuración de fixtures v2 diferente de la preparada")
            if name in {"v2-receiver-a", "v2-receiver-b"} and environment.get("LAB_GUARDED") != ("1" if name.endswith("b") else "0"):
                raise LabError("política del receptor v2 inesperada")
            if not container["State"]["Running"] or host.get("Privileged"):
                raise LabError("contenedor v2 detenido o privilegiado")
            application = name.startswith("v2-app-")
            if (host.get("NanoCpus") != (250000000 if application else 1000000000)
                or host.get("Memory") != (64 if application else 96) * 1024 * 1024
                or host.get("PidsLimit") != 32):
                raise LabError("recursos del banco v2 distintos de la versión congelada")
            attachments = container["NetworkSettings"]["Networks"]
            if set(attachments) != {network_name} or any(container["NetworkSettings"]["Ports"].values()):
                raise LabError("conexión externa o puerto publicado en v2")
            if not host.get("ReadonlyRootfs") or not any(
                x.startswith("no-new-privileges") for x in host.get("SecurityOpt", [])
            ):
                raise LabError("falta contención del contenedor v2")
            if any(m.get("Type") in {"bind", "volume"} for m in container.get("Mounts", [])):
                raise LabError("montaje persistente o del anfitrión no autorizado en v2")
            route4 = docker("exec", name, "cat", "/proc/net/route")
            route6 = docker("exec", name, "cat", "/proc/net/ipv6_route")
            if any(line.split()[1] == "00000000" and line.split()[7] == "00000000"
                   for line in route4.splitlines()[1:]):
                raise LabError("salida IPv4 predeterminada en v2")
            if has_ipv6_default_route(route6):
                raise LabError("salida IPv6 predeterminada en v2")
            a = attachments[network_name]
            images[name] = container["Image"]
            targets.append({"container": name, "image_id": container["Image"],
                            "nano_cpus": host["NanoCpus"], "memory_limit_bytes": host["Memory"], "pids_limit": host["PidsLimit"],
                            "ipv4": a["IPAddress"], "ipv6": a["GlobalIPv6Address"], "mac": a["MacAddress"]})
    expected = {v["container"]: (v["ipv4"], v["ipv6"]) for v in APPS.values()}
    expected.update({r["container"]: ("192.168.60." + r["address"].split("::")[-1], r["address"])
                     for r in RECEIVERS.values()})
    expected.update({"v2-sender": ("192.168.60.10", SENDER),
                     "v2-router": ("192.168.60.254", "fd57:2026:60::fe")})
    if any((t["ipv4"], t["ipv6"]) != expected[t["container"]] for t in targets):
        raise LabError("dirección de un activo v2 inesperada")
    for app in APPS.values():
        for address in [app["ipv4"], app["ipv6"]]:
            status, data = http_json(address, 8088, "/health")
            if status != 200 or data.get("ready") is not True:
                raise LabError("servicio v2 indisponible por alguna familia")
    states = {asset: wait_receiver(receiver) for asset, receiver in RECEIVERS.items()}
    locked = root / "images.lock.json"
    if locked.exists() and json.loads(locked.read_text()) != images:
        if not allow_refreeze:
            raise LabError("las imágenes v2 cambiaron; reconstruya explícitamente el banco y genere una nueva certificación")
        previous = json.loads(locked.read_text())
        write_json(root / ("images.previous_" + uuid4().hex[:8] + ".json"), previous)
        write_json(locked, images)
    if freeze and not locked.exists():
        write_json(locked, images)
    if freeze:
        image_override(root, images, retain=True)
    return {"bank": VERSION, "source_sha256": source_hash(), "kernel": os.uname().release,
            "targets": targets, "slaac": {a: slaac_addresses(s) for a, s in states.items()},
            "images_frozen": locked.exists(),
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "fixture_seed_sha256": hashlib.sha256(seed.encode()).hexdigest(),
            "software": {"radvd": docker("exec", "v2-router", "dpkg-query", "-W", "-f=${Version}", "radvd").strip(),
                         "scapy": docker("exec", "v2-sender", "python", "-c", "import scapy; print(scapy.__version__)").strip(),
                         "docker": docker("version", "--format", "{{.Server.Version}}").strip()}}


def app_family(address, *, independent=False):
    nonce = uuid4().hex
    status, session = http_json(address, 8088, "/session", nonce=nonce,
                                data={"user": "viewer", "password": "lab-viewer"}, independent=independent)
    if status != 200 or not isinstance(session.get("token"), str):
        raise LabError("control positivo de sesión v2 falló")
    token = session["token"]
    status, catalog = http_json(address, 8088, "/catalog", token=token, nonce=nonce, independent=independent)
    handles = catalog.get("handles")
    if status != 200 or not isinstance(handles, list) or len(handles) != 3 or any(
        not isinstance(h, str) or len(h) != 12 or any(c not in "0123456789abcdef" for c in h) for h in handles
    ):
        raise LabError("catálogo de referencia v2 inválido")
    records, own_markers = [], []
    unauthorized_object = False
    for handle in handles:
        path = "/objects/" + handle
        status, body = http_json(address, 8088, path, token=token, nonce=nonce, independent=independent)
        valid_document = status == 200 and body.get("kind") == "document" and isinstance(body.get("marker"), str)
        unauthorized_object |= valid_document and body.get("owner") == "other"
        if valid_document and body.get("owner") == "viewer":
            own_markers.append(hashlib.sha256(body["marker"].encode()).hexdigest())
        records.append({"path": path, "status": status, "body": body})
    if len(own_markers) != 1:
        raise LabError("control positivo de recurso propio falló")
    status, public = http_json(address, 8088, "/download?name=guide.txt", token=token, nonce=nonce, independent=independent)
    if status != 200 or public.get("kind") != "public_document":
        raise LabError("control positivo de descarga falló")
    private_access = False
    for name in ["../private/audit_marker.txt", "%2e%2e%2fprivate%2faudit_marker.txt"]:
        path = "/download?name=" + urllib.parse.quote(name, safe="")
        status, body = http_json(address, 8088, path, token=token, nonce=nonce, independent=independent)
        private_access |= status == 200 and body.get("kind") == "internal_configuration" and isinstance(body.get("marker"), str)
        records.append({"path": path, "status": status, "body": body})
    status, body = http_json(address, 8088, "/admin", token=token, nonce=nonce, independent=independent)
    admin_access = status == 200 and body.get("kind") == "admin_configuration"
    records.append({"path": "/admin", "status": status, "body": body})
    _, trace = http_json(address, 8088, "/trace?nonce=" + nonce, independent=independent)
    events = trace.get("events", [])
    if any(not any(e.get("path") == r["path"] and e.get("status") == r["status"] for e in events) for r in records):
        raise LabError("registro del servidor no corrobora las respuestas")
    return {"nonce": nonce, "records": records, "server_trace": events,
            "own_marker_sha256": own_markers[0], "object_authorization": unauthorized_object,
            "file_boundary": private_access, "admin_access": admin_access}


def reset_receiver(receiver):
    docker("restart", "-t", "1", receiver["container"])
    return wait_receiver(receiver)


def probe(receiver, profile, store, case):
    nonce = uuid4().hex[:16]
    started = time.monotonic()
    command = ["docker", "exec", "v2-sender", "python", "/app/v2/sender.py", profile, receiver["address"], nonce]
    if profile == "dad_na":
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 8)[0] or process.stdout.readline().strip() != "READY":
                raise LabError("captura DAD v2 no preparada")
            docker("exec", receiver["container"], "ip", "-6", "addr", "add", receiver["dad"] + "/64", "dev", "eth0")
            output, _ = process.communicate(timeout=8)
            if process.returncode:
                raise LabError("emisor DAD v2 falló")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    else:
        output = docker(*command[1:], timeout=15)
    data = json.loads(output)
    raw = base64.b64decode(data.pop("pcap_b64"), validate=True)
    if not 1 <= data.get("packet_count", 0) <= 3 or not 24 <= len(raw) <= 10000:
        raise LabError("captura v2 fuera del perfil o sin prueba transmitida")
    reference, digest = store.evidence(case, "pcap", raw)
    time.sleep(1.1 if profile == "dad_na" else 0.7)
    return snapshot(receiver), {**data, "nonce": nonce, "pcap_ref": reference, "pcap_sha256": digest,
                                "started_at": started}


def neighbor(state):
    return next((n.get("lladdr") for n in state["neighbors"] if n.get("dst") == SENDER), None)


def nd_effect(profile, before, after, receiver, proof):
    if profile == "ra_route":
        return any(r.get("dst") == "default" for r in after["routes"])
    if profile == "ra_mtu":
        return after["mtu"] != before["mtu"] or any(
            change["mtu"] != before["mtu"]
            and proof["started_at"] <= change["observed_at"] <= after["observed_at"]
            for change in after["observer"].get("mtu_changes", [])
        )
    if profile == "na_neighbor":
        return neighbor(after) != neighbor(before)
    if profile == "dad_na":
        return any(a.get("local") == receiver["dad"] and a.get("dadfailed")
                   for iface in after["addresses"] for a in iface.get("addr_info", []))
    raise LabError("perfil ND fuera del catálogo v2")


def certificate(root, output, authorization):
    if not authorization.strip():
        raise LabError("se requiere referencia de autorización para certificar v2")
    manifest = preflight(root, freeze=True)
    audit_id = "cert_v2_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + uuid4().hex[:6]
    store = RunStore(output / audit_id, audit_id)
    records, findings = [], set()
    result = {"bank": VERSION, "audit_id": audit_id, "authorization_ref": authorization,
              "purpose": "lab_certification_not_agent_evaluation", "llm_calls": 0,
              "status": "running", "checks": records, "manifest": manifest}
    write_json(store.root / "certificate.json", result)
    write_json(store.root / "manifest.json", manifest)
    truth_bytes = (root / "ground_truth.json").read_bytes()
    write_json(store.root / "ground_truth.json", json.loads(truth_bytes))
    write_json(store.root / "policy.json", json.loads((root / "policy.json").read_bytes()))
    started = time.monotonic()

    def save_case(case, asset, evidence, *, passed, kind, condition=None, observed=None):
        reference, digest = store.evidence(case + "_state", "json", json.dumps(evidence, sort_keys=True).encode())
        record = {"case_id": case, "asset_id": asset, "kind": kind, "passed": bool(passed),
                  "condition": condition, "observed": observed, "evidence_ref": reference,
                  "evidence_sha256": digest}
        records.append(record)
        if condition and observed is True:
            findings.add((asset, condition))
        store.event("certifier", "case_completed", task_id=case, payload=record)
        write_json(store.root / "certificate.json", result)
        if time.monotonic() - started > 600:
            raise LabError("presupuesto temporal de certificación v2 agotado")

    try:
        for asset, receiver in RECEIVERS.items():
            state = wait_receiver(receiver)
            save_case(asset + "_slaac", asset, state, passed=bool(slaac_addresses(state)), kind="slaac_control")
        for asset, app in APPS.items():
            families = {}
            for family in ["ipv4", "ipv6"]:
                primary = app_family(app[family])
                confirmation = app_family(app[family], independent=True)
                if any(primary[k] != confirmation[k] for k in [*APP_CONDITIONS[:2], "admin_access", "own_marker_sha256"]):
                    raise LabError("los clientes independientes discrepan en v2")
                families[family] = {"primary": primary, "confirmation": confirmation}
            own_match = families["ipv4"]["primary"]["own_marker_sha256"] == families["ipv6"]["primary"]["own_marker_sha256"]
            save_case(asset + "_same_resource", asset, families, passed=own_match, kind="dualstack_control")
            observations = [
                families["ipv4"]["primary"]["object_authorization"] or families["ipv6"]["primary"]["object_authorization"],
                families["ipv4"]["primary"]["file_boundary"] or families["ipv6"]["primary"]["file_boundary"],
                not families["ipv4"]["primary"]["admin_access"] and families["ipv6"]["primary"]["admin_access"],
            ]
            for condition, observed, expected in zip(APP_CONDITIONS, observations, APP_EXPECTED[asset[-1]]):
                save_case(asset + "_" + condition, asset, families,
                          passed=observed == expected, kind="access_condition", condition=condition, observed=observed)
        for asset, receiver in RECEIVERS.items():
            effects = {}
            for profile in ["ra_route", "ra_mtu", "na_neighbor", "dad_na"]:
                # La restauración verificada del caso anterior es el inicio de este caso.
                before = wait_receiver(receiver)
                try:
                    if profile == "na_neighbor":
                        docker("exec", receiver["container"], "ip", "-6", "neigh", "replace", SENDER,
                               "lladdr", SENDER_MAC, "nud", "permanent" if asset == "receiver_b" else "reachable", "dev", "eth0")
                        before = snapshot(receiver)
                    case = asset + "_" + profile
                    after, proof = probe(receiver, profile, store, case)
                    effect = nd_effect(profile, before, after, receiver, proof)
                    observed_packets = after["observer"]["router_advertisements" if profile.startswith("ra_") else "neighbor_advertisements"]
                    visible = any(p.get("source") in {SENDER, "fe80::57:20ff:fe26:6010"} for p in observed_packets)
                    restored = reset_receiver(receiver)
                    proof_valid = visible and bool(slaac_addresses(before)) and bool(slaac_addresses(restored))
                    effects[profile] = bool(effect)
                    condition = {"ra_route": "untrusted_router_advertisement", "ra_mtu": "untrusted_router_advertisement",
                                 "na_neighbor": "neighbor_override", "dad_na": "dad_interference"}[profile]
                    save_case(case, asset, {"before": before, "after": after, "restored": restored, "probe": proof},
                              passed=proof_valid and bool(effect) == (asset == "receiver_a"), kind="nd_policy_condition",
                              condition=condition, observed=bool(effect) if proof_valid else None)
                except Exception:
                    reset_receiver(receiver)
                    raise
            for control_profile, variant, expected in [
                ("control", "overlap", False), ("control_middle", "overlap_middle", False),
                ("plain", "atomic", True), ("control", "incomplete_chain", False),
            ]:
                before = wait_receiver(receiver)
                try:
                    case = asset + "_" + variant
                    control_state, control_probe = probe(receiver, control_profile, store, case + "_control")
                    after, variant_probe = probe(receiver, variant, store, case + "_variant")
                    control_ok = any(d["nonce"] == control_probe["nonce"] for d in control_state["observer"]["udp_deliveries"])
                    delivered = any(d["nonce"] == variant_probe["nonce"] for d in after["observer"]["udp_deliveries"])
                    visible = sum(f["id"] == variant_probe["fragment_id"] for f in after["observer"]["fragments"]) >= variant_probe["packet_count"]
                    restored = reset_receiver(receiver)
                    save_case(case, asset, {"before": before, "control": control_state, "after": after,
                              "restored": restored, "control_probe": control_probe, "variant_probe": variant_probe},
                              passed=control_ok and visible and delivered == expected and bool(slaac_addresses(restored)),
                              kind="protocol_conformance", observed=bool(delivered))
                except Exception:
                    reset_receiver(receiver)
                    raise
        truth = json.loads(truth_bytes)
        positive = {(e["asset_id"], e["defect_key"]) for e in truth["entries"] if e["present"]}
        negative = {(e["asset_id"], e["defect_key"]) for e in truth["entries"] if not e["present"]}
        result.update(status="certified" if all(r["passed"] for r in records) and findings == positive else "failed",
                      checks_passed=sum(r["passed"] for r in records), checks_total=len(records),
                      distinct_conditions=len(positive), negative_conditions=len(negative),
                      verified_conditions=sorted([list(k) for k in findings]),
                      ground_truth_sha256=hashlib.sha256(truth_bytes).hexdigest())
    except Exception as exc:
        result.update(status="failed", failure_type=type(exc).__name__, failure_reason=str(exc)[:240])
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_json(store.root / "certificate.json", result)
        store.close()
    return store.root, result


def verify_certificate(root):
    """Recalcula hashes de estados, PCAP y referencia, sin ejecutar pruebas."""
    data = json.loads((root / "certificate.json").read_text())
    errors = []

    def matches(reference, digest):
        if not isinstance(reference, str) or not isinstance(digest, str):
            return False
        path = (root / reference).resolve()
        return path.is_relative_to(root.resolve()) and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest

    def check_packets(value):
        if isinstance(value, dict):
            if "pcap_ref" in value and not matches(value.get("pcap_ref"), value.get("pcap_sha256")):
                errors.append("packet_changed_or_missing")
            for child in value.values():
                check_packets(child)
        elif isinstance(value, list):
            for child in value:
                check_packets(child)

    for record in data["checks"]:
        if not matches(record.get("evidence_ref"), record.get("evidence_sha256")):
            errors.append(record["case_id"] + ":state_changed_or_missing")
        else:
            check_packets(json.loads((root / record["evidence_ref"]).read_text()))
    if data.get("ground_truth_sha256") and not matches("ground_truth.json", data["ground_truth_sha256"]):
        errors.append("ground_truth_changed_or_missing")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest != data.get("manifest"):
        errors.append("manifest_changed")
    return {"valid": not errors, "status": data["status"], "checked_states": len(data["checks"]), "errors": errors}
