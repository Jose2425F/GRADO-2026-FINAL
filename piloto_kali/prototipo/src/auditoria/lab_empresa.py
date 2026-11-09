"""Banco NovaFlow S.A.S.: empresa sintética que ejercita las cinco capacidades.

Tres segmentos internos aislados con datos ficticios y controles contrastables:
  - DMZ        : servicios IPv4 (nmap) y credenciales (hydra), hosts débiles y endurecido.
  - Corporativo: aplicaciones dual-stack (acceso de aplicación), cuatro escenarios.
  - Datacenter : protocolos IPv6 (NDP/SLAAC y fragmentación), receptor abierto y protegido.

La lógica de aplicación y protocolo es idéntica a la del banco v2 ya certificado; solo
cambia el direccionamiento del segmento NovaFlow. No modifica los archivos congelados de v2.
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

VERSION = "docker-empresa-1.0"
DEPLOY = Path(__file__).resolve().parents[3] / "despliegue"
EMPRESA = DEPLOY / "empresa"
COMPOSE = EMPRESA / "docker-compose.empresa.yml"
COMPANY = "NovaFlow S.A.S."

# --- Datacenter (protocolos IPv6) --------------------------------------------
SLAAC_PREFIX = "fd57:2026:70:1::/64"
ROUTER_LL = "fe80::57:20ff:fe26:70fe"
SENDER = "fd57:2026:70::10"
SENDER_LL = "fe80::57:20ff:fe26:7010"
SENDER_MAC = "02:57:20:26:70:10"
RECEIVERS = {
    "receiver_a": {"container": "nova-receiver-a", "address": "fd57:2026:70::20", "dad": "fd57:2026:70::30"},
    "receiver_b": {"container": "nova-receiver-b", "address": "fd57:2026:70::21", "dad": "fd57:2026:70::31"},
}

# --- Corporativo (aplicaciones dual-stack) -----------------------------------
APP_CONDITIONS = ("object_authorization", "file_boundary", "ipv6_authorization_gap")
APP_SCENARIOS = {"app_crm": "alpha", "app_erp": "beta", "app_portal": "gamma", "app_intranet": "strict"}
APP_EXPECTED = {"alpha": (True, True, True), "beta": (False, True, True),
                "gamma": (True, False, False), "strict": (False, False, False)}
APPS = {
    "app_crm": {"container": "nova-app-crm", "ipv4": "192.168.69.11", "ipv6": "fd57:2026:69::11"},
    "app_erp": {"container": "nova-app-erp", "ipv4": "192.168.69.12", "ipv6": "fd57:2026:69::12"},
    "app_portal": {"container": "nova-app-portal", "ipv4": "192.168.69.13", "ipv6": "fd57:2026:69::13"},
    "app_intranet": {"container": "nova-app-intranet", "ipv4": "192.168.69.14", "ipv6": "fd57:2026:69::14"},
}

# --- DMZ (servicios y credenciales IPv4) -------------------------------------
# Cada credencial declara el nombre de variable de entorno del que el auditor toma la
# contraseña sintética. Los hosts débiles aceptan la credencial conocida; el bastión
# guarda una contraseña distinta de la que el auditor intenta: control negativo.
DMZ_BRIDGE = "br-nova-dmz"
CREDENTIALS = {
    "portal": {"container": "nova-portal", "address": "192.168.71.11", "env": "LAB_NOVA_PORTAL",
               "services": [("ssh", 22), ("ftp", 21)], "expected": "accepted"},
    "legacy": {"container": "nova-legacy", "address": "192.168.71.13", "env": "LAB_NOVA_HTTP",
               "username": "console", "services": [("http-get", 8080)], "expected": "accepted"},
    "records": {"container": "nova-records", "address": "192.168.71.14", "env": "LAB_NOVA_DB",
                "services": [("postgres", 5432)], "expected": "accepted"},
    "bastion": {"container": "nova-bastion", "address": "192.168.71.12", "env": "LAB_NOVA_BASTION_GUESS",
                "services": [("ssh", 22), ("ftp", 21)], "expected": "rejected"},
}
SERVICE_PORTS = {asset: sorted(port for _, port in host["services"]) for asset, host in CREDENTIALS.items()}
# El auditor guarda una contraseña fija que NO coincide con la real del bastión.
BASTION_GUESS = "ChangeMe123!"

ADDRESSES = {a for app in APPS.values() for a in (app["ipv4"], app["ipv6"])}
ADDRESSES.update(r["address"] for r in RECEIVERS.values())

NETWORKS = {
    "nova_dmz": ("br-nova-dmz", {"192.168.71.0/24"},
                 {host["container"] for host in CREDENTIALS.values()}),
    "nova_corp": ("br-nova-corp", {"192.168.69.0/24", "fd57:2026:69::/64"},
                  {app["container"] for app in APPS.values()}),
    "nova_datacenter": ("br-nova-dc", {"192.168.70.0/24", "fd57:2026:70::/64"},
                        {"nova-router", "nova-sender", "nova-receiver-a", "nova-receiver-b"}),
}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())


def docker(*args, timeout=15):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              check=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(f"Docker NovaFlow falló en {args[0]}; revise el estado del banco") from exc


def inspect(kind, name):
    return json.loads(docker(kind, "inspect", name))[0]


def source_hash():
    paths = [COMPOSE, DEPLOY / "robusto/app_target.py", DEPLOY / "ipv6_sender.py", Path(__file__)]
    paths += sorted(EMPRESA.glob("dmz/*"))
    paths += sorted(EMPRESA.glob("datacenter/*"))
    digest = hashlib.sha256()
    for path in paths:
        if path.is_file() and path.suffix not in {".pyc"}:
            digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


# --- Secretos sintéticos del banco -------------------------------------------
KNOWN_ENVS = ("LAB_NOVA_PORTAL", "LAB_NOVA_HTTP", "LAB_NOVA_DB")


def prepare(root):
    """Genera lab.env con la semilla y las contraseñas sintéticas del banco."""
    root.mkdir(parents=True, exist_ok=True)
    env = root / "lab.env"
    if not env.exists():
        lines = ["LAB_FIXTURE_SEED=" + secrets.token_hex(24)]
        for name in KNOWN_ENVS:
            lines.append(f"{name}=NovaFlow-{secrets.token_hex(8)}")
        # Contraseña real del bastión: distinta de la que el auditor intentará.
        lines.append("LAB_NOVA_BASTION_REAL=" + secrets.token_hex(20))
        with os.fdopen(os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write("\n".join(lines) + "\n")
    if env.is_symlink() or env.stat().st_mode & 0o077:
        raise LabError("lab.env NovaFlow debe ser privado con permisos 0600")
    entries = []
    for asset, host in CREDENTIALS.items():
        present = host["expected"] == "accepted"
        for service, _port in host["services"]:
            entries.append({"asset_id": asset, "defect_key": service.replace("-", "_") + "_default_credential",
                            "present": present})
    for asset, scenario in APP_SCENARIOS.items():
        for condition, present in zip(APP_CONDITIONS, APP_EXPECTED[scenario]):
            entries.append({"asset_id": asset, "defect_key": condition, "present": present})
    for asset in RECEIVERS:
        for condition in ("untrusted_router_advertisement", "neighbor_override", "dad_interference"):
            entries.append({"asset_id": asset, "defect_key": condition, "present": asset == "receiver_a"})
    write_json(root / "ground_truth.json", {
        "bank": VERSION, "company": COMPANY, "entries": entries,
        "scope": "Credenciales por defecto en la DMZ, defectos de acceso dual-stack y condiciones de "
                 "confianza ND; sin duplicación por familia o variante.",
        "excluded": "El descubrimiento de servicios (nmap), SLAAC y la conformidad de fragmentación son "
                    "controles funcionales, no defectos positivos.",
    })
    write_json(root / "policy.json", {
        "bank": VERSION, "company": COMPANY, "execution": "predefined_profiles",
        "credentials": {k: {"address": v["address"], "services": v["services"], "expected": v["expected"]}
                        for k, v in CREDENTIALS.items()},
        "apps": APPS, "receivers": RECEIVERS, "slaac_prefix": SLAAC_PREFIX,
        "approved_ports": [21, 22, 5432, 8080, 8088, 8000, 53000], "maximum_packets_per_probe": 3,
        "maximum_runtime_seconds": 900, "no_remote_commands_or_shells": True,
        "nd_security_requirement": "Aceptar anuncios del router legítimo; rechazar modificaciones del emisor de prueba.",
    })


def known_password(env_name):
    """Contraseña sintética que el auditor conoce; para el bastión, el intento fijo."""
    if env_name == "LAB_NOVA_BASTION_GUESS":
        return BASTION_GUESS
    value = os.environ.get(env_name)
    if not value:
        raise LabError(f"falta {env_name} en el entorno; exporte lab.env antes de auditar NovaFlow")
    return value


def load_auditor_environment(root):
    """Exporta al proceso del auditor las contraseñas conocidas y el intento del bastión."""
    env = {}
    for line in (root / "lab.env").read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    for name in KNOWN_ENVS:
        if name in env:
            os.environ[name] = env[name]
    os.environ["LAB_NOVA_BASTION_GUESS"] = BASTION_GUESS


def compose(root, action):
    if action not in {"up", "down"}:
        raise ValueError("acción NovaFlow desconocida")
    if not (root / "policy.json").is_file() or not (root / "lab.env").is_file():
        raise LabError("ejecute laboratorio-empresa preparar")
    command = ["docker", "compose", "--env-file", str((root / "lab.env").resolve()), "-f", str(COMPOSE)]
    try:
        if action == "up":
            subprocess.run(command + ["up", "-d", "--build", "--force-recreate"], check=True)
        else:
            subprocess.run(command + ["down", "--volumes"], check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError("Compose NovaFlow no completó la operación") from exc


# --- HTTP de aplicación / observador (idéntico a v2, direcciones NovaFlow) ----
def http_json(address, port, path, *, token=None, nonce=None, data=None, independent=False):
    if address not in ADDRESSES or port not in {8000, 8088}:
        raise LabError("objetivo HTTP fuera del catálogo NovaFlow")
    interface = "br-nova-corp" if port == 8088 else "br-nova-dc"
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


def app_family(address, *, independent=False):
    nonce = uuid4().hex
    status, session = http_json(address, 8088, "/session", nonce=nonce,
                                data={"user": "viewer", "password": "lab-viewer"}, independent=independent)
    if status != 200 or not isinstance(session.get("token"), str):
        raise LabError("control positivo de sesión NovaFlow falló")
    token = session["token"]
    status, catalog = http_json(address, 8088, "/catalog", token=token, nonce=nonce, independent=independent)
    handles = catalog.get("handles")
    if status != 200 or not isinstance(handles, list) or len(handles) != 3 or any(
        not isinstance(h, str) or len(h) != 12 or any(c not in "0123456789abcdef" for c in h) for h in handles
    ):
        raise LabError("catálogo de referencia NovaFlow inválido")
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
        raise LabError("control positivo de recurso propio NovaFlow falló")
    status, public = http_json(address, 8088, "/download?name=guide.txt", token=token, nonce=nonce, independent=independent)
    if status != 200 or public.get("kind") != "public_document":
        raise LabError("control positivo de descarga NovaFlow falló")
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
        raise LabError("registro del servidor NovaFlow no corrobora las respuestas")
    return {"nonce": nonce, "records": records, "server_trace": events,
            "own_marker_sha256": own_markers[0], "object_authorization": unauthorized_object,
            "file_boundary": private_access, "admin_access": admin_access}


# --- Datacenter: estado, SLAAC y sondas (idéntico a v2, direcciones NovaFlow) -
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
                      and r.get("prefix") == "fd57:2026:70:1::" for r in advertisements):
                return state
        except (LabError, OSError, ValueError):
            pass
        time.sleep(0.25)
    raise LabError("receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto")


def reset_receiver(receiver):
    docker("restart", "-t", "1", receiver["container"])
    return wait_receiver(receiver)


def probe(receiver, profile, store, case):
    nonce = uuid4().hex[:16]
    started = time.monotonic()
    command = ["docker", "exec", "nova-sender", "python", "/app/datacenter/sender.py", profile, receiver["address"], nonce]
    if profile == "dad_na":
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 8)[0] or process.stdout.readline().strip() != "READY":
                raise LabError("captura DAD NovaFlow no preparada")
            docker("exec", receiver["container"], "ip", "-6", "addr", "add", receiver["dad"] + "/64", "dev", "eth0")
            output, _ = process.communicate(timeout=8)
            if process.returncode:
                raise LabError("emisor DAD NovaFlow falló")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    else:
        output = docker(*command[1:], timeout=15)
    data = json.loads(output)
    raw = base64.b64decode(data.pop("pcap_b64"), validate=True)
    if not 1 <= data.get("packet_count", 0) <= 3 or not 24 <= len(raw) <= 10000:
        raise LabError("captura NovaFlow fuera del perfil o sin prueba transmitida")
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
    raise LabError("perfil ND fuera del catálogo NovaFlow")


# --- Preflight (comprobación de estado del banco) -----------------------------
def preflight(root):
    policy_bytes = (root / "policy.json").read_bytes()
    if json.loads(policy_bytes).get("bank") != VERSION:
        raise LabError("configuración de otro banco")
    env_path = root / "lab.env"
    if env_path.is_symlink() or env_path.stat().st_mode & 0o077:
        raise LabError("lab.env NovaFlow debe ser privado con permisos 0600")
    report = {"bank": VERSION, "company": COMPANY, "segments": {}}
    for network_name, (bridge, subnets, members) in NETWORKS.items():
        network = inspect("network", network_name)
        if network.get("Internal") is not True:
            raise LabError(f"red {network_name} sin aislamiento")
        if network.get("Driver") != "bridge" or network.get("Options", {}).get("com.docker.network.bridge.name") != bridge:
            raise LabError(f"puente inesperado en {network_name}")
        if {c["Subnet"] for c in network["IPAM"]["Config"]} != subnets:
            raise LabError(f"subredes inesperadas en {network_name}")
        if {c["Name"] for c in network.get("Containers", {}).values()} != members:
            raise LabError(f"contenedores ajenos o faltantes en {network_name}")
        for name in sorted(members):
            container = inspect("container", name)
            if not container["State"]["Running"] or container["HostConfig"].get("Privileged"):
                raise LabError(f"contenedor {name} detenido o privilegiado")
            attachments = container["NetworkSettings"]["Networks"]
            if set(attachments) != {network_name} or any(container["NetworkSettings"]["Ports"].values()):
                raise LabError(f"conexión externa o puerto publicado en {name}")
        report["segments"][network_name] = sorted(members)
    # Servicios de aplicación disponibles por ambas familias.
    for app in APPS.values():
        for address in (app["ipv4"], app["ipv6"]):
            status, data = http_json(address, 8088, "/health")
            if status != 200 or data.get("ready") is not True:
                raise LabError("servicio de aplicación NovaFlow indisponible por alguna familia")
    # Servicios de la DMZ accesibles (consola legada por HTTP).
    status, _ = http_legacy_health()
    if status != 200:
        raise LabError("consola legada NovaFlow indisponible")
    # Receptores con SLAAC y anuncio legítimo.
    slaac = {asset: slaac_addresses(wait_receiver(receiver)) for asset, receiver in RECEIVERS.items()}
    report.update(source_sha256=source_hash(), kernel=os.uname().release, slaac=slaac,
                  policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
                  docker=docker("version", "--format", "{{.Server.Version}}").strip())
    return report


def http_legacy_health():
    address, port = CREDENTIALS["legacy"]["address"], 8080
    check_route(address, DMZ_BRIDGE)
    try:
        with OPENER.open(f"http://{address}:{port}/health", timeout=4) as response:
            return response.status, json.loads(response.read(4096))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except OSError as exc:
        raise LabError("no se pudo contactar la consola legada NovaFlow") from exc
