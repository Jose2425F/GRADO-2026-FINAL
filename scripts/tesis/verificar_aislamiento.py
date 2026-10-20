#!/usr/bin/env python3
"""Comprobación negativa RNF-08; solo plan salvo --ejecutar --autorizacion LAB-PROPIO.

No levanta bancos, no modifica rutas, no consulta APIs ni ejecuta auditorías. El
operador debe levantar y verificar primero un laboratorio cerrado. Con ejecución
explícita se inspeccionan sus redes y se emiten cuatro intentos TCP finitos desde
el espacio de red de CADA contenedor esperado, sin depender de sus herramientas.
Un timeout o un rechazo TCP no se interpretan como aislamiento aprobado.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PILOT = ROOT / "piloto_kali/prototipo"
SCENARIOS = ("original", "sucursal", "comercial", "mixto", "reforzado")
# nsenter trabaja en el anfitrión local: nunca aceptar un Docker Context remoto.
DOCKER = ("docker", "--host", "unix:///var/run/docker.sock")
# Documentación: no DNS, HTTP, credenciales ni escaneo de servicios de terceros.
# La ausencia de respuesta de estas direcciones NO basta para aprobar: también
# deben faltar rutas de salida y el kernel debe rechazar la conexión explícitamente.
DESTINATIONS = (
    {"family": 4, "address": "198.51.100.254", "port": 443},
    {"family": 4, "address": "203.0.113.254", "port": 443},
    {"family": 6, "address": "2001:db8:ffff:fffe::254", "port": 443},
    {"family": 6, "address": "2001:db8:ffff:ffff::254", "port": 443},
)
INSPECT_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},'
                  '"pid":{{json .State.Pid}},"running":{{json .State.Running}},'
                  '"network_mode":{{json .HostConfig.NetworkMode}},'
                  '"privileged":{{json .HostConfig.Privileged}},'
                  '"networks":{{json .NetworkSettings.Networks}}}')
MIN_ENV = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}

# Se ejecuta con el Python DEL ANFITRIÓN y únicamente cambia el espacio de red.
# No utiliza la shell, ni instala/monta archivos en los contenedores.
PROBE_SCRIPT = r'''
import errno, json, socket, subprocess, sys
cfg=json.loads(sys.argv[1]); answer={"routes":{},"probes":[]}
def ip(args):
    try:
        p=subprocess.run([cfg["ip"],"-j",*args],capture_output=True,text=True,
                         timeout=2,check=False,env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
        if p.returncode:
            return {"returncode":p.returncode,"reason":"no_route" if
                p.returncode==2 and "Network is unreachable" in p.stderr else "ip_error"}
        return {"returncode":0,"data":json.loads(p.stdout)}
    except subprocess.TimeoutExpired: return {"returncode":None,"reason":"ip_timeout"}
    except (OSError,ValueError): return {"returncode":None,"reason":"ip_unavailable_or_invalid"}
for family in (4,6):
    answer["routes"][str(family)]={"table":ip(["-"+str(family),"route","show","table","all"]),
        "rules":ip(["-"+str(family),"rule","show"])}
answer["links"]=ip(["link","show"])
answer["addresses"]=ip(["address","show"])
for target in cfg["destinations"]:
    row=dict(target); row["route_get"]=ip(["-"+str(target["family"]),"route","get",target["address"]])
    sock=None
    try:
        sock=socket.socket(socket.AF_INET if target["family"]==4 else socket.AF_INET6,socket.SOCK_STREAM)
        sock.settimeout(0.75); sock.connect((target["address"],target["port"]))
        row["connect"]={"status":"connected"}
    except (socket.timeout,TimeoutError): row["connect"]={"status":"timeout"}
    except OSError as exc:
        blocked={errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM}
        row["connect"]={"status":"blocked" if exc.errno in blocked else
            "refused" if exc.errno==errno.ECONNREFUSED else "error","errno":exc.errno}
    finally:
        if sock is not None: sock.close()
    answer["probes"].append(row)
print(json.dumps(answer,separators=(",",":")))
'''


@dataclass(frozen=True)
class Network:
    name: str
    bridge: str
    subnets: tuple[str, ...]
    members: tuple[str, ...]


@dataclass(frozen=True)
class Lab:
    scenario: str
    networks: tuple[Network, ...]
    slaac_prefix: str


class CheckError(Exception):
    """Motivo cerrado; nunca contiene stdout, stderr ni valores de entorno."""


def definition(scenario: str) -> Lab:
    if scenario not in SCENARIOS:
        raise ValueError("Laboratorio no admitido.")
    sys.path[:0] = [str(ROOT / "scripts"), str(PILOT / "src")]
    if scenario == "original":
        from auditoria import lab_empresa as lab
    else:
        from tesis.laboratorios import Context
        lab = Context(scenario).lab  # Construye metadatos; NO prepare/preflight/compose.
    return Lab(scenario, tuple(Network(name, bridge, tuple(sorted(subnets)),
        tuple(sorted(members))) for name, (bridge, subnets, members) in sorted(lab.NETWORKS.items())),
        lab.SLAAC_PREFIX)


def plan(lab: Lab) -> dict:
    names = [n.name for n in lab.networks]
    members = [c for n in lab.networks for c in n.members]
    if (lab.scenario not in SCENARIOS or len(names) != 3 or len(set(names)) != 3
        or not members or len(members) != len(set(members))
        or any(not n.members or not n.subnets for n in lab.networks)):
        raise ValueError("Se necesitan los tres segmentos y sus miembros únicos del laboratorio cerrado.")
    allowed = [ip_network(s) for n in lab.networks for s in n.subnets]
    allowed.append(ip_network(lab.slaac_prefix))
    if any(any(ip_address(d["address"]) in n for n in allowed) for d in DESTINATIONS):
        raise ValueError("El destino negativo coincide con un segmento autorizado.")
    return {"schema": "novaflow-isolation-check/1", "requirement": "RNF-08",
        "scenario": lab.scenario, "status": "not_executed", "requirement_status": "PARCIAL",
        "created_at": datetime.now(timezone.utc).isoformat(), "api_calls": 0,
        "audit_runs": 0, "lab_mutations": 0, "networks": [asdict(n) for n in lab.networks],
        "slaac_prefix": lab.slaac_prefix, "destinations": list(DESTINATIONS),
        "planned_tcp_attempts": sum(len(n.members) for n in lab.networks) * len(DESTINATIONS),
        "maximum_seconds": 240, "containers": [], "issues": [],
        "limitations": ["Comprueba el estado y rutas observados de un laboratorio cerrado en este instante; no certifica redes externas ni configuraciones futuras.",
            "Un timeout, ECONNREFUSED, una herramienta ausente o un banco apagado no acreditan aislamiento.",
            "No prueba la salida desde el propio anfitrión: Kali requiere conectividad con el proveedor de IA.",
            "Requiere el Docker local en /var/run/docker.sock; no admite un Docker Context remoto ni Docker rootless.",
            "No inicia, restaura ni detiene laboratorios; no consume posiciones del estudio con API."],
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def command_json(runner, command: list[str], timeout=15):
    try:
        result = runner(command, capture_output=True, text=True, check=False,
                        timeout=timeout, env=MIN_ENV)
    except subprocess.TimeoutExpired:
        raise CheckError("command_timeout") from None
    except OSError:
        raise CheckError("command_unavailable") from None
    if result.returncode:
        raise CheckError("command_failed")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise CheckError("invalid_command_json") from None


def container_info(runner, name):
    return command_json(runner, [*DOCKER, "container", "inspect", "--format", INSPECT_FORMAT, name])


def valid_container(info, name, network):
    return (isinstance(info, dict) and info.get("name") == "/" + name
        and isinstance(info.get("id"), str) and bool(info["id"])
        and type(info.get("pid")) is int and info["pid"] > 0
        and info.get("running") is True and info.get("privileged") is False
        and info.get("network_mode") not in {"host", "none"}
        and not str(info.get("network_mode", "")).startswith("container:")
        and isinstance(info.get("networks"), dict) and set(info["networks"]) == {network})


def outside_routes(routes, allowed, family):
    extra = ("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32") if family == 4 else ("::1/128", "fe80::/10", "ff00::/8")
    permitted = [ip_network(s) for s in (*allowed, *extra) if ip_network(s).version == family]
    bad = []
    for route in routes:
        if not isinstance(route, dict):
            raise CheckError("invalid_route_schema")
        if route.get("type", "unicast") in {"blackhole", "unreachable", "prohibit", "throw"}:
            continue
        try:
            dst = route.get("dst", "default")
            network = ip_network(("0.0.0.0/0" if family == 4 else "::/0") if dst == "default" else dst)
        except (ValueError, TypeError):
            raise CheckError("invalid_route_destination") from None
        if network.version != family or not any(network.subnet_of(p) for p in permitted):
            bad.append(route)
    return bad


def expected_addresses(info, segment):
    attachment = info["networks"][segment.name]
    addresses = []
    for subnet in segment.subnets:
        network = ip_network(subnet)
        key = "IPAddress" if network.version == 4 else "GlobalIPv6Address"
        try: address = ip_address(attachment.get(key, ""))
        except ValueError: raise CheckError("container_address_missing") from None
        if address not in network: raise CheckError("container_address_outside_segment")
        addresses.append(str(address))
    return addresses


def namespace_control(data, addresses, subnets):
    """Control positivo LOCAL: interfaz activa, IP esperada y ruta de enlace.

    No depende de que SSH, HTTP u otro servicio esté disponible; tampoco envía
    paquetes adicionales. Impide aprobar porque se entró en una red sin configurar.
    """
    for kind in ("links", "addresses"):
        result = data.get(kind, {})
        if not isinstance(result, dict) or result.get("returncode") != 0 or not isinstance(result.get("data"), list):
            raise CheckError("namespace_state_unavailable")
    active = {link.get("ifname") for link in data["links"]["data"] if isinstance(link, dict)
        and link.get("ifname") != "lo" and "UP" in link.get("flags", [])
        and ("LOWER_UP" in link.get("flags", []) or link.get("operstate") == "UP")}
    checked = []
    for value in addresses:
        address = ip_address(value)
        network = next(ip_network(s) for s in subnets if address in ip_network(s))
        found = False
        for interface in data["addresses"]["data"]:
            if not isinstance(interface, dict) or interface.get("ifname") not in active: continue
            for entry in interface.get("addr_info", []):
                if (not isinstance(entry, dict) or entry.get("local") != value
                    or entry.get("tentative") or entry.get("dadfailed")
                    or {"tentative", "dadfailed"}.intersection(entry.get("flags", []))): continue
                for route in data["routes"][str(address.version)]["table"]["data"]:
                    if (route.get("dst") == str(network) and route.get("dev") == interface["ifname"]
                        and not route.get("gateway") and route.get("type", "unicast") == "unicast"):
                        found = True
        checked.append({"address": value, "network": str(network), "active_interface_and_route": found})
    return {"passed": bool(checked) and all(x["active_interface_and_route"] for x in checked),
        "active_interfaces": sorted(active), "addresses_checked": checked}


def adjudicate_probe(data, allowed, addresses, segment_subnets):
    if not isinstance(data, dict) or not isinstance(data.get("routes"), dict) or not isinstance(data.get("probes"), list):
        raise CheckError("invalid_probe_schema")
    forbidden = []
    for family in (4, 6):
        item = data["routes"].get(str(family), {})
        if not isinstance(item, dict): raise CheckError("invalid_probe_schema")
        for kind in ("table", "rules"):
            result = item.get(kind, {})
            if not isinstance(result, dict) or result.get("returncode") != 0 or not isinstance(result.get("data"), list):
                raise CheckError("incomplete_routes_or_rules")
        forbidden += outside_routes(item["table"]["data"], allowed, family)
    keys = [(p.get("family"), p.get("address"), p.get("port")) for p in data["probes"] if isinstance(p, dict)]
    expected = [(p["family"], p["address"], p["port"]) for p in DESTINATIONS]
    if sorted(keys) != sorted(expected):
        raise CheckError("incomplete_or_duplicate_probes")
    status = "passed"
    reasons = []
    if forbidden:
        status = "failed"; reasons.append("route_outside_authorized_segments")
    for probe in data["probes"]:
        route = probe.get("route_get", {})
        connection = probe.get("connect", {})
        if not isinstance(route, dict) or not isinstance(connection, dict): raise CheckError("invalid_probe_schema")
        connect = connection.get("status")
        if route.get("returncode") == 0 or connect in {"connected", "refused"}:
            status = "failed"; reasons.append("external_route_or_reachability_observed")
        elif route.get("reason") != "no_route" or connect != "blocked":
            if status != "failed": status = "partial"
            reasons.append("negative_connectivity_not_proven")
    control = namespace_control(data, addresses, segment_subnets)
    if not control["passed"]:
        if status != "failed": status = "partial"
        reasons.append("active_namespace_and_authorized_route_not_proven")
    return {"status": status, "reasons": sorted(set(reasons)), "forbidden_routes": forbidden,
        "namespace_control": control, "observations": data}


def execute(lab: Lab, *, authorization: str, runner=subprocess.run,
            which=shutil.which, clock=time.monotonic, euid=os.geteuid) -> dict:
    if authorization != "LAB-PROPIO":
        raise ValueError("Para comprobar el laboratorio indique --autorizacion LAB-PROPIO.")
    receipt = plan(lab); started = clock(); receipt["status"] = "partial"
    binaries = {name: which(name) for name in ("docker", "nsenter", "ip")}
    if not all(binaries.values()):
        receipt["issues"].append("required_binary_missing"); return receipt
    if euid() != 0 and not which("sudo"):
        receipt["issues"].append("nsenter_requires_root_or_sudo"); return receipt
    def bounded_runner(command, **kwargs):
        remaining = receipt["maximum_seconds"] - (clock() - started)
        if remaining <= 0: raise CheckError("global_time_budget_exhausted")
        kwargs["timeout"] = min(kwargs["timeout"], remaining)
        return runner(command, **kwargs)
    snapshots = {}
    try:
        # Validar TODOS los segmentos antes de emitir una sola conexión.
        for net in lab.networks:
            raw = command_json(bounded_runner, [*DOCKER, "network", "inspect", net.name])
            if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
                raise CheckError("invalid_network_inspect")
            info = raw[0]
            subnets = {x.get("Subnet") for x in info.get("IPAM", {}).get("Config", [])}
            members = {x.get("Name") for x in info.get("Containers", {}).values()}
            if (info.get("Name") != net.name or info.get("Internal") is not True
                or info.get("Driver") != "bridge" or subnets != set(net.subnets)
                or members != set(net.members)
                or info.get("Options", {}).get("com.docker.network.bridge.name") != net.bridge):
                receipt["status"] = "failed"; raise CheckError("network_identity_or_isolation_mismatch")
            network_id = info.get("Id")
            if not isinstance(network_id, str) or not network_id: raise CheckError("missing_network_identity")
            member_ids = {value["Name"]: key for key, value in info["Containers"].items()}
            receipt.setdefault("inspected_networks", []).append(info)
            for name in net.members:
                container = container_info(bounded_runner, name)
                if (not valid_container(container, name, net.name)
                    or container["id"] != member_ids[name]
                    or container["networks"][net.name].get("NetworkID") != network_id):
                    receipt["status"] = "failed"; raise CheckError("container_identity_or_attachment_mismatch")
                expected_addresses(container, net)
                snapshots[name] = container
        allowed = tuple(s for n in lab.networks for s in n.subnets) + (lab.slaac_prefix,)
        for net in lab.networks:
            for name in net.members:
                if clock() - started > receipt["maximum_seconds"] - 20:
                    raise CheckError("global_time_budget_exhausted")
                before = container_info(bounded_runner, name)
                if before != snapshots[name]: raise CheckError("container_changed_before_probe")
                addresses = expected_addresses(before, net)
                cfg = json.dumps({"ip": binaries["ip"], "destinations": DESTINATIONS,
                    "expected_addresses": addresses, "segment_subnets": net.subnets}, separators=(",", ":"))
                command = [binaries["nsenter"], "--target", str(before["pid"]), "--net", "--",
                    sys.executable, "-I", "-S", "-c", PROBE_SCRIPT, cfg]
                if euid() != 0: command = [which("sudo"), "-n", *command]
                result = command_json(bounded_runner, command, timeout=20)
                row = {"container": name, "segment": net.name, "container_id": before["id"],
                    **adjudicate_probe(result, allowed, addresses, net.subnets)}
                if container_info(bounded_runner, name) != before:
                    row.update(status="partial", reasons=["container_changed_during_probe"])
                receipt["containers"].append(row)
        # Una modificación de red durante la comprobación invalida el recibo.
        for previous in receipt["inspected_networks"]:
            current = command_json(bounded_runner, [*DOCKER, "network", "inspect", previous["Name"]])
            if current != [previous]: raise CheckError("network_changed_during_check")
        statuses = [r["status"] for r in receipt["containers"]]
        expected_count = sum(len(n.members) for n in lab.networks)
        receipt["status"] = "failed" if "failed" in statuses else "passed" if len(statuses) == expected_count and all(s == "passed" for s in statuses) else "partial"
    except CheckError as exc:
        receipt["issues"].append(str(exc))
    except (KeyError, TypeError, AttributeError):
        receipt["issues"].append("invalid_inspection_schema")
    if any(row["status"] == "failed" for row in receipt["containers"]):
        receipt["status"] = "failed"
    receipt["requirement_status"] = "VALIDADO" if receipt["status"] == "passed" else "PARCIAL"
    receipt["elapsed_seconds"] = round(clock() - started, 3)
    receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
    return receipt


def write_receipt(path: Path, receipt: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        raise ValueError("El archivo de salida ya existe o es un enlace; utilice una ruta nueva.")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2); stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", choices=SCENARIOS, required=True)
    parser.add_argument("--output", type=Path, required=True, help="JSON nuevo; no se sobrescriben evidencias.")
    parser.add_argument("--ejecutar", action="store_true", help="Comprobar Docker y emitir sondas; por defecto solo plan.")
    parser.add_argument("--autorizacion", default="", help="LAB-PROPIO; obligatorio únicamente con --ejecutar.")
    args = parser.parse_args(argv)
    try:
        if args.output.exists() or args.output.is_symlink(): raise ValueError("La salida ya existe; elija otro nombre.")
        lab = definition(args.lab)
        result = execute(lab, authorization=args.autorizacion) if args.ejecutar else plan(lab)
        write_receipt(args.output, result)
    except (ValueError, OSError):
        print("No se generó recibo: revise autorización, dependencias y una ruta de salida nueva.", file=sys.stderr)
        return 3
    print(f"Aislamiento {args.lab}: {result['status']}. API: 0. Recibo: {args.output}")
    return 0 if result["status"] in {"passed", "not_executed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
