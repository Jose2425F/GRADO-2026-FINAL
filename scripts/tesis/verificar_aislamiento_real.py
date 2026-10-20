#!/usr/bin/env python3
"""Recibos RNF-08 reales, finitos y sin API; conserva bancos y experimentos.

El plan es el modo predeterminado. --ejecutar --autorizacion LAB-PROPIO permite
iniciar SOLO configuraciones ya existentes, sin build/pull/recreate, verificar
TCP en tres representantes y detener el banco conservando contenedores y datos.
--modo kali comprueba TCP positivo con bind desde bridges reales del anfitrión;
sus negativos intersegmento y de salida son exclusivamente consultas pasivas.
No ejecuta prepare/preflight, auditorías, HTTP, shell dentro del banco ni cambios
de firewall/rutas. No confunde pruebas unitarias con ejecución real.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import shutil
import socket
import errno
import struct
import subprocess
import sys
import time

from tesis.verificar_aislamiento import DOCKER, PILOT, ROOT, SCENARIOS, definition

OUTPUT = ROOT / "docs/verificacion-postevaluacion"
PROTECTED = PILOT / ".verificacion/verificacion-real-postevaluacion/huellas-protegidas.json"
MIN_ENV = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
IP = shutil.which("ip", path=MIN_ENV["PATH"]) or "/usr/sbin/ip"
SCRIPT_VERSION = "novaflow-real-isolation/2-kali"
DOCUMENTATION_ROUTES = {4: "192.0.2.1", 6: "2001:db8::1"}
KALI_LIMITS = [
    "TCP finito sin payload desde direcciones reales del anfitrión asignadas a bridges del banco; no se prueba la aplicación.",
    "Solo endpoints controlados, activos y obtenidos del inventario Docker del mismo banco; nunca se conecta a destinos externos.",
    "La ruta se consulta de nuevo después de bind y antes de cada connect; se exige el bridge del destino sin gateway.",
    "La matriz L3 entre segmentos desde el anfitrión no está fijada: los negativos intersegmento son solo consultas de ruta, NO VERIFICADO.",
    "La salida externa se examina únicamente con route get a direcciones de documentación; no se transmiten paquetes a ellas.",
    "El JSON del firewall es una captura de solo lectura, no una comprobación de las reglas vigentes después del arranque del banco.",
    "Un timeout o rechazo no demuestra aislamiento. RNF-08 permanece PARCIAL; no se extrapola a todo puerto, protocolo o proceso.",
]
CONTAINER_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"pid":{{json .State.Pid}},'
    '"running":{{json .State.Running}},"network_mode":{{json .HostConfig.NetworkMode}},'
    '"privileged":{{json .HostConfig.Privileged}},"user":{{json .Config.User}},'
    '"cap_add":{{json .HostConfig.CapAdd}},"cap_drop":{{json .HostConfig.CapDrop}},'
    '"networks":{{json .NetworkSettings.Networks}}}')
NETWORK_FORMAT = ('{"name":{{json .Name}},"id":{{json .Id}},"internal":{{json .Internal}},'
    '"driver":{{json .Driver}},"enable_ipv6":{{json .EnableIPv6}},'
    '"ipam":{{json .IPAM.Config}},"options":{{json .Options}},"members":{{json .Containers}}}')
LIMITS = [
    "Solo tres contenedores representantes por banco: portal, app-crm y sender; no todos los procesos ni miembros.",
    "Conexiones TCP sin payload: DMZ IPv4, corporativo y datacenter IPv4/IPv6; no son auditorías de aplicación.",
    "Negativos solo a endpoints vivos de otros segmentos de ESTE banco; ningún sistema externo real.",
    "No se prueba salida del anfitrión, DNS, UDP, servicios externos, ataques ni configuraciones futuras.",
    "La validación literal de RNF-08 permanece PARCIAL aunque el alcance observado resulte PASS.",
    "Un timeout, rechazo TCP o control positivo fallido nunca basta para acreditar bloqueo.",
    "Las capacidades del PID 1 y del proceso Python de comprobación son una instantánea, no todos los procesos.",
]

# Linux netlink read-only dump. Avoids installing iproute2 in images which lack it.
# No RTM_NEW/DEL requests. All sockets and files belong to the existing exec user.
REMOTE = r'''
import errno,json,os,socket,struct,sys,time
from pathlib import Path
cfg=json.loads(sys.argv[1]); out={"method":"docker_exec_existing_python_netlink_read_only"}
def attrs(data):
 ans={}; pos=0
 while pos+4<=len(data):
  size,kind=struct.unpack_from("=HH",data,pos)
  if size<4 or pos+size>len(data):raise ValueError("invalid_attr")
  ans[kind&0x3fff]=data[pos+4:pos+size];pos+=(size+3)&~3
 return ans
def integer(data):return struct.unpack("=I",data)[0]
def dump(kind,body):
 s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0);s.settimeout(2)
 try:
  s.bind((0,0));s.send(struct.pack("=IHHII",16+len(body),kind,0x301,731,0)+body);ans=[]
  while True:
   data=s.recv(1048576);pos=0
   while pos+16<=len(data):
    size,typ,flags,seq,pid=struct.unpack_from("=IHHII",data,pos)
    if size<16 or pos+size>len(data):raise ValueError("invalid_netlink")
    payload=data[pos+16:pos+size];pos+=(size+3)&~3
    if typ==3:return ans
    if typ==2:raise OSError("netlink_error")
    ans.append((typ,payload))
 finally:s.close()
def network_state():
 links=[];addresses=[];routes={};rules={}
 for typ,b in dump(18,struct.pack("=BBHiII",0,0,0,0,0,0)):
  if typ!=16:continue
  fam,_,kind,index,flags,change=struct.unpack_from("=BBHiII",b);a=attrs(b[16:])
  links.append({"index":index,"name":a.get(3,b"").split(b"\0")[0].decode(),"up":bool(flags&1),"lower_up":bool(flags&0x10000)})
 for typ,b in dump(22,struct.pack("=BBBBI",0,0,0,0,0)):
  if typ!=20:continue
  fam,prefix,flags,scope,index=struct.unpack_from("=BBBBI",b);a=attrs(b[8:])
  if fam not in (2,10):continue
  value=a.get(2,a.get(1));flags=integer(a[8]) if 8 in a else flags
  if value:addresses.append({"family":4 if fam==2 else 6,"address":socket.inet_ntop(fam,value),"prefix":prefix,"interface":index,"tentative":bool(flags&64),"dadfailed":bool(flags&8)})
 for fam,family in [(2,4),(10,6)]:
  routes[str(family)]=[];rules[str(family)]=[]
  for typ,b in dump(26,struct.pack("=BBBBBBBBI",fam,0,0,0,0,0,0,0,0)):
   if typ!=24:continue
   f,dlen,slen,tos,table,proto,scope,rtype,flags=struct.unpack_from("=BBBBBBBBI",b);a=attrs(b[12:])
   if f!=fam:continue
   zero="0.0.0.0" if family==4 else "::"
   row={"family":family,"dst":socket.inet_ntop(f,a[1])+"/"+str(dlen) if 1 in a else zero+"/"+str(dlen),"table":integer(a[15]) if 15 in a else table,"type":rtype,"scope":scope,"protocol":proto,"flags":flags}
   if 4 in a:row["interface"]=integer(a[4])
   if 5 in a:row["gateway"]=socket.inet_ntop(f,a[5])
   if 7 in a:row["source"]=socket.inet_ntop(f,a[7])
   if 9 in a:row["multipath"]=True
   routes[str(family)].append(row)
  for typ,b in dump(34,struct.pack("=BBBBBBBBI",fam,0,0,0,0,0,0,0,0)):
   if typ!=32:continue
   f,dlen,slen,tos,table,_,_,action,flags=struct.unpack_from("=BBBBBBBBI",b);a=attrs(b[12:])
   if f!=fam:continue
   rules[str(family)].append({"family":family,"table":integer(a[15]) if 15 in a else table,"action":action,"flags":flags,"dst_prefix":dlen,"src_prefix":slen,"tos":tos,"priority":integer(a[6]) if 6 in a else 0,"suppress_prefixlen":integer(a[14]) if 14 in a else 4294967295,"selector_attributes":sorted(k for k in a if k not in (6,14,15,21))})
 return {"status":"available","links":links,"addresses":addresses,"routes":routes,"rules":rules}
def proc_status(path):
 allowed={"Uid","Gid","CapInh","CapPrm","CapEff","CapBnd","CapAmb","NoNewPrivs","Seccomp"}
 try:return {k:v.strip() for line in Path(path).read_text().splitlines() if ":" in line for k,v in [line.split(":",1)] if k in allowed}
 except OSError:return {"reason":"proc_status_unavailable"}
out["privileges"]={"pid1":proc_status("/proc/1/status"),"exec_process":proc_status("/proc/self/status"),"exec_uid":os.getuid(),"exec_euid":os.geteuid(),"exec_gid":os.getgid()}
try:out["network_state"]=network_state()
except (OSError,ValueError,struct.error):out["network_state"]={"status":"unavailable","reason":"netlink_state_unavailable"}
out["probes"]=[]
for target in cfg.get("targets",[]):
 row=dict(target);sock=None;start=time.monotonic()
 try:
  sock=socket.socket(socket.AF_INET if target["family"]==4 else socket.AF_INET6,socket.SOCK_STREAM);sock.settimeout(0.65)
  sock.connect((target["address"],target["port"]));row["connect"]={"status":"connected"}
 except (socket.timeout,TimeoutError):row["connect"]={"status":"timeout"}
 except OSError as exc:
  row["connect"]={"status":"blocked" if exc.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EACCES,errno.EPERM) else "refused" if exc.errno==errno.ECONNREFUSED else "error","errno":exc.errno}
 finally:
  if sock is not None:sock.close()
 row["elapsed_seconds"]=round(time.monotonic()-start,6);out["probes"].append(row)
print(json.dumps(out,separators=(",",":")))
'''


class CheckError(Exception):
    """Closed reason only; never returns raw Docker stderr or environment."""


def now():
    return datetime.now(timezone.utc).isoformat()


def command(args, *, decode=True, timeout=15, runner=subprocess.run):
    try:
        p = runner(args, capture_output=True, text=True, check=False,
                   timeout=min(timeout, 15), env=MIN_ENV)
    except subprocess.TimeoutExpired:
        raise CheckError("command_timeout") from None
    except OSError:
        raise CheckError("command_unavailable") from None
    if p.returncode:
        raise CheckError("command_failed")
    if not decode:
        return p.stdout
    try:
        return json.loads(p.stdout)
    except (ValueError, TypeError):
        raise CheckError("invalid_command_json") from None


def paths(scenario):
    state = PILOT / (".lab-empresa" if scenario == "original" else ".lab-suite/" + scenario)
    compose = ROOT / "piloto_kali/despliegue/empresa/docker-compose.empresa.yml" if scenario == "original" else state / "compose.json"
    return compose, state / "lab.env"


def configuration(scenario):
    compose, env = paths(scenario)
    if not compose.is_file() or not env.is_file():
        raise CheckError("existing_config_or_env_missing")
    if compose.is_symlink() or env.is_symlink():
        raise CheckError("config_symlink_refused")
    if env.stat().st_mode & 0o077:
        raise CheckError("existing_env_permissions_not_private")
    try:
        import yaml
        data = json.loads(compose.read_text()) if compose.suffix == ".json" else yaml.safe_load(compose.read_text())
        images = sorted({s["image"] for s in data["services"].values()})
    except (ImportError, ValueError, KeyError, TypeError):
        raise CheckError("existing_config_unreadable") from None
    return {"compose":str(compose.relative_to(ROOT)),"env":str(env.relative_to(ROOT)),
        "compose_sha256":sha256(compose),"images":images}


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def protected_check():
    if not PROTECTED.is_file():
        raise CheckError("protected_manifest_missing")
    try:
        manifest = json.loads(PROTECTED.read_text())
        if not isinstance(manifest, dict) or not manifest:
            raise ValueError
        changed = sum(not (ROOT / p).is_file() or sha256(ROOT / p) != value for p, value in manifest.items())
    except (ValueError, OSError, TypeError):
        raise CheckError("protected_manifest_invalid") from None
    return {"files_checked":len(manifest),"changed_or_missing":changed,"unchanged":changed == 0,
        "manifest_sha256":sha256(PROTECTED)}


def active_jobs(proc=Path("/proc")):
    """Detect audit/panel processes without recording argv or credentials."""
    patterns = {"evaluacion.py", "laboratorio_empresa.py", "laboratorio_suite.py", "orquestacion_langgraph.py",
                "panel.py", "panel_web.py", "dualstack_panel.py", "ejecutar_estudio_novaflow.py", "iniciar_estudio_kpi.py"}
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            raw = (entry / "cmdline").read_bytes().split(b"\0")
            args = [x.decode(errors="replace") for x in raw if x]
        except OSError:
            continue
        if not args:
            continue
        exe = Path(args[0]).name
        if exe not in {"python", "python3", "python3.13", "uvicorn", "gunicorn", "node"}:
            continue
        if any(Path(x).name in patterns for x in args[1:]) or "auditoria.panel" in args or "auditoria.cli" in args:
            found.append({"pid":int(entry.name),"reason":"audit_or_panel_process_present"})
    return found


def no_running_containers():
    return not bool(command([*DOCKER,"ps","-q"],decode=False).strip())


def endpoints(lab):
    answer = []
    for network in lab.networks:
        members = list(network.members)
        if network.name.endswith("_dmz"):
            kind,source,peer,port = "dmz", next(x for x in members if x.endswith("-portal")), next(x for x in members if x.endswith("-legacy")),8080
        elif network.name.endswith("_corp"):
            kind,source,peer,port = "corp", next(x for x in members if x.endswith("-app-crm")),next(x for x in members if "-app-" in x and not x.endswith("-app-crm")),8088
        else:
            kind,source,peer,port = "dc", next(x for x in members if x.endswith("-sender")),next(x for x in members if x.endswith("-receiver-a")),8000
        answer.append({"segment":kind,"network":network.name,"source":source,"peer":peer,"port":port,"families":[ip_network(s).version for s in network.subnets]})
    return answer


def inspect_container(name):
    return command([*DOCKER,"container","inspect","--format",CONTAINER_FORMAT,name])


def address_of(info, network, family):
    key = "IPAddress" if family == 4 else "GlobalIPv6Address"
    try:
        value = info["networks"][network][key]
        if ip_address(value).version != family:
            raise ValueError
        return value
    except (ValueError, KeyError, TypeError):
        raise CheckError("endpoint_address_unavailable") from None


def targets(spec, infos):
    return [{"target_segment":spec["segment"],"target_container":spec["peer"],"family":family,
             "address":address_of(infos[spec["peer"]],spec["network"],family),"port":spec["port"]}
            for family in spec["families"]]


def observe(source, destinations):
    return command([*DOCKER,"exec",source,"python","-I","-S","-c",REMOTE,
        json.dumps({"targets":destinations},separators=(",",":"))])


def check_network(lab_network, data, infos):
    reasons = []
    if data.get("internal") is not True or data.get("driver") != "bridge":
        reasons.append("network_not_internal_bridge")
    if data.get("name") != lab_network.name:
        reasons.append("network_name_mismatch")
    if data.get("options",{}).get("com.docker.network.bridge.name") != lab_network.bridge:
        reasons.append("network_bridge_mismatch")
    if {x.get("Subnet") for x in data.get("ipam",[])} != set(lab_network.subnets):
        reasons.append("network_subnet_mismatch")
    if {x.get("Name") for x in (data.get("members") or {}).values()} != set(lab_network.members):
        reasons.append("network_member_mismatch")
    if any(ip_network(s).version == 6 for s in lab_network.subnets) and not data.get("enable_ipv6"):
        reasons.append("network_ipv6_disabled")
    for name in lab_network.members:
        info = infos[name]
        if (info.get("name") != "/" + name or info.get("running") is not True or not info.get("pid")
            or info.get("privileged") is not False or set(info.get("networks",{})) != {lab_network.name}
            or info.get("network_mode") in {"host","none"}
            or str(info.get("network_mode","")).startswith("container:")):
            reasons.append("container_membership_or_mode_invalid")
        for family in [ip_network(s).version for s in lab_network.subnets]:
            try:
                addr = ip_address(address_of(info,lab_network.name,family))
                if not any(addr in ip_network(s) for s in lab_network.subnets if ip_network(s).version == family):
                    reasons.append("container_address_outside_expected_subnet")
            except CheckError:
                reasons.append("container_address_unavailable")
    return {"status":"PASS" if not reasons else "FAIL","reasons":sorted(set(reasons)),"expected":asdict(lab_network),"observed":data}


def check_routes(observation, spec, lab, source_info):
    state = observation.get("network_state",{})
    if state.get("status") != "available":
        return {"status":"PARTIAL","reasons":["network_state_unavailable"]}
    reasons = []
    local = next(n for n in lab.networks if n.name == spec["network"])
    permitted = [ip_network(s) for s in local.subnets]
    if spec["segment"] == "dc":
        permitted.append(ip_network(lab.slaac_prefix))
    permitted.extend(ip_network(s) for s in ("127.0.0.0/8","169.254.0.0/16","224.0.0.0/4","255.255.255.255/32","::1/128","fe80::/10","ff00::/8"))
    forbidden = []
    default_routes = []
    for family in (4,6):
        for route in state.get("routes",{}).get(str(family),[]):
            try:
                dst = ip_network(route["dst"],strict=False)
            except (ValueError,KeyError,TypeError):
                reasons.append("route_invalid");continue
            # Types 6/7/8/9 are explicit blackhole/unreachable/prohibit/throw.
            if dst.prefixlen == 0 and route.get("type") not in (6,7,8,9):
                default_routes.append(route)
            if route.get("type") in (6,7,8,9):
                continue
            if route.get("multipath") or route.get("gateway") or not any(dst.version == n.version and dst.subnet_of(n) for n in permitted):
                forbidden.append(route)
        rules = state.get("rules",{}).get(str(family),[])
        if not rules:
            reasons.append("routing_rules_missing")
        if any(r.get("action") != 1 or r.get("table") not in (253,254,255) or r.get("src_prefix") or r.get("dst_prefix") or r.get("tos") or r.get("flags") or r.get("suppress_prefixlen",4294967295)!=4294967295 or r.get("selector_attributes") for r in rules):
            reasons.append("routing_rules_unexpected")
    if forbidden:
        reasons.append("route_outside_source_segment_or_gateway")
    if default_routes:
        reasons.append("default_route_present")
    active = {x["index"] for x in state.get("links",[]) if x.get("up") and x.get("lower_up") and x.get("name") != "lo"}
    for family in spec["families"]:
        expected = address_of(source_info,spec["network"],family)
        if not any(x.get("address") == expected and x.get("interface") in active and not x.get("tentative") and not x.get("dadfailed") for x in state.get("addresses",[])):
            reasons.append("source_address_not_active")
        subnet = next(s for s in local.subnets if ip_network(s).version == family)
        if not any(r.get("dst") == subnet and r.get("interface") in active and r.get("type") == 1 and not r.get("gateway") for r in state.get("routes",{}).get(str(family),[])):
            reasons.append("source_connected_route_missing")
    return {"status":"PASS" if not reasons else "FAIL","reasons":sorted(set(reasons)),"default_routes":default_routes,"forbidden_routes":forbidden,"observed":state}


def assess_negatives(probes, positive_endpoints, route_status):
    results = []
    for row in probes:
        key = (row["target_container"],row["family"],row["address"],row["port"])
        live = key in positive_endpoints
        status = row.get("connect",{}).get("status")
        verdict = "FAIL" if status == "connected" else "PASS" if status == "blocked" and live and route_status == "PASS" else "PARTIAL"
        reason = "cross_segment_connected" if verdict == "FAIL" else "blocked_with_live_endpoint_and_no_route" if verdict == "PASS" else "negative_inconclusive"
        results.append({**row,"endpoint_positive_control":live,"status":verdict,"reason":reason})
    return results


def usable_in_subnets(value, subnets):
    if value.is_unspecified or value.is_multicast or value.is_loopback or getattr(value,"scope_id",None):
        return False
    return any(value.version==ip_network(subnet).version and value in ip_network(subnet)
               and (value.version==6 or value not in (ip_network(subnet).network_address,ip_network(subnet).broadcast_address))
               for subnet in subnets)


def selected_kali_specs(lab, *, segment="todos", interface=None, source_address=None):
    """Selecciona exclusivamente bridges y direcciones del catálogo autorizado."""
    specs = endpoints(lab)
    for spec in specs:
        spec["interface"] = next(n.bridge for n in lab.networks if n.name == spec["network"])
    if segment != "todos":
        specs = [spec for spec in specs if spec["segment"] == segment]
    if interface:
        specs = [spec for spec in specs if spec["interface"] == interface]
    if source_address:
        try:
            source = ip_address(source_address)
        except ValueError:
            raise CheckError("source_address_invalid") from None
        specs = [spec for spec in specs if any(usable_in_subnets(source,network.subnets)
                 for network in lab.networks if network.name == spec["network"])]
    if not specs:
        raise CheckError("source_selection_outside_lab_catalogue")
    return specs


def firewall_snapshot(path):
    """Resume una captura existente. Nunca invoca nft ni interpreta xt opacos."""
    if path is None:
        return {"status":"NO_VERIFICADO","reason":"firewall_snapshot_not_supplied"}
    path = Path(path)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError
        data = json.loads(path.read_text())
        items = data["nftables"]
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ValueError
        chains = [item["chain"] for item in items if "chain" in item]
        rules = [item["rule"] for item in items if "rule" in item]
        identity = lambda row: {key:row.get(key) for key in ("family","table","chain","handle") if key in row}
        outputs = [{key:chain.get(key) for key in ("family","table","name","handle","type","hook","prio","policy")}
                   for chain in chains if chain.get("hook") == "output"]
        opaque = [{**identity(rule),"extensions":[expr["xt"].get("name") for expr in rule.get("expr",[]) if "xt" in expr]}
                  for rule in rules if any("xt" in expr for expr in rule.get("expr",[]))]
        users = [{"family":chain.get("family"),"table":chain.get("table"),"handle":chain.get("handle"),
                  "rules":sum(rule.get("family")==chain.get("family") and rule.get("table")==chain.get("table") and rule.get("chain")=="DOCKER-USER" for rule in rules)}
                 for chain in chains if chain.get("name")=="DOCKER-USER"]
        counters = [expr["counter"] for rule in rules for expr in rule.get("expr",[]) if "counter" in expr]
        return {"status":"SNAPSHOT_READ_ONLY","path":str(path.resolve()),"sha256":sha256(path),
                "tables":sum("table" in item for item in items),"chains":len(chains),"rules":len(rules),
                "output_hooks":outputs,"output_filter_present":any(chain.get("type")=="filter" for chain in outputs),
                "docker_user":users,"opaque_xt":opaque,
                "eth0_rules":[identity(rule) for rule in rules if '"eth0"' in json.dumps(rule)],
                "nonzero_counters":sum(bool(counter.get("packets") or counter.get("bytes")) for counter in counters),
                "limitations":["Snapshot supplied by the operator; not refreshed with privileged commands.",
                                "NAT output hooks do not establish filtering of host-originated traffic.",
                                "Opaque xt extension arguments and other namespaces/mechanisms are not reconstructed."]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise CheckError("firewall_snapshot_invalid") from None


def host_network_state():
    """Consultas iproute2 de solo lectura; no cambia enlaces, rutas ni reglas."""
    return {"addresses":command([IP,"-j","address","show"]),
            "routes":{str(f):command([IP,"-j",f"-{f}","route","show","table","all"]) for f in (4,6)},
            "rules":{str(f):command([IP,"-j",f"-{f}","rule","show"]) for f in (4,6)}}


def kali_route_get(address, family, source=None):
    """RTM_GETROUTE vía iproute2; no es una sonda ni transmite al destino."""
    try:
        if ip_address(address).version != family or (source and ip_address(source).version != family):
            raise ValueError
    except (ValueError, TypeError):
        raise CheckError("route_query_address_invalid") from None
    args = [IP,"-j",f"-{family}","route","get",address]
    if source:
        args += ["from",source]
    rows = command(args)
    if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):
        raise CheckError("route_query_ambiguous")
    return rows[0]


def kali_sources(lab, spec, state, *, source_address=None):
    network = next(n for n in lab.networks if n.name==spec["network"])
    sources = []
    for link in state.get("addresses",[]):
        if link.get("ifname") != network.bridge or "UP" not in link.get("flags",[]):
            continue
        for address in link.get("addr_info",[]):
            try:
                value = ip_address(address.get("local"))
            except (ValueError, TypeError):
                continue
            flags = address.get("flags",[])
            if (value.version not in spec["families"] or address.get("scope") != "global"
                or address.get("tentative") or address.get("dadfailed")
                or "tentative" in flags or "dadfailed" in flags
                or value.is_unspecified or value.is_multicast or value.is_loopback
                or (source_address and value != ip_address(source_address))):
                continue
            if usable_in_subnets(value,network.subnets):
                sources.append({"interface":network.bridge,"address":str(value),"family":value.version,
                                "prefix_length":address.get("prefixlen"),"selection":"active_host_address_in_configured_subnet"})
    return sorted(sources,key=lambda row:(row["family"],row["address"]))


def validate_kali_target(lab, target, infos):
    """Una lista cerrada de endpoints reales, no rangos arbitrarios ni documentación."""
    try:
        spec = next(spec for spec in endpoints(lab) if spec["segment"]==target["target_segment"])
        network = next(n for n in lab.networks if n.name==spec["network"])
        info = infos[target["target_container"]]
        address = ip_address(target["address"])
        if (target["target_container"] != spec["peer"] or target["port"] != spec["port"]
                or target["family"] not in spec["families"] or address.version!=target["family"]
                or info.get("running") is not True or not info.get("pid")
                or set(info.get("networks",{}))!={spec["network"]}
                or str(address)!=address_of(info,spec["network"],target["family"])
                or not usable_in_subnets(address,network.subnets)):
            raise ValueError
        return network
    except (KeyError, ValueError, TypeError, StopIteration):
        raise CheckError("controlled_active_endpoint_required") from None


def direct_kali_route(route, interface, source=None):
    if (route.get("dev") != interface or interface=="eth0" or route.get("gateway")
            or route.get("via") or route.get("multipath") or route.get("nexthops")
            or route.get("type","unicast") not in ("unicast",1)):
        return False
    observed = route.get("prefsrc",route.get("src"))
    try:
        return not source or not observed or ip_address(observed)==ip_address(source)
    except (ValueError, TypeError):
        return False


def kali_tcp_probe(lab, spec, target, source, infos, *, route_reader=None, socket_factory=None):
    """Bind, ruta inmediatamente anterior al connect y origen efectivo comprobado."""
    network = validate_kali_target(lab,target,infos)
    route_reader = route_reader or kali_route_get
    socket_factory = socket_factory or socket.socket
    try:
        address = ip_address(source["address"])
        if (source["interface"] != network.bridge or address.version!=source["family"] or source["family"]!=target["family"]
                or spec["segment"]!=target["target_segment"] or source["interface"]!=spec["interface"]
                or not usable_in_subnets(address,network.subnets)):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise CheckError("source_not_in_destination_audit_segment") from None
    row = {**target,"checked_at":now(),"interface":source["interface"],"source_address":str(address),
           "protocol":"TCP","expected_policy":"PERMITIR_HOST_A_SEGMENTO_SERVICIO_CATALOGADO",
           "test":"bound_tcp_connect_no_payload","connection_attempted":False,"payload_bytes":0,
           "status":"NO_VERIFICADO","script_version":SCRIPT_VERSION}
    sock = None
    try:
        # A first route guard prevents even constructing a socket on an unsafe path.
        route = route_reader(target["address"],target["family"],str(address))
        row["route_before_bind"] = route
        if not direct_kali_route(route,network.bridge,str(address)):
            raise CheckError("unsafe_route_no_connection")
        sock = socket_factory(socket.AF_INET if target["family"]==4 else socket.AF_INET6,socket.SOCK_STREAM)
        sock.settimeout(0.65)
        sock.bind((str(address),0) if target["family"]==4 else (str(address),0,0,0))
        row["bound_source"] = sock.getsockname()[0]
        if ip_address(row["bound_source"].split("%",1)[0]) != address:
            row["status"]="FAIL"
            raise CheckError("bound_source_mismatch_no_connection")
        route = route_reader(target["address"],target["family"],str(address))
        row["route_immediately_before_connect"] = route
        if not direct_kali_route(route,network.bridge,str(address)):
            raise CheckError("route_changed_no_connection")
        row["connection_attempted"] = True
        sock.connect((target["address"],target["port"]))
        row["observed"] = "connected"
        row["status"] = "PASS"
    except CheckError as exc:
        row["reason"] = str(exc)
        row.setdefault("observed","not_attempted")
    except (socket.timeout,TimeoutError):
        row.update(observed="timeout",reason="positive_control_inconclusive")
    except OSError as exc:
        row.update(observed="refused" if exc.errno==errno.ECONNREFUSED else "socket_error",errno=exc.errno,
                   reason="positive_control_inconclusive")
    finally:
        if sock is not None:
            try:
                effective = sock.getsockname()[0].split("%",1)[0]
                row["effective_source_address"] = effective
                if ip_address(effective)!=address:
                    row.update(status="FAIL",reason="effective_source_mismatch")
            except (OSError,ValueError,IndexError):
                if row["status"]!="FAIL":
                    row.update(status="NO_VERIFICADO",reason="effective_source_unavailable")
            sock.close()
    return row


def kali_passive_negative(lab, target, source, infos, *, route_reader=None):
    network = validate_kali_target(lab,target,infos)
    row = {**target,"checked_at":now(),"interface":source["interface"],"source_address":source["address"],
           "protocol":"TCP_NOT_SENT","expected_policy":"MATRIZ_L3_INTERSEGMENTOS_NO_FIJADA",
           "test":"passive_route_lookup_only","connection_attempted":False,"status":"NO_VERIFICADO",
           "reason":"no_explicit_intersegment_deny_policy_no_connection","script_version":SCRIPT_VERSION}
    try:
        row["route"]=(route_reader or kali_route_get)(target["address"],target["family"],source["address"])
        row["route_to_controlled_bridge_without_gateway"]=direct_kali_route(row["route"],network.bridge)
    except CheckError as exc:
        row["route_reason"]=str(exc)
    return row


def kali_passive_external(source, firewall, *, route_reader=None):
    destination = DOCUMENTATION_ROUTES[source["family"]]
    row = {"checked_at":now(),"interface":source["interface"],"source_address":source["address"],
           "family":source["family"],"address":destination,"port":None,"protocol":"ROUTE_LOOKUP_ONLY",
           "expected_policy":"DENEGAR_SALIDA_NO_AUTORIZADA","test":"passive_external_route_and_firewall_snapshot",
           "connection_attempted":False,"payload_bytes":0,"status":"NO_VERIFICADO",
           "destination_is_documentation_not_probed":True,"script_version":SCRIPT_VERSION,
           "output_filter_in_snapshot":firewall.get("output_filter_present"),
           "reason":"external_connectivity_never_probed_and_egress_not_fully_accredited"}
    try:
        row["route"]=(route_reader or kali_route_get)(destination,source["family"],source["address"])
        row["potential_egress_outside_audit_bridge"]=bool(row["route"].get("gateway") or row["route"].get("dev")!=source["interface"])
    except CheckError as exc:
        row["route_reason"]=str(exc)
    return row


def verify_kali(receipt, lab, specs, infos, networks, segments, *, source_address=None, deadline=None):
    receipt["stage"]="kali_host_network_snapshot"
    state=host_network_state();receipt["host_network_state"]=state
    firewall=receipt.get("firewall_snapshot",{})
    all_targets=[target for spec in endpoints(lab) for target in targets(spec,infos)]
    deadline = deadline or time.monotonic()+240
    live=set()
    for spec in specs:
        seg=segments[spec["segment"]];seg["configuration"]=networks[spec["network"]]
        seg["firewall_snapshot_reference"]=firewall.get("path")
        seg["sources"]=kali_sources(lab,spec,state,source_address=source_address)
        if any(check["status"]!="PASS" for check in networks.values()):
            seg["reason_codes"].append("lab_network_configuration_not_validated_no_connections")
            continue
        selected=[]
        for family in spec["families"]:
            candidates=[source for source in seg["sources"] if source["family"]==family]
            if not candidates:
                if not source_address or ip_address(source_address).version==family:
                    seg["reason_codes"].append("active_host_source_unavailable_ipv"+str(family))
                continue
            target=next(target for target in all_targets if target["target_segment"]==spec["segment"] and target["family"]==family)
            # Prefer the source selected by the current kernel route when it is
            # one of the actual local addresses; explicit source always wins.
            try:
                automatic=kali_route_get(target["address"],family)
                preferred=automatic.get("prefsrc",automatic.get("src"))
            except CheckError:
                preferred=None
            source=next((candidate for candidate in candidates if candidate["address"]==preferred),candidates[0])
            selected.append(source)
            for attempt in range(1,6):
                if time.monotonic()>=deadline:
                    raise CheckError("lab_global_timeout")
                current=inspect_container(target["target_container"])
                if any(current.get(key)!=infos[target["target_container"]].get(key) for key in ("id","pid","networks")) or current.get("running") is not True:
                    seg["reason_codes"].append("controlled_endpoint_changed_no_connection");break
                probe=kali_tcp_probe(lab,spec,target,source,infos)
                probe["attempt"]=attempt;seg["positive_attempts"].append(probe)
                if probe["status"]=="PASS":
                    live.add((target["target_container"],family,target["address"],target["port"]));break
                if not probe["connection_attempted"] or probe["status"]=="FAIL":
                    break
                if attempt<5:time.sleep(1)
        seg["selected_sources"]=selected
        seg["positive_status"]="PASS" if selected and all(any(row["status"]=="PASS" and row["family"]==source["family"] for row in seg["positive_attempts"]) for source in selected) and not seg["reason_codes"] else "NO_VERIFICADO"
    receipt["stage"]="kali_passive_negative_controls"
    for spec in specs:
        seg=segments[spec["segment"]]
        for source in seg.get("selected_sources",[]):
            if time.monotonic()>=deadline:
                raise CheckError("lab_global_timeout")
            for target in all_targets:
                if target["family"]!=source["family"] or target["target_segment"]==spec["segment"]:
                    continue
                row=kali_passive_negative(lab,target,source,infos)
                row["endpoint_positive_control"]=(target["target_container"],target["family"],target["address"],target["port"]) in live
                seg["negative"].append(row)
            seg.setdefault("external_route_inspections",[]).append(kali_passive_external(source,firewall))
        seg["status"]="FAIL" if any(row["status"]=="FAIL" for row in seg["positive_attempts"]) else "NO_VERIFICADO"
    receipt["status"]="FAIL" if any(seg["status"]=="FAIL" for seg in segments.values()) else "NO_VERIFICADO"
    receipt["all_containers_stable_during_verification"]=all(
        (current:=inspect_container(name)).get("running") is True and all(current.get(key)==info.get(key) for key in ("id","pid","networks"))
        for name,info in infos.items())
    if not receipt["all_containers_stable_during_verification"]:
        receipt["reason_codes"].append("lab_container_changed_during_verification")


def write_json(path, data):
    path.parent.mkdir(parents=True,exist_ok=True)
    # O_EXCL preserves previous real executions, including failures.
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as stream:
        json.dump(data,stream,ensure_ascii=False,indent=2);stream.write("\n")


def write_receipt(path,data):
    """Integridad del recibo, nunca del fichero de credenciales del banco."""
    sidecar=path.with_suffix(path.suffix+".sha256")
    if path.exists() or sidecar.exists():
        raise FileExistsError("receipt_or_integrity_file_already_exists")
    write_json(path,data)
    with os.fdopen(os.open(sidecar,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as stream:
        stream.write(sha256(path)+"  "+path.name+"\n")


def plan(scenario, *, mode="containers", segment="todos", interface=None, source_address=None, firewall_json=None):
    if mode not in {"containers","kali"}:
        raise CheckError("verification_mode_invalid")
    lab = definition(scenario)
    compose, env = paths(scenario)
    representatives = selected_kali_specs(lab,segment=segment,interface=interface,source_address=source_address) if mode=="kali" else endpoints(lab)
    result = {"schema":"novaflow-real-isolation/2","requirement":"RNF-08","lab":scenario,
        "status":"NOT_EXECUTED","requirement_status":"PARCIAL","created_at":now(),
        "mode":mode,"script_version":SCRIPT_VERSION,
        "config_paths":{"compose":str(compose.relative_to(ROOT)),"env":str(env.relative_to(ROOT))},
        "representatives":representatives,"api_calls":0,"audit_runs":0,
        "limits":{"lab_seconds":240,"command_seconds":15,"socket_seconds":0.65,"payload_bytes":0,"positive_max_attempts":5},
        "limitations":KALI_LIMITS if mode=="kali" else LIMITS,"checker_sha256":sha256(Path(__file__))}
    if mode=="kali":
        result.update(source_selection={"segment":segment,"interface":interface,"address":source_address,
                      "actual_addresses_selected_only_during_execution":True},firewall_snapshot=firewall_snapshot(firewall_json))
    return result


def execute(scenario, *, authorization, output_dir=OUTPUT, run_id=None, mode="containers", segment="todos", interface=None, source_address=None, firewall_json=None):
    if authorization != "LAB-PROPIO":
        raise ValueError("explicit_authorization_required")
    receipt = plan(scenario,mode=mode,segment=segment,interface=interface,source_address=source_address,firewall_json=firewall_json);lab = definition(scenario);specs=receipt["representatives"]
    pending = "NO_VERIFICADO" if mode=="kali" else "PARTIAL"
    receipt.update(status=pending,started_at=now(),execution="REAL",reason_codes=[],lifecycle=[],segments=[])
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    start=time.monotonic();deadline=start+240;started=False;compose,env=paths(scenario)
    private_environment_before=None
    compose_cmd=[*DOCKER,"compose","--env-file",str(env),"-f",str(compose)]
    segment_receipts={s["segment"]:{"schema":"novaflow-real-isolation-segment/1","lab":scenario,
        "segment":s["segment"],"requirement":"RNF-08","requirement_status":"PARCIAL","execution":"REAL",
        "mode":mode,"script_version":SCRIPT_VERSION,"status":pending,"representative":s,"positive_attempts":[],"negative":[],"reason_codes":[],"limitations":receipt["limitations"]}
        for s in specs}
    try:
        receipt["protected_before"]=protected_check()
        if not receipt["protected_before"]["unchanged"]:
            raise CheckError("protected_files_already_changed")
        receipt["jobs_before"]=active_jobs()
        if receipt["jobs_before"]:
            raise CheckError("audit_or_panel_process_present")
        if not no_running_containers():
            raise CheckError("running_container_present_before_lab")
        receipt["configuration"]=configuration(scenario)
        # Compare the entire existing credential file only in memory. Never
        # publish its contents, env fingerprint or individual password hashes.
        private_environment_before=sha256(env)
        receipt["stage"]="image_availability"
        receipt["images"]=[command([*DOCKER,"image","inspect","--format",'{"id":{{json .Id}}}',image]) for image in receipt["configuration"]["images"]]
        receipt["stage"]="start_existing_lab"
        started=True
        try:
            command([*compose_cmd,"up","-d","--no-build","--no-recreate","--pull","never"],decode=False)
            receipt["lifecycle"].append({"action":"compose_up_existing_no_build_no_recreate_no_pull","status":"PASS","at":now()})
        except CheckError as exc:
            receipt["lifecycle"].append({"action":"compose_up_existing_no_build_no_recreate_no_pull","status":"PARTIAL","reason":str(exc),"at":now()})
            raise
        # Start grace is bounded and records every failed positive attempt.
        receipt["stage"]="network_configuration"
        infos={name:inspect_container(name) for n in lab.networks for name in n.members}
        networks={n.name:check_network(n,command([*DOCKER,"network","inspect","--format",NETWORK_FORMAT,n.name]),infos) for n in lab.networks}
        receipt["network_checks"]=networks
        if mode=="kali":
            verify_kali(receipt,lab,specs,infos,networks,segment_receipts,source_address=source_address,deadline=deadline)
            return receipt
        receipt["stage"]="positive_tcp_controls"
        positive_endpoints=set()
        for spec in specs:
            if time.monotonic()>deadline:
                raise CheckError("lab_global_timeout")
            seg=segment_receipts[spec["segment"]];seg["configuration"]=networks[spec["network"]]
            seg["container_snapshots"]={name:infos[name] for name in next(n for n in lab.networks if n.name==spec["network"]).members}
            expected=targets(spec,infos)
            for attempt in range(1,6):
                try:
                    observation=observe(spec["source"],expected)
                    row={"attempt":attempt,"at":now(),"observation":observation}
                except CheckError as exc:
                    row={"attempt":attempt,"at":now(),"reason":str(exc)};observation={}
                seg["positive_attempts"].append(row)
                probes=observation.get("probes",[])
                if len(probes)==len(expected) and all(p.get("connect",{}).get("status")=="connected" for p in probes):
                    for p in probes:positive_endpoints.add((p["target_container"],p["family"],p["address"],p["port"]))
                    break
                if attempt<5 and time.monotonic()+1<deadline:
                    time.sleep(1)
            seg["positive_status"]="PASS" if all((t["target_container"],t["family"],t["address"],t["port"]) in positive_endpoints for t in expected) else "PARTIAL"
            seg["route_check"]=check_routes(observation,spec,lab,infos[spec["source"]])
            seg["privileges"]=observation.get("privileges",{"reason":"live_proc_snapshot_unavailable"})
        receipt["stage"]="negative_tcp_controls"
        for spec in specs:
            if time.monotonic()>deadline:
                raise CheckError("lab_global_timeout")
            seg=segment_receipts[spec["segment"]]
            negative_targets=[t for other in specs if other["segment"]!=spec["segment"] for t in targets(other,infos)]
            try:
                observation=observe(spec["source"],negative_targets)
                seg["negative_observation"]=observation
                seg["negative_route_check"]=check_routes(observation,spec,lab,infos[spec["source"]])
                seg["negative"]=assess_negatives(observation.get("probes",[]),positive_endpoints,seg["negative_route_check"]["status"])
                if len(seg["negative"])!=len(negative_targets):seg["reason_codes"].append("incomplete_negative_attempts")
            except CheckError as exc:
                seg["reason_codes"].append(str(exc))
            current=inspect_container(spec["source"])
            if current["id"]!=infos[spec["source"]]["id"] or current["pid"]!=infos[spec["source"]]["pid"] or current["networks"]!=infos[spec["source"]]["networks"]:
                seg["reason_codes"].append("representative_changed_during_probes")
            failures=(seg["configuration"]["status"]=="FAIL" or seg["route_check"]["status"]=="FAIL" or seg.get("negative_route_check",{}).get("status")=="FAIL" or any(x["status"]=="FAIL" for x in seg["negative"]))
            complete=(seg["positive_status"]=="PASS" and seg["route_check"]["status"]=="PASS" and seg.get("negative_route_check",{}).get("status")=="PASS" and len(seg["negative"])==len(negative_targets) and all(x["status"]=="PASS" for x in seg["negative"]) and not seg["reason_codes"])
            seg["status"]="FAIL" if failures else "PASS" if complete else "PARTIAL"
        receipt["stage"]="final_identity_check"
        final_infos={name:inspect_container(name) for name in infos}
        receipt["all_containers_stable_during_verification"]=all(
            final_infos[name]["running"] is True and all(final_infos[name][key]==info[key] for key in ("id","pid","networks"))
            for name,info in infos.items())
        if not receipt["all_containers_stable_during_verification"]:
            receipt["reason_codes"].append("lab_container_changed_during_verification")
        receipt["status"]="FAIL" if any(s["status"]=="FAIL" for s in segment_receipts.values()) else "PASS" if all(s["status"]=="PASS" for s in segment_receipts.values()) else "PARTIAL"
    except CheckError as exc:
        receipt["reason_codes"].append(str(exc))
    finally:
        if started:
            try:
                command([*compose_cmd,"stop","--timeout","2"],decode=False)
                receipt["lifecycle"].append({"action":"compose_stop_conserve_containers_and_data","status":"PASS","at":now()})
            except CheckError as exc:
                receipt["lifecycle"].append({"action":"compose_stop_conserve_containers_and_data","status":"PARTIAL","reason":str(exc),"at":now()});receipt["reason_codes"].append("stop_not_confirmed")
        try:
            receipt["no_running_containers_after"]=no_running_containers()
            receipt["protected_after"]=protected_check()
            receipt["configuration_unchanged"]=(configuration(scenario)==receipt.get("configuration")
                and sha256(env)==private_environment_before) if private_environment_before is not None else None
            if not receipt["protected_after"]["unchanged"]:receipt["reason_codes"].append("protected_files_changed")
            if receipt["configuration_unchanged"] is False:receipt["reason_codes"].append("existing_config_changed")
            if not receipt["no_running_containers_after"]:receipt["reason_codes"].append("containers_still_running")
        except CheckError as exc:
            receipt["reason_codes"].append(str(exc))
        if receipt["reason_codes"] and receipt["status"]=="PASS":receipt["status"]=pending
        receipt.update(finished_at=now(),elapsed_seconds=round(time.monotonic()-start,3))
        for kind,seg in segment_receipts.items():
            seg["lab_reason_codes"]=receipt["reason_codes"];seg["started_at"]=receipt["started_at"];seg["finished_at"]=receipt["finished_at"]
            if receipt["reason_codes"] and seg["status"]=="PASS":seg["status"]=pending
            prefix="aislamiento-kali-real" if mode=="kali" else "aislamiento-real"
            path=Path(output_dir)/f"{prefix}-{run_id}-{scenario}-{kind}.json"
            write_receipt(path,seg)
            receipt["segments"].append({"segment":kind,"status":seg["status"],"requirement_status":"PARCIAL","receipt":str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)})
        prefix="aislamiento-kali-real" if mode=="kali" else "aislamiento-real"
        write_receipt(Path(output_dir)/f"{prefix}-{run_id}-{scenario}.json",receipt)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab",choices=(*SCENARIOS,"todos"),default="todos")
    parser.add_argument("--ejecutar",action="store_true")
    parser.add_argument("--autorizacion",default="")
    parser.add_argument("--salida",type=Path,default=OUTPUT)
    parser.add_argument("--modo","--mode",choices=("containers","contenedores","kali"),default="containers")
    parser.add_argument("--segmento",choices=("todos","dmz","corp","dc"),default="todos")
    parser.add_argument("--interfaz","--interface")
    parser.add_argument("--origen","--source-address")
    parser.add_argument("--firewall-json",type=Path)
    args=parser.parse_args()
    mode="containers" if args.modo=="contenedores" else args.modo
    if mode!="kali" and (args.interfaz or args.origen or args.segmento!="todos" or args.firewall_json):
        parser.error("--interfaz, --origen, --segmento y --firewall-json requieren --modo kali")
    scenarios=SCENARIOS if args.lab=="todos" else (args.lab,)
    kwargs={"mode":mode,"segment":args.segmento,"interface":args.interfaz,"source_address":args.origen,"firewall_json":args.firewall_json}
    # Validate every selection before starting any bank in a multi-lab run.
    try:
        for scenario in scenarios:plan(scenario,**kwargs)
    except CheckError as exc:
        parser.error(str(exc))
    run_id=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    for scenario in scenarios:
        if args.ejecutar:
            result=execute(scenario,authorization=args.autorizacion,output_dir=args.salida,run_id=run_id,**kwargs)
            print(json.dumps({"lab":scenario,"status":result["status"],"requirement_status":result["requirement_status"],"reason_codes":result["reason_codes"],"segments":result["segments"]},ensure_ascii=False),flush=True)
            if not result.get("no_running_containers_after",False):return 2
        else:
            print(json.dumps(plan(scenario,**kwargs),ensure_ascii=False))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
