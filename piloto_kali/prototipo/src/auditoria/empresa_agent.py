"""Perfiles del banco NovaFlow para el controlador común: las cinco capacidades.

Despacha cada tarea al motor ya revisado (nmap, hydra, aplicación dual-stack, sondas
IPv6) y adjudica con corroboración independiente y sin etiquetas del evaluador.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from uuid import uuid4

from . import lab_empresa as lab
from .authentication import corroborate
from .contracts import (AuditRequest, Category, CredentialProfile, LabPolicy, LabSegment,
                        Target, Task, TaskResult, TaskStatus)
from .policy import PolicyError

CATEGORIES = [Category.IPV4_SERVICES, Category.IPV4_CREDENTIALS, Category.APPLICATION_ACCESS,
              Category.IPV6_NDP, Category.IPV6_FRAGMENTATION]
ND = ("ra_route", "ra_mtu", "na_neighbor", "dad_na")
FRAG = {"overlap": ("control", False), "overlap_middle": ("control_middle", False),
        "atomic": ("plain", True), "incomplete_chain": ("control", False)}

RULES = {
 "ssh_default_credential": ("Credencial SSH por defecto aceptada", "https://cwe.mitre.org/data/definitions/1392.html", "Rotar la credencial sintética, exigir claves y bloquear el usuario reutilizado."),
 "ftp_default_credential": ("Credencial FTP por defecto aceptada", "https://cwe.mitre.org/data/definitions/1392.html", "Retirar el acceso FTP con contraseña o rotar la credencial y restringir el usuario."),
 "postgres_default_credential": ("Credencial PostgreSQL por defecto aceptada", "https://cwe.mitre.org/data/definitions/521.html", "Rotar la credencial del rol y exigir una política de contraseñas robusta."),
 "http_get_default_credential": ("Credencial de consola HTTP por defecto aceptada", "https://cwe.mitre.org/data/definitions/1392.html", "Rotar la credencial de la consola y restringir el acceso a la red de gestión."),
 "object_authorization": ("Autorización por objeto ausente", "https://cwe.mitre.org/data/definitions/639.html", "Verificar propiedad y permisos del recurso en cada solicitud."),
 "file_boundary": ("Límite de descarga permite recursos internos ficticios", "https://cwe.mitre.org/data/definitions/22.html", "Normalizar una sola vez y verificar que la ruta resuelta permanezca en el directorio público."),
 "ipv6_authorization_gap": ("Autorización administrativa inconsistente por familia IP", "https://cwe.mitre.org/data/definitions/863.html", "Aplicar la misma autorización a todos los listeners IPv4 e IPv6."),
 "untrusted_router_advertisement": ("Anuncio de emisor no autorizado modifica configuración IPv6", "https://www.rfc-editor.org/rfc/rfc4861", "Limitar anuncios a routers de confianza mediante controles del enlace y del receptor."),
 "neighbor_override": ("Emisor no autorizado cambia una asociación de vecino conocida", "https://www.rfc-editor.org/rfc/rfc4861", "Proteger asociaciones críticas y validar el origen en el enlace autorizado."),
 "dad_interference": ("Emisor de prueba interfiere con detección de direcciones duplicadas", "https://www.rfc-editor.org/rfc/rfc4862", "Controlar mensajes ND del enlace y supervisar fallos DAD sin deshabilitarlo."),
}


def _credential_profile(asset, service, port):
    host = lab.CREDENTIALS[asset]
    return CredentialProfile(ref=f"{asset}_{service.replace('-', '_')}", service=service, port=port,
                             username=host.get("username", "labuser"), password_env=host["env"],
                             condition="default_credential")


def targets():
    values = []
    for asset, host in lab.CREDENTIALS.items():
        refs = [f"{asset}_{service.replace('-', '_')}" for service, _ in host["services"]]
        values.append(Target(asset_id=asset, address=host["address"], interface=lab.DMZ_BRIDGE,
                             ports=lab.SERVICE_PORTS[asset], credential_refs=refs))
    for asset, app in lab.APPS.items():
        for family in ("ipv4", "ipv6"):
            values.append(Target(asset_id=asset, address=app[family], interface="br-nova-corp", ports=[8088]))
    for asset, receiver in lab.RECEIVERS.items():
        values.append(Target(asset_id=asset, address=receiver["address"], interface="br-nova-dc", ports=[53000]))
    return values


def policy():
    segments = []
    for name, (bridge, subnets, _members) in lab.NETWORKS.items():
        if name == "nova_dmz":
            ports = [21, 22, 5432, 8080]
        elif name == "nova_corp":
            ports = [8088]
        else:
            ports = [8000, 53000]
        for i, subnet in enumerate(sorted(subnets)):
            segments.append(LabSegment(name=f"{name}_{i}", network=subnet, interface=bridge, allowed_ports=ports))
    return LabPolicy(policy_id="docker-empresa-controller-1", allowed_categories=CATEGORIES,
                     max_token_budget=80000, segments=segments)


def request(authorization, architecture="multiagent", tokens=60000, llm=True, stop=False):
    now = datetime.now(timezone.utc)
    return AuditRequest(bank="empresa", audit_id="emp_" + architecture + "_" + uuid4().hex[:12],
        operator="operador_laboratorio", authorization_ref=authorization, architecture=architecture,
        categories=CATEGORIES, targets=targets(),
        scope_ipv4=["192.168.69.0/24", "192.168.70.0/24", "192.168.71.0/24"],
        scope_ipv6=["fd57:2026:69::/64", "fd57:2026:70::/64"],
        not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=45),
        max_runtime_seconds=2400, max_attempts=1, token_budget=tokens if llm else 0,
        llm_mode="scheduler" if llm else "disabled", llm_provider="openai", stop_on_verified_access=stop)


def authorize_empresa(req, pol, *, task=None):
    """Revalida la solicitud y, al despachar, la acción concreta sin emitir tráfico."""
    approved_policy = policy()
    if not req.not_before <= datetime.now(timezone.utc) <= req.not_after:
        raise PolicyError("outside_window", "fuera de la ventana autorizada")
    if pol != approved_policy:
        raise PolicyError("empresa_scope_denied", "la política no coincide con el banco NovaFlow")
    if set(req.categories) != set(CATEGORIES) or not set(req.categories) <= set(pol.allowed_categories):
        raise PolicyError("category_denied", "categorías no autorizadas por el banco NovaFlow")
    scopes = []
    for values, version in ((req.scope_ipv4, 4), (req.scope_ipv6, 6)):
        for value in values:
            network = ip_network(value, strict=True)
            if network.version != version:
                raise PolicyError("scope_version", "versión IP del alcance incorrecta")
            if not any(network.version == ip_network(segment.network).version
                       and network.subnet_of(ip_network(segment.network)) for segment in pol.segments):
                raise PolicyError("scope_denied", "alcance solicitado fuera del banco NovaFlow")
            scopes.append(network)
    for target in req.targets:
        address = ip_address(target.address)
        if not any(address in scope for scope in scopes):
            raise PolicyError("target_out_of_scope", "objetivo fuera del alcance solicitado")
        segments = [segment for segment in pol.segments if address in ip_network(segment.network)]
        if len(segments) != 1 or target.interface != segments[0].interface:
            raise PolicyError("interface_denied", "interfaz no autorizada para el objetivo")
        if not set(target.ports) <= set(segments[0].allowed_ports):
            raise PolicyError("port_denied", "puerto fuera del perfil autorizado")
    if (req.bank != "empresa" or req.targets != targets()
            or req.case_ids or req.max_attempts != 1 or req.token_budget > approved_policy.max_token_budget
            or req.execution_policy != "predefined_profiles"
            or (req.token_budget and req.llm_mode != "scheduler")):
        raise PolicyError("empresa_scope_denied", "el banco NovaFlow solo admite su catálogo, política y perfiles cerrados")
    if task is not None:
        if task.target not in req.targets:
            raise PolicyError("target_out_of_scope", "la tarea no corresponde a un objetivo autorizado")
        if task.agent_type not in req.categories:
            raise PolicyError("category_denied", "categoría de la tarea no autorizada")
        if task not in build_plan(req):
            raise PolicyError("empresa_profile_denied", "la tarea no coincide con un perfil autorizado del catálogo")


def build_plan(req):
    tasks = []
    for t in req.targets:
        if t.asset_id in lab.CREDENTIALS and ":" not in t.address:
            host = lab.CREDENTIALS[t.asset_id]
            tasks.append(Task(task_id=req.audit_id + "_" + t.asset_id + "_services", target=t,
                agent_type=Category.IPV4_SERVICES, protocol="tcp",
                action_profile="nmap_tcp_services_v1", timeout_seconds=120))
            for service, port in host["services"]:
                tasks.append(Task(task_id=req.audit_id + "_" + t.asset_id + "_" + service.replace("-", "_"),
                    target=t, agent_type=Category.IPV4_CREDENTIALS, protocol="tcp",
                    action_profile=f"hydra_{service.replace('-', '_')}_single_v1", timeout_seconds=60))
        elif t.asset_id in lab.APPS and ":" not in t.address:
            tasks.append(Task(task_id=req.audit_id + "_" + t.asset_id + "_application", target=t,
                agent_type=Category.APPLICATION_ACCESS, protocol="http_dualstack",
                action_profile="http_application_dualstack_v2", timeout_seconds=180))
        elif t.asset_id in lab.RECEIVERS:
            previous = None
            for p in ("slaac", *ND, *FRAG):
                task = Task(task_id=req.audit_id + "_" + t.asset_id + "_" + p, target=t,
                    agent_type=Category.IPV6_FRAGMENTATION if p in FRAG else Category.IPV6_NDP,
                    case_id="EMP_" + p.upper(), protocol="ipv6", action_profile="ipv6_" + p + "_v2",
                    dependencies=[previous] if previous else [], timeout_seconds=180)
                tasks.append(task)
                previous = task.task_id
    return tasks


# --- Ejecución ---------------------------------------------------------------
def _run_nmap(task, store):
    from .agentes.agente_ipv4_servicios import run_nmap
    return run_nmap(task, store, timeout_seconds=task.timeout_seconds)


def _run_hydra(task, store):
    from .agentes.agente_ipv4_credenciales import run_hydra
    service = task.action_profile.removeprefix("hydra_").removesuffix("_single_v1").replace("_", "-")
    port = next(p for s, p in lab.CREDENTIALS[task.target.asset_id]["services"] if s == service)
    # Asegurar que el entorno del auditor conoce la contraseña del intento.
    env = lab.CREDENTIALS[task.target.asset_id]["env"]
    if not os.environ.get(env):
        os.environ[env] = lab.known_password(env)
    profile = _credential_profile(task.target.asset_id, service, port)
    return run_hydra(task, profile, store, timeout_seconds=task.timeout_seconds)


def _run_application(task, store):
    app = lab.APPS[task.target.asset_id]
    primary = {f: lab.app_family(app[f]) for f in ("ipv4", "ipv6")}
    confirmation = {f: lab.app_family(app[f], independent=True) for f in ("ipv4", "ipv6")}
    payload = {"asset_id": task.target.asset_id, "target": task.target.address,
               "profile": task.action_profile, "families": primary}
    corroboration = {**payload, "families": confirmation, "channel": "independent_http_client"}
    evidence, eh = store.evidence(task.task_id + "_state", "json", json.dumps(payload, sort_keys=True).encode())
    diagnostic, dh = store.evidence(task.task_id + "_confirmation", "json", json.dumps(corroboration, sort_keys=True).encode())
    a, b = _application(primary["ipv4"]), _application(primary["ipv6"])
    summary = {"bank": "empresa", "access_observed": a[0] or b[0] or a[1] or b[1] or (not a[2] and b[2])}
    return TaskResult(task_id=task.task_id, status=TaskStatus.COMPLETED, evidence_ref=evidence,
                      evidence_sha256=eh, diagnostic_ref=diagnostic, diagnostic_sha256=dh, observations=summary)


def _run_protocol(task, store):
    receiver = lab.RECEIVERS[task.target.asset_id]
    p = task.action_profile.removeprefix("ipv6_").removesuffix("_v2")
    payload = {"asset_id": task.target.asset_id, "target": task.target.address, "profile": task.action_profile}
    before = lab.wait_receiver(receiver)
    payload["before"] = before
    if p == "slaac":
        payload["after"] = before
        payload["restored"] = before
    else:
        try:
            if p == "na_neighbor":
                lab.docker("exec", receiver["container"], "ip", "-6", "neigh", "replace", lab.SENDER, "lladdr",
                           lab.SENDER_MAC, "nud", "permanent" if task.target.asset_id == "receiver_b" else "reachable", "dev", "eth0")
                payload["before"] = lab.snapshot(receiver)
            if p in ND:
                payload["after"], payload["probe"] = lab.probe(receiver, p, store, task.task_id)
            elif p in FRAG:
                control, _expected = FRAG[p]
                payload["control"], payload["control_probe"] = lab.probe(receiver, control, store, task.task_id + "_control")
                payload["after"], payload["probe"] = lab.probe(receiver, p, store, task.task_id + "_variant")
            else:
                raise PolicyError("empresa_profile_denied", "perfil NovaFlow desconocido")
        finally:
            payload["restored"] = lab.reset_receiver(receiver)
    corroboration = {**payload, "channel": "packet_observer_and_kernel_state"}
    evidence, eh = store.evidence(task.task_id + "_state", "json", json.dumps(payload, sort_keys=True).encode())
    diagnostic, dh = store.evidence(task.task_id + "_confirmation", "json", json.dumps(corroboration, sort_keys=True).encode())
    summary = {"restored": True, "bank": "empresa"}
    if p in ND:
        summary["state_changed"] = bool(lab.nd_effect(p, payload["before"], payload["after"], receiver, payload["probe"]))
    elif p in FRAG:
        summary["control_received"] = any(x["nonce"] == payload["control_probe"]["nonce"] for x in payload["control"]["observer"]["udp_deliveries"])
        summary["variant_udp_delivered"] = any(x["nonce"] == payload["probe"]["nonce"] for x in payload["after"]["observer"]["udp_deliveries"])
    return TaskResult(task_id=task.task_id, status=TaskStatus.COMPLETED, evidence_ref=evidence,
                      evidence_sha256=eh, diagnostic_ref=diagnostic, diagnostic_sha256=dh, observations=summary)


def run_task(task, store):
    if task.target not in targets():
        raise PolicyError("empresa_target_denied", "activo ajeno al banco NovaFlow")
    if task.action_profile == "nmap_tcp_services_v1":
        return _run_nmap(task, store)
    if task.action_profile.startswith("hydra_"):
        return _run_hydra(task, store)
    if task.action_profile == "http_application_dualstack_v2":
        return _run_application(task, store)
    if task.action_profile.startswith("ipv6_"):
        return _run_protocol(task, store)
    raise PolicyError("empresa_profile_denied", "perfil fuera del catálogo NovaFlow")


# --- Adjudicación ------------------------------------------------------------
def _artifact(root, reference, digest):
    from .validation import _matches
    if not _matches(root, reference, digest):
        raise ValueError("evidencia NovaFlow modificada o ausente")
    return json.loads((root / reference).read_text())


def _packets(root, value):
    from .validation import _matches
    if isinstance(value, dict):
        if "pcap_ref" in value and not _matches(root, value["pcap_ref"], value["pcap_sha256"]):
            raise ValueError("captura NovaFlow modificada")
        for item in value.values():
            _packets(root, item)
    elif isinstance(value, list):
        for item in value:
            _packets(root, item)


def _application(facts):
    import hashlib
    records = facts["records"]
    trace = facts["server_trace"]
    if any(not any(e["path"] == r["path"] and e["status"] == r["status"] and e["nonce"] == facts["nonce"] for e in trace) for r in records):
        raise ValueError("traza HTTP insuficiente")
    objects = [r for r in records if r["path"].startswith("/objects/") and r["status"] == 200
               and r["body"].get("kind") == "document" and isinstance(r["body"].get("marker"), str)]
    own = [r for r in objects if r["body"].get("owner") == "viewer"]
    if len(own) != 1 or hashlib.sha256(own[0]["body"]["marker"].encode()).hexdigest() != facts["own_marker_sha256"]:
        raise ValueError("recurso propio no corroborado")
    return (any(r["body"].get("owner") == "other" for r in objects),
            any(r["path"].startswith("/download?") and r["status"] == 200 and r["body"].get("kind") == "internal_configuration"
                and isinstance(r["body"].get("marker"), str) for r in records),
            any(r["path"] == "/admin" and r["status"] == 200 and r["body"].get("kind") == "admin_configuration" for r in records))


def assess(root, task, result):
    if task.target not in targets():
        raise ValueError("objetivo fuera de catálogo")
    # IPv4 servicios: descubrimiento, control sin defecto.
    if task.action_profile == "nmap_tcp_services_v1":
        if result.status not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}:
            raise ValueError("descubrimiento incompleto")
        _artifact(root, result.evidence_ref, result.evidence_sha256)
        return []
    # IPv4 credenciales: defecto si la credencial es aceptada y corroborada.
    if task.action_profile.startswith("hydra_"):
        if result.status not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}:
            raise ValueError("autenticación incompleta")
        data = _artifact(root, result.evidence_ref, result.evidence_sha256)
        if data.get("target") != task.target.address or data.get("profile") != task.action_profile:
            raise ValueError("evidencia de otra tarea")
        if data.get("outcome") != "accepted":
            return []
        if not result.diagnostic_ref:
            raise ValueError("falta corroboración independiente de la credencial")
        confirmation = _artifact(root, result.diagnostic_ref, result.diagnostic_sha256)
        if confirmation.get("outcome") != "accepted" or confirmation.get("target") != task.target.address:
            raise ValueError("corroboración independiente no confirma la credencial")
        service = task.action_profile.removeprefix("hydra_").removesuffix("_single_v1")
        return [service + "_default_credential"]
    # Acceso de aplicación dual-stack.
    if task.action_profile == "http_application_dualstack_v2":
        if result.status not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}:
            raise ValueError("tarea incompleta")
        data = _artifact(root, result.evidence_ref, result.evidence_sha256)
        corroboration = _artifact(root, result.diagnostic_ref, result.diagnostic_sha256)
        if corroboration.get("channel") != "independent_http_client":
            raise ValueError("cliente independiente ausente")
        observations = {}
        for f in ("ipv4", "ipv6"):
            first, second = data["families"][f], corroboration["families"][f]
            a, b = _application(first), _application(second)
            if a != b or first["nonce"] == second["nonce"] or first["own_marker_sha256"] != second["own_marker_sha256"]:
                raise ValueError("clientes independientes discrepan")
            observations[f] = a
        if data["families"]["ipv4"]["own_marker_sha256"] != data["families"]["ipv6"]["own_marker_sha256"]:
            raise ValueError("familias con recursos distintos")
        a, b = observations["ipv4"], observations["ipv6"]
        return [k for k, present in zip(lab.APP_CONDITIONS, (a[0] or b[0], a[1] or b[1], not a[2] and b[2])) if present]
    # Protocolos IPv6 (NDP/SLAAC y fragmentación).
    if result.status not in {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}:
        raise ValueError("tarea incompleta")
    data = _artifact(root, result.evidence_ref, result.evidence_sha256)
    corroboration = _artifact(root, result.diagnostic_ref, result.diagnostic_sha256)
    for artifact in (data, corroboration):
        if any(artifact.get(k) != v for k, v in [("asset_id", task.target.asset_id), ("target", task.target.address), ("profile", task.action_profile)]):
            raise ValueError("evidencia de otra tarea")
        _packets(root, artifact)
    receiver = lab.RECEIVERS[task.target.asset_id]
    if corroboration.get("channel") != "packet_observer_and_kernel_state" or any(data[k] != corroboration[k] for k in data):
        raise ValueError("estado del observador no corroborado")
    if not lab.slaac_addresses(data["before"]) or not lab.slaac_addresses(data["restored"]) or data["restored"]["mtu"] != 1500:
        raise ValueError("SLAAC o restauración incompleta")
    p = task.action_profile.removeprefix("ipv6_").removesuffix("_v2")
    if p == "slaac":
        return []
    proof = data["probe"]
    after = data["after"]
    if p in ND:
        observed = after["observer"]["router_advertisements" if p.startswith("ra_") else "neighbor_advertisements"]
        if not any(packet["source"] in {lab.SENDER, lab.SENDER_LL} for packet in observed):
            raise ValueError("sonda no observada")
        condition = {"ra_route": "untrusted_router_advertisement", "ra_mtu": "untrusted_router_advertisement",
                     "na_neighbor": "neighbor_override", "dad_na": "dad_interference"}[p]
        return [condition] if lab.nd_effect(p, data["before"], after, receiver, proof) else []
    if p not in FRAG:
        raise ValueError("perfil desconocido")
    delivered = any(x["nonce"] == proof["nonce"] for x in after["observer"]["udp_deliveries"])
    control = data["control_probe"]
    if (not any(x["nonce"] == control["nonce"] for x in data["control"]["observer"]["udp_deliveries"])
            or sum(f["id"] == proof["fragment_id"] for f in after["observer"]["fragments"]) < proof["packet_count"]
            or delivered != FRAG[p][1]):
        raise ValueError("control de conformidad no aprobado")
    return []


def validation_record(root, task, result):
    try:
        conditions = assess(root, task, result)
        valid = True
        state = "candidate" if conditions else "observed"
        reason = "empresa_independent_evidence_valid"
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        valid = False if result.evidence_ref or result.status == TaskStatus.COMPLETED else None
        state = "indeterminate"
        reason = "empresa_evidence_incomplete_or_changed"
    return {"task_id": task.task_id, "case_id": task.case_id, "asset_id": task.target.asset_id,
            "action_profile": task.action_profile, "state": state, "reason": reason,
            "evidence_integrity": {"valid": valid, "diagnostic": valid, "packet": valid, "control_packet": None},
            "independent_confirmation": valid is True}


def adjudicate(root, task, result):
    try:
        conditions = assess(root, task, result)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return []
    reproductions = {
        "nmap_tcp_services_v1": "Doble barrido de servicios y contraste de versiones.",
        "http_application_dualstack_v2": "Clientes HTTP independientes por familia IP.",
    }
    default_repro = "Herramienta de auditoría y cliente independiente de corroboración."
    out = []
    for key in conditions:
        out.append({"asset_id": task.target.asset_id, "address": task.target.address, "defect_key": key,
                    "state": "verified", "severity": "high" if key.endswith("default_credential") else "medium",
                    "title": RULES[key][0], "condition": key, "reference": RULES[key][1], "remediation": RULES[key][2],
                    "task_id": task.task_id, "evidence_ref": result.evidence_ref, "confirmation_ref": result.diagnostic_ref,
                    "independent_confirmation": True,
                    "reproduction": reproductions.get(task.action_profile, default_repro),
                    "rule_version": "empresa-1", "scope_note": "Condición de laboratorio sintético NovaFlow; no implica CVE del kernel."})
    return out
