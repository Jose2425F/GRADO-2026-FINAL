"""Explicaciones de evidencia para el cliente, sin invocar modelos de IA."""
from __future__ import annotations

import hashlib
from pathlib import Path

ASSET_NAMES = {
    "app_a": "Portal de clientes", "app_b": "Gestión documental", "app_c": "Portal de proveedores",
    "app_d": "Portal interno", "receiver_a": "Equipo de Administración", "receiver_b": "Equipo de Operaciones",
    "objetivo_ipv4":"Objetivo IPv4", "objetivo_ipv6":"Objetivo IPv6",
    "portal":"Acceso remoto y archivos", "bastion":"Bastión de administración",
    "legacy":"Consola de administración", "records":"Base de datos de respaldo",
    "app_crm":"CRM", "app_erp":"ERP", "app_portal":"Portal de clientes NovaFlow", "app_intranet":"Intranet",
}

AGENT_NAMES = {
    "application_access": "Acceso a aplicaciones", "ipv4_services": "Servicios IPv4",
    "ipv4_credentials": "Credenciales IPv4", "ipv6_ndp": "Configuración IPv6",
    "ipv6_fragmentation": "Fragmentación IPv6",
    "ipv6_services":"Servicios IPv6",
}
PROFILE_NAMES = {
    "nmap_tcp_open_ports_personal_v1":"Descubrimiento automático de puertos TCP 1–65535",
    "http_application_dualstack_v2": "Permisos de acceso por IPv4 e IPv6",
    "ipv6_slaac_v2": "Asignación legítima de direcciones IPv6",
    "ipv6_ra_route_v2": "Confianza en anuncios de rutas IPv6",
    "ipv6_ra_mtu_v2": "Cambios del tamaño de paquete IPv6",
    "ipv6_na_neighbor_v2": "Protección de vecinos conocidos",
    "ipv6_dad_na_v2": "Detección de direcciones duplicadas",
    "ipv6_overlap_v2": "Descarte de fragmentos superpuestos",
    "ipv6_overlap_middle_v2": "Descarte de superposición intermedia",
    "ipv6_atomic_v2": "Procesamiento de fragmentos atómicos",
    "ipv6_incomplete_chain_v2": "Descarte de cadenas incompletas",
    "nmap_tcp_services_v1": "Inventario de servicios de red",
    "http_application_personal_v1":"Permisos web sobre recursos de prueba configurados",
    "nmap_tcp_services_personal_v1":"Inventario TCP y reconocimiento de servicios",
}
for _service,_label in [('ssh','SSH'),('ftp','FTP'),('postgres','PostgreSQL'),('http_get','HTTP Basic')]:
    PROFILE_NAMES['hydra_'+_service+'_single_v1']='Credencial autorizada en '+_label

STATUS_NAMES = {
    "running": "En curso", "pending": "Pendiente", "complete": "Finalizada",
    "partial": "Finalizada con incidencias", "dry_run": "Simulación",
    "interrupted": "Interrumpida", "completed": "Completada",
    "completed_no_findings": "Completada sin hallazgos", "failed": "Fallida",
    "blocked": "Bloqueada", "cancelled": "Cancelada", "skipped": "Omitida",
    "rejected": "Solicitud rechazada",
}
EXPLANATIONS = {
    "object_authorization": {
        "title": "Un usuario puede consultar documentos de otro usuario",
        "meaning": "La aplicación entregó un documento ajeno a una sesión de prueba que no era su propietaria.",
        "impact": "En una aplicación real, este fallo podría exponer información privada de otras personas.",
        "fix": "Comprobar en el servidor que el usuario tiene permiso sobre cada documento solicitado.",
    },
    "file_boundary": {
        "title": "La descarga permite acceder a un recurso interno",
        "meaning": "Una solicitud de descarga alcanzó un archivo ficticio que debía quedar fuera del directorio público.",
        "impact": "Un fallo equivalente podría revelar archivos de configuración o información interna.",
        "fix": "Normalizar la ruta y permitir la descarga solo si el archivo queda dentro del directorio público.",
    },
    "ipv6_authorization_gap": {
        "title": "La protección administrativa cambia entre IPv4 e IPv6",
        "meaning": "Una familia IP denegó el acceso administrativo y la otra lo permitió para la misma cuenta de prueba.",
        "impact": "Usar otra familia de direcciones podría permitir eludir una comprobación de permisos.",
        "fix": "Aplicar las mismas comprobaciones de autenticación y autorización en IPv4 e IPv6.",
    },
    "untrusted_router_advertisement": {
        "title": "El receptor acepta cambios de red de un emisor no confiable",
        "meaning": "Un anuncio de prueba modificó la configuración de ruta o el tamaño de paquete del receptor IPv6.",
        "impact": "En un enlace equivalente, un emisor no autorizado podría alterar la configuración de conectividad.",
        "fix": "Limitar los anuncios a routers autorizados y comprobar los controles del enlace y del receptor.",
    },
    "neighbor_override": {
        "title": "Un emisor no confiable cambia un vecino conocido",
        "meaning": "La prueba modificó la asociación de un vecino IPv6 que el receptor ya conocía.",
        "impact": "Una asociación incorrecta podría desviar o interrumpir comunicaciones en el mismo enlace.",
        "fix": "Proteger las asociaciones críticas y validar los anuncios de vecinos del enlace autorizado.",
    },
    "dad_interference": {
        "title": "Un emisor interfiere con la asignación de direcciones IPv6",
        "meaning": "Los mensajes de prueba afectaron la detección de direcciones duplicadas del receptor.",
        "impact": "Un comportamiento equivalente podría impedir que un equipo configure una dirección utilizable.",
        "fix": "Controlar los mensajes de vecinos y supervisar fallos de asignación sin desactivar la detección de duplicados.",
    },
}
for _service,_label in [('ssh','SSH'),('ftp','FTP'),('postgres','PostgreSQL'),('http_get','HTTP Basic')]:
    EXPLANATIONS[_service+'_default_credential']={
        'title':'El servicio '+_label+' acepta la credencial de prueba',
        'meaning':'La herramienta de auditoría y un cliente independiente confirmaron el acceso con la credencial autorizada.',
        'impact':'Una credencial conocida o reutilizada podría permitir accesos no autorizados al servicio.',
        'fix':'Rotar la credencial, evitar contraseñas por defecto y restringir el acceso al servicio.'}


def finding_card(finding: dict, *, preliminary: bool = False) -> dict:
    from auditoria.modulo_reportes import finding_identifier
    condition = finding.get("condition") or finding.get("defect_key", "")
    explanation = EXPLANATIONS.get(condition, {})
    return {
        "id": f"{finding.get('asset_id', '')}:{finding.get('defect_key', condition)}",
        "finding_id": finding_identifier(finding),
        "title": explanation.get("title") or finding.get("title", "Condición observada"),
        "asset": ASSET_NAMES.get(finding.get("asset_id"), finding.get("asset_id", "Objetivo")),
        "asset_id": finding.get("asset_id"), "address": finding.get("address", ""),
        "severity": finding.get("severity", "unknown"),
        "meaning": explanation.get("meaning") or "La evidencia conservada describe la condición indicada en este hallazgo.",
        "impact": explanation.get("impact") or "El alcance y el impacto deben interpretarse según la condición y la evidencia de esta prueba.",
        "fix": explanation.get("fix") or finding.get("remediation", "Revisar la recomendación técnica del informe."),
        "confirmation": "Resultado preliminar: pendiente del cierre de la auditoría." if preliminary else (
            "Corroborado con un cliente HTTP independiente o con captura de paquetes y estado del receptor."
            if finding.get("rule_version") == "v2-1" else finding.get("reproduction", "Ver la evidencia del informe técnico.")
        ),
        "preliminary": preliminary,
        "evidence": finding.get("evidence_ref", ""),
        "confirmation_ref": finding.get("confirmation_ref", ""),
        "scope": finding.get("scope_note", "Condición observada en el laboratorio autorizado."),
        "task_id": finding.get("task_id"),
        "condition": condition,
        "reference": finding.get("reference", ""),
    }


def preliminary_findings(directory: Path, plan: list[dict], tasks: list[dict], read_file) -> list[dict]:
    """Reutiliza el adjudicador v2 sobre tareas terminadas; nunca escribe evidencia.

    Los digest se calculan para esta lectura: no sustituyen las referencias del
    informe final. La UI presenta estas observaciones como preliminares.
    """
    from auditoria.contracts import Task, TaskResult
    from auditoria.v2_agent import assess, RULES

    finished = {t["id"] for t in tasks if t.get("status") in {"completed", "completed_no_findings"}}
    findings = []
    for raw in plan:
        if raw.get("task_id") not in finished:
            continue
        try:
            task = Task.model_validate(raw)
            ref = f"evidence/{task.task_id}_state.json"
            confirmation = f"evidence/{task.task_id}_confirmation.json"
            data, independent = read_file(directory / ref), read_file(directory / confirmation)
            if data is None or independent is None:
                continue
            result = TaskResult(task_id=task.task_id, status="completed", evidence_ref=ref,
                                evidence_sha256=hashlib.sha256(data).hexdigest(), diagnostic_ref=confirmation,
                                diagnostic_sha256=hashlib.sha256(independent).hexdigest())
            for condition in assess(directory, task, result):
                rule = RULES[condition]
                findings.append(finding_card({
                    "asset_id": task.target.asset_id, "address": task.target.address,
                    "condition": condition, "defect_key": condition, "task_id": task.task_id,
                    "title": rule[0], "remediation": rule[2], "severity": "medium",
                    "evidence_ref": ref, "confirmation_ref": confirmation,
                    "scope_note": "Observación de laboratorio; pendiente de publicación final.",
                }, preliminary=True))
        except (OSError, ValueError, TypeError, KeyError, AssertionError):
            continue
    return findings


def present_run(run: dict, report: dict, plan: list[dict], preliminary: list[dict]) -> dict:
    task_by_id = {t.get("task_id"): t for t in plan}
    tasks = []
    for original in run.get("tasks", []):
        task = {**original}
        task["label"] = PROFILE_NAMES.get(task.get("profile"), task.get("profile") or "Prueba de auditoría")
        task["asset_name"] = ASSET_NAMES.get(task.get("asset"), task.get("asset") or "Objetivo")
        task["agent_name"] = AGENT_NAMES.get(task.get("agent"), task.get("agent") or "Auditor")
        task["status_name"] = STATUS_NAMES.get(task.get("status"), task.get("status", ""))
        if run.get('bank')=='personal' and task.get('profile')=='nmap_tcp_services_personal_v1' and task.get('status')=='completed_no_findings':task['status_name']='Inventario completado'
        if task.get('profile')=='nmap_tcp_open_ports_personal_v1' and task.get('status')=='completed_no_findings':task['status_name']='Descubrimiento TCP completado'
        tasks.append(task)
    final = bool(report) and run.get("mode") == "live"
    cards = [finding_card(f) for f in report.get("findings", []) if f.get("state") == "verified"] if final else preliminary
    if run.get("mode") != "live":
        cards = []
    cards.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f["severity"], 4), f["asset"]))
    checked = sum(t["status"] in {"completed", "completed_no_findings"} for t in tasks)
    issues = [t for t in tasks if t["status"] in {"failed", "blocked", "cancelled"}]
    assets = {t["asset"] for t in tasks if t.get("asset")}
    affected = {f["asset_id"] for f in cards if f.get("asset_id")}
    if run.get("mode") != "live":
        summary = f"Se prepararon {run.get('total', 0)} tareas. Esta simulación no ejecutó pruebas de red y no demuestra hallazgos."
    elif final:
        summary = f"Se completaron {checked} de {run.get('total', 0)} tareas del alcance de {len(assets)} objetivos. Se confirmaron {len(cards)} condiciones en {len(affected)} objetivos."
        if issues:
            summary += f" {len(issues)} tareas tuvieron incidencias; su cobertura debe revisarse."
        if not cards:
            summary += " No confirmar hallazgos en estas pruebas no demuestra ausencia de vulnerabilidades."
    elif run.get("status") == "interrupted":
        summary = f"La auditoría se interrumpió antes de publicar su informe final. Se completaron {checked} de {run.get('total', 0)} tareas; las observaciones disponibles siguen siendo preliminares."
    else:
        summary = f"La auditoría lleva {checked} tareas completadas. Las observaciones disponibles son preliminares y se revisarán al cerrar."
    has_credentials=run.get('bank')=='personal' and report.get('purpose')=='service_inventory_with_default_credentials'
    has_web=run.get('bank')=='personal' and report.get('purpose')=='network_vulnerability_evaluation'
    is_inventory=run.get('bank')=='personal' and not (has_credentials or has_web)
    inventory=[]
    if run.get('bank')=='personal':
        for item in report.get('inventory',[]):
            if not isinstance(item,dict) or item.get('task_id') not in task_by_id:continue
            original=task_by_id[item['task_id']].get('target',{})
            allowed=set(original.get('ports',[]))
            automatic=task_by_id[item['task_id']].get('action_profile')=='nmap_tcp_open_ports_personal_v1'
            def authorized(port):return type(port) is int and 1<=port<=65535 and (automatic or port in allowed)
            services=[{k:v.get(k) for k in ['port','protocol','state','name','product','version']} for v in item.get('services',[])
                      if isinstance(v,dict) and authorized(v.get('port')) and v.get('state')=='open']
            ports=[{'port':v.get('port'),'state':v.get('state')} for v in item.get('ports',[])
                   if isinstance(v,dict) and authorized(v.get('port'))]
            inventory.append({'asset':ASSET_NAMES.get(original.get('asset_id'),original.get('asset_id')),
                              'address':original.get('address'),'services':services,'ports':ports})
        service_count=sum(len(i['services']) for i in inventory)
        swept=report.get('purpose')=='service_inventory_with_default_credentials'
        base=f"Inventario TCP: {checked} de {run.get('total',0)} perfiles completados; {service_count} servicios abiertos observados."
        if has_web:
            summary=base+f' Pruebas de vulnerabilidad configuradas: {len(cards)} condiciones confirmadas; revisar la cobertura por equipo.'
        elif swept and cards:
            summary=base+f" Prueba de credenciales por defecto: {len(cards)} credenciales débiles aceptadas y corroboradas."
        elif swept:
            summary=base+" No se confirmaron credenciales por defecto en los servicios probados."
        else:
            summary=base+" No se aplicaron pruebas de vulnerabilidad ni las condiciones de referencia de v2."
        if not final:summary='Inventario TCP en curso o interrumpido; consulta la consola y espera el cierre para interpretar los resultados.'
        if issues:summary+=f' Hay {len(issues)} perfiles con incidencias; revisar su cobertura.'
    events = []
    for event in run.get("events", [])[:30]:
        task = task_by_id.get(event.get("task"), {})
        asset = task.get("target", {}).get("asset_id")
        name = ASSET_NAMES.get(asset, asset or "el laboratorio")
        profile = PROFILE_NAMES.get(task.get("action_profile"), "prueba de auditoría")
        labels = {
            "request_accepted": "La solicitud fue aceptada", "plan_created": "Se preparó el plan de pruebas",
            "task_admitted": f"Analizando {name}: {profile}",
            "task_terminal": f"{name}: {STATUS_NAMES.get(event.get('status'), 'prueba terminada')}",
            "decision": "El planificador eligió una prueba permitida", "report_saved": "El informe y la evidencia están disponibles",
            "request_started": "Consultando al planificador de IA", "llm_ready": "Planificador de IA conectado",
            "llm_fallback": "Se continúa con la planificación de respaldo", "provider_retry": "Reintento del proveedor de IA",
        }
        events.append({"time": event.get("time"), "label": labels.get(event.get("kind"), "Evento de la auditoría"), "issue": bool(event.get("reason"))})
    return {"cards": cards, "final": final, "summary": summary, "checked": checked,
            "issues": issues, "tasks": tasks, "events": events, "affected": len(affected),
            "assets": len(assets), "report_tokens": 0, "is_inventory":is_inventory,
            "has_credentials":has_credentials,"has_web":has_web,"company":"NovaFlow S.A.S." if run.get('bank')=='empresa' else 'Mi laboratorio' if run.get('bank')=='personal' else 'Empresa Andina Demo',
            "inventory":inventory,"automatic_ports":report.get('port_mode')=='auto',"service_count":sum(len(i['services']) for i in inventory)}


def executive_view(brief: dict) -> dict:
    """Agrupa las mismas condiciones confirmadas para responsables del negocio."""
    themes = [
        ('Acceso a servicios', {'ssh_default_credential','ftp_default_credential','postgres_default_credential','http_get_default_credential'}, 'Responsable de sistemas',
         'Rotar credenciales conocidas, restringir servicios y repetir la comprobación con evidencia independiente.'),
        ('Protección de información', {'object_authorization','file_boundary'}, 'Responsable de aplicaciones',
         'Revisar permisos sobre documentos y descargas; encargar la corrección y una nueva prueba de acceso.'),
        ('Consistencia de controles IPv4 e IPv6', {'ipv6_authorization_gap'}, 'Responsables de aplicaciones y redes',
         'Aplicar los mismos permisos por ambas familias de red y comprobar que el acceso administrativo quede restringido.'),
        ('Continuidad de la conectividad', {'untrusted_router_advertisement','neighbor_override','dad_interference'}, 'Responsable de redes',
         'Revisar qué equipos pueden cambiar la configuración IPv6 y comprobar los controles del enlace y de los receptores.'),
    ]
    groups = []
    assigned = set()
    for name,conditions,owner,action in themes:
        cards = [c for c in brief['cards'] if c['condition'] in conditions]
        if cards:
            groups.append({'name':name,'count':len(cards),'assets':sorted({c['asset'] for c in cards}), 'owner':owner,'action':action,
                           'impacts':list(dict.fromkeys(c['impact'] for c in cards))})
            assigned.update(c['id'] for c in cards)
    others = [c for c in brief['cards'] if c['id'] not in assigned]
    if others:
        groups.append({'name':'Otros controles revisados','count':len(others),'assets':sorted({c['asset'] for c in others}),
                       'owner':'Responsable técnico de seguridad','action':'Revisar el informe técnico y acordar correcciones y verificación.',
                       'impacts':list(dict.fromkeys(c['impact'] for c in others))})
    return {'groups':groups,'conclusion':f"Se confirmaron {len(brief['cards'])} condiciones que requieren revisión en {brief['affected']} objetivos del laboratorio."
            if brief['cards'] else 'No se confirmaron condiciones problemáticas dentro de la cobertura ejecutada.'}
