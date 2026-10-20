"""Perfiles v2 para el controlador común; adjudicación sin etiquetas del evaluador."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from . import lab_v2 as lab
from .contracts import AuditRequest, Category, LabPolicy, LabSegment, Target, Task, TaskResult, TaskStatus
from .policy import PolicyError

CATEGORIES = [Category.APPLICATION_ACCESS, Category.IPV6_NDP, Category.IPV6_FRAGMENTATION]
ND = ('ra_route', 'ra_mtu', 'na_neighbor', 'dad_na')
FRAG = {'overlap': ('control', False), 'overlap_middle': ('control_middle', False),
        'atomic': ('plain', True), 'incomplete_chain': ('control', False)}
RULES = {
 'object_authorization': ('Autorización por objeto ausente', 'https://cwe.mitre.org/data/definitions/639.html', 'Verificar propiedad y permisos del recurso en cada solicitud.'),
 'file_boundary': ('Límite de descarga permite recursos internos ficticios', 'https://cwe.mitre.org/data/definitions/22.html', 'Normalizar una sola vez y verificar que la ruta resuelta permanezca en el directorio público.'),
 'ipv6_authorization_gap': ('Autorización administrativa inconsistente por familia IP', 'https://cwe.mitre.org/data/definitions/863.html', 'Aplicar la misma autorización a todos los listeners IPv4 e IPv6.'),
 'untrusted_router_advertisement': ('Anuncio de emisor no autorizado modifica configuración IPv6', 'https://www.rfc-editor.org/rfc/rfc4861', 'Limitar anuncios a routers de confianza mediante controles del enlace y del receptor.'),
 'neighbor_override': ('Emisor no autorizado cambia una asociación de vecino conocida', 'https://www.rfc-editor.org/rfc/rfc4861', 'Proteger asociaciones críticas y validar el origen en el enlace autorizado.'),
 'dad_interference': ('Emisor de prueba interfiere con detección de direcciones duplicadas', 'https://www.rfc-editor.org/rfc/rfc4862', 'Controlar mensajes ND del enlace y supervisar fallos DAD sin deshabilitarlo.'),
}


def targets():
    values = [Target(asset_id=asset, address=app[f], interface='br-lab-v2-apps', ports=[8088])
              for asset, app in lab.APPS.items() for f in ('ipv4', 'ipv6')]
    return values + [Target(asset_id=asset, address=r['address'], interface='br-lab-v2-ndp', ports=[53000])
                     for asset, r in lab.RECEIVERS.items()]


def policy():
    return LabPolicy(policy_id='docker-v2-controller-1', allowed_categories=CATEGORIES, max_token_budget=60000,
        segments=[LabSegment(name=name+'_'+str(i), network=subnet, interface=bridge,
                             allowed_ports=[8088] if name=='lab_v2_apps' else [8000,53000])
                  for name,(bridge,subnets,_) in lab.NETWORKS.items() for i,subnet in enumerate(sorted(subnets))])


def request(authorization, architecture='multiagent', tokens=40000, llm=True, stop=False):
    now = datetime.now(timezone.utc)
    return AuditRequest(bank='v2', audit_id='v2_'+architecture+'_'+uuid4().hex[:12], operator='operador_laboratorio',
        authorization_ref=authorization, architecture=architecture, categories=CATEGORIES, targets=targets(),
        scope_ipv4=['192.168.59.0/24','192.168.60.0/24'], scope_ipv6=['fd57:2026:59::/64','fd57:2026:60::/64'],
        not_before=now-timedelta(minutes=1), not_after=now+timedelta(minutes=30), max_runtime_seconds=1200,
        max_attempts=1, token_budget=tokens if llm else 0, llm_mode='scheduler' if llm else 'disabled',
        llm_provider='openai', stop_on_verified_access=stop)


def authorize_v2(req, pol):
    canonical = policy()
    if (pol != canonical or req.targets != targets() or set(req.categories)!=set(CATEGORIES)
        or req.scope_ipv4!=['192.168.59.0/24','192.168.60.0/24']
        or req.scope_ipv6!=['fd57:2026:59::/64','fd57:2026:60::/64'] or req.case_ids
        or req.max_attempts != 1 or req.token_budget > canonical.max_token_budget
        or (req.token_budget and req.llm_mode!='scheduler')):
        raise PolicyError('v2_scope_denied', 'el banco v2 solo admite su catálogo, política y perfiles cerrados')


def build_plan(req):
    tasks=[]
    for t in req.targets:
        if t.asset_id in lab.APPS and ':' not in t.address:
            tasks.append(Task(task_id=req.audit_id+'_'+t.asset_id+'_application', target=t,
                agent_type=Category.APPLICATION_ACCESS, protocol='http_dualstack',
                action_profile='http_application_dualstack_v2', timeout_seconds=180))
        elif t.asset_id in lab.RECEIVERS:
            previous=None
            for p in ('slaac', *ND, *FRAG):
                task=Task(task_id=req.audit_id+'_'+t.asset_id+'_'+p, target=t,
                    agent_type=Category.IPV6_FRAGMENTATION if p in FRAG else Category.IPV6_NDP,
                    case_id='V2_'+p.upper(), protocol='ipv6', action_profile='ipv6_'+p+'_v2',
                    dependencies=[previous] if previous else [], timeout_seconds=180)
                tasks.append(task);previous=task.task_id
    return tasks


def run_task(task, store):
    admitted = next((t for t in targets() if t==task.target), None)
    if admitted is None: raise PolicyError('v2_target_denied','activo ajeno al banco v2')
    payload={'asset_id':task.target.asset_id,'target':task.target.address,'profile':task.action_profile}
    if task.action_profile=='http_application_dualstack_v2' and task.target.asset_id in lab.APPS:
        app=lab.APPS[task.target.asset_id]
        primary={f:lab.app_family(app[f]) for f in ('ipv4','ipv6')}
        confirmation={f:lab.app_family(app[f],independent=True) for f in ('ipv4','ipv6')}
        payload['families']=primary
        corroboration={**payload,'families':confirmation,'channel':'independent_http_client'}
    else:
        receiver=lab.RECEIVERS[task.target.asset_id]
        p=task.action_profile.removeprefix('ipv6_').removesuffix('_v2')
        before=lab.wait_receiver(receiver)
        payload['before']=before
        if p=='slaac':
            payload['after']=before;payload['restored']=before
        else:
            try:
                if p=='na_neighbor':
                    lab.docker('exec',receiver['container'],'ip','-6','neigh','replace',lab.SENDER,'lladdr',
                        lab.SENDER_MAC,'nud','permanent' if task.target.asset_id=='receiver_b' else 'reachable','dev','eth0')
                    payload['before']=lab.snapshot(receiver)
                if p in ND:
                    payload['after'],payload['probe']=lab.probe(receiver,p,store,task.task_id)
                elif p in FRAG:
                    control,_expected=FRAG[p]
                    payload['control'],payload['control_probe']=lab.probe(receiver,control,store,task.task_id+'_control')
                    payload['after'],payload['probe']=lab.probe(receiver,p,store,task.task_id+'_variant')
                else: raise PolicyError('v2_profile_denied','perfil v2 desconocido')
            finally:
                payload['restored']=lab.reset_receiver(receiver)
        corroboration={**payload,'channel':'packet_observer_and_kernel_state'}
    evidence,eh=store.evidence(task.task_id+'_state','json',json.dumps(payload,sort_keys=True).encode())
    diagnostic,dh=store.evidence(task.task_id+'_confirmation','json',json.dumps(corroboration,sort_keys=True).encode())
    summary={'restored': True,'bank':'v2'}
    if task.action_profile=='http_application_dualstack_v2':
        a,b=_application(primary['ipv4']),_application(primary['ipv6'])
        summary['access_observed']=a[0] or b[0] or a[1] or b[1] or (not a[2] and b[2])
    elif p in ND:
        summary['state_changed']=bool(lab.nd_effect(p,payload['before'],payload['after'],receiver,payload['probe']))
    elif p in FRAG:
        summary['control_received']=any(x['nonce']==payload['control_probe']['nonce'] for x in payload['control']['observer']['udp_deliveries'])
        summary['variant_udp_delivered']=any(x['nonce']==payload['probe']['nonce'] for x in payload['after']['observer']['udp_deliveries'])
    return TaskResult(task_id=task.task_id,status=TaskStatus.COMPLETED,evidence_ref=evidence,evidence_sha256=eh,
        diagnostic_ref=diagnostic,diagnostic_sha256=dh,observations=summary)


def _artifact(root, reference, digest):
    from .validation import _matches
    if not _matches(root,reference,digest): raise ValueError('evidencia v2 modificada o ausente')
    return json.loads((root/reference).read_text())


def _packets(root, value):
    from .validation import _matches
    if isinstance(value,dict):
        if 'pcap_ref' in value and not _matches(root,value['pcap_ref'],value['pcap_sha256']):
            raise ValueError('captura v2 modificada')
        for item in value.values(): _packets(root,item)
    elif isinstance(value,list):
        for item in value: _packets(root,item)


def _application(facts):
    records=facts['records'];trace=facts['server_trace']
    if any(not any(e['path']==r['path'] and e['status']==r['status'] and e['nonce']==facts['nonce'] for e in trace) for r in records):
        raise ValueError('traza HTTP insuficiente')
    objects=[r for r in records if r['path'].startswith('/objects/') and r['status']==200
             and r['body'].get('kind')=='document' and isinstance(r['body'].get('marker'),str)]
    own=[r for r in objects if r['body'].get('owner')=='viewer']
    import hashlib
    if len(own)!=1 or hashlib.sha256(own[0]['body']['marker'].encode()).hexdigest()!=facts['own_marker_sha256']:
        raise ValueError('recurso propio no corroborado')
    return (any(r['body'].get('owner')=='other' for r in objects),
        any(r['path'].startswith('/download?') and r['status']==200 and r['body'].get('kind')=='internal_configuration'
            and isinstance(r['body'].get('marker'),str) for r in records),
        any(r['path']=='/admin' and r['status']==200 and r['body'].get('kind')=='admin_configuration' for r in records))


def assess(root,task,result):
    if result.status not in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS}: raise ValueError('tarea incompleta')
    if task.target not in targets(): raise ValueError('objetivo fuera de catálogo')
    data=_artifact(root,result.evidence_ref,result.evidence_sha256)
    corroboration=_artifact(root,result.diagnostic_ref,result.diagnostic_sha256)
    for artifact in (data,corroboration):
        if any(artifact.get(k)!=v for k,v in [('asset_id',task.target.asset_id),('target',task.target.address),('profile',task.action_profile)]):
            raise ValueError('evidencia de otra tarea')
        _packets(root,artifact)
    if task.action_profile=='http_application_dualstack_v2':
        if corroboration.get('channel')!='independent_http_client': raise ValueError('cliente independiente ausente')
        observations={}
        for f in ('ipv4','ipv6'):
            first,second=data['families'][f],corroboration['families'][f]
            a,b=_application(first),_application(second)
            if a!=b or first['nonce']==second['nonce'] or first['own_marker_sha256']!=second['own_marker_sha256']:
                raise ValueError('clientes independientes discrepan')
            observations[f]=a
        if data['families']['ipv4']['own_marker_sha256']!=data['families']['ipv6']['own_marker_sha256']:
            raise ValueError('familias con recursos distintos')
        a,b=observations['ipv4'],observations['ipv6']
        return [k for k,present in zip(lab.APP_CONDITIONS,(a[0] or b[0],a[1] or b[1],not a[2] and b[2])) if present]
    receiver=lab.RECEIVERS[task.target.asset_id]
    if corroboration.get('channel')!='packet_observer_and_kernel_state' or any(data[k]!=corroboration[k] for k in data):
        raise ValueError('estado del observador no corroborado')
    if not lab.slaac_addresses(data['before']) or not lab.slaac_addresses(data['restored']) or data['restored']['mtu']!=1500:
        raise ValueError('SLAAC o restauración incompleta')
    p=task.action_profile.removeprefix('ipv6_').removesuffix('_v2')
    if p=='slaac': return []
    proof=data['probe'];after=data['after']
    if p in ND:
        observed=after['observer']['router_advertisements' if p.startswith('ra_') else 'neighbor_advertisements']
        if not any(packet['source'] in {lab.SENDER,'fe80::57:20ff:fe26:6010'} for packet in observed):
            raise ValueError('sonda no observada')
        condition={'ra_route':'untrusted_router_advertisement','ra_mtu':'untrusted_router_advertisement',
                   'na_neighbor':'neighbor_override','dad_na':'dad_interference'}[p]
        return [condition] if lab.nd_effect(p,data['before'],after,receiver,proof) else []
    if p not in FRAG: raise ValueError('perfil desconocido')
    delivered=any(x['nonce']==proof['nonce'] for x in after['observer']['udp_deliveries'])
    control=data['control_probe']
    if (not any(x['nonce']==control['nonce'] for x in data['control']['observer']['udp_deliveries'])
        or sum(f['id']==proof['fragment_id'] for f in after['observer']['fragments'])<proof['packet_count']
        or delivered!=FRAG[p][1]): raise ValueError('control de conformidad no aprobado')
    return []


def validation_record(root,task,result):
    try:
        conditions=assess(root,task,result);valid=True;state='candidate' if conditions else 'observed';reason='v2_independent_evidence_valid'
    except (OSError,ValueError,KeyError,TypeError,IndexError):
        valid=False if result.evidence_ref or result.status==TaskStatus.COMPLETED else None
        state='indeterminate';reason='v2_evidence_incomplete_or_changed'
    return {'task_id':task.task_id,'case_id':task.case_id,'asset_id':task.target.asset_id,'action_profile':task.action_profile,
        'state':state,'reason':reason,'evidence_integrity':{'valid':valid,'diagnostic':valid,'packet':valid,'control_packet':None},
        'independent_confirmation':valid is True}


def adjudicate(root,task,result):
    try: conditions=assess(root,task,result)
    except (OSError,ValueError,KeyError,TypeError,IndexError): return []
    return [{'asset_id':task.target.asset_id,'address':task.target.address,'defect_key':key,'state':'verified',
        'severity':'medium','title':RULES[key][0],'condition':key,'reference':RULES[key][1],'remediation':RULES[key][2],
        'task_id':task.task_id,'evidence_ref':result.evidence_ref,'confirmation_ref':result.diagnostic_ref,
        'independent_confirmation':True,'reproduction':'Clientes HTTP independientes o contraste del observador de paquetes y estado del kernel.',
        'rule_version':'v2-1','scope_note':'Condición de laboratorio y requisito público de confianza; no implica CVE del kernel.'}
        for key in conditions]
