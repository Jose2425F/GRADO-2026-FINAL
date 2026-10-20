"""Contexto de los roles LLM: datos tipados y anónimos, sin secretos ni verdad del evaluador."""
import json

ROLE_MAP={'ipv4_services':'network','ipv6_services':'network','ipv4_credentials':'credentials',
          'application_access':'applications','ipv6_ndp':'ipv6','ipv6_fragmentation':'fragmentation'}
ROLE_NAMES={'network':'Especialista de descubrimiento','credentials':'Especialista de acceso',
 'applications':'Especialista de aplicaciones','ipv6':'Especialista de red IPv6',
 'fragmentation':'Especialista de fragmentación','generalist':'Agente único'}
CONDITIONS={'object_authorization','file_boundary','ipv6_authorization_gap','untrusted_router_advertisement',
 'neighbor_override','dad_interference','ssh_default_credential','ftp_default_credential','postgres_default_credential','http_get_default_credential'}


def context_for(tasks,results,findings,role):
    selected=[t for t in tasks if role=='generalist' or ROLE_MAP.get(str(t.agent_type))==role]
    aliases={t.task_id:'t'+str(i).zfill(3) for i,t in enumerate(tasks)}
    by_id={r.task_id:r for r in results}
    asset_ids=list(dict.fromkeys(t.target.asset_id for t in tasks))
    asset_aliases={asset:'a'+str(i).zfill(3) for i,asset in enumerate(asset_ids)}
    states={}
    for task in selected:
        status=str(by_id[task.task_id].status.value) if task.task_id in by_id else 'pending'
        states[status]=states.get(status,0)+1
    ids={t.task_id for t in selected}
    confirmed=[f for f in findings if f.get('task_id') in ids and f.get('condition') in CONDITIONS and f.get('state')=='verified']
    priority={f['task_id'] for f in confirmed}
    ordered=sorted(selected,key=lambda t:t.task_id not in priority)
    service_names={'ssh','ftp','http','https','http-proxy','postgres','postgresql','mysql','microsoft-ds','ms-wbt-server','smtp','domain','redis','unknown'}
    services={};observations={}
    for task in selected:
        result=by_id.get(task.task_id)
        if not result:continue
        for service in result.services:
            name=service.name if service.name in service_names else 'other'
            services[name]=services.get(name,0)+1
        for key in ['restored','state_changed','control_received','variant_udp_delivered']:
            value=result.observations.get(key)
            if type(value) is bool:
                label=key+('_true' if value else '_false');observations[label]=observations.get(label,0)+1
    facts=[]
    for task in ordered:
        result=by_id.get(task.task_id)
        if not result:continue
        fact={'task':aliases[task.task_id],'asset':asset_aliases[task.target.asset_id],'status':result.status.value,
              'confirmed_conditions':sorted({f['condition'] for f in confirmed if f['task_id']==task.task_id})}
        opened=[]
        for service in result.services:
            if service.state=='open' and type(service.port) is int and 1<=service.port<=65535:
                opened.append({'tcp_port':service.port,'service':service.name if service.name in service_names else 'other'})
        if opened:fact['open_services']=opened[:8]
        if result.authentication and result.authentication.outcome in {'accepted','rejected','indeterminate','transport_error'}:
            fact['tool_authentication']=result.authentication.outcome
        web=result.observations.get('application_checks',{})
        if isinstance(web,dict):
            checks={k:v for k,v in web.items() if k in {'object_authorization','file_boundary','ipv6_authorization_gap'} and v in {'confirmed','not_detected','incomplete','not_supported','not_requested'}}
            if checks:fact['web_observations']=checks
        facts.append(fact)
        if len(facts)==4:break
    asset_summaries=[]
    for asset in dict.fromkeys(t.target.asset_id for t in selected):
        asset_tasks=[t for t in selected if t.target.asset_id==asset]
        task_ids={t.task_id for t in asset_tasks}
        confirmed_here=sorted({f['condition'] for f in confirmed if f['task_id'] in task_ids})
        issues=sum(by_id[t.task_id].status.value in {'failed','blocked','cancelled'} for t in asset_tasks if t.task_id in by_id)
        asset_summaries.append({'asset':asset_aliases[asset],'tasks':len(asset_tasks),'confirmed_conditions':confirmed_here,'incidents':issues})
    return {'role':role,'assets_total':len(asset_summaries),'confirmed_assets':sum(bool(a['confirmed_conditions']) for a in asset_summaries),
            'asset_summaries':asset_summaries[:16],
            'task_assets':{aliases[t.task_id]:asset_aliases[t.target.asset_id] for t in ordered if t.task_id in by_id} ,'tasks_total':len(selected),'task_states':states,'task_facts':facts,
            'evidence_tasks':[aliases[t.task_id] for t in ordered if t.task_id in by_id][:24],
            'confirmed_conditions':sorted({f['condition'] for f in confirmed}),
            'service_observations':services,'protocol_observations':observations,
            'coverage_note':'Los alias aNNN representan activos distintos sin revelar IP. Solo perfiles ejecutados; no se conoce la verdad de referencia. Conteos de observaciones, no equipos únicos. Hasta 4 tareas detalladas/8 servicios por tarea y 24 referencias; detalle parcial, nunca exhaustivo.'}



ACTION_NAMES = {
 'rotate_credential':'Rotar la credencial y verificar el acceso',
 'restrict_service':'Revisar la exposición del servicio',
 'review_ipv6_trust':'Revisar la política de confianza IPv6',
 'review_evidence':'Resolver la evidencia incompleta',
 'check_patch_level':'Contrastar versión y parches del fabricante',
 'repeat_authorized_check':'Repetir la comprobación autorizada',
 'retain_control':'Conservar y verificar el control protegido',
 'review_application_permissions':'Corregir los permisos de la aplicación',
}
ROLE_ACTIONS={
 'network':['restrict_service','check_patch_level','review_evidence','repeat_authorized_check'],
 'credentials':['rotate_credential','review_evidence','repeat_authorized_check','retain_control'],
 'ipv6':['review_ipv6_trust','review_evidence','repeat_authorized_check','retain_control'],
 'fragmentation':['review_evidence','repeat_authorized_check','retain_control'],
 'applications':['review_application_permissions','review_evidence','repeat_authorized_check','retain_control'],
 'generalist':list(ACTION_NAMES),
}


def action_schema(context):
    # Cada alternativa une el activo a sus referencias. El proveedor recibe las
    # mismas restricciones de tamaño y pertenencia que comprueba el validador.
    variants=[]
    for asset in context['asset_summaries']:
        refs=[ref for ref in context['evidence_tasks'] if context['task_assets'].get(ref)==asset['asset']]
        if not refs:continue
        variants.append({'type':'object','additionalProperties':False,
        'properties':{'asset':{'type':'string','enum':[asset['asset']]},
            'action':{'type':'string','enum':ROLE_ACTIONS[context['role']]},
            'why':bounded_text(250),'verification':bounded_text(250),
            'evidence_tasks':{'type':'array','minItems':1,'maxItems':8,'items':{'type':'string','enum':refs}}},
        'required':['asset','action','why','verification','evidence_tasks']})
    if not variants:return {'type':'array','maxItems':0,'items':{'type':'string'}}
    return {'type':'array','maxItems':3,'items':{'anyOf':variants}}


def bounded_text(maximum):
    return {'type':'string','minLength':1,'maxLength':maximum,'pattern':r'^[^\x00-\x1f]+$'}


def validate_actions(value,context):
    if not isinstance(value,list) or len(value)>3:raise ValueError('invalid_actions')
    assets={a['asset'] for a in context['asset_summaries']}
    for action in value:
        if not isinstance(action,dict) or set(action)!={'asset','action','why','verification','evidence_tasks'}:raise ValueError('invalid_action')
        if action['asset'] not in assets or action['action'] not in ROLE_ACTIONS[context['role']]:raise ValueError('invalid_action_scope')
        for field in ['why','verification']:
            if not isinstance(action[field],str) or not 1<=len(action[field])<=250 or any(ord(c)<32 for c in action[field]):raise ValueError('invalid_action_text')
        refs=action['evidence_tasks']
        if not isinstance(refs,list) or not 1<=len(refs)<=8 or any(not isinstance(ref,str) or ref not in context['evidence_tasks'] or context['task_assets'].get(ref)!=action['asset'] for ref in refs):raise ValueError('invalid_action_evidence')
    return value
