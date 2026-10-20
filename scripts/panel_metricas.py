"""Métricas operativas y comparación exploratoria; no inventa verdad de referencia."""
import hashlib
import json
import math
import re
from collections import Counter


def number(value):
    return value if type(value) in {int,float} and math.isfinite(value) and value>=0 else None


def operation_metrics(run,report):
    total=run.get('total',0);tasks=run.get('tasks',[])
    done=sum(t.get('status') in {'completed','completed_no_findings'} for t in tasks)
    inventory=report.get('inventory',[])
    scanned=sum(i.get('scan_status') in {'completed','completed_no_findings'} for i in inventory if isinstance(i,dict))
    return {'tasks_total':total,'tasks_completed':done,'completion_percent':round(done/total*100,2) if total else None,
            'addresses_requested':len(inventory) if inventory else None,'addresses_inventoried':scanned if inventory else None,
            'inventory_percent':round(scanned/len(inventory)*100,2) if inventory else None,
            'elapsed_seconds':number(run.get('seconds')),'known_tokens':number(run.get('llm',{}).get('known_tokens')),
            'token_usage_complete':run.get('llm',{}).get('usage_complete') is True,
            'execution_seconds':number(report.get('metrics',{}).get('execution_seconds')),
            'expert_review_seconds':number(report.get('metrics',{}).get('expert_review_seconds')),
            'detection_coverage':None,'detection_note':'La cobertura de detección requiere condiciones de referencia; completar tareas no equivale a detectar todas las vulnerabilidades.'}


def scope_signature(request,plan):
    fields=['bank','targets','personal','applications','scope_ipv4','scope_ipv6','categories','case_ids','max_attempts','stop_on_verified_access']
    scope={k:request.get(k) for k in fields}
    scope['expert_mode']=bool(request.get('expert_mode'))
    task_ids={t.get('task_id'):i for i,t in enumerate(plan)}
    scope['plan']=[{'target':t.get('target'),'profile':t.get('action_profile'),'timeout':t.get('timeout_seconds'),
                    'dependencies':[task_ids.get(d,-1) for d in t.get('dependencies',[])]} for t in plan]
    if isinstance(request.get('personal'),dict) and request['personal'].get('port_mode')=='auto':
        # El orden de recepción puede variar con dos trabajadores. Comparar el
        # mismo catálogo y dependencias, no el orden de llegada de sus resultados.
        descriptors={t.get('task_id'):{'target':t.get('target'),'profile':t.get('action_profile'),'timeout':t.get('timeout_seconds')} for t in plan}
        canonical=lambda value:json.dumps(value,sort_keys=True)
        scope['plan']=sorted([{**descriptors[t.get('task_id')],
            'dependencies':sorted([descriptors.get(d,{'missing_dependency':True}) for d in t.get('dependencies',[])],key=canonical)} for t in plan],key=canonical)
    return hashlib.sha256(json.dumps(scope,sort_keys=True).encode()).hexdigest()


def assistance_diagnostics(value,architecture):
    """Explicar incidencias con campos contados, sin publicar prompts ni respuestas."""
    summary=value['run'].get('llm',{})
    llm=value.get('report',{}).get('llm',{})
    calls=llm.get('calls',[])
    calls=[c for c in calls if isinstance(c,dict)] if isinstance(calls,list) else []
    rejected=[c for c in calls if c.get('status')=='fallback']
    reasons=Counter(c.get('reason') if isinstance(c.get('reason'),str) and c.get('reason') in {
        'token_budget_exhausted','invalid_specialist_response','provider_timeout','provider_connection_failed',
        'runtime_budget_exhausted','usage_unavailable','response_incomplete','invalid_review_text','invalid_review_evidence',
        'invalid_action_evidence','invalid_action_text','invalid_action_scope','invalid_review_json','invalid_actions','invalid_action','invalid_review'} else 'other' for c in rejected)
    messages={
        'token_budget_exhausted':'decisiones resueltas con respaldo local por saldo insuficiente en el presupuesto de planificación',
        'invalid_specialist_response':'revisiones rechazadas por el validador de respuestas',
        'provider_timeout':'llamadas que agotaron la espera',
        'provider_connection_failed':'fallos de conexión con el proveedor',
        'runtime_budget_exhausted':'decisiones de respaldo por límite de tiempo',
        'usage_unavailable':'incidencias con consumo no informado',
        'response_incomplete':'respuestas incompletas',
        'invalid_review_text':'revisiones cuyo texto incumplió la longitud o el formato permitido',
        'invalid_review_evidence':'revisiones con referencias no admitidas',
        'invalid_action_evidence':'acciones con referencias ajenas al equipo o no admitidas',
        'invalid_action_text':'acciones cuyo texto incumplió la longitud o el formato permitido',
        'invalid_action_scope':'acciones fuera del alcance permitido',
        'invalid_review_json':'respuestas de revisión que no pudieron interpretarse como JSON',
        'invalid_actions':'listas de acciones con formato o cantidad no admitidos',
        'invalid_action':'acciones con estructura no admitida',
        'invalid_review':'revisiones con estructura no admitida',
        'other':'otras incidencias de planificación o revisión'}
    count=summary.get('fallbacks',0)
    count=count if type(count) is int and count>=0 else 0
    if count>len(rejected):reasons['other']+=count-len(rejected)
    # Sin detalle histórico no se supone que una decisión de respaldo haya enviado una generación.
    generations=sum(c.get('generation_sent') is True for c in calls) if calls else None
    return {'architecture':architecture,'label':'Agente único' if architecture=='single' else 'Multiagente',
            'api_generations':generations,'fallbacks':count,
            'planning_accepted':sum(c.get('status')=='accepted' and c.get('phase')!='specialist_review' for c in calls),
            'reviews_accepted':sum(c.get('status')=='accepted' and c.get('phase')=='specialist_review' for c in calls),
            'incidents':[{'count':n,'code':code,'message':messages[code]} for code,n in reasons.items()]}


def compare_runs(single,multi):
    """Cada argumento contiene run/request/plan/manifest/report/evaluation públicos locales."""
    from tesis.presupuesto_deteccion import partial_budget_valid,budget_record_valid
    reasons=[]
    partial=[partial_budget_valid(v) for v in (single,multi)]
    assistance=[assistance_diagnostics(v,a) for v,a in [(single,'single'),(multi,'multiagent')]]
    for value,architecture in [(single,'single'),(multi,'multiagent')]:
        run=value['run'];report=value['report']
        if run.get('architecture')!=architecture:reasons.append('Selecciona una ejecución de cada arquitectura en su campo correspondiente.')
        if run.get('mode')!='live' or run.get('status')!='complete' or not report:reasons.append('Ambas ejecuciones deben ser reales y estar completas.')
        if not partial[0 if architecture=='single' else 1] and any(t.get('status') not in {'completed','completed_no_findings'} for t in run.get('tasks',[])):reasons.append('Hay tareas incompletas; conserva ese intento y compara otra pareja completa.')
        if value['manifest'].get('detection_budget',{}).get('applied') is True and not budget_record_valid(value):
            reasons.append('El límite de tareas o sus omisiones no concilian con los resultados.')
        if run.get('llm',{}).get('usage_complete') is not True:reasons.append('El consumo de tokens está incompleto.')
        if run.get('llm',{}).get('fallbacks'):
            diagnostic=assistance[0 if architecture=='single' else 1]
            details='; '.join(f"{i['message']}: {i['count']}" for i in diagnostic['incidents'])
            reasons.append(f"{diagnostic['label']}: {details}. No cumple el criterio de esta comparación de IA sin respaldo. El intento se conserva como resultado con incidencias.")
        if value.get('evaluation',{}).get('evidence_valid') is False:reasons.append('La evidencia no supera el contraste de integridad; esta pareja no es apta.')
    if scope_signature({**single['request'],'expert_mode':single['manifest'].get('expert_mode',single['request'].get('expert_mode',False))},single['plan'])!=scope_signature({**multi['request'],'expert_mode':multi['manifest'].get('expert_mode',multi['request'].get('expert_mode',False))},multi['plan']):
        reasons.append('El alcance, los perfiles o la revisión especializada son diferentes. Repite el mismo catálogo en ambas arquitecturas.')
    sources=[]
    for value in [single,multi]:
        manifest=value['manifest'];sources.append(manifest.get('source_sha256') or manifest.get('adapter_sha256'))
    if not all(isinstance(s,str) and len(s)==64 for s in sources) or sources[0]!=sources[1]:reasons.append('No se acredita la misma versión del auditor.')
    if single['manifest'].get('adapter_sha256')!=multi['manifest'].get('adapter_sha256'):reasons.append('Las versiones del controlador externo son diferentes.')
    if single['manifest'].get('extensions_sha256')!=multi['manifest'].get('extensions_sha256'):reasons.append('Las versiones de los adaptadores adicionales son diferentes.')
    auditor_sources=[v['manifest'].get('auditor_source_sha256') for v in [single,multi]]
    if any(auditor_sources) and (auditor_sources[0]!=auditor_sources[1] or any(not isinstance(s,str) or not re.fullmatch(r'[a-f0-9]{64}',s) for s in auditor_sources)):
        reasons.append('Las versiones completas del código auditor son diferentes o no están acreditadas.')
    graphs=[v['manifest'].get('orchestration') for v in [single,multi]]
    if any(graphs):
        fields=['engine','version','graph','source_sha256']
        identities=[{k:g.get(k) for k in fields} if isinstance(g,dict) else {} for g in graphs]
        if identities[0]!=identities[1] or any(not identity.get(k) for identity in identities for k in fields):
            reasons.append('El motor o la versión del grafo de orquestación son diferentes o no están acreditados.')
    if single['run'].get('bank')!=multi['run'].get('bank'):reasons.append('Los bancos o laboratorios son diferentes.')
    if single['manifest'].get('scenario') or multi['manifest'].get('scenario'):
        keys=['id','version','source_sha256','images','fixture_sha256']
        if [{k:v['manifest'].get('scenario',{}).get(k) for k in keys} for v in [single,multi]][0]!=[{k:v['manifest'].get('scenario',{}).get(k) for k in keys} for v in [single,multi]][1]:reasons.append('Los escenarios o sus imágenes/configuraciones son diferentes; compara las arquitecturas dentro del mismo laboratorio.')
    if single['run'].get('llm',{}).get('model')!=multi['run'].get('llm',{}).get('model'):reasons.append('Los modelos son diferentes.')
    if single['request'].get('token_budget')!=multi['request'].get('token_budget'):reasons.append('Los presupuestos de tokens son diferentes.')
    policies=[{key:v['manifest'].get('detection_budget',{}).get(key) for key in ('applied','task_limit','catalogue_size','policy')} for v in (single,multi)]
    if policies[0]!=policies[1]:
        reasons.append('Las políticas o límites de cobertura parcial son diferentes.')
    keys=['reasoning_effort','max_output_tokens','service_tier','output_contract']
    configs=[{key:v['report'].get('llm',{}).get('configuration',{}).get(key) for key in keys} for v in [single,multi]]
    if configs[0]!=configs[1]:reasons.append('Las configuraciones de la IA son diferentes.')
    reasons=list(dict.fromkeys(reasons))
    result={'eligible':not reasons,'classification':'exploratory','reasons':reasons,'formal_study':False,'assistance':assistance,
            'TRTO_percent':None,'IDE_percent':None,'ETV_ratio':None,'token_reduction_percent':None,
            'truth_available':False,'note':'Comparación descriptiva de dos ejecuciones; no se incorpora automáticamente al estudio formal ni demuestra causalidad.'}
    if reasons:return result
    a,b=single['run'],multi['run']
    ta,tb=number(a.get('seconds')),number(b.get('seconds'))
    if ta and tb is not None:result['TRTO_percent']=round((ta-tb)/ta*100,4)
    ka,kb=number(a['llm'].get('known_tokens')),number(b['llm'].get('known_tokens'))
    if ka and kb is not None:result['token_reduction_percent']=round((ka-kb)/ka*100,4)
    ea,eb=single.get('evaluation',{}),multi.get('evaluation',{})
    truth=ea.get('ground_truth_sha256')
    negative_compatible=(all(type(e.get('negative_conditions_total')) is int and e['negative_conditions_total']>=0
                             and type(e.get('unknown_negative_controls')) is int and e['unknown_negative_controls']>=0
                             and type(e.get('TN')) is int and e['TN']>=0
                             and e['TN']+e['unknown_negative_controls']<=e['negative_conditions_total'] for e in (ea,eb))
                         and ea.get('negative_conditions_total')==eb.get('negative_conditions_total')) if all(partial) else (
                         all(e.get('unknown_negative_controls',0)==0 for e in (ea,eb))
                         and ea.get('TN',0)+ea.get('FP',0)==eb.get('TN',0)+eb.get('FP',0))
    valid_truth=(isinstance(truth,str) and re.fullmatch(r'[a-f0-9]{64}',truth) and truth==eb.get('ground_truth_sha256')
                 and all(e.get('evidence_valid') is True for e in [ea,eb]) and negative_compatible
                 and all(type(e.get(k)) is int and e[k]>=0 for e in [ea,eb] for k in ['TP','FP','FN','TN'])
                 and ea['TP']+ea['FN']==eb['TP']+eb['FN'])
    if valid_truth:
        pu,pm=ea['TP'],eb['TP'];result['truth_available']=True
        if pu>0:result['IDE_percent']=round((pm-pu)/pu*100,4)
        if pu>0 and pm>0 and ka is not None and kb and ka>0:result['ETV_ratio']=round((ka/pu)/(kb/pm),4)
    else:result['detection_note']='IDE y ETV pendientes: faltan evaluaciones con la misma referencia verificable. Los hallazgos observados no sustituyen los verdaderos positivos.'
    return result
