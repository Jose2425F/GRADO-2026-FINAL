"""Registro manual de cinco parejas por laboratorio; lectura local, sin API.

El primer intento de cada posición es el resultado registrado. Los errores no
desaparecen al repetir una práctica. La aptitud se calcula con la evidencia y
con la misma identidad del grafo, modelo, alcance y presupuesto.
"""
from __future__ import annotations
import math
import re
from pathlib import Path

STUDY_ID = 'langgraph_manual_20261018'
PAIRS = 5


def validate_context(value):
    if (not isinstance(value,dict) or set(value)!={'study_id','pair'}
        or value.get('study_id')!=STUDY_ID or type(value.get('pair')) is not int
        or not 1<=value['pair']<=PAIRS):
        raise ValueError('Selecciona una pareja de 1 a 5 de la evaluación manual LangGraph.')
    return {'study_id':STUDY_ID,'pair':value['pair']}


def validate_registered_start(options,records):
    from tesis.protocolo_manual import protocol,validate_next
    configured=protocol()
    limits=configured.get('task_limits') or {}
    limit=limits.get(options.get('scenario') or 'integrado',configured.get('task_limit'))
    if (configured.get('task_limit_status')!='confirmed' or limit is None
        or configured.get('execution_enabled') is not True or configured.get('task_limit_applied') is not True):
        raise ValueError('El protocolo está pendiente de tu confirmación del límite de tareas; todavía no inicies las 50 corridas.')
    if options.get('tokens')!=configured['tokens'] or not options.get('expert_mode') or options.get('ia')!='openai':
        raise ValueError('Mantén OpenAI, revisión LLM y los mismos 60.000 tokens del protocolo.')
    return validate_next(options,records)


def public_orchestration(value):
    if not isinstance(value,dict) or value.get('engine')!='langgraph':return {}
    result={'engine':'langgraph'}
    for key in ['version','graph','source_sha256']:
        item=value.get(key)
        pattern=r'[a-f0-9]{64}' if key=='source_sha256' else r'[A-Za-z0-9_.+-]{1,100}'
        if isinstance(item,str) and re.fullmatch(pattern,item):result[key]=item
    return result


def public_context(value):
    if not isinstance(value,dict):return {}
    try:result=validate_context({k:value[k] for k in ['study_id','pair']})
    except (KeyError,ValueError):return {}
    from tesis.laboratorios import PROFILES
    if value.get('scenario') not in {'integrado',*PROFILES}:return {}
    if value.get('architecture') not in {'single','multiagent'}:return {}
    return {**result,'scenario':value['scenario'],'architecture':value['architecture']}


def ensure_empty_position(root, options):
    """Antes de crear un trabajo, nunca sobrescribir un intento de evaluación."""
    context=options.get('manual_context')
    if not context:return
    scenario=options.get('scenario') or 'integrado'
    for path in Path(root).rglob('panel_job.json'):
        if path.is_symlink() or path.stat().st_size>100_000:continue
        try:
            import json
            old=json.loads(path.read_text()).get('options',{})
        except (OSError,ValueError,AttributeError):continue
        if (isinstance(old,dict) and old.get('manual_context')==context and old.get('architecture')==options['architecture']
            and (old.get('scenario') or 'integrado')==scenario):
            raise ValueError('Esta posición ya tiene un intento registrado. Consérvalo; para practicar de nuevo desmarca Registrar en evaluación manual.')


def protocol_record_reasons(value, configured, slot):
    """Contrasta el registro capturado con el protocolo; no reevalúa evidencia."""
    run=value['run'];request=value['request'];manifest=value['manifest'];report=value['report']
    llm=report.get('llm',{})
    configuration=llm.get('configuration',{})
    configuration=configuration if isinstance(configuration,dict) else {}
    reasons=[]
    if (llm.get('model')!=configured['model']
        or run.get('llm',{}).get('model')!=configured['model']):
        reasons.append('El modelo configurado no corresponde a gpt-6.1-sol, fijado por el protocolo.')
    budget=request.get('token_budget')
    measured=llm.get('known_tokens');total=llm.get('total_tokens')
    if (type(budget) is not int or budget!=configured['tokens']
        or type(measured) is not int or not 0<measured<=configured['tokens']
        or type(total) is not int or total!=measured
        or run.get('llm',{}).get('known_tokens')!=measured
        or llm.get('usage_complete') is not True):
        reasons.append('El presupuesto de 60.000 tokens o su consumo completo no concilian con el protocolo.')

    def finite(value):
        return type(value) in {int,float} and math.isfinite(value) and value>=0

    cost=llm.get('cost_estimate_usd');known_cost=llm.get('known_cost_estimate_usd')
    if (not finite(cost) or not finite(known_cost) or cost!=known_cost
        or (finite(cost) and cost>configured['max_cost_usd'])
        or llm.get('cost_limit_usd')!=configured['max_cost_usd']
        or configuration.get('cost_limit_usd')!=configured['max_cost_usd']):
        reasons.append('El costo medido completo o el límite de USD 2 no concilian con el protocolo.')
    runtime=manifest.get('maximum_runtime_seconds');requested_runtime=request.get('max_runtime_seconds')
    seconds=run.get('seconds')
    if (type(runtime) is not int or runtime!=configured['max_runtime_seconds']
        or type(requested_runtime) is not int or requested_runtime!=runtime
        or not finite(seconds) or seconds==0
        or (finite(seconds) and seconds>runtime)):
        reasons.append('El tiempo medido o el límite de 2.400 segundos no concilian con el protocolo.')

    captured=manifest.get('manual_protocol',{})
    captured=captured if isinstance(captured,dict) else {}
    if (captured.get('protocol_sha256')!=configured['protocol_sha256']
        or type(captured.get('sequence')) is not int or captured['sequence']!=slot['sequence']):
        reasons.append('La posición no acredita la huella y el orden capturados del protocolo vigente.')
    restoration=captured.get('restoration',{})
    if (not isinstance(restoration,dict)
        or any(not isinstance(restoration.get(key),str) or not re.fullmatch(r'[a-f0-9]{32}',restoration[key])
               for key in ['id','activation_id'])):
        reasons.append('Falta el recibo de restauración activado para esta corrida.')
    scenario=slot['scenario']
    recorded_budget=manifest.get('detection_budget',{})
    recorded_budget=recorded_budget if isinstance(recorded_budget,dict) else {}
    if (len(value.get('plan',[]))!=configured['catalog_task_counts'][scenario]
        or recorded_budget.get('task_limit')!=configured['task_limits'][scenario]):
        reasons.append('El catálogo o el límite de tareas no corresponden al laboratorio del protocolo.')
    return reasons


def summary(runs, root, read_json):
    from auditoria.dashboard import collect_run, process_identity
    from panel_metricas import compare_runs
    from tesis.laboratorios import catalog
    from tesis.estudio import describe
    from tesis.presupuesto_deteccion import expected_review_roles,budget_record_valid
    from tesis.protocolo_manual import protocol,next_slot
    configured=protocol()
    slots={(slot['scenario'],slot['pair'],slot['architecture']):slot for slot in configured['schedule']}
    scenarios=[{'id':'integrado','name':'NovaFlow · banco integrado'},*catalog()]
    groups={row['id']:{**row,'label':row['name'],'completed_runs':0,'completed_pairs':0,
        'failed_runs':0,'pairs':[]} for row in scenarios}
    # El historial general muestra las últimas cien entradas; una práctica
    # posterior no debe expulsar de la evaluación un primer intento registrado.
    runs=list(runs)
    keys={r.get('key') for r in runs}
    for path in Path(root).rglob('manifest.json'):
        manifest=read_json(path,{})
        context=public_context(manifest.get('manual_context')) if isinstance(manifest,dict) else {}
        key=path.parent.relative_to(root).as_posix()
        if not context or key in keys:continue
        try:run=collect_run(path.parent,Path(root))
        except (OSError,ValueError,TypeError,KeyError,AttributeError):continue
        request=read_json(path.parent/'request.json',{})
        run.update(manual_context=context,orchestration=public_orchestration(manifest.get('orchestration')),
                   bank=request.get('bank','empresa'))
        runs.append(run);keys.add(key)
    # Conservar reservas que fallan antes de crear RunStore/manifiesto.
    for path in Path(root).rglob('panel_job.json'):
        job=read_json(path,{})
        if not isinstance(job,dict) or not isinstance(job.get('options'),dict):continue
        options=job['options']
        try:context=validate_context(options.get('manual_context'))
        except ValueError:continue
        scenario=options.get('scenario') or 'integrado';architecture=options.get('architecture')
        context=public_context({**context,'scenario':scenario,'architecture':architecture})
        if not context or any(r.get('manual_context')==context and r.get('key','').startswith(path.parent.relative_to(root).as_posix()+'/') for r in runs):continue
        status=read_json(path.parent/'panel_status.json',{})
        alive=(isinstance(status,dict) and status.get('identity') is not None
            and process_identity(status.get('pid'))==status.get('identity'))
        key=path.parent.relative_to(root).as_posix()
        if key in keys:continue
        runs.append({'key':key,'name':job.get('name','Intento sin informe'),'started_at':job.get('created_at',''),
            'manual_context':context,'architecture':architecture,'bank':'empresa','mode':'live',
            'status':'running' if alive else 'interrupted','tasks':[],'llm':{},'orchestration':{}})
        keys.add(key)
    recorded=[]
    for run in sorted(runs,key=lambda r:(r.get('started_at') or '',r.get('key') or '')):
        context=public_context(run.get('manual_context'))
        if context.get('study_id')!=STUDY_ID:continue
        if context['architecture']!=run.get('architecture'):continue
        directory=Path(root)/run['key']
        value={'run':run,**{name:read_json(directory/(name+'.json'),[] if name=='plan' else {})
                for name in ['request','plan','manifest','report','evaluation']}}
        recorded.append((context,value))
    cell={};duplicates=0
    for context,value in recorded:
        key=(context['scenario'],context['pair'],context['architecture'])
        if key in cell:duplicates+=1
        else:cell[key]=value
    metrics={key:[] for key in ['TRTO_percent','IDE_percent','ETV_ratio','token_reduction_percent']}
    completed=failed=pairs=0
    def display(value):
        if not value:return None
        run=value['run']
        return {'run_id':run.get('key'),'key':run.get('key'),'status':run.get('status'),
                'name':run.get('name'),'known_tokens':run.get('llm',{}).get('known_tokens'),
                'seconds':run.get('seconds')}
    for scenario,group in groups.items():
        local_metrics={key:[] for key in metrics}
        for pair in range(1,PAIRS+1):
            single=cell.get((scenario,pair,'single'));multi=cell.get((scenario,pair,'multiagent'))
            row={'pair':pair,'single':display(single),'multiagent':display(multi),
                 'complete':False,'eligible':False,'reasons':[]}
            for value in [single,multi]:
                if not value:continue
                status=value['run'].get('status')
                if status=='complete':group['completed_runs']+=1;completed+=1
                elif status not in {'running','pending'}:group['failed_runs']+=1;failed+=1
            if single and multi:
                comparison=compare_runs(single,multi)
                reasons=list(comparison['reasons'])
                if comparison.get('truth_available') is not True and not comparison['reasons']:
                    reasons.append('Falta una referencia común íntegra y una cobertura parcial verificable para IDE y ETV.')
                reported_models=[]
                for value in [single,multi]:
                    slot=slots[(scenario,pair,value['run']['architecture'])]
                    reasons.extend(protocol_record_reasons(value,configured,slot))
                    source=value['manifest'].get('auditor_source_sha256')
                    if not isinstance(source,str) or not re.fullmatch(r'[a-f0-9]{64}',source):
                        reasons.append('Falta la huella completa del código auditor.')
                    graph=public_orchestration(value['manifest'].get('orchestration'))
                    if not all(graph.get(k) for k in ['engine','version','graph','source_sha256']):
                        reasons.append('No se acredita la identidad completa del grafo LangGraph.')
                    bank=value['manifest'].get('scenario',{})
                    images=bank.get('images') if isinstance(bank,dict) else None
                    if (not isinstance(bank,dict) or bank.get('id')!=scenario or not bank.get('version')
                        or not all(isinstance(bank.get(k),str) and re.fullmatch(r'[a-f0-9]{64}',bank[k])
                                   for k in ['source_sha256','fixture_sha256'])
                        or not isinstance(images,dict) or not images
                        or any(not isinstance(k,str) or not isinstance(v,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',v) for k,v in images.items())):
                        reasons.append('Falta la identidad verificable de configuración e imágenes del laboratorio.')
                    llm=value['report'].get('llm',{})
                    calls=[c for c in llm.get('calls',[]) if isinstance(c,dict) and c.get('generation_sent') is True]
                    if llm.get('provider')!='openai' or not calls:
                        reasons.append('La posición no acredita una generación por la API de OpenAI.')
                    models={c['response_model'] for c in calls if isinstance(c.get('response_model'),str) and c['response_model']}
                    if len(models)!=1 or any(not isinstance(c.get('response_model'),str) or not c['response_model'] for c in calls):
                        reasons.append('No se acredita un único modelo real en todas las generaciones de la posición.')
                    reported_models.append(models)
                    tokens=value['run'].get('llm',{}).get('known_tokens')
                    if type(tokens) is not int or tokens<=0:
                        reasons.append('La posición no tiene un consumo de tokens medido y positivo.')
                    reviews=llm.get('specialist_reviews',[])
                    expected=expected_review_roles(value)
                    if (not isinstance(reviews,list) or len(reviews)!=len(expected)
                        or {r.get('role') for r in reviews if isinstance(r,dict) and r.get('status')=='accepted'}!=expected):
                        reasons.append('Falta una revisión especializada aceptada para esta arquitectura.')
                    if value['evaluation'].get('evidence_valid') is not True:
                        reasons.append('Falta evidencia íntegra validada para los KPI.')
                    if not budget_record_valid(value):
                        reasons.append('Falta el registro verificable del límite proporcional del 60 %.')
                if reported_models[0]!=reported_models[1]:
                    reasons.append('La API respondió con modelos reales diferentes entre arquitecturas.')
                receipts=[]
                for value in [single,multi]:
                    captured=value['manifest'].get('manual_protocol',{})
                    receipt=captured.get('restoration',{}) if isinstance(captured,dict) else {}
                    receipts.append(receipt if isinstance(receipt,dict) else {})
                if any(receipts[0].get(key) and receipts[0].get(key)==receipts[1].get(key)
                       for key in ['id','activation_id']):
                    reasons.append('La pareja reutiliza una restauración o una activación entre posiciones.')
                row['reasons']=list(dict.fromkeys(reasons))
                row['complete']=row['eligible']=not row['reasons']
                row['metrics']={key:comparison.get(key) if row['eligible'] else None for key in metrics}
                if row['eligible']:
                    group['completed_pairs']+=1;pairs+=1
                    for key,number in row['metrics'].items():
                        if type(number) in {int,float}:metrics[key].append(number);local_metrics[key].append(number)
            group['pairs'].append(row)
        group['analysis']={key:describe(values) for key,values in local_metrics.items()}
    positions=[{'scenario':c['scenario'],'pair':c['pair'],'architecture':c['architecture']} for c,_ in recorded]
    try:following=next_slot(positions);order_error=None
    except ValueError as exc:following=None;order_error=str(exc)
    records=[]
    def tokens(calls,key):
        numbers=[c.get(key) for c in calls]
        return sum(numbers) if all(type(n) is int and n>=0 for n in numbers) else None
    import hashlib,json
    from panel_metricas import scope_signature
    for slot in configured['schedule']:
        scenario=slot['scenario'];pair=slot['pair'];architecture=slot['architecture']
        value=cell.get((scenario,pair,architecture));group=groups[scenario]
        comparison=group['pairs'][pair-1]
        row={**slot,'laboratory':group['label'],'recorded':value is not None,'status':'not_started',
            'run_id':None,'protocol_sha256':configured['protocol_sha256'],'eligible_pair':comparison['eligible'],
            'exclusion_reasons':comparison['reasons']}
        if value:
            run=value['run'];report=value['report'];manifest=value['manifest'];evaluation=value['evaluation']
            llm=report.get('llm',{});calls=[c for c in llm.get('calls',[]) if isinstance(c,dict) and c.get('generation_sent') is True]
            graph=manifest.get('orchestration',{});bank=manifest.get('scenario',{})
            if not isinstance(bank,dict):bank={}
            manual_protocol=manifest.get('manual_protocol',{})
            manual_protocol=manual_protocol if isinstance(manual_protocol,dict) else {}
            restoration=manual_protocol.get('restoration',{})
            restoration=restoration if isinstance(restoration,dict) else {}
            row.update(run_id=run.get('key'),audit_id=report.get('audit_id'),status=run.get('status'),
                started_at=run.get('started_at'),seconds=run.get('seconds'),
                execution_seconds=report.get('metrics',{}).get('execution_seconds'),
                review_seconds=report.get('metrics',{}).get('expert_review_seconds'),
                input_tokens=tokens(calls,'input_tokens') if llm else None,
                output_tokens=tokens(calls,'provider_output_tokens') if llm else None,
                text_output_tokens=tokens(calls,'output_tokens') if llm else None,
                provider_output_tokens=tokens(calls,'provider_output_tokens') if llm else None,
                reasoning_tokens=tokens(calls,'thought_tokens') if llm else None,
                total_tokens=llm.get('total_tokens'),known_tokens=llm.get('known_tokens'),
                usage_complete=llm.get('usage_complete'),token_usage_complete=llm.get('usage_complete'),
                cost_estimate_usd=llm.get('cost_estimate_usd'),known_cost_estimate_usd=llm.get('known_cost_estimate_usd'),
                cost_limit_usd=llm.get('cost_limit_usd'),api_generations=len(calls) if llm else None,
                fallbacks=llm.get('fallbacks'),model=llm.get('model'),
                reported_models=sorted({c['response_model'] for c in calls if isinstance(c.get('response_model'),str)}),
                TP=evaluation.get('TP'),FP=evaluation.get('FP'),FN=evaluation.get('FN'),TN=evaluation.get('TN'),
                unknown_negative_controls=evaluation.get('unknown_negative_controls'),evidence_valid=evaluation.get('evidence_valid'),
                negative_conditions_total=evaluation.get('negative_conditions_total'),
                source_sha256=manifest.get('auditor_source_sha256'),adapter_sha256=manifest.get('adapter_sha256'),
                extensions_sha256=manifest.get('extensions_sha256'),graph_sha256=graph.get('source_sha256'),
                graph_version=graph.get('graph'),langgraph_version=graph.get('version'),
                scenario_source_sha256=bank.get('source_sha256'),fixture_sha256=bank.get('fixture_sha256'),
                images_sha256=hashlib.sha256(json.dumps(bank['images'],sort_keys=True).encode()).hexdigest() if bank.get('images') else None,
                ground_truth_sha256=evaluation.get('ground_truth_sha256'),
                token_budget=value['request'].get('token_budget'),max_runtime_seconds=manifest.get('maximum_runtime_seconds'),
                scope_sha256=scope_signature({**value['request'],'expert_mode':manifest.get('expert_mode',False)},value['plan']),
                restoration_id=restoration.get('id'),
                task_limit=manifest.get('detection_budget',{}).get('task_limit'),
                catalogue_size=manifest.get('detection_budget',{}).get('catalogue_size'),
                executed_tasks=report.get('detection_budget',{}).get('executed_tasks'),
                task_limit_applied=manifest.get('detection_budget',{}).get('applied'),
                recorded_protocol_sha256=manual_protocol.get('protocol_sha256'),
                specialist_reviews_accepted=sum(r.get('status')=='accepted' for r in llm.get('specialist_reviews',[]) if isinstance(r,dict)),
                specialist_reviews_expected=len(expected_review_roles(value)))
        records.append(row)
    return {'study_id':STUDY_ID,'status':'manual','planned_runs':50,'planned_pairs':25,
            'protocol':configured,'next_slot':following,'order_error':order_error,
            'ready':configured.get('task_limit_status')=='confirmed' and configured.get('execution_enabled') is True and configured.get('task_limit_applied') is True and bool(configured.get('task_limit') or configured.get('task_limits')) and not order_error,
            'message':'Falta decidir y confirmar el límite de tareas antes de iniciar las 50 corridas.' if configured.get('task_limit_status')!='confirmed' else 'Sigue el orden registrado y restaura antes de cada corrida.',
            'records':records,
            'completed_runs':completed,'completed_pairs':pairs,'failed_runs':failed,
            'recorded_runs':len(cell),'total_attempts':len(recorded),'duplicate_attempts':duplicates,
            'scenarios':list(groups.values()),'analysis':{key:describe(values) for key,values in metrics.items()},
            'note':'Cinco parejas por laboratorio. El primer intento queda registrado, incluso si falla. Los KPI se presentan por laboratorio; el agregado es descriptivo y no demuestra causalidad.'}
