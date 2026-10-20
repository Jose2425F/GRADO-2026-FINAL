"""Registro y análisis del estudio NovaFlow; no consulta la API al leerlo."""
from __future__ import annotations
import json
import math
from pathlib import Path
from random import Random
from statistics import mean, median, stdev

ROOT=Path(__file__).resolve().parents[2]
MONITOR=ROOT/'piloto_kali/prototipo/.lab/novaflow_estudio.json'
ACTIVE={'preparing','acceptance','pilot','formal','restoring'}


def public_status(path=MONITOR):
    try:
        if path.is_symlink() or path.stat().st_size>100_000:return {}
        data=json.loads(path.read_text())
        if not isinstance(data,dict):return {}
        from auditoria.dashboard import process_identity
        alive=type(data.get('pid')) is int and process_identity(data['pid'])==data.get('identity') and data.get('identity') is not None
        keys=['id','status','phase','pilot_runs','formal_runs','pairs_planned','runs_planned','known_cost_usd','held_usd','budget_usd','message','last_run_key','started_at','ended_at',
              'predecessor_id','prior_budget_commitment_usd','prior_known_cost_usd','prior_unknown_reserved_usd','known_cost_total_usd','budget_committed_usd','unknown_reserved_total_usd']
        result={k:data[k] for k in keys if k in data}
        if data.get('status')=='stopped' and data.get('message','').startswith('Detenido: interrupted_attempt_preserved;'):
            from tesis.interrupciones import additional_study_minimum
            recovery=additional_study_minimum(data.get('id'),path.parent.parent/'corridas')
            extra=recovery.get('additional_known_minimum_usd',0)
            known=result.get('known_cost_total_usd');committed=result.get('budget_committed_usd')
            if extra>0 and all(type(v) in {int,float} and math.isfinite(v) for v in [known,committed]) and known+extra<=committed:
                result.update(known_cost_total_usd=round(known+extra,8),unknown_reserved_total_usd=round(committed-known-extra,8),
                    accounting_recovery=recovery)
        result['analysis']={'metrics':{}}
        metrics=data.get('analysis',{}).get('metrics',{})
        for key in ['TRTO_percent','IDE_percent','ETV_ratio']:
            raw=metrics.get(key,{})
            if isinstance(raw,dict):
                result['analysis']['metrics'][key]={k:v for k,v in raw.items() if k in {'n','mean','median','sd','min','max','q1','q3'} and type(v) in {int,float} and math.isfinite(v)}
        result['active']=alive and data.get('status') in ACTIVE
        if data.get('status') in ACTIVE and not alive:result.update(status='interrupted',message='El conductor se interrumpió; no se reanudan ni reemplazan intentos automáticamente.')
        return result
    except (OSError,ValueError,TypeError,AttributeError):return {}


def orders(pairs, seed):
    if type(pairs) is not int or not 1<=pairs<=30:raise ValueError('De 1 a 30 parejas.')
    rng=Random(seed);first=['single']*((pairs+1)//2)+['multiagent']*(pairs//2);rng.shuffle(first)
    return [{'block':i+1,'order':[arm,'multiagent' if arm=='single' else 'single']} for i,arm in enumerate(first)]


def percentiles(values, fraction):
    data=sorted(values);position=(len(data)-1)*fraction;lower=int(position);upper=min(lower+1,len(data)-1)
    return data[lower]+(data[upper]-data[lower])*(position-lower)


def describe(values):
    values=[v for v in values if isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v)]
    if not values:return {'n':0}
    result={'n':len(values),'mean':mean(values),'median':median(values),'min':min(values),'max':max(values),
            'q1':percentiles(values,.25),'q3':percentiles(values,.75),'sd':stdev(values) if len(values)>1 else None}
    if len(values)>1:
        rng=Random(20261017);draws=[mean(rng.choices(values,k=len(values))) for _ in range(4000)]
        result['mean_ci95_percentile_bootstrap']=[percentiles(draws,.025),percentiles(draws,.975)]
    return result


def llm_pair_reasons(row):
    """Elegibilidad de la versión NovaFlow: un cierre técnico solo no acredita IA."""
    reasons=[]
    if row.get('status')!='complete' or row.get('tasks_valid')!=32:reasons.append('incomplete_audit')
    if row.get('evidence_valid') is not True:reasons.append('invalid_evidence')
    if row.get('usage_complete') is not True:reasons.append('unknown_usage')
    if row.get('fallbacks')!=0:reasons.append('fallback_or_unknown')
    if type(row.get('api_calls')) is not int or row['api_calls']<1:reasons.append('no_measured_API_calls')
    reviews=row.get('review_roles',[])
    expected_roles={'generalist'} if row.get('architecture')=='single' else {'network','credentials','applications','ipv6','fragmentation'}
    expected=len(expected_roles)
    if (not isinstance(reviews,list) or len(reviews)!=expected or row.get('accepted_reviews')!=expected
        or any(not isinstance(r,dict) or r.get('status')!='accepted' or not isinstance(r.get('role'),str) for r in reviews)
        or {r.get('role') for r in reviews if isinstance(r,dict)}!=expected_roles):
        reasons.append('missing_or_rejected_reviews')
    if type(row.get('known_tokens')) is not int or row['known_tokens']<=0:reasons.append('missing_tokens')
    return reasons


def paired_metrics(single, multi):
    reasons={arm:llm_pair_reasons(row) for arm,row in [('single',single),('multiagent',multi)]}
    context=[]
    if single.get('architecture')!='single' or multi.get('architecture')!='multiagent':context.append('wrong_architecture')
    for key in ['ground_truth_sha256','context_sha256','study_id']:
        if not isinstance(single.get(key),str) or not single[key] or single[key]!=multi.get(key):context.append('different_or_missing_'+key)
    models=single.get('reported_models')
    if not isinstance(models,list) or len(models)!=1 or not isinstance(models[0],str) or not models[0] or models!=multi.get('reported_models'):
        context.append('different_or_missing_model')
    eligible=not context and not any(reasons.values())
    result={'eligible_llm_pair':eligible,'exclusion_reasons':reasons,'context_errors':context}
    if context:return result
    # Las interrupciones no cuentan como auditorías rápidas. La detección conserva todos los intentos.
    if eligible:
        if all(type(r.get('elapsed_seconds')) in {int,float} and math.isfinite(r['elapsed_seconds']) and r['elapsed_seconds']>0 for r in [single,multi]):
            result['TRTO_percent']=100*(single['elapsed_seconds']-multi['elapsed_seconds'])/single['elapsed_seconds']
            result['time_difference_seconds']=single['elapsed_seconds']-multi['elapsed_seconds']
    if all(type(r.get('TP')) is int and type(r.get('FN')) is int for r in [single,multi]):
        recall=lambda r:r['TP']/(r['TP']+r['FN']) if r['TP']+r['FN'] else None
        a,b=recall(single),recall(multi)
        if a is not None and b is not None:result['recall_difference_pp']=100*(b-a)
        if single['TP']>0:result['IDE_percent']=100*(multi['TP']-single['TP'])/single['TP']
        if eligible and all(r['TP']>0 for r in [single,multi]):
            result['ETV_ratio']=(single['known_tokens']/single['TP'])/(multi['known_tokens']/multi['TP'])
    if eligible:
        result['token_difference']=single.get('known_tokens',0)-multi.get('known_tokens',0)
    return result


def settle_reservation(state, record, reserve=.20, tokens_limit=20_000):
    cost=record.get('cost_usd');tokens=record.get('known_tokens')
    measurable=(record.get('usage_complete') is True and type(cost) in {int,float} and math.isfinite(cost)
                and 0<=cost<=reserve and type(tokens) is int and 0<=tokens<=tokens_limit)
    if measurable:
        state.update(held_usd=round(state['held_usd']-reserve,8),known_cost_usd=round(state['known_cost_usd']+cost,8))
    return measurable


def budget_available(state,reserve=.20):
    values=[state.get('prior_budget_commitment_usd',0),state['known_cost_usd'],state['held_usd'],reserve,state['budget_usd']]
    return all(type(v) in {int,float} and math.isfinite(v) and v>=0 for v in values) and sum(values[:4])<=values[4]+1e-9


def budget_totals(state,rows):
    # El gasto conocido de una corrida incompleta está DENTRO de su reserva, no se suma dos veces.
    partial=sum(r.get('known_cost_lower_bound_usd',0) or 0 for r in rows if r.get('usage_complete') is not True)
    known=state.get('prior_known_cost_usd',0)+state['known_cost_usd']+partial
    committed=state.get('prior_budget_commitment_usd',0)+state['known_cost_usd']+state['held_usd']
    return {'known_cost_total_usd':round(known,8),'budget_committed_usd':round(committed,8),
            'unknown_reserved_total_usd':round(max(0,committed-known),8)}


def analyze(rows, phase):
    rows=[r for r in rows if r['phase']==phase];blocks={}
    for row in rows:
        arms=blocks.setdefault(row['block'],{})
        if row['architecture'] in arms:raise ValueError('duplicate_audit_slot; no sobrescribir ni mezclar posiciones')
        arms[row['architecture']]=row
    pairs=[]
    for block,arms in sorted(blocks.items()):
        if set(arms)=={'single','multiagent'}:pairs.append({'block':block,**paired_metrics(arms['single'],arms['multiagent'])})
    keys=['TRTO_percent','IDE_percent','ETV_ratio','recall_difference_pp','time_difference_seconds','token_difference']
    return {'phase':phase,'runs_started':len(rows),'pairs_observed':len(pairs),
            'pairs_eligible_llm':sum(p['eligible_llm_pair'] for p in pairs),'pairs':pairs,
            'metrics':{key:describe([p[key] for p in pairs if key in p]) for key in keys},
            'arms':{arm:{'attempts':sum(r['architecture']==arm for r in rows),
              'completed':sum(r['architecture']==arm and r.get('status')=='complete' for r in rows),
              'elapsed_seconds_completed':describe([r.get('elapsed_seconds') for r in rows if r['architecture']==arm and r.get('status')=='complete']),
              'known_tokens_all_attempts':describe([r.get('known_tokens',0) for r in rows if r['architecture']==arm])} for arm in ['single','multiagent']},
            'note':'Remuestreo por parejas; tareas repetidas no son réplicas independientes. Piloto y muestra separados. TRTO y ETV requieren auditorías completas, evidencia válida, uso medido, API enviada, cero respaldos y todas las revisiones aceptadas. IDE y recall conservan intentos con adjudicación disponible; no atribuyen por sí solos el resultado al LLM. Intervalos exploratorios condicionados al banco y las parejas observadas; con pocos bloques son inestables.'}
