"""Diseño y análisis por laboratorio. Leer o preparar no inicia auditorías ni API."""
from __future__ import annotations
import hashlib
import json
import math
from random import Random
from statistics import mean
from tesis.estudio import orders,describe
from tesis.laboratorios import catalog

KEYS=['TRTO_percent','IDE_percent','ETV_ratio','recall_difference_pp']


def draft():
    labs=[{'id':'original','name':'NovaFlow · banco original','tasks':32},*catalog()]
    rng=Random(20261018);sequence=[]
    for lab in labs:
        for pair in orders(6,20261018+labs.index(lab)):
            sequence.append({'lab_id':lab['id'],'within_lab_pair':pair['block'],'order':pair['order'],'expected_tasks':lab['tasks']})
    rng.shuffle(sequence)
    for i,pair in enumerate(sequence,1):pair['block']=i
    return {'status':'draft_requires_acceptance_and_freeze','labs':labs,'formal_pairs':30,'formal_runs':60,
        'pilot_pairs':5,'pilot_runs':10,'tokens_per_run':60000,'budget_usd':20,
        'unit':'Una pareja de ejecuciones dentro del mismo laboratorio y configuración.',
        'order':sequence,'aggregation':'Primero indicadores por pareja y laboratorio; resumen macro de medias de laboratorio con igual peso.',
        'note':'Propuesta exploratoria: seis parejas por cada uno de cinco bancos. No es un cálculo de potencia ni certificación institucional. Las variantes reutilizan imágenes y motores; no representan cinco empresas reales independientes. No mezclar corridas históricas de otra versión.'}


def finite(value):return type(value) in {int,float} and math.isfinite(value)


def pair_metrics(a,b):
    values={}
    complete=all(r.get('status')=='complete' and type(r.get('expected_tasks')) is int and r.get('tasks_valid')==r['expected_tasks'] for r in [a,b])
    if complete and finite(a.get('seconds')) and finite(b.get('seconds')) and a['seconds']>0 and b['seconds']>0:
        values['TRTO_percent']=100*(a['seconds']-b['seconds'])/a['seconds']
    if all(type(r.get(k)) is int and r[k]>=0 for r in [a,b] for k in ['TP','FN']):
        if a['TP']>0:values['IDE_percent']=100*(b['TP']-a['TP'])/a['TP']
        if a['TP']+a['FN']>0 and b['TP']+b['FN']>0:
            values['recall_difference_pp']=100*(b['TP']/(b['TP']+b['FN'])-a['TP']/(a['TP']+a['FN']))
        if all(r.get('usage_complete') is True and r['TP']>0 and finite(r.get('known_tokens')) and r['known_tokens']>0 for r in [a,b]):
            values['ETV_ratio']=(a['known_tokens']/a['TP'])/(b['known_tokens']/b['TP'])
    return values


def analyze(rows):
    groups={};labs={};pairs=[];issues=[]
    for row in rows:
        lab=row['lab_id'];labs.setdefault(lab,[]).append(row)
        if type(row.get('pair')) is int and row['pair']>0:groups.setdefault((lab,row['pair']),[]).append(row)
    for (lab,block),attempts in sorted(groups.items()):
        arms={r['architecture']:r for r in attempts}
        if len(attempts)!=2 or set(arms)!={'single','multiagent'}:
            issues.append({'lab_id':lab,'pair':block,'reason':'missing_or_duplicate_attempts','attempts':len(attempts)});continue
        a,b=arms['single'],arms['multiagent']
        identity=['configuration_sha256','reference_sha256','model','token_budget','expected_tasks']
        if any(a.get(k) is None or a.get(k)!=b.get(k) for k in identity):
            issues.append({'lab_id':lab,'pair':block,'reason':'incompatible_configuration_or_reference','attempts':2});continue
        pairs.append({'lab_id':lab,'pair':block,**pair_metrics(a,b)})
    by_lab={lab:{'attempts':len(attempts),'completed':sum(r.get('status')=='complete' for r in attempts),
        'fallbacks':sum(r.get('fallbacks',0) or 0 for r in attempts),
        'metrics':{k:describe([p[k] for p in pairs if p['lab_id']==lab and k in p]) for k in KEYS}} for lab,attempts in labs.items()}
    macro={}
    for key in KEYS:
        available=[data['metrics'][key]['mean'] for data in by_lab.values() if data['metrics'][key]['n']]
        macro[key]={'labs_observed':len(available),'mean_of_lab_means':mean(available) if available else None,
            'pairs_observed':sum(key in p for p in pairs)}
    return {'classification':'exploratory','formal_study':False,'attempts':len(rows),'by_lab':by_lab,'pairs':pairs,'unpaired_or_incompatible':issues,'macro_metrics':macro,
      'note':'Todos los intentos permanecen. Fallos no cuentan como tiempos rápidos; detección conserva FN cuando hay adjudicación. Tokens desconocidos no se convierten en cero. Macro pondera igual los laboratorios disponibles; informar cuántos están representados. No sumar TP de referencias diferentes para afirmar una mejora global.'}


def read_rows(root):
    rows=[]
    for path in sorted(root.rglob('manifest.json')):
        if path.is_symlink():continue
        manifest=json.loads(path.read_text());scenario=manifest.get('scenario',{})
        if not scenario.get('id') or scenario.get('phase')!='practice':continue
        directory=path.parent
        if not (directory/'report.json').exists() or not (directory/'evaluation.json').exists():continue
        report=json.loads((directory/'report.json').read_text());evaluation=json.loads((directory/'evaluation.json').read_text());llm=report.get('llm',{})
        config={'scenario':{k:scenario.get(k) for k in ['id','version','source_sha256','images','fixture_sha256']},
            'source':manifest.get('source_sha256'),'adapter':manifest.get('adapter_sha256'),'extensions':manifest.get('extensions_sha256'),
            'llm':{k:llm.get('configuration',{}).get(k) for k in ['reasoning_effort','max_output_tokens','service_tier','review_max_output_tokens','review_timeout_seconds']}}
        timing=json.loads((directory.parent/'timing.json').read_text()) if (directory.parent/'timing.json').exists() else {}
        rows.append({'lab_id':scenario['id'],'pair':scenario.get('pair',0),'architecture':report.get('architecture'),
            'status':report.get('status'),'seconds':timing.get('elapsed_seconds',report.get('metrics',{}).get('elapsed_seconds')),
            'expected_tasks':scenario.get('tasks'),'tasks_valid':evaluation.get('tasks_valid'),
            'TP':evaluation.get('TP') if evaluation.get('evidence_valid') is True else 0,
            'FN':evaluation.get('FN') if evaluation.get('evidence_valid') is True else (evaluation.get('TP',0)+evaluation.get('FN',0)),
            'known_tokens':llm.get('known_tokens'),'usage_complete':llm.get('usage_complete'),
            'fallbacks':llm.get('fallbacks'),'model':llm.get('model'),'token_budget':llm.get('budget'),
            'configuration_sha256':hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest(),
            'reference_sha256':evaluation.get('ground_truth_sha256'),'run':str(directory)})
    return rows
