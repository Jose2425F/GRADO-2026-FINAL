"""Evaluador reservado del banco integrado. Nunca se importa desde los prompts LLM."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path


def conditions_for(task):
    profile=task.action_profile
    if profile.startswith('hydra_'):return {profile.removeprefix('hydra_').removesuffix('_single_v1')+'_default_credential'}
    if profile=='http_application_dualstack_v2':return {'object_authorization','file_boundary','ipv6_authorization_gap'}
    if profile in {'ipv6_ra_route_v2','ipv6_ra_mtu_v2'}:return {'untrusted_router_advertisement'}
    if profile=='ipv6_na_neighbor_v2':return {'neighbor_override'}
    if profile=='ipv6_dad_na_v2':return {'dad_interference'}
    return set()


def score(directory: Path, truth_path: Path, *, engine=None, validator=None, bank_id="docker-empresa-1.0"):
    from auditoria.contracts import Task, TaskResult
    if validator is None:
        from laboratorio_empresa import validation_for
        validator=validation_for
    if engine is None:
        from auditoria import empresa_agent
        engine=empresa_agent
    raw=truth_path.read_bytes();truth=json.loads(raw)
    if truth.get('bank')!=bank_id:raise ValueError('Referencia de otro banco.')
    entries=truth.get('entries')
    if not isinstance(entries,list) or not entries or len(entries)>128:raise ValueError('Referencia inválida.')
    reference={}
    for entry in entries:
        if not isinstance(entry,dict) or type(entry.get('present')) is not bool or not all(isinstance(entry.get(k),str) for k in ['asset_id','defect_key']):raise ValueError('Referencia inválida.')
        key=(entry['asset_id'],entry['defect_key'])
        if key in reference:raise ValueError('Referencia duplicada.')
        reference[key]=entry['present']
    tasks=[Task.model_validate(t) for t in json.loads((directory/'plan.json').read_text())]
    if any(t.target not in engine.targets() for t in tasks):raise ValueError('Objetivos de otro banco.')
    report=json.loads((directory/'report.json').read_text());results={r['task_id']:TaskResult.model_validate(r) for r in report.get('tasks',[])}
    checked=set();detected=set();valid=True;functional=[]
    for task in tasks:
        result=results.get(task.task_id)
        if not result or result.status.value not in {'completed','completed_no_findings'}:
            functional.append({'task_id':task.task_id,'valid':False});continue
        record,findings=validator(directory,task,result)
        accepted=record.get('evidence_integrity',{}).get('valid') is True and (task.action_profile=='nmap_tcp_services_v1' or record.get('independent_confirmation') is True)
        functional.append({'task_id':task.task_id,'valid':accepted})
        if not accepted:valid=False;continue
        checked.update((task.target.asset_id,c) for c in conditions_for(task))
        detected.update((f['asset_id'],f['defect_key']) for f in findings)
    present={k for k,v in reference.items() if v};absent=set(reference)-present
    return {'ground_truth_sha256':hashlib.sha256(raw).hexdigest(),'bank':truth['bank'],
        'TP':len(present & detected),'FP':len(detected-present),'FN':len(present-detected),
        'TN':len((absent & checked)-detected),'unknown_negative_controls':len(absent-checked),
        'negative_conditions_total':len(absent),
        'intentional_budget_omissions':sum(r.status.value=='skipped' and r.reason_code=='task_budget_not_selected' for r in results.values()),
        'unscored_findings':len(detected-set(reference)), 'evidence_valid':valid,
        'tasks_checked':len(functional),'tasks_valid':sum(v['valid'] for v in functional),
        'acceptance_passed':bool(tasks) and all(v['valid'] for v in functional) and detected==present and absent<=checked,
        'note':'Evaluación del banco reservado; no se envía al modelo. FN incluye positivos no detectados, incluso si su tarea no fue seleccionada. TN sólo incluye negativos comprobados; los no examinados se registran aparte. Los candidatos CVE no cuentan como TP.'}
