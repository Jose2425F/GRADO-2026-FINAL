"""Proyecciones de evidencia para el panel, sin escritura ni invocaciones de IA."""
import re
from .llm_contexto import ACTION_NAMES
from .candidatos import correlate


def inventory_from_results(report, plan, technical):
    verified={t['id'] for t in technical if t.get('hash_matches') is True}
    task_by_id={t.get('task_id'):t for t in plan};items=[]
    for result in report.get('tasks',[]):
        task=task_by_id.get(result.get('task_id'),{})
        if task.get('action_profile')!='nmap_tcp_services_v1' or result.get('task_id') not in verified or result.get('status') not in {'completed','completed_no_findings'}:continue
        target=task.get('target',{});allowed=target.get('ports',[])
        services=[{k:s.get(k) for k in ['port','protocol','state','name','product','version']} for s in result.get('services',[]) if isinstance(s,dict) and s.get('port') in allowed and s.get('state')=='open']
        items.append({'asset':target.get('asset_id'),'address':target.get('address'),'host_state':'up',
                      'services':services,'ports':[{'port':s['port'],'state':'open'} for s in services]})
    return items


def candidates_for_view(report, plan, technical):
    # Recalcular desde las observaciones íntegras evita confiar en textos arbitrarios.
    if 'cve_candidates' not in report:return []
    verified={t['id'] for t in technical if t.get('hash_matches') is True}
    tasks={t.get('task_id'):t for t in plan};values=[]
    for result in report.get('tasks',[]):
        task=tasks.get(result.get('task_id'))
        if not task or result.get('task_id') not in verified or result.get('status') not in {'completed','completed_no_findings'}:continue
        target=task.get('target',{})
        for candidate in correlate(result.get('services',[])):
            if candidate['port'] not in target.get('ports',[]):continue
            values.append({**candidate,'address':target.get('address'),'task_id':result['task_id'],'evidence_ref':result.get('evidence_ref')})
    return values


def actions_for_view(payload, plan):
    values=payload.get('prioritized_actions',[])
    if not isinstance(values,list):return []
    assets=list(dict.fromkeys(t.get('target',{}).get('asset_id') for t in plan));out=[]
    for action in values[:3]:
        if not isinstance(action,dict) or action.get('action') not in ACTION_NAMES:continue
        alias=action.get('asset');match=re.fullmatch(r'a([0-9]{3,5})',alias) if isinstance(alias,str) else None
        if not match or int(match[1])>=len(assets):continue
        asset=assets[int(match[1])];refs=action.get('evidence_tasks')
        if not isinstance(refs,list) or not 1<=len(refs)<=8:continue
        addresses=[];valid=True
        for ref in refs:
            match=re.fullmatch(r't([0-9]{3,5})',ref) if isinstance(ref,str) else None
            if not match or int(match[1])>=len(plan):valid=False;break
            target=plan[int(match[1])].get('target',{})
            if target.get('asset_id')!=asset:valid=False;break
            if target.get('address') not in addresses:addresses.append(target.get('address'))
        if not valid:continue
        if any(not isinstance(action.get(k),str) or not 1<=len(action[k])<=250 or any(ord(c)<32 for c in action[k]) for k in ['why','verification']):continue
        out.append({'asset':alias,'addresses':addresses,'title':ACTION_NAMES[action['action']],
                    'why':action['why'],'verification':action['verification'],'evidence_tasks':refs})
    return out
