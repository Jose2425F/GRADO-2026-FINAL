"""Recuperar mínimos medidos de una corrida interrumpida, sin API ni escrituras."""
from __future__ import annotations
import hashlib
import json
import math
import re
import sqlite3
from contextlib import closing
from pathlib import Path


def recover_usage(slot: Path):
    databases=list(slot.glob('*/events.sqlite3'))
    if len(databases)!=1 or databases[0].is_symlink():return {}
    database=databases[0]
    try:
        if database.stat().st_size>128*1024*1024:return {}
        with closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True)) as connection:
            rows=connection.execute('select event_id,component,kind,payload_json from events order by monotonic_ns limit 20001').fetchall()
        if len(rows)>20000:return {}
        calls=[];seen=set();starts=set();finishes=set();terminals=0;decisions=0;planning_starts=0;fallbacks=0
        for event_id,component,kind,raw in rows:
            if len(raw)>262144:return {}
            value=json.loads(raw)
            if not isinstance(value,dict):return {}
            if kind=='task_terminal':terminals+=1
            if component!='llm':continue
            request_id=value.get('client_request_id')
            if kind in {'api_request_started','api_request_finished'} and isinstance(request_id,str):
                (starts if kind=='api_request_started' else finishes).add(request_id)
            if kind=='request_started':planning_starts+=1
            if kind!='decision':continue
            decisions+=1;fallbacks+=value.get('status')=='fallback'
            if value.get('generation_sent') is not True:continue
            response_id=value.get('response_id')
            key=response_id if isinstance(response_id,str) and response_id else event_id
            if key in seen:continue
            seen.add(key);calls.append(value)
        fields=['input_tokens','provider_output_tokens','cached_tokens','cache_write_tokens','total_tokens']
        valid=[c for c in calls if all(type(c.get(k)) is int and 0<=c[k]<=1000000000 for k in fields)
               and c['cached_tokens']+c['cache_write_tokens']<=c['input_tokens']
               and c['total_tokens']==c['input_tokens']+c['provider_output_tokens']]
        from auditoria.openai_provider import estimated_cost
        price=estimated_cost(valid,complete=False)
        return {'known_tokens':sum(c['total_tokens'] for c in valid),'cost_usd':None,'usage_complete':False,
            'known_cost_lower_bound_usd':price['known_cost_estimate_usd'],'api_calls':len(calls),
            'closed_generations_with_usage':len(valid),'generations_without_usage':len(calls)-len(valid),
            'pending_transport_requests':len(starts-finishes),'pending_planning_requests':max(0,planning_starts-decisions),
            'fallbacks':fallbacks,'task_terminal_events':terminals,'accounting_source':'closed_decisions_in_sqlite',
            'events_sha256':hashlib.sha256(database.read_bytes()).hexdigest(),
            'accounting_note':'Mínimo de respuestas registradas. Falta cierre del informe; no acredita uso total ni libera la reserva.'}
    except (OSError,ValueError,sqlite3.Error,TypeError):return {}


def additional_study_minimum(study_id, runs_root):
    """Complemento de presentación: conserva intactos monitor, reserva e intentos."""
    if not isinstance(study_id,str) or not re.fullmatch(r'estudio_novaflow_\d{8}T\d{6}',study_id):return {}
    folder=runs_root/'kpi_novaflow'/study_id;attempts=folder/'attempts.json'
    try:
        if folder.is_symlink() or attempts.is_symlink() or attempts.stat().st_size>1000000:return {}
        rows=json.loads(attempts.read_text())
        if not isinstance(rows,list) or len(rows)>100:return {}
        extra=0.;recovered=[];seen_slots=set()
        for row in rows:
            if not isinstance(row,dict) or row.get('status')!='interrupted':continue
            phase,arm,block=row.get('phase'),row.get('architecture'),row.get('block')
            if phase not in {'pilot','formal'} or arm not in {'single','multiagent'} or type(block) is not int or not 1<=block<=30:continue
            position=(phase,arm,block)
            if position in seen_slots:return {}
            seen_slots.add(position)
            slot=folder/phase/f'block_{block:02d}_{arm}'
            if slot.is_symlink() or not slot.resolve().is_relative_to(folder.resolve()) or list(slot.glob('*/report.json')):continue
            value=recover_usage(slot)
            if not value:continue
            prior=row.get('known_cost_lower_bound_usd') or 0
            if type(prior) not in {int,float} or not math.isfinite(prior) or prior<0:continue
            extra+=max(0,value['known_cost_lower_bound_usd']-prior)
            recovered.append({'block':block,'architecture':arm,'known_tokens':value['known_tokens'],
                'known_cost_lower_bound_usd':value['known_cost_lower_bound_usd']})
        return {'additional_known_minimum_usd':round(extra,8),'attempts':recovered}
    except (OSError,ValueError,TypeError):return {}
