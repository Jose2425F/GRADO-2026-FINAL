#!/usr/bin/env python3
"""Piloto y estudio emparejado NovaFlow. Sin --ejecutar no hace tráfico ni API."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import math
import os
import signal
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError, HTTPError

ROOT=Path(__file__).resolve().parents[1]
PILOT=ROOT/'piloto_kali/prototipo';PYTHON=PILOT/'.venv/bin/python'
sys.path[:0]=[str(ROOT/'scripts'),str(PILOT/'src')]
from tesis.estudio import MONITOR, orders, analyze, settle_reservation, budget_available, budget_totals, llm_pair_reasons
from tesis.presupuesto import DEFAULT_AUDIT_TOKENS
from auditoria.dashboard import process_identity
from auditoria.openai_provider import load_openai_config, PRICING
from auditoria import lab_empresa as lab
from preparar_cierre_tesis import fingerprint

FAULT_BITS=(1<<7)|(1<<14)
TOKEN_LIMIT=DEFAULT_AUDIT_TOKENS
RUN_RESERVE=round(TOKEN_LIMIT*max(PRICING[k] for k in ['input_per_million','cached_per_million','cache_write_per_million','output_per_million'])/1_000_000,8)


def now():return datetime.now(timezone.utc).isoformat()

def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n');tmp.chmod(0o600);tmp.replace(path)


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def code_identity():
    return {'auditor_and_extensions':fingerprint(),'driver':digest(Path(__file__)),
            'analysis':digest(ROOT/'scripts/tesis/estudio.py'),'bank':lab.source_hash()}


def comparison_context(protocol):
    """Identidad completa; cambios del conductor o entorno requieren otro contexto."""
    value={'sources':protocol['code_identity'],**{k:protocol.get(k) for k in ['images','ground_truth_sha256','model','environment',
        'tokens_per_run','expert_mode','specialist_prompt_version','review_max_output_tokens','review_timeout_seconds']}}
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def check_kernel():
    if int(Path('/proc/sys/kernel/tainted').read_text())&FAULT_BITS:raise ValueError('kernel_failure; recuperar Kali; no se reemplaza el intento')


def image_identity():
    names=sorted({name for _,_,members in lab.NETWORKS.values() for name in members})
    raw=subprocess.run(['docker','inspect','--format','{{.Name}} {{.Image}}',*names],capture_output=True,text=True,check=True,timeout=20).stdout
    return dict(line.strip('/').split() for line in raw.splitlines())


def guarded(command, log, max_seconds):
    with log.open('ab') as output:
        log.chmod(0o600)
        child=subprocess.Popen(command,cwd=ROOT,stdout=output,stderr=output,start_new_session=True)
        started=time.monotonic()
        try:
            while child.poll() is None:
                check_kernel()
                if time.monotonic()-started>max_seconds:raise ValueError('controller_timeout')
                time.sleep(.25)
            return child.returncode
        finally:
            if child.poll() is None:
                from tesis.procesos import terminate_group
                terminate_group(child)


def ensure_identity(protocol):
    check_kernel()
    if code_identity()!=protocol['code_identity']:raise ValueError('source_changed; detener y preparar otra versión')
    if image_identity()!=protocol['images']:raise ValueError('images_changed; detener y preparar otro banco')
    if digest(labroot/'ground_truth.json')!=protocol['ground_truth_sha256']:raise ValueError('reference_changed')
    config=load_openai_config(PILOT/'.lab')
    if {'model':config.model,'reasoning_effort':config.reasoning_effort,'max_output_tokens':config.max_output_tokens}!=protocol['model']:raise ValueError('provider_configuration_changed')


def restore(protocol,log):
    ensure_identity(protocol)
    command=['docker','compose','--env-file',str(labroot/'lab.env'),'-f',str(lab.COMPOSE),'up','-d','--no-build','--force-recreate']
    if guarded(command,log,180)!=0:raise ValueError('restore_failed')
    ensure_identity(protocol)
    wait_preflight(labroot,log)


def wait_preflight(root,log=None,*,attempts=10):
    """Esperar al arranque HTTP; no repetir auditorías ni tolerar un alcance inválido."""
    for attempt in range(1,attempts+1):
        check_kernel()
        try:return lab.preflight(root)
        except HTTPError:raise
        except (URLError,ConnectionError,TimeoutError) as exc:
            if log:
                with log.open('a') as stream:stream.write(json.dumps({'event':'readiness_transport_retry','check':attempt,'error_type':type(exc).__name__,'at':now()})+'\n')
            if attempt==attempts:raise ValueError('readiness_transport_unavailable; auditoría siguiente no iniciada') from None
            time.sleep(1)


def load_continuation():
    """Continuar solo un piloto detenido entre corridas, conservando su protocolo original."""
    old=json.loads(MONITOR.read_text());name=old.get('id','')
    if not re.fullmatch(r'estudio_novaflow_\d{8}T\d{6}',name):raise ValueError('Identificador de estudio inválido')
    if (old.get('status')!='stopped' or old.get('phase')!='pilot' or old.get('formal_runs')!=0
        or old.get('held_usd')!=0 or old.get('message') not in {'Detenido: URLError','Detenido: readiness_transport_unavailable; auditoría siguiente no iniciada'}):
        raise ValueError('El estado requiere revisión; solo se continúa el corte de disponibilidad entre corridas piloto')
    folder=PILOT/'corridas/kpi_novaflow'/name
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Cohorte no disponible')
    # Una continuación anterior nunca sobrescribe el protocolo inicial ni su huella.
    protocol_path=folder/old.get('protocol_file','protocol.json')
    if protocol_path.parent!=folder or protocol_path.is_symlink():raise ValueError('Protocolo de continuación inválido')
    protocol=json.loads(protocol_path.read_text());current=code_identity()
    if any(current.get(k)!=protocol['code_identity'].get(k) for k in current if k!='driver'):
        raise ValueError('Cambió el auditor, análisis o banco: no continuar esta cohorte')
    if image_identity()!=protocol['images']:raise ValueError('Cambió la imagen del banco')
    if digest(labroot/'ground_truth.json')!=protocol['ground_truth_sha256']:raise ValueError('Cambió la referencia')
    rows=json.loads((folder/'attempts.json').read_text())
    if not rows or old.get('pilot_runs')!=len(rows):raise ValueError('Registro de intentos inconsistente')
    expected=[(b['block'],a) for b in protocol['pilot_order'] for a in b['order']]
    actual=[(r.get('block'),r.get('architecture')) for r in rows]
    if actual!=expected[:len(rows)]:raise ValueError('Los intentos no siguen el orden predefinido')
    if any(r.get('phase')!='pilot' or r.get('status')!='complete' or not r.get('usage_complete') or r.get('tasks_valid')!=32
           or type(r.get('cost_usd')) not in {int,float} or not 0<=r['cost_usd']<=RUN_RESERVE for r in rows):
        raise ValueError('No se repiten ni reemplazan intentos fallidos o con uso desconocido')
    if abs(sum(r['cost_usd'] for r in rows)-old['known_cost_usd'])>1e-7:raise ValueError('Gasto inconsistente')
    if not budget_available(old,RUN_RESERVE):raise ValueError('No queda reserva')
    for row in rows:
        slot=folder/'pilot'/f"block_{row['block']:02d}_{row['architecture']}"
        reports=list(slot.glob('*/report.json'))
        if len(reports)!=1 or reports[0].parent.relative_to(PILOT/'corridas').as_posix()!=row.get('run_key'):
            raise ValueError('No se localizó el intento original; no continuar')
        if json.loads(reports[0].read_text()).get('llm',{}).get('cost_estimate_usd')!=row['cost_usd']:
            raise ValueError('El costo no coincide con el informe original')
    if (folder/'formal_design.json').exists():raise ValueError('La muestra ya tiene diseño congelado; revisión separada')
    amended={**protocol,'code_identity':current,'continued_at':now(),'previous_protocol_sha256':digest(protocol_path),
             'previous_stop':{k:old.get(k) for k in ['message','ended_at','pilot_runs','formal_runs','known_cost_usd']},
             'amendment':'Espera de disponibilidad HTTP tras restaurar, fuera del tiempo medido. Auditor, imágenes, referencia, modelo, presupuestos y orden sin cambios. Continúa la posición no iniciada; conserva la corrida piloto previa.'}
    return folder,amended,old,rows


def load_predecessor(*, new_images=False):
    """Nueva versión tras un fallo piloto: no repite posiciones dentro de la cohorte antigua."""
    old=json.loads(MONITOR.read_text());name=old.get('id','')
    if not re.fullmatch(r'estudio_novaflow_\d{8}T\d{6}',name):raise ValueError('Identificador previo inválido')
    usage_stop=old.get('message','').startswith('Detenido: unknown_usage_or_cost;')
    pilot_stop=old.get('message')=='Detenido: pilot_not_operational; revisar antes de congelar la muestra'
    interrupted_stop=old.get('message','').startswith('Detenido: interrupted_attempt_preserved;')
    if old.get('status')!='stopped' or old.get('phase')!='pilot' or old.get('formal_runs')!=0 or not (usage_stop or pilot_stop or interrupted_stop):
        raise ValueError('Nueva versión requiere un piloto detenido por uso desconocido, no operativo o interrumpido; no sustituye muestras formales')
    folder=PILOT/'corridas/kpi_novaflow'/name
    if folder.is_symlink() or not folder.is_dir():raise ValueError('Cohorte previa no disponible')
    protocol_path=folder/old.get('protocol_file','protocol.json')
    if protocol_path.parent!=folder or protocol_path.is_symlink():raise ValueError('Protocolo previo inválido')
    protocol=json.loads(protocol_path.read_text())
    previous_reserve=protocol.get('run_reserve_usd')
    if type(previous_reserve) not in {int,float} or not math.isfinite(previous_reserve) or not 0<previous_reserve<=20:
        raise ValueError('Reserva histórica no disponible o inválida')
    if protocol['code_identity'].get('auditor_and_extensions')==code_identity().get('auditor_and_extensions'):
        raise ValueError('No cambió la versión del auditor; no repetir el piloto fallido')
    current_images=image_identity()
    if digest(labroot/'ground_truth.json')!=protocol['ground_truth_sha256']:
        raise ValueError('Referencia diferente: no reutilizar el estudio anterior')
    changed_images=current_images!=protocol['images']
    if changed_images and not new_images:
        raise ValueError('Banco o referencia diferente: revisar antes de abrir otra versión')
    if new_images and not changed_images:
        raise ValueError('No hay imágenes nuevas que registrar')
    config=load_openai_config(PILOT/'.lab')
    if protocol['model']!={'model':config.model,'reasoning_effort':config.reasoning_effort,'max_output_tokens':config.max_output_tokens}:
        raise ValueError('Modelo diferente al autorizado')
    rows=json.loads((folder/'attempts.json').read_text())
    expected=[(b['block'],a) for b in protocol['pilot_order'] for a in b['order']]
    if not rows or old.get('pilot_runs')!=len(rows) or [(r.get('block'),r.get('architecture')) for r in rows]!=expected[:len(rows)]:
        raise ValueError('Registro previo inconsistente')
    settled=0.;partial=0.;unknown=0;recovered=[]
    for row in rows:
        if row.get('phase')!='pilot':raise ValueError('No sustituir resultados formales')
        slot=folder/'pilot'/f"block_{row['block']:02d}_{row['architecture']}"
        reports=list(slot.glob('*/report.json'))
        if not reports and interrupted_stop and row.get('status')=='interrupted' and row.get('usage_complete') is False and row.get('cost_usd') is None:
            from tesis.interrupciones import recover_usage
            price_keys=['input_per_million','output_per_million','cached_per_million','cache_write_per_million','currency','service_tier']
            if any(protocol.get('pricing',{}).get(k)!=PRICING[k] for k in price_keys):raise ValueError('Tarifa de recuperación diferente al protocolo previo')
            value=recover_usage(slot)
            if not value or not 0<=value['known_cost_lower_bound_usd']<=previous_reserve:
                raise ValueError('No se pudo recuperar el mínimo del intento interrumpido; conservar la reserva y revisar')
            unknown+=1;partial+=value['known_cost_lower_bound_usd']
            recovered.append({'block':row['block'],'architecture':row['architecture'],**value})
            continue
        if len(reports)!=1 or reports[0].is_symlink() or reports[0].parent.relative_to(PILOT/'corridas').as_posix()!=row.get('run_key'):
            raise ValueError('Informe previo no disponible')
        llm=json.loads(reports[0].read_text()).get('llm',{})
        cost=llm.get('cost_estimate_usd');lower=llm.get('known_cost_estimate_usd')
        if llm.get('usage_complete') is not row.get('usage_complete') or cost!=row.get('cost_usd'):
            raise ValueError('Consumo previo no coincide con el informe')
        if type(lower) not in {int,float} or not math.isfinite(lower) or not 0<=lower<=previous_reserve:
            raise ValueError('Costo conocido previo inválido')
        if row.get('usage_complete') is True:
            if type(cost) not in {int,float} or not math.isfinite(cost) or not 0<=cost<=previous_reserve or abs(cost-lower)>1e-8:
                raise ValueError('Costo previo inválido')
            settled+=cost
        else:
            if cost is not None:raise ValueError('Uso incompleto con costo total declarado')
            unknown+=1;partial+=lower
    if (usage_stop and not unknown) or abs(settled-old['known_cost_usd'])>1e-7 or abs(unknown*previous_reserve-old['held_usd'])>1e-7:
        raise ValueError('Reservas previas inconsistentes')
    prior={k:old.get(k,0) for k in ['prior_budget_commitment_usd','prior_known_cost_usd','prior_unknown_reserved_usd']}
    if any(type(v) not in {int,float} or not math.isfinite(v) or v<0 for v in prior.values()) or abs(prior['prior_known_cost_usd']+prior['prior_unknown_reserved_usd']-prior['prior_budget_commitment_usd'])>1e-7:
        raise ValueError('Saldo heredado inválido')
    commitment=round(prior['prior_budget_commitment_usd']+settled+old['held_usd'],8)
    known=round(prior['prior_known_cost_usd']+settled+partial,8)
    carry={'predecessor_id':name,'prior_budget_commitment_usd':commitment,'prior_known_cost_usd':known,
           'prior_unknown_reserved_usd':round(commitment-known,8)}
    if old.get('budget_usd')!=20 or not budget_available({**carry,'known_cost_usd':0.,'held_usd':0.,'budget_usd':20},RUN_RESERVE):
        raise ValueError('Presupuesto global insuficiente')
    if any(p.is_symlink() for p in folder.rglob('*')):raise ValueError('La cohorte previa contiene enlaces')
    receipt={'id':name,'monitor':old,'files':{p.relative_to(folder).as_posix():digest(p) for p in folder.rglob('*') if p.is_file()},
        'interrupted_usage_recovery':recovered,
        'image_transition':{'changed':changed_images,'previous':protocol['images'],'current':current_images,
            'acceptance_required':True,'pool_with_predecessor':False}}
    return carry,receipt


def child_run(slot):
    from laboratorio_empresa import run_panel
    spec=json.loads((slot/'slot.json').read_text())
    started=time.monotonic();stamp=now()
    code=run_panel(spec['options'],slot,study_context=spec['membership'])
    save(slot/'timing.json',{'started_at':stamp,'ended_at':now(),'elapsed_seconds':time.monotonic()-started,
                           'boundary':'Desde entrada a run_panel hasta retorno tras persistir report, evaluation y eventos; restauración y arranque del proceso excluidos.'})
    return code


def summarize(slot,entry,code):
    reports=list(slot.glob('*/report.json'));record={**entry,'exit_code':code,'status':'interrupted','usage_complete':False,'known_tokens':0,'cost_usd':None}
    if len(reports)!=1:
        from tesis.interrupciones import recover_usage
        record.update(recover_usage(slot))
        databases=list(slot.glob('*/events.sqlite3'))
        if len(databases)==1:record['run_key']=databases[0].parent.relative_to(PILOT/'corridas').as_posix()
        return record
    directory=reports[0].parent;report=json.loads(reports[0].read_text());ev=json.loads((directory/'evaluation.json').read_text()) if (directory/'evaluation.json').exists() else {};llm=report.get('llm',{})
    timing=json.loads((slot/'timing.json').read_text()) if (slot/'timing.json').exists() else {}
    record.update(status=report['status'],run_key=directory.relative_to(PILOT/'corridas').as_posix(),
       elapsed_seconds=timing.get('elapsed_seconds'),execution_seconds=report['metrics'].get('execution_seconds'),
       review_seconds=report['metrics'].get('expert_review_seconds'),known_tokens=llm.get('known_tokens',0),usage_complete=llm.get('usage_complete') is True,
       cost_usd=llm.get('cost_estimate_usd'),known_cost_lower_bound_usd=llm.get('known_cost_estimate_usd'),fallbacks=llm.get('fallbacks'),api_calls=sum(c.get('generation_sent') is True for c in llm.get('calls',[])),
       reported_models=llm.get('configuration',{}).get('reported_models',[]),
       accepted_reviews=sum(r.get('status')=='accepted' for r in llm.get('specialist_reviews',[])),
       review_roles=[{'role':r.get('role'),'status':r.get('status'),'reason':r.get('reason')} for r in llm.get('specialist_reviews',[])],
       provider_reasons=sorted({str(c['reason']) for c in llm.get('calls',[]) if c.get('reason')}),
       **{k:ev.get(k) for k in ['TP','FP','FN','TN','tasks_valid','evidence_valid','unknown_negative_controls','ground_truth_sha256']})
    # Referencias inválidas o incompletas nunca acreditan TP/TN; no se descarta el intento.
    if ev.get('evidence_valid') is not True:
        reference=json.loads((labroot/'ground_truth.json').read_text());record.update(TP=0,FN=sum(e['present'] for e in reference['entries']),TN=0,adjudication_unavailable=True)
    return record


def report_public(folder,protocol,state,rows):
    state.update(budget_totals(state,rows))
    public=ROOT/'docs'/folder.name;public.mkdir(parents=True,exist_ok=True)
    save(folder/'attempts.json',rows)
    analyses={phase:analyze(rows,phase) for phase in ['pilot','formal']}
    for phase,value in analyses.items():save(folder/(phase+'_analysis.json'),value)
    state['analysis']=analyses['formal']
    headers=['# Estudio NovaFlow con API','',f"Estado: **{state['status']}**. {state['message']}",'',
      f"Piloto: 3 parejas / 6 corridas. Evaluación predefinida: {protocol['planned_formal_pairs']} parejas / {2*protocol['planned_formal_pairs']} corridas. Mismo banco, modelo y {protocol['tokens_per_run']:,} tokens por auditoría. Tope conjunto USD 20. Reserva por corrida USD {protocol['run_reserve_usd']:.2f}; si no queda saldo se detiene, aunque falten posiciones.",
      '',f"Gasto conocido acumulado (mínimo estimado): USD {state['known_cost_total_usd']:.6f}. Comprometido, incluyendo reservas: USD {state['budget_committed_usd']:.6f} de USD 20. Diferencia aún reservada/no conciliada: USD {state['unknown_reserved_total_usd']:.6f}.",
      '', '| Fase | Pareja | Arquitectura | Estado | Segundos totales | Tokens conocidos | TP/FP/FN/TN | USD estimados |', '|---|---:|---|---|---:|---:|---|---:|']
    for r in rows:
        secs=f"{r['elapsed_seconds']:.3f}" if isinstance(r.get('elapsed_seconds'),(int,float)) else '—'
        price=f"{r['cost_usd']:.6f}" if isinstance(r.get('cost_usd'),(int,float)) else 'Desconocido'
        headers.append(f"| {r['phase']} | {r['block']} | {r['architecture']} | {r['status']} | {secs} | {r['known_tokens']} | {'/'.join(str(r.get(k,'—')) for k in ['TP','FP','FN','TN'])} | {price} |")
    headers+=['','El piloto no forma parte de la muestra final. Los intentos fallidos se conservan y no se reemplazan automáticamente. TRTO y ETV exigen un par completo con evidencia válida, API medida, cero respaldos y todas las revisiones aceptadas. IDE y recall conservan los intentos con adjudicación y no acreditan por sí solos una mejora atribuible al LLM. Los denominadores y las exclusiones se publican por indicador.',
      '', 'Los intervalos son exploratorios por bloques. Repetir el mismo banco no añade diversidad de vulnerabilidades. No se garantiza potencia estadística ni aceptación institucional.',
      '', 'Tarifa verificada: https://developers.openai.com/api/docs/models/gpt-6.1-sol',
      'Diseño emparejado: https://www.itl.nist.gov/div898/handbook/prc/section3/prc311.htm',
      'Tamaño muestral: https://www.itl.nist.gov/div898/handbook/prc/section2/prc222.htm',
      '', 'Los informes técnicos y ejecutivos de cada corrida están disponibles en el historial del panel. El registro privado preserva protocolo, manifiestos, trazas y evidencia.']
    if protocol.get('previous_stop'):
        previous=protocol['previous_stop']
        headers+=['','## Incidencia y continuación conservadas','',f"{previous.get('ended_at')}: {previous.get('message')}. Había {previous.get('pilot_runs')} corrida piloto registrada y {previous.get('formal_runs')} formales. Costo conocido: USD {previous.get('known_cost_usd')}. La continuación conserva esos resultados; añade espera de disponibilidad antes del siguiente intento, fuera del tiempo de auditoría. El protocolo original y el estado detenido permanecen intactos en el registro privado."]
    if protocol.get('predecessor'):
        previous=protocol['predecessor']
        headers+=['','## Nueva versión y presupuesto compartido','',f"Cohorte previa: [{previous['id']}](../{previous['id']}/LEEME.md). Sus intentos, incluidos los fallos, se conservan íntegros como antecedentes. No se mezclan con este piloto ni la muestra formal. Se heredan USD {state['prior_budget_commitment_usd']:.6f} comprometidos dentro del mismo tope de USD 20. Se mantiene la reserva del consumo desconocido; no se ha recuperado ni declarado su costo total.",
                  '',protocol['amendment']]
    (public/'LEEME.md').write_text('\n'.join(headers)+'\n')
    save(public/'resumen.json',{**{k:v for k,v in state.items() if k not in ['pid','identity']},'attempts':rows,
         'pilot':analyses['pilot'],'formal':analyses['formal']})
    save(folder/'state.json',state);save(MONITOR,state)


labroot=PILOT/'.lab-empresa'


def pilot_operational(rows):
    expected={(block,arm) for block in range(1,4) for arm in ['single','multiagent']}
    return (len(rows)==6 and {(r.get('block'),r.get('architecture')) for r in rows}==expected
        and all(r.get('phase')=='pilot' and not llm_pair_reasons(r) for r in rows)
        and analyze(rows,'pilot')['pairs_eligible_llm']==3)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ejecutar',action='store_true');parser.add_argument('--solo-piloto',action='store_true')
    parser.add_argument('--parejas-formales',type=int,default=30,help='De 1 a 30 parejas, fijadas antes del piloto por recursos; no cambia cohortes anteriores ni permite seleccionar por resultados.')
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--continuar',action='store_true',help='Continuar explícitamente un piloto detenido entre corridas por disponibilidad HTTP; nunca repetir intentos.')
    mode.add_argument('--nueva-version',action='store_true',help='Nuevo piloto tras corregir la versión; conserva cohorte y reserva anteriores bajo el mismo USD 20.')
    parser.add_argument('--nuevas-imagenes',action='store_true',help='Solo con --nueva-version: registrar nuevas imágenes, conservar las anteriores como otra versión y exigir aceptación sin IA antes del piloto.')
    parser.add_argument('--slot',type=Path,help=argparse.SUPPRESS);args=parser.parse_args()
    if args.slot:return child_run(args.slot)
    if not 1<=args.parejas_formales<=30:parser.error('--parejas-formales debe estar entre 1 y 30')
    if args.nuevas_imagenes and not args.nueva_version:parser.error('--nuevas-imagenes requiere --nueva-version')
    if not args.ejecutar:
        print(f'Diseño: 6 corridas piloto separadas y {2*args.parejas_formales} de evaluación, {TOKEN_LIMIT} tokens/corrida, reserva USD {RUN_RESERVE:.2f}, tope global USD 20. Sin tráfico ni API. --ejecutar comienza; --solo-piloto detiene antes de la muestra.');return 0
    check_kernel()
    if MONITOR.exists() and not (args.continuar or args.nueva_version):raise ValueError('Existe un estudio registrado; revisar su estado, no crear otro ni repetir fallos automáticamente')
    # Exclusión mutua entre conductores; el panel consulta MONITOR y bloquea operaciones paralelas.
    lockpath=MONITOR.with_suffix('.lock');lockpath.parent.mkdir(parents=True,exist_ok=True)
    lock=lockpath.open('a');lockpath.chmod(0o600)
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:raise ValueError('Hay otro estudio activo')
    from auditoria.dashboard import collect_state
    if any(r.get('status')=='running' for r in collect_state(PILOT/'corridas')['runs']):raise ValueError('Hay una auditoría activa')
    c=load_openai_config(PILOT/'.lab')
    if (c.model,c.reasoning_effort,c.max_output_tokens)!=('gpt-6.1-sol','low',2048):raise ValueError('Configuración fuera del diseño')
    wait_preflight(labroot)
    continuing=load_continuation() if args.continuar else None
    predecessor=load_predecessor(new_images=True) if args.nuevas_imagenes else load_predecessor() if args.nueva_version else None
    name='estudio_novaflow_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    folder=continuing[0] if continuing else PILOT/'corridas/kpi_novaflow'/name
    if not continuing:folder.mkdir(parents=True,exist_ok=False)
    rows=[];protocol={'id':name,'created_at':now(),'bank':'docker-empresa-1.0','code_identity':code_identity(),
      'images':image_identity(),'ground_truth_sha256':digest(labroot/'ground_truth.json'),
      'model':{'model':c.model,'reasoning_effort':c.reasoning_effort,'max_output_tokens':c.max_output_tokens},
      'tokens_per_run':TOKEN_LIMIT,'budget_usd':20,'run_reserve_usd':RUN_RESERVE,
      'specialist_prompt_version':'specialist-review-4','review_max_output_tokens':2048,'review_timeout_seconds':60,
      'pricing':{**PRICING,'verified_on':'2026-10-17'},'expert_mode':True,
      'environment':{'kernel':os.uname().release,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'logical_cpus':os.cpu_count(),'tainted_at_freeze':int(Path('/proc/sys/kernel/tainted').read_text()),
          'memory_kib':int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])},
      'pilot_order':orders(3,20261017),'formal_order_draft':orders(args.parejas_formales,20261018),
      'planned_formal_pairs':args.parejas_formales,'primary_outcome':'paired_recall_difference','exploratory':True,
      'time_boundary':'run_panel entry through persisted final artifacts; excludes restoration and process startup',
      'stop_rules':['kernel_fault','source_images_or_reference_changed','unknown_usage_or_cost','budget_reservation_denied','provider_failure','restoration_failed','interrupted_controller'],
      'no_automatic_replacements':True,'pilot_excluded_from_formal':True,
      'note':'Tamaño fijado antes del piloto por tiempo y presupuesto disponibles; no garantiza potencia ni aceptación institucional. Orden formal propuesto antes del piloto y congelado antes de observar la muestra final.'}
    if continuing:
        folder,protocol,previous,rows=continuing;name=protocol['id']
    if predecessor:
        carry,receipt=predecessor
        save(folder/'predecessor_receipt.json',receipt)
        protocol.update(predecessor={'id':carry['predecessor_id'],'receipt_sha256':digest(folder/'predecessor_receipt.json'),**carry},
            amendment=f'Nueva versión con {TOKEN_LIMIT} tokens para ambas arquitecturas (60 % planificación, 40 % revisión). Revisión specialist-review-4: límites de texto y referencias por activo expresados en el esquema, salida máxima 2048 y rechazos específicos, sin relajar validadores. Espera hasta 60 s y plazo restante, cero reintentos. Recuperación de mínimos de uso desde respuestas cerradas cuando falta el informe, sin liberar reservas desconocidas. Reserva por intento USD {RUN_RESERVE:.2f}, mismo tope global USD 20 con gasto y reservas previos. Banco, referencia y modelo iguales. Piloto nuevo explícito; no sustituye ni elimina intentos anteriores.')
        if args.nuevas_imagenes:
            protocol['amendment']=protocol['amendment'].replace('Banco, referencia y modelo iguales.',
                'Imágenes nuevas registradas en predecessor_receipt.json; referencia y modelo iguales. La aceptación funcional se repite antes de enviar API y no se combinan resultados entre las dos versiones de imágenes.')
    protocol_file='protocol-continuation-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json' if continuing else 'protocol.json'
    save(folder/protocol_file,protocol);phash=digest(folder/protocol_file)
    state={'id':name,'status':'preparing','phase':'acceptance','pid':os.getpid(),'identity':process_identity(os.getpid()),'started_at':now(),
           'pilot_runs':0,'formal_runs':0,'pairs_planned':protocol['planned_formal_pairs'],'runs_planned':2*protocol['planned_formal_pairs'],'known_cost_usd':0.,'held_usd':0.,'budget_usd':20,'message':'Aceptación del banco antes de enviar API.'}
    state['protocol_file']=protocol_file
    if predecessor:state.update(predecessor[0])
    if continuing:
        save(folder/('state-before-continuation-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json'),previous)
        state.update(started_at=previous['started_at'],pilot_runs=previous['pilot_runs'],known_cost_usd=previous['known_cost_usd'],
                     phase='pilot',message='Continuación explícita: se conserva el piloto anterior y su gasto; no se repite.')
        state.update({k:previous[k] for k in ['predecessor_id','prior_budget_commitment_usd','prior_known_cost_usd','prior_unknown_reserved_usd'] if k in previous})
    report_public(folder,protocol,state,rows)
    try:
        # Aceptación sin IA de esta versión; nunca cuenta como piloto o corrida formal.
        if not continuing:
            acceptance=folder/'acceptance';acceptance.mkdir()
            membership={'study_id':name,'phase':'acceptance','block':0,'protocol_sha256':phash}
            save(acceptance/'slot.json',{'options':{'authorization':'LAB-PROPIO','scope':'empresa','architecture':'single','ia':'none','tokens':0,'mode':'live'},'membership':membership})
            state.update(status='acceptance');report_public(folder,protocol,state,rows)
            code=guarded([str(PYTHON),str(Path(__file__).resolve()),'--slot',str(acceptance)],folder/'controller.log',2700)
            evaluations=list(acceptance.glob('*/evaluation.json'))
            if code or len(evaluations)!=1 or not json.loads(evaluations[0].read_text()).get('acceptance_passed'):raise ValueError('bank_acceptance_failed; no API enviada')
            save(folder/'acceptance.json',json.loads(evaluations[0].read_text()))
        elif not json.loads((folder/'acceptance.json').read_text()).get('acceptance_passed'):
            raise ValueError('No existe aceptación previa válida')
        for phase,order in [('pilot',protocol['pilot_order']),('formal',protocol['formal_order_draft'])]:
            if phase=='formal':
                pilot=analyze(rows,'pilot')
                if not pilot_operational(rows):raise ValueError('pilot_not_operational; revisar antes de congelar la muestra')
                if args.solo_piloto:break
                save(folder/'formal_design.json',{'frozen_at':now(),'pairs':protocol['planned_formal_pairs'],'runs':2*protocol['planned_formal_pairs'],'order':order,'protocol_sha256':phash,'pilot_summary':pilot,
                    'selection_rule':'Número predefinido antes del piloto por tiempo y presupuesto; descripción exploratoria, sin seleccionar por significación ni signo favorable.'})
            for block in order:
                for architecture in block['order']:
                    if any(r['phase']==phase and r['block']==block['block'] and r['architecture']==architecture for r in rows):continue
                    state.update(status='restoring',phase=phase,message=f"Restaurando antes de {phase}, pareja {block['block']}, {architecture}.");report_public(folder,protocol,state,rows)
                    restore(protocol,folder/'controller.log')
                    if not budget_available(state,RUN_RESERVE):raise ValueError('budget_reservation_denied')
                    entry={'phase':phase,'block':block['block'],'architecture':architecture,'started_at':now(),
                           'study_id':name,'protocol_sha256':phash,'context_sha256':comparison_context(protocol)}
                    slot=folder/phase/f"block_{block['block']:02d}_{architecture}";slot.mkdir(parents=True,exist_ok=False)
                    membership={'study_id':name,'phase':phase,'block':block['block'],'protocol_sha256':phash}
                    save(slot/'slot.json',{'options':{'authorization':'LAB-PROPIO','scope':'empresa','architecture':architecture,'ia':'openai','tokens':TOKEN_LIMIT,'mode':'live','expert_mode':True},'membership':membership})
                    save(slot/'panel_job.json',{'name':f"NovaFlow · {phase} · pareja {block['block']:02d} · {architecture}"})
                    state.update(status=phase,message=f"Ejecutando {phase}, pareja {block['block']}, {architecture}.",held_usd=state['held_usd']+RUN_RESERVE)
                    rows.append({**entry,'status':'running','usage_complete':False,'known_tokens':0,'cost_usd':None});state[phase+'_runs']+=1
                    report_public(folder,protocol,state,rows)
                    interruption=None
                    try:code=guarded([str(PYTHON),str(Path(__file__).resolve()),'--slot',str(slot)],folder/'controller.log',2700)
                    except (Exception,KeyboardInterrupt) as exc:code=130;interruption=exc
                    record=summarize(slot,entry,code);rows[-1]=record
                    state['last_run_key']=record.get('run_key')
                    measurable=settle_reservation(state,record,RUN_RESERVE,TOKEN_LIMIT)
                    report_public(folder,protocol,state,rows)
                    if interruption is not None:
                        reason=str(interruption).split(';',1)[0] if isinstance(interruption,ValueError) else ''
                        raise ValueError('interrupted_attempt_preserved; '+(reason if reason in {'kernel_failure','controller_timeout'} else type(interruption).__name__))
                    if not measurable:raise ValueError('unknown_usage_or_cost; reserva retenida, intento conservado, sin reintento')
                    ensure_identity(protocol)
                    if record.get('reported_models')!=[c.model]:raise ValueError('reported_model_changed')
                    if any('http_' in reason or 'provider' in reason for reason in record.get('provider_reasons',[])):raise ValueError('provider_failure')
        state.update(status='pilot_complete' if args.solo_piloto else 'complete',message='Piloto completado; muestra sin iniciar.' if args.solo_piloto else 'Finalizaron las posiciones previstas; revisar denominadores e incidencias, sin reemplazar intentos.')
    except (Exception,KeyboardInterrupt) as exc:
        # Nunca publicar cuerpos HTTP, logs o configuración privada.
        reason=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
        state.update(status='stopped',message='Detenido: '+reason)
    finally:
        state['ended_at']=now();report_public(folder,protocol,state,rows)
        print(json.dumps({'id':name,'status':state['status'],'pilot_runs':state['pilot_runs'],'formal_runs':state['formal_runs'],'known_cost_usd':state['known_cost_usd'],'held_usd':state['held_usd'],'message':state['message']},ensure_ascii=False),flush=True)
        lock.close()
    return 0 if state['status'] in {'pilot_complete','complete'} else 3


if __name__=='__main__':raise SystemExit(main())
