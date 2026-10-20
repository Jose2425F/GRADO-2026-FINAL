#!/usr/bin/env python3
"""Comprobación local por defecto. --ejecutar inicia API y el estudio autorizado."""
import argparse
import json
import os
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from auditoria.cli import source_fingerprint
from auditoria.lab_v2 import preflight, verify_certificate
from auditoria.openai_provider import load_openai_config

ROOT=Path(__file__).resolve().parents[1]
PILOT=ROOT/'piloto_kali/prototipo'
PLAN=ROOT/'docs/plan-evaluacion-empresa-2026-10-14/protocolo.json'
STATE=PLAN.parent/'ejecucion.json'
FAULT_BITS=(1<<7)|(1<<14)

def dump(path,value):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');temp.replace(path)

def check_local():
    plan=json.loads(PLAN.read_text())
    if plan['auditor_source_sha256']!=source_fingerprint():raise ValueError('Cambió la huella del auditor; preparar otro protocolo antes de ejecutar.')
    if int(Path('/proc/sys/kernel/tainted').read_text()) & FAULT_BITS:raise ValueError('El kernel registra fallo; recuperar la VM antes de ejecutar.')
    c=load_openai_config(PILOT/'.lab')
    if (c.model,c.reasoning_effort,c.max_output_tokens)!=('gpt-6.1-sol','low',2048):raise ValueError('La configuración no coincide con el protocolo.')
    integrity=verify_certificate(ROOT/plan['certificate'])
    if not integrity['valid'] or integrity['status']!='certified':raise ValueError('El certificado no es apto.')
    preflight(PILOT/'.lab-v2')
    return plan

def remaining_budget(summary, budget):
    cost=summary.get('cost_estimate_usd')
    if summary.get('status')!='accepted' or summary.get('usage_complete') is not True:
        raise ValueError('La comprobación API no fue aceptada con uso completo. No se inicia la cohorte.')
    if not isinstance(cost,(int,float)) or isinstance(cost,bool) or not 0<=cost<=budget:
        raise ValueError('No se conoce un costo válido de la comprobación.')
    rest=round(budget-cost,8)
    if rest<18:raise ValueError('No queda la reserva conservadora para las 30 corridas.')
    return rest

def guarded(command,log_path):
    # No se devuelve stdout ni datos privados a la interfaz. El proceso tiene su
    # propio grupo para poder detener herramientas pendientes ante fallo del host.
    with log_path.open('w') as log:
        os.chmod(log_path,0o600)
        child=subprocess.Popen(command,cwd=PILOT,stdout=log,stderr=log,start_new_session=True)
        try:
            while child.poll() is None:
                if int(Path('/proc/sys/kernel/tainted').read_text()) & FAULT_BITS:
                    raise ValueError('Se detectó fallo del kernel. El intento iniciado se conserva y no se repite.')
                time.sleep(2)
            return child.returncode
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=15)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
            raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ejecutar',action='store_true',help='Enviar API e iniciar solo después del aviso de recarga y verificación de tarifas.')
    args=parser.parse_args()
    plan=check_local()
    if not args.ejecutar:
        print('LISTO LOCALMENTE: 30 ejecuciones, USD 20, sin llamadas API. Esperando aviso de recarga.')
        return
    if STATE.exists():raise SystemExit('Existe registro de ejecución. Revisarlo; no lanzar otra cohorte ni repetir fallos automáticamente.')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    logs=PILOT/'.lab'/'estudio_kpi_logs';logs.mkdir(parents=True,exist_ok=True)
    from auditoria.dashboard import process_identity
    state={'status':'checking_api','pid':os.getpid(),'identity':process_identity(os.getpid()),'started_at':datetime.now(timezone.utc).isoformat(),'budget_usd':plan['budget_usd'],'api_calls_started':None,'access_check_cost_usd':None,'output_parent':'corridas/kpi_v2_api'}
    dump(STATE,state)
    try:
        code=guarded([str(PILOT/'.venv/bin/python'),'scripts/check_openai.py','--config','.lab'],logs/(stamp+'_acceso.log'))
        if code!=0:raise ValueError('La comprobación API no fue aceptada. Diagnóstico conservado; estudio sin iniciar.')
        check=json.loads((PILOT/'.lab/openai_check.json').read_text())
        remaining=remaining_budget(check,plan['budget_usd'])
        state.update(status='running',access_check_cost_usd=check['cost_estimate_usd'],experiment_budget_usd=remaining)
        dump(STATE,state)
        code=guarded([str(PILOT/'.venv/bin/auditoria'),'experimento-v2','--autorizacion','LAB-PROPIO','--bloques','15','--semilla',str(plan['seed']),'--salida',plan['execution_output'],'--tokens','60000','--costo-maximo-usd',str(remaining)],logs/(stamp+'_estudio.log'))
        candidates=sorted((PILOT/plan['execution_output']).glob('experimento_v2_*'))
        # Solo el experimento creado por este lanzamiento, con fecha posterior al inicio.
        candidates=[p for p in candidates if p.name.split('_')[2]>=stamp]
        if len(candidates)!=1:raise ValueError('No se identificó una única cohorte nueva. Revisar los registros locales.')
        experiment=candidates[0];state['experiment_key']=experiment.relative_to(PILOT/'corridas').as_posix()
        from archivar_evaluacion import archive
        archive(experiment,ROOT/'docs/evaluacion-api-empresa-2026-10-14')
        evaluation=json.loads((experiment/'evaluation.json').read_text())
        state.update(status='complete' if code==0 and evaluation['formal_cohort_complete'] else 'stopped',exit_code=code,runs_started=evaluation['runs_started'],pairs_eligible=evaluation['pairs_eligible'])
    except (OSError,ValueError,KeyboardInterrupt) as exc:
        state.update(status='stopped',reason=str(exc) if isinstance(exc,ValueError) else 'interrupcion_o_error_local')
        print('DETENIDO: revisar ejecucion.json y registros privados. No se reintenta automáticamente.')
    finally:
        state['ended_at']=datetime.now(timezone.utc).isoformat();dump(STATE,state)
    print('Estado del estudio:',state['status'])
    if state['status']!='complete':raise SystemExit(3)

if __name__=='__main__':main()
