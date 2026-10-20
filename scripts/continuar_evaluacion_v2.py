"""Continúa posiciones no iniciadas de un diseño congelado; nunca reemplaza fallos.
No ejecutarlo hasta recuperar la VM y comprobar su estado. Requiere --ejecutar.
"""
import argparse,json,time
from pathlib import Path
from auditoria import lab_v2
from auditoria.cli import execute_v2,host_resources,source_fingerprint
from auditoria.laboratorio import operation_lock
from auditoria.metrics import summarize_experiment
from auditoria.openai_provider import load_openai_config
from auditoria.store import write_json


def resume(root,config,credentials,authorization):
    root=Path(root).resolve();config=Path(config).resolve();credentials=Path(credentials).resolve()
    design=json.loads((root/'design.json').read_text());attempts=json.loads((root/'attempts.json').read_text())
    if source_fingerprint()!=design['auditor_source_sha256']:
        raise ValueError('El código cambió; no se puede continuar esta cohorte con otra versión.')
    taint=int(Path('/proc/sys/kernel/tainted').read_text())
    if taint & ((1<<7)|(1<<14)):
        raise ValueError('El kernel conserva indicadores DIE o SOFTLOCKUP. Recupere la VM antes de medir.')
    metadata=lab_v2.preflight(config)
    expected=design['bank_manifest']
    for key in ['bank','kernel','source_sha256','fixture_seed_sha256']:
        if metadata[key]!=expected[key]:raise ValueError('Contexto de laboratorio diferente en '+key)
    images=lambda m:{t['container']:(t['image_id'],t['nano_cpus'],t['memory_limit_bytes'],t['pids_limit']) for t in m['targets']}
    if images(metadata)!=images(expected):raise ValueError('Imágenes o recursos diferentes del banco congelado.')
    if any(a['status']=='running' for a in attempts):raise ValueError('Hay un intento sin cierre; revise su evidencia antes de continuar.')
    used=0.0
    for attempt in attempts:
        if not attempt.get('run_path'):
            raise ValueError('Un intento iniciado no conserva informe con uso medido; revise su cierre antes de continuar.')
        p=Path(attempt['run_path']);p=p if p.is_absolute() else root/p
        llm=json.loads((p/'report.json').read_text())['llm']
        if not llm.get('usage_complete') or llm.get('status')!='accepted':
            raise ValueError('Una corrida tiene rechazo o uso API incompleto; requiere resolver el proveedor antes de continuar.')
        used+=llm.get('cost_estimate_usd') or 0
    positions={(a['block'],a['architecture']) for a in attempts}
    load_openai_config(credentials)
    with operation_lock():
        for block in design['blocks']:
            for order,architecture in enumerate(block['order'],1):
                if (block['block'],architecture) in positions:continue
                if used+design['tokens']*10/1_000_000>design['cost_budget_usd']:
                    raise ValueError('No hay reserva suficiente dentro del presupuesto original.')
                started=time.monotonic();lab_v2.compose(config,'reset');lab_v2.preflight(config)
                attempt={'block':block['block'],'order':order,'architecture':architecture,'status':'running',
                    'restoration_seconds':round(time.monotonic()-started,6),'host_resources':host_resources()}
                attempts.append(attempt);write_json(root/'attempts.json',attempts)
                try:
                    state=execute_v2(config,credentials,root/'runs',authorization,architecture,tokens=design['tokens'])
                    attempt.update(status=state['report']['status'],run_path=state['run_path'])
                    llm=state['report']['llm'];used+=llm.get('cost_estimate_usd') or 0
                    if llm.get('status')!='accepted' or not llm.get('usage_complete'):
                        raise ValueError('Proveedor no aceptado o uso desconocido; no se envían otras generaciones.')
                except Exception as exc:
                    if attempt['status']=='running':
                        attempt.update(status='failed',error_type=type(exc).__name__,usage_requires_review=True)
                    raise
                finally:
                    write_json(root/'attempts.json',attempts);summarize_experiment(root,root/'ground_truth.json')
    return summarize_experiment(root,root/'ground_truth.json')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--experimento',required=True);p.add_argument('--config',default='.lab-v2')
    p.add_argument('--credenciales',default='.lab');p.add_argument('--autorizacion',required=True);p.add_argument('--ejecutar',action='store_true')
    a=p.parse_args()
    if not a.ejecutar:p.error('Se requiere --ejecutar después de recuperar y comprobar la VM.')
    result=resume(a.experimento,a.config,a.credenciales,a.autorizacion)
    print('Corridas',result['runs_started'],'pares aptos',result['pairs_eligible'])
