#!/usr/bin/env python3
"""Suite de cuatro laboratorios cerrados. Sin --openai, auditar no consume API."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1];PILOT=ROOT/'piloto_kali/prototipo'
sys.path[:0]=[str(ROOT/'scripts'),str(PILOT/'src')]
from tesis.laboratorios import Context,catalog,profile,STATE,private_json
from auditoria.dashboard import process_identity,collect_state
from tesis.estudio import public_status


def kernel_ok():
    if int(Path('/proc/sys/kernel/tainted').read_text())&((1<<7)|(1<<14)):raise ValueError('kernel_failure; recuperar Kali antes de continuar')


def activity():
    try:
        p=STATE/'active.json'
        if p.is_symlink():return {}
        d=json.loads(p.read_text());alive=process_identity(d.get('pid',-1))==d.get('identity') and d.get('identity') is not None
        return {k:d.get(k) for k in ['action','scenario','status','message']}|{'active':alive and d.get('status')=='running'}
    except (OSError,ValueError,TypeError):return {}


@contextmanager
def operation(action,scenario):
    STATE.mkdir(parents=True,exist_ok=True,mode=0o700);STATE.chmod(0o700)
    with (STATE/'operation.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Hay otra operación de laboratorios activa.') from None
        if public_status().get('active') or any(r.get('status')=='running' for r in collect_state(PILOT/'corridas')['runs']):raise ValueError('Hay otra auditoría o estudio activo.')
        data={'pid':os.getpid(),'identity':process_identity(os.getpid()),'status':'running','action':action,'scenario':scenario,'message':'Operación de suite en curso.'}
        private_json(STATE/'active.json',data)
        try:yield
        finally:
            data.update(status='finished',message='Operación finalizada; consulta su resultado.');private_json(STATE/'active.json',data)


def compose(ctx,action):
    kernel_ok()
    command=['docker','compose','--env-file',str(ctx.state/'lab.env'),'-f',str(ctx.lab.COMPOSE)]
    if action=='up':
        # Una suite activa por vez; nunca se eliminan contenedores ajenos para hacer espacio.
        running=subprocess.run(['docker','ps','--filter','label=novaflow.suite=1','--format','{{.Label "novaflow.scenario"}}'],capture_output=True,text=True,check=True,timeout=10).stdout.splitlines()
        if any(name!=ctx.id for name in running):raise ValueError('Baja el otro escenario de la suite antes de activar este.')
        command+=['up','-d','--no-build','--force-recreate']
    else:command+=['down','--volumes']
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    if result.returncode:raise ValueError('Compose no completó la operación del escenario; revisar disponibilidad de imágenes y redes.')
    if action=='up':
        saved=json.loads((ctx.state/'prepared.json').read_text());saved['images']=images(ctx);private_json(ctx.state/'prepared.json',saved)


def images(ctx):
    names=sorted({name for _,_,members in ctx.lab.NETWORKS.values() for name in members})
    raw=subprocess.run(['docker','inspect','--format','{{.Name}} {{.Image}}',*names],capture_output=True,text=True,check=True,timeout=15).stdout
    return dict(line.strip('/').split() for line in raw.splitlines())


def ready(ctx):
    from urllib.error import URLError,HTTPError
    from auditoria.lab import LabError
    for attempt in range(12):
        kernel_ok()
        try:
            prepared=json.loads((ctx.state/'prepared.json').read_text())
            if prepared.get('images')!=images(ctx):raise ValueError('Cambió una imagen del escenario.')
            return ctx.preflight()
        except HTTPError:raise ValueError('El servicio del escenario devolvió un error HTTP.') from None
        except (URLError,ConnectionError,TimeoutError):
            if attempt==11:raise ValueError('El escenario no estuvo disponible dentro del plazo.') from None
            time.sleep(1)
        except LabError as exc:
            # La salud HTTP legada envuelve errores de transporte. Esperar solo
            # esa condición de arranque; no repetir fallos de rutas o catálogo.
            if str(exc)!='no se pudo contactar la consola legada NovaFlow' or not isinstance(exc.__cause__,OSError):raise
            if attempt==11:raise ValueError('La consola del escenario no estuvo disponible dentro del plazo.') from None
            time.sleep(1)


def audit(ctx,options,output,pair=0):
    from laboratorio_empresa import run_panel
    output.mkdir(parents=True,exist_ok=True)
    if not (output/'panel_job.json').exists():private_json(output/'panel_job.json',{'name':ctx.spec['name']+(' · aceptación sin IA' if options['ia']=='none' else ' · práctica '+options['architecture'])})
    capsule=STATE/'capsules'/ctx.id/(time.strftime('%Y%m%dT%H%M%S',time.gmtime())+'_'+str(os.getpid()))
    capsule.mkdir(parents=True,exist_ok=False,mode=0o700)
    for filename in ['ground_truth.json','policy.json','lab.env','compose.json','http_target.py','prepared.json']:
        shutil.copy2(ctx.state/filename,capsule/filename);(capsule/filename).chmod(0o600)
    for source in [Path(__file__),ROOT/'scripts/tesis/laboratorios.py',ROOT/'scripts/laboratorio_empresa.py',ROOT/'scripts/tesis/orquestacion_langgraph.py',ROOT/'scripts/tesis/evaluacion.py']:
        shutil.copy2(source,capsule/source.name);(capsule/source.name).chmod(0o600)
    shutil.copytree(ctx.state/'protocol',capsule/'protocol')
    ctx.lab.preflight_original=ctx.lab.preflight
    def checked(_root):return ready(ctx)
    # Context.preflight necesita la implementación original para evitar recursión.
    ctx.preflight_base=ctx.lab.preflight_original
    ctx.lab.preflight=checked
    started=time.monotonic()
    code=run_panel(options,output,bank_context=ctx)
    private_json(output/'timing.json',{'elapsed_seconds':time.monotonic()-started,'boundary':'Entrada a run_panel hasta retorno después de persistir informe, evaluación y eventos; sin restauración ni arranque del intérprete.'})
    reports=list(output.glob('*/report.json'))
    if len(reports)==1:
        report=json.loads(reports[0].read_text())
        if report.get('status')=='rejected' or report.get('authorization_rejection'):
            # Conservar el rechazo tal como se cerró; no inspeccionar Docker.
            return code
        directory=reports[0].parent;manifest=json.loads((directory/'manifest.json').read_text())
        manifest['scenario'].update(pair=options.get('manual_context',{}).get('pair',pair),images=images(ctx),fixture_sha256=hashlib.sha256((ctx.state/'lab.env').read_bytes()).hexdigest(),capsule=capsule.relative_to(STATE).as_posix(),phase='acceptance' if options['ia']=='none' else 'manual_evaluation' if options.get('manual_context') else 'practice')
        private_json(directory/'manifest.json',manifest)
    return code


def acceptance_all():
    from ejecutar_estudio_novaflow import guarded
    if (STATE/'acceptance.json').exists():
        history=STATE/'acceptance-history';history.mkdir(exist_ok=True,mode=0o700)
        shutil.copy2(STATE/'acceptance.json',history/(time.strftime('%Y%m%dT%H%M%S',time.gmtime())+'.json'))
    from tesis.orquestacion_langgraph import engine_metadata
    receipt={'status':'running','version':'novaflow-suite-2','orchestration':engine_metadata(),'scenarios':[],'new_api_generations':0}
    private_json(STATE/'acceptance.json',receipt)
    for row in catalog():
        ctx=Context(row['id']);ctx.prepare();entry={'id':ctx.id,'status':'preparing','expected_tasks':row['tasks']};receipt['scenarios'].append(entry)
        private_json(STATE/'acceptance.json',receipt)
        compose(ctx,'up');ready(ctx)
        stamp=time.strftime('%Y%m%dT%H%M%S',time.gmtime())
        output=PILOT/'corridas/suite_acceptance'/ctx.id/stamp;output.mkdir(parents=True,exist_ok=False)
        spec={'options':{'authorization':'LAB-PROPIO','scope':'empresa','architecture':'single','ia':'none','tokens':0,'mode':'live'},'scenario':ctx.id,'parent_pid':os.getpid(),'parent_identity':process_identity(os.getpid())}
        private_json(output/'slot.json',spec)
        entry.update(status='running',output=output.relative_to(PILOT/'corridas').as_posix());private_json(STATE/'acceptance.json',receipt)
        code=guarded([str(PILOT/'.venv/bin/python'),str(Path(__file__).resolve()),'--slot',str(output)],STATE/'acceptance.log',2700)
        evs=list(output.glob('*/evaluation.json'));ev=json.loads(evs[0].read_text()) if len(evs)==1 else {}
        entry.update(status='accepted' if code==0 and ev.get('acceptance_passed') else 'failed',evaluation={k:ev.get(k) for k in ['tasks_checked','tasks_valid','TP','FP','FN','TN','acceptance_passed','evidence_valid']})
        private_json(STATE/'acceptance.json',receipt)
        if entry['status']!='accepted':receipt['status']='stopped';private_json(STATE/'acceptance.json',receipt);return 3
        compose(ctx,'down')
    receipt['status']='accepted';private_json(STATE/'acceptance.json',receipt);return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',nargs='?',choices=['catalogo','preparar','levantar','estado','bajar','auditar','aceptar-todos'],default='catalogo')
    p.add_argument('--lab',choices=[r['id'] for r in catalog()]);p.add_argument('--slot',type=Path)
    p.add_argument('--arquitectura',choices=['single','multiagent'],default='single');p.add_argument('--openai',action='store_true');p.add_argument('--tokens',type=int,default=60000)
    p.add_argument('--pareja',type=int,default=0);p.add_argument('--autorizacion',default='LAB-PROPIO');p.add_argument('--output',type=Path);p.add_argument('--job',type=Path)
    args=p.parse_args()
    if args.slot:
        spec=json.loads((args.slot/'slot.json').read_text())
        if spec['parent_pid']!=os.getppid() or process_identity(os.getppid())!=spec['parent_identity']:raise ValueError('Proceso de aceptación no autorizado.')
        return audit(Context(spec['scenario']),spec['options'],args.slot)
    if args.job:
        from dualstack_panel import validate_options
        options=validate_options(json.loads(args.job.read_text())['options']);args.lab=options['scenario'];args.action='auditar'
    if args.action=='catalogo':print(json.dumps(catalog(),ensure_ascii=False,indent=2));return 0
    if args.action!='preparar' and args.action!='aceptar-todos' and not args.lab:p.error('Indica --lab.')
    with operation(args.action,args.lab):
        if args.action!='preparar':kernel_ok()
        if args.action=='preparar':
            for row in catalog():
                if not args.lab or row['id']==args.lab:Context(row['id']).prepare()
            print('Laboratorios preparados con configuración y referencia separadas. Cero API.');return 0
        if args.action=='aceptar-todos':return acceptance_all()
        ctx=Context(args.lab)
        if args.action=='levantar':ctx.prepare();compose(ctx,'up');ready(ctx);return 0
        if args.action=='bajar':compose(ctx,'down');return 0
        if args.action=='estado':ready(ctx);print('Escenario listo: '+ctx.id);return 0
        if not args.job:
            from dualstack_panel import validate_options
            options=validate_options({'name':ctx.spec['name'],'authorization':args.autorizacion,'scope':'empresa','scenario':ctx.id,'architecture':args.arquitectura,'ia':'openai' if args.openai else 'none','tokens':args.tokens if args.openai else 0,'expert_mode':bool(args.openai)})
        if not 0<=args.pareja<=1000:raise ValueError('Pareja fuera de rango.')
        output=args.output or PILOT/'corridas/suite_practices'/ctx.id/time.strftime('%Y%m%dT%H%M%S',time.gmtime());output.mkdir(parents=True,exist_ok=True)
        return audit(ctx,options,output,args.pareja)


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        # No imprimir stdout de Docker, variables de entorno ni errores con cuerpos HTTP.
        if 'aceptar-todos' in sys.argv:
            try:
                receipt=json.loads((STATE/'acceptance.json').read_text());receipt['status']='stopped';private_json(STATE/'acceptance.json',receipt)
            except (OSError,ValueError):pass
        print('Suite detenida: '+(str(exc) if type(exc) is ValueError else type(exc).__name__),file=sys.stderr);raise SystemExit(3)
