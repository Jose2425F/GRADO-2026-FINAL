#!/usr/bin/env python3
"""Recalcula la aceptación publicada sin root, sondas ni proveedor externo.

Requiere Python 3.13 y las dependencias del aplicativo (incluidos Pydantic,
PyYAML y Scapy). verificar.py permanece independiente de esas dependencias.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import importlib.util
from importlib.metadata import version
import io
from ipaddress import ip_address
import json
import os
from pathlib import Path,PurePosixPath
import socket
import stat
import sys
import tempfile
import zipfile

EXPECTED={'integrado':32,'sucursal':25,'comercial':28,'mixto':32,'reforzado':37}
SCORE_KEYS=['ground_truth_sha256','bank','TP','FP','FN','TN','unknown_negative_controls',
    'negative_conditions_total','intentional_budget_omissions','unscored_findings',
    'evidence_valid','tasks_checked','tasks_valid','acceptance_passed']


def sha(raw):return hashlib.sha256(raw).hexdigest()


def audit(event,args):
    if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.spawn'}:
        raise RuntimeError('El recálculo no ejecuta procesos ni herramientas.')
    if event in {'socket.connect','socket.sendto','socket.sendmsg','socket.bind'}:
        connection=args[0]
        if getattr(connection,'family',None)!=getattr(socket,'AF_NETLINK',None):
            raise RuntimeError('El recálculo no abre conexiones ni envía sondas.')
    if event=='socket.getaddrinfo' and args[0] is not None:
        try:ip_address(str(args[0]).split('%',1)[0])
        except ValueError:raise RuntimeError('El recálculo no consulta nombres DNS.') from None


def verify_publication(folder):
    spec=importlib.util.spec_from_file_location('centinela_verify_113',folder/'verificar.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    old=sys.argv;output=io.StringIO()
    try:
        sys.argv=[str(folder/'verificar.py')]
        with contextlib.redirect_stdout(output):module.main()
    finally:sys.argv=old
    receipt=json.loads(output.getvalue())
    if receipt.get('verified') is not True:raise ValueError('Publicación no verificada.')
    return receipt


def safe_extract(source,selected,destination):
    total=0
    for name in selected:
        relative=PurePosixPath(name);info=source.getinfo(name)
        if (relative.is_absolute() or '..' in relative.parts or relative.as_posix()!=name
            or info.is_dir() or not stat.S_ISREG(info.external_attr>>16) or info.file_size>25_000_000):
            raise ValueError('Entrada no apta para extracción temporal: '+name)
        total+=info.file_size
        if total>200_000_000:raise ValueError('El conjunto supera el límite de lectura.')
        path=destination/relative;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(source.read(name))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,help='Repositorio con las fuentes de la versión publicada.')
    parser.add_argument('--bank',choices=list(EXPECTED),help='Recalcula sólo un banco; por defecto exige los cinco.')
    parser.add_argument('--output',type=Path,help='Guarda el recibo de recálculo, sin modificar la evidencia.')
    parser.add_argument('--supplementary-multiagent',action='store_true',help='Añade el suplemento Multiagent de32 tareas, separado de las154 canónicas.')
    args=parser.parse_args()
    if sys.version_info[:2]!=(3,13):raise SystemExit('Utiliza Python 3.13 con las dependencias del aplicativo.')
    folder=Path(__file__).resolve().parent;repo=(args.repo or folder.parents[2]).resolve()
    integrity=verify_publication(folder)
    summary=json.loads((folder/'resumen-validacion.json').read_text())
    accepted=summary['catalogue_final_accepted'];banks=[args.bank] if args.bank else list(EXPECTED)
    if any(bank not in accepted or accepted[bank].get('accepted') is not True for bank in banks):
        raise ValueError('Todavía falta la aceptación final del catálogo solicitado.')
    jobs=[(bank,accepted[bank],False) for bank in banks]
    if args.supplementary_multiagent:
        supplement=summary.get('supplementary_multiagent')
        if not isinstance(supplement,dict) or supplement.get('accepted') is not True:
            raise ValueError('Todavía falta la aceptación final del suplemento Multiagent.')
        jobs.append(('integrado',supplement,True))
    provenance=json.loads((folder/'procedencia-codigo.json').read_text())
    for source in provenance['files']:
        if source['kind']!='runtime_source':continue
        path=repo/source['path']
        if not path.is_file() or path.is_symlink() or sha(path.read_bytes())!=source['descriptor_sha256']:
            raise ValueError('Fuente de ejecución distinta de la versión aceptada: '+source['path'])
    sys.addaudithook(audit)
    sys.path[:0]=[str(repo/'scripts'),str(repo/'piloto_kali/prototipo/src')]
    from tesis.evaluacion import score
    manifest=json.loads((folder/'integridad-evidencias.json').read_text());results={};supplement_result=None
    with zipfile.ZipFile(folder/manifest['archive']) as archive,tempfile.TemporaryDirectory(prefix='centinela-recalculo-') as directory:
        destination=Path(directory);names=archive.namelist();selected=[]
        for bank,run_info,is_supplement in jobs:
            prefix=run_info['source']+'/'
            reference='evidencias/referencias-post-ejecucion/'+bank+'.json'
            if reference not in names:raise ValueError('Falta la referencia pública posterior a la ejecución: '+bank)
            selected.extend(name for name in names if name.startswith(prefix));selected.append(reference)
        safe_extract(archive,sorted(set(selected)),destination)
        for bank,run_info,is_supplement in jobs:
            public=destination/run_info['source']
            operator=json.loads((public/'operator-public.json').read_text());original=operator['operator_evaluation']
            reference=destination/'evidencias/referencias-post-ejecucion'/ (bank+'.json')
            if sha(reference.read_bytes())!=original['ground_truth_sha256']:
                raise ValueError('Referencia distinta de la utilizada por el evaluador: '+bank)
            reports=list((public/'controller/runs').glob('*/report.json'))
            if len(reports)!=1:raise ValueError('No hay una corrida final única: '+bank)
            report=json.loads(reports[0].read_text())
            expected_architecture='multiagent' if is_supplement else 'single'
            if report.get('architecture')!=expected_architecture:raise ValueError('Arquitectura inesperada: '+bank)
            if len(report['tasks'])!=EXPECTED[bank] or any(row.get('status') not in {'completed','completed_no_findings'} for row in report['tasks']):
                raise ValueError('Estados o número de tareas inesperados: '+bank)
            if bank=='integrado':
                from auditoria import empresa_agent,lab_empresa
                from laboratorio_empresa import validation_for
                engine=empresa_agent;validator=validation_for;bank_id=lab_empresa.VERSION
            else:
                from tesis.laboratorios import Context
                context=Context(bank);engine=context.agent;validator=context.validation;bank_id=context.lab.VERSION
            current=score(reports[0].parent,reference,engine=engine,validator=validator,bank_id=bank_id)
            if any(current[key]!=original[key] for key in SCORE_KEYS):raise ValueError('El recálculo discrepa del operador: '+bank)
            if current['tasks_valid']!=EXPECTED[bank] or current['acceptance_passed'] is not True or current['evidence_valid'] is not True:
                raise ValueError('La evidencia no supera la aceptación: '+bank)
            assessed={key:current[key] for key in SCORE_KEYS}
            if is_supplement:supplement_result=assessed|{'run_id':run_info['run_id'],'architecture':'multiagent'}
            else:results[bank]=assessed
    total=sum(result['tasks_valid'] for result in results.values())
    if not args.bank and total!=154:raise ValueError('El conjunto no contiene las 154 tareas válidas.')
    receipt={'schema':'centinela-public-recalculation/1','verified':True,'banks':results,
        'execution_uid':os.geteuid(),'python':sys.version.split()[0],
        'dependencies':{name:version(name) for name in ['pydantic','scapy','PyYAML']},
        'tasks_valid':total,'full_154_recalculated':not bool(args.bank),'integrity':integrity,
        'supplementary_multiagent':supplement_result,'supplementary_tasks_valid':32 if supplement_result else 0,
        'total_task_executions_checked':total+(32 if supplement_result else 0),
        'source_archive_sha256':manifest['archive_sha256'],
        'code_commit':provenance['code_commit'],'external_network_connections':False,'tools_executed':False,'api_calls':0,
        'historical_campaign_kpis_recalculated':False,'reference_scope':'Etiquetas publicadas después de la ejecución y cotejadas por SHA-256.'}
    if args.output:args.output.write_text(json.dumps(receipt,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(receipt,ensure_ascii=False))

if __name__=='__main__':main()
