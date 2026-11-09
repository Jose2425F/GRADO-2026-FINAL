#!/usr/bin/env python3
"""Verifica el paquete público v3 con biblioteca estándar, sin red ni extracción."""
from pathlib import Path, PurePosixPath
import argparse, hashlib, json, stat, zipfile, xml.etree.ElementTree as ET


def sha(data): return hashlib.sha256(data).hexdigest()


def relative(name):
    p=PurePosixPath(name)
    if not p.parts or p.is_absolute() or '..' in p.parts or '\\' in name or '\x00' in name:
        raise ValueError('Ruta fuera de alcance: '+name)
    return p


def local_file(base,name):
    name=relative(name);target=base/Path(*name.parts)
    if not target.resolve().is_relative_to(base.resolve()):raise ValueError('Archivo fuera de alcance')
    if any((base/Path(*name.parts[:n])).is_symlink() for n in range(1,len(name.parts)+1)):
        raise ValueError('Enlace no permitido: '+str(name))
    if not target.is_file():raise ValueError('Falta archivo: '+str(name))
    return target


def junit(data,passed,subtests,skipped):
    root=ET.fromstring(data);cases=list(root.iter('testcase'));suites=list(root.iter('testsuite'))
    if any(case.find('failure') is not None or case.find('error') is not None for case in cases):
        raise ValueError('JUnit con fallos')
    skips=sum(case.find('skipped') is not None for case in cases)
    counted=sum(int(suite.attrib['tests']) for suite in suites)
    if (len(cases)-skips,counted-len(cases),skips)!=(passed,subtests,skipped):
        raise ValueError('Conteo JUnit distinto del resumen')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,help='Clon que contiene las evidencias históricas conservadas.')
    parser.add_argument('--solo-paquete',action='store_true',help='No coteja los ZIP anteriores del clon.')
    args=parser.parse_args();here=Path(__file__).resolve().parent
    repo=(args.repo or (here if args.solo_paquete else here.parents[2])).resolve()
    publication=json.loads((here/'integridad-publicacion.json').read_text())
    for row in publication['files']:
        name=relative(row['path']);target=local_file(here,row['path'])
        data=target.read_bytes()
        if len(data)!=row['bytes'] or sha(data)!=row['sha256']:raise ValueError('Publicación alterada: '+str(name))
    manifest=json.loads((here/'integridad-evidencias.json').read_text());archive=local_file(here,manifest['archive']);raw=archive.read_bytes()
    if len(raw)!=manifest['archive_bytes'] or sha(raw)!=manifest['archive_sha256']:raise ValueError('ZIP alterado')
    expected={row['entry']:row for row in manifest['entries']}
    if len(expected)!=len(manifest['entries']) or len(expected)!=manifest['entry_count']:raise ValueError('Inventario duplicado')
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        if len(names)!=len(set(names)) or set(names)!=set(expected):raise ValueError('Entradas distintas del inventario')
        if sum(i.file_size for i in z.infolist())>300_000_000:raise ValueError('Límite de lectura excedido')
        for info in z.infolist():
            name=relative(info.filename)
            if info.is_dir() or not stat.S_ISREG(info.external_attr>>16) or info.file_size>30_000_000:raise ValueError('Entrada no regular o demasiado grande')
            if name.suffix.lower() in {'.doc','.docx','.docm','.dotx','.dotm'}:raise ValueError('Word no permitido')
            data=z.read(info.filename);row=expected[info.filename]
            if len(data)!=row['bytes'] or sha(data)!=row['sha256']:raise ValueError('Entrada alterada: '+info.filename)
        before=json.loads(z.read('evidencia115/antes/resumen.json'));after=json.loads(z.read('evidencia115/despues/resumen.json'))
        if len(after['cases'])!=6 or after['task_results_read']!=186:raise ValueError('Casos guardados incompletos')
        tasks=findings=0
        for case in after['cases']:
            bank=case['bank'];prefix='evidencia115/despues/'+bank+'/'
            request=json.loads(z.read(prefix+'request.source.json'));plan=json.loads(z.read(prefix+'plan.source.json'))
            original=json.loads(z.read(prefix+'report.source.json'));report=json.loads(z.read(prefix+'report.json'))
            if sha(z.read(prefix+'report.source.json'))!=case['source_report_sha256']:raise ValueError('Origen distinto')
            if request['audit_id']!=original['audit_id'] or report['audit_id']!=original['audit_id']:raise ValueError('Auditoría distinta')
            if report['tasks']!=original['tasks'] or {x['task_id'] for x in plan}!={x['task_id'] for x in report['tasks']}:raise ValueError('Resultados o plan distintos')
            if report['inventory']!=original['inventory']:raise ValueError('Inventario original alterado')
            if report['scope']['ipv4']!=request['scope_ipv4'] or report['scope']['ipv6']!=request['scope_ipv6']:raise ValueError('Alcance distinto')
            if len(report['findings'])!=len(original['findings']):raise ValueError('Hallazgos distintos')
            for old,new in zip(original['findings'],report['findings']):
                if {k:v for k,v in new.items() if k!='finding_id'}!={k:v for k,v in old.items() if k!='finding_id'}:raise ValueError('Hallazgo modificado')
                identifier=old.get('finding_id') or str(old.get('asset_id',''))+':'+str(old.get('defect_key') or old.get('condition',''))
                if new['finding_id']!=identifier:raise ValueError('ID no estable')
            tasks+=len(report['tasks']);findings+=len(report['findings'])
        if (tasks,findings)!=(186,59):raise ValueError('Totales inesperados')
        pdf=json.loads(z.read('evidencia115/cotejo-pdf-real.json'))
        if pdf['all_after_passed'] is not True:raise ValueError('Cotejo PDF no aprobado')
        close=json.loads(z.read('evidencia115/cotejo-cierre-reparado.json'))
        if close['passed'] is not True or len(close['cases'])!=2:raise ValueError('Cierres no cotejados')
        b=json.loads(z.read('evidencia115/fuentes-antes-regresion-final.json'))
        a=json.loads(z.read('evidencia115/fuentes-despues-regresion-final.json'))
        if a!=b or len(a)!=592:raise ValueError('Fuente de las pruebas cambió')
        supplement=json.loads(z.read('suplemento-validacion/recibo-consolidacion.json'))
        if supplement['fuentes_iguales'] is not True or supplement['union_misma_bateria']['ejecucion_unica_completa'] is not False:raise ValueError('Épocas de prueba incorrectas')
        if supplement['union_misma_bateria']['aprobadas']!=1014 or supplement['union_misma_bateria']['subpruebas_aprobadas']!=112:raise ValueError('Suplemento no compatible')
        sb=json.loads(z.read('suplemento-validacion/source-before.json'));sa=json.loads(z.read('suplemento-validacion/source-after.json'))
        if sb!=sa or sb!=b:raise ValueError('Fuentes suplementarias distintas')
        junit(z.read('evidencia115/pruebas-115-cierre-final.xml'),73,44,0)
        junit(z.read('evidencia115/regresion-115-final.xml'),1013,110,2)
        junit(z.read('suplemento-validacion/nmap-loopback-junit.xml'),1,2,0)
    preserved=0
    if not args.solo_paquete:
        historical=json.loads((here/'conservacion-publica.json').read_text())
        for row in historical['files']:
            name=relative(row['path']);target=local_file(repo,row['path'])
            data=target.read_bytes()
            if len(data)!=row['bytes'] or sha(data)!=row['sha256']:raise ValueError('Paquete anterior alterado: '+str(name))
            preserved+=1
    print(json.dumps({'verified':True,'publication_files':len(publication['files']),'zip_entries':len(expected),'stored_cases':6,
        'stored_results_read':tasks,'stored_findings_read':findings,'historical_zip_files_checked':preserved,
        'directed_tests':73,'directed_subtests':44,'broad_regression_tests':1013,'broad_regression_subtests':110,
        'supplement_tests':1,'supplement_subtests':2,'compatible_union_tests':1014,'compatible_union_subtests':112,
        'single_complete_regression_execution':False,'new_audits_executed':False,'historical_kpis_recomputed':False,
        'network':False,'tools_executed':False,'zip_extracted':False},ensure_ascii=False))


if __name__=='__main__':main()
