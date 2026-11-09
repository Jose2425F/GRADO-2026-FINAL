#!/usr/bin/env python3
"""Verifica bytes y ZIP sin extraer, ejecutar herramientas ni utilizar red."""
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import zipfile


def sha(raw):return hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--historicos',type=Path)
    args=parser.parse_args();root=Path(__file__).resolve().parent
    publication=json.loads((root/'integridad-publicacion.json').read_text())
    allowed_adjustment=(root/'../../ajustes-profesor/2026-11-09-roles-origen').resolve()
    for item in publication['files']:
        target=(root/item['path']).resolve()
        if target.parent not in {root,allowed_adjustment}:raise ValueError('Ruta de publicación fuera de alcance')
        raw=target.read_bytes()
        if len(raw)!=item['bytes'] or sha(raw)!=item['sha256']:raise ValueError('Archivo modificado: '+item['path'])
    manifest=json.loads((root/'integridad-evidencias.json').read_text());archive=root/manifest['archive']
    raw=archive.read_bytes()
    if len(raw)!=manifest['archive_bytes'] or sha(raw)!=manifest['archive_sha256']:raise ValueError('ZIP modificado')
    expected={row['entry']:row for row in manifest['entries']}
    if len(expected)!=manifest['entry_count']:raise ValueError('Inventario duplicado')
    public_exports=0
    with zipfile.ZipFile(archive) as source:
        names=source.namelist()
        if len(names)!=len(set(names)) or set(names)!=set(expected):raise ValueError('Entradas ZIP distintas del inventario')
        for name in names:
            relative=PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Ruta ZIP inválida')
            entry=expected[name];raw=source.read(name)
            if len(raw)!=entry['bytes'] or sha(raw)!=entry['sha256']:raise ValueError('Entrada ZIP modificada: '+name)
            if relative.name=='manifest-public.json':
                exported=json.loads(raw)
                if exported.get('exact_fixture_secrets_scan_passed') is not True:raise ValueError('Exportación no aprobada')
                for reference,pin in exported['files'].items():
                    part=PurePosixPath(reference)
                    if part.is_absolute() or '..' in part.parts:raise ValueError('Ruta de exportación inválida')
                    key=str(relative.parent/part)
                    if key not in expected:raise ValueError('Exportación incompleta: '+key)
                    content=source.read(key)
                    if len(content)!=pin['bytes'] or sha(content)!=pin['sha256']:raise ValueError('Exportación alterada: '+key)
                public_exports+=1
    historical=json.loads((root/'conservacion-historica.json').read_text())
    historical_checked=0
    if args.historicos:
        repo=args.historicos.resolve()
        for revision in historical['revisions']:
            for entry in revision['files']:
                target=repo/entry['path']
                if target.is_symlink() or not target.is_file():raise ValueError('Falta evidencia anterior: '+entry['path'])
                raw=target.read_bytes()
                if len(raw)!=entry['bytes'] or sha(raw)!=entry['sha256']:raise ValueError('Evidencia anterior modificada: '+entry['path'])
                historical_checked+=1
    print(json.dumps({'verified':True,'files':len(publication['files']),'zip_entries':len(expected),
        'status':manifest['status'],'public_export_manifests':public_exports,'previous_file_checks_repeated_now':historical_checked,
        'network':False,'tools_executed':False,'api_calls':0},ensure_ascii=False))

if __name__=='__main__':main()
