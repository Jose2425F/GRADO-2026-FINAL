#!/usr/bin/env python3
"""Prepara propuesta o resume prácticas con pareja explícita; no ejecuta pruebas."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]
from tesis.estudio_multilab import draft,analyze,read_rows
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resumir',action='store_true');args=p.parse_args()
folder=ROOT/'docs/estudio-multilaboratorio';folder.mkdir(exist_ok=True)
if args.resumir:
    data=analyze(read_rows(ROOT/'piloto_kali/prototipo/corridas/suite_practices'));name='resumen-exploratorio.json'
else:data=draft();name='protocolo-borrador.json'
(folder/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n');print(folder/name)
