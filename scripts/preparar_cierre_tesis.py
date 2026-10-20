#!/usr/bin/env python3
"""Preparación y aceptación del banco de tesis; no inicia una muestra API."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'piloto_kali/prototipo/src'))
sys.path.insert(0,str(ROOT/'scripts'))
OUTPUT=ROOT/'piloto_kali/prototipo/.verificacion/cierre-tesis'


def fingerprint():
    files=[]
    for base in ['piloto_kali/prototipo/src/auditoria','scripts/tesis']:
        files.extend(p for p in (ROOT/base).rglob('*.py') if '__pycache__' not in str(p))
    files.extend(ROOT/p for p in ['scripts/laboratorio_empresa.py','scripts/llm_especialistas.py'])
    return hashlib.sha256(''.join(str(p.relative_to(ROOT))+hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)).encode()).hexdigest()


def prepare():
    from auditoria import empresa_agent as agent
    tasks=agent.build_plan(agent.request('LAB-PROPIO',tokens=0,llm=False))
    from random import Random
    random=Random(20261017);order=[]
    for block in range(1,16):
        arms=['single','multiagent'];random.shuffle(arms)
        order.append({'block':block,'order':arms})
    return {'schema_version':1,'status':'draft_requires_acceptance_and_pilot','bank':'docker-empresa-1.0',
      'source_sha256':fingerprint(),'created_at':datetime.now(timezone.utc).isoformat(),
      'tasks_per_run':len(tasks),'pairs_planned':15,'runs_planned':30,'seed':20261017,'order':order,
      'budget_usd':20,'tokens_per_run':20000,'expert_mode':True,'specialist_prompt_version':'specialist-review-3',
      'primary_outcome':'paired_recall_difference','exploratory':True,'paid_calls':0,
      'requirements':['independent_bank_acceptance','pilot_single_and_multi','provider_model_and_price_verified','immutable_bank_images','same_budget_and_model','all_attempts_preserved'],
      'note':'Borrador nuevo: no sustituye resultados históricos ni acredita congelación o suficiencia académica.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.parse_args();OUTPUT.mkdir(parents=True,exist_ok=True)
    protocol=prepare();path=OUTPUT/'protocolo-borrador.json';path.write_text(json.dumps(protocol,ensure_ascii=False,indent=2)+'\n')
    print('Borrador preparado: 15 parejas, banco integrado, 20.000 tokens/corrida y USD 20 de tope total. Aún no congelado.')
    print('No se ha iniciado el estudio formal ni una llamada API.')

if __name__=='__main__':main()
