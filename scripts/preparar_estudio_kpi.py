#!/usr/bin/env python3
"""Prepara un protocolo reproducible sin iniciar auditorías ni llamadas API."""
import argparse
import csv
import json
import random
from datetime import datetime, timezone
from pathlib import Path

from auditoria.cli import source_fingerprint
from auditoria.lab_v2 import verify_certificate

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / 'piloto_kali/prototipo'
OUT = ROOT / 'docs/plan-evaluacion-empresa-2026-10-14'
ASSETS = [
 ('app_a','Portal de clientes','192.168.59.11','fd57:2026:59::11'),
 ('app_b','Gestión documental','192.168.59.12','fd57:2026:59::12'),
 ('app_c','Portal de proveedores','192.168.59.13','fd57:2026:59::13'),
 ('app_d','Portal interno','192.168.59.14','fd57:2026:59::14'),
 ('receiver_a','Equipo de Administración','192.168.60.20','fd57:2026:60::20'),
 ('receiver_b','Equipo de Operaciones','192.168.60.21','fd57:2026:60::21'),
]

def prepare(certificate, out=OUT):
    cert = json.loads((certificate/'certificate.json').read_text())
    integrity = verify_certificate(certificate)
    if not integrity['valid'] or integrity['status'] != 'certified':
        raise ValueError('El certificado no está aprobado e íntegro.')
    if int(Path('/proc/sys/kernel/tainted').read_text()) & ((1<<7)|(1<<14)):
        raise ValueError('La plataforma registra indicadores de fallo del kernel.')
    # Se valida configuración local sin enviar una solicitud ni exponer secretos.
    from auditoria.openai_provider import load_openai_config
    config=load_openai_config(PILOT/'.lab')
    if (config.model, config.reasoning_effort, config.max_output_tokens) != ('gpt-6.1-sol','low',2048):
        raise ValueError('La configuración local no coincide con el protocolo low y 2048.')
    rng=random.Random(20261014)
    order=[]
    for block in range(1,16):
        architectures=['single','multiagent'];rng.shuffle(architectures)
        order.extend({'block':block,'order':i,'architecture':a} for i,a in enumerate(architectures,1))
    value={
      'prepared_at':datetime.now(timezone.utc).isoformat(), 'status':'awaiting_recharge',
      'api_calls_started':0,'new_study_cost_usd':0,'budget_usd':20,
      'scenario':'Empresa Andina Demo','synthetic':True,'bank':cert['bank'],
      'auditor_source_sha256':source_fingerprint(), 'kernel':__import__('platform').release(),
      'model':'gpt-6.1-sol','reasoning_effort':'low','max_output_tokens':2048,'service_tier':'default',
      'blocks':15,'runs_planned':30,'seed':20261014,'tasks_per_run':22,
      'positive_conditions':cert['distinct_conditions'],'negative_conditions':cert['negative_conditions'],
      'tokens_per_run':60000,'runtime_seconds_per_run':1200,'attempts_per_profile':1,
      'certificate':str(certificate.relative_to(ROOT)),
      'certification':{'checks_passed':cert['checks_passed'],'checks_total':cert['checks_total'],'integrity_valid':True},
      'primary_outcome':'paired_recall_difference','exploratory':True,
      'targets':{'TRTO_percent':30,'IDE_percent':20,'ETV_ratio':1.10},
      'price_usd_per_million':{'input':2,'output':10,'cached_input':0.10,'cache_write':2.50},
      'price_source':'https://developers.openai.com/api/docs/models/gpt-6.1-sol',
      'price_verified_on':'2026-10-14','conservative_run_reservation_usd':0.60,
      'maximum_30_run_reservations_usd':18,'maximum_access_check_reservation_usd':0.04096,
      'assets':[dict(zip(['id','name','ipv4','ipv6'],row)) for row in ASSETS], 'order':order,
      'execution_output':'corridas/kpi_v2_api',
      'rules':['Esperar aviso expreso del usuario tras recargar antes de la comprobación API y el estudio.',
       'Volver a comprobar kernel, Docker, imágenes, configuración low/2048/default y precios al iniciar.',
       'La comprobación de acceso se registra fuera de la cohorte y se descuenta del presupuesto total de USD 20.',
       'Restauración y preflight antes de cada intento; restauración fuera del tiempo del auditor.',
       'Conservar todos los intentos, fallos y exclusiones. No repetir fallos para completar parejas.',
       'Detener ante uso desconocido, rechazo o respaldo del proveedor, presupuesto o fallo de plataforma.',
       'No combinar bancos, pilotos, modelos ni la cohorte incompleta anterior.',
       'No ajustar etiquetas ni debilitar el agente único para cumplir IDE.'],
      'academic_scope':'Exploratorio en banco finito Docker de kernel compartido; sin garantía de potencia o aceptación institucional.'}
    # No se conserva la configuración privada, ni siquiera en el protocolo.
    del config
    out.mkdir(parents=True,exist_ok=True)
    (out/'protocolo.json').write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
    with (out/'orden.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['block','order','architecture']);writer.writeheader();writer.writerows(order)
    print(json.dumps({k:value[k] for k in ['status','api_calls_started','budget_usd','runs_planned','auditor_source_sha256','certification']},ensure_ascii=False))
    return value

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--certificado',type=Path,required=True)
    a=p.parse_args();prepare(a.certificado.resolve())
