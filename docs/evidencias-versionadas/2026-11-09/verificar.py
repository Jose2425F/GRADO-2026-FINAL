#!/usr/bin/env python3
"""Verifica copias e indicadores conservados sin red, Docker ni API."""
from pathlib import Path
from zipfile import ZipFile
from statistics import mean
import hashlib, json, math

ROOT=Path(__file__).resolve().parent
sha=lambda raw:hashlib.sha256(raw).hexdigest()
integrity=json.loads((ROOT/'integridad-publicacion.json').read_text())
for row in integrity['archivos']:
    path=ROOT/row['archivo']
    if not path.is_file():raise SystemExit('Falta archivo: '+row['archivo'])
    if sha(path.read_bytes())!=row['sha256']:raise SystemExit('SHA incorrecta: '+row['archivo'])
    if path.stat().st_size!=row['bytes']:raise SystemExit('Tamaño incorrecto: '+row['archivo'])
archive_count=0
for path in sorted(ROOT.glob('*-integridad.json')):
    m=json.loads(path.read_text())
    with ZipFile(ROOT/m['archivo_zip']) as z:
        assert sorted(z.namelist())==sorted(r['archivo'] for r in m['archivos'])
        assert len(z.namelist())==len(set(z.namelist()))
        for row in m['archivos']:
            raw=z.read(row['archivo'])
            assert len(raw)==row['bytes'],row['archivo']
            assert sha(raw)==row['sha256_publicado']==row['sha256_original'],row['archivo']
            archive_count+=1

analysis=json.loads((ROOT/'comparacion-campanas-20261109.json').read_text())
historical_groups=json.loads((ROOT/'referencia-historica-20261018/pairs.json').read_text())
historical_runs=json.loads((ROOT/'referencia-historica-20261018/runs.json').read_text())
historic_by_id={r['run_id']:r for r in historical_runs}
names=['TRTO_percent','IDE_percent','ETV_ratio']
def metric(tu,tm,ku,km,pu,pm):
    return dict(zip(names,[100*(tu-tm)/tu,100*(pm-pu)/pu,(ku/pu)/(km/pm)]))
historic_values=[]
for group in historical_groups:
    for p in group['pairs']:
        if not p['eligible']:continue
        a=historic_by_id[p['single']['run_id']];b=historic_by_id[p['multiagent']['run_id']]
        # Historical exports already preserve elapsed seconds as "seconds".
        m=metric(a['seconds'],b['seconds'],a['known_tokens'],b['known_tokens'],a['TP'],b['TP'])
        for key in names:assert math.isclose(m[key],p['metrics'][key],rel_tol=1e-10),key
        historic_values.append(m)

new_values=[];common_values=[];seen=set()
with ZipFile(ROOT/'campana-api-20261108.zip') as z:
    for p in analysis['new_pairs']:
        reports={};evaluations={}
        for mode,rid in p['runs'].items():
            assert rid not in seen;seen.add(rid)
            reports[mode]=json.loads(z.read(rid+'/report.json'))
            evaluations[mode]=json.loads(z.read(rid+'/evaluation.json'))
            manifest=json.loads(z.read(rid+'/manifest.json'))
            assert manifest['manual_context']['scenario']==p['scenario']
            assert manifest['manual_context']['pair']==p['pair']
            assert manifest['manual_context']['architecture']==mode
            assert reports[mode]['status']=='complete'
            assert evaluations[mode]['ground_truth_sha256']
        a,b=reports['single'],reports['multiagent'];ea,eb=evaluations['single'],evaluations['multiagent']
        assert ea['ground_truth_sha256']==eb['ground_truth_sha256']
        m=metric(a['metrics']['elapsed_seconds'],b['metrics']['elapsed_seconds'],a['llm']['known_tokens'],b['llm']['known_tokens'],ea['TP'],eb['TP'])
        for key in names:assert math.isclose(m[key],p['metrics_full_precision'][key],rel_tol=1e-10),key
        new_values.append(m)
        if p['in_historic_eligible_positions']:common_values.append(m)
assert len(historic_values)==23 and len(new_values)==25 and len(common_values)==23 and len(seen)==50
result={'archivos_sueltos_verificados':len(integrity['archivos']),'entradas_zip_verificadas':archive_count}
for label,values,expected in [('octubre_23',historic_values,analysis['historical']['means_full_precision']),
                              ('noviembre_25',new_values,analysis['new_campaign']['means_full_precision']),
                              ('noviembre_23_posiciones_comunes',common_values,analysis['common_23_positions']['new_means_full_precision'])]:
    values={k:mean(m[k] for m in values) for k in names}
    for key in names:assert math.isclose(values[key],expected[key],rel_tol=1e-10),key
    result[label]=values
print(json.dumps(result,ensure_ascii=False,indent=2))
