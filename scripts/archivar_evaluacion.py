"""Copia y reevalúa una cápsula experimental sin red ni configuración privada."""
import argparse,csv,hashlib,json,shutil,statistics
from pathlib import Path
from auditoria.metrics import summarize_experiment


def dump(path,value):Path(path).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')


def archive(source,out):
    source=Path(source).resolve();out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    for name in ['design.json','policy.json','ground_truth.json','stop.json']:
        if (source/name).exists():shutil.copy2(source/name,out/name)
    attempts=json.loads((source/'attempts.json').read_text())
    for a in attempts:
        if a.get('run_path'):
            run=Path(a['run_path']);run=run if run.is_absolute() else source/run
            target=out/'runs'/run.name
            shutil.copytree(run,target,dirs_exist_ok=True)
            a['run_path']=str(target.relative_to(out))
    dump(out/'attempts.json',attempts)
    evaluation=summarize_experiment(out,out/'ground_truth.json')
    reports={r['audit_id']:json.loads((Path(r['run_path'])/'report.json').read_text()) for r in evaluation['runs'] if r.get('run_path')}
    for row in evaluation['runs']:
        if row.get('run_path'):row['run_path']=str(Path(row['run_path']).relative_to(out))
    for pair in evaluation['pairs']:
        for role in ['single','multiagent']:
            if pair.get(role,{}).get('run_path'):pair[role]['run_path']=str(Path(pair[role]['run_path']).relative_to(out))
    dump(out/'evaluation.json',evaluation)
    csv_fields=['block','order','architecture','status','TP','FP','FN','TN','precision','recall','tokens','cost_estimate_usd','elapsed_seconds','restoration_seconds','completion','run_path']
    with (out/'runs.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=csv_fields,extrasaction='ignore',lineterminator='\n');writer.writeheader();writer.writerows(evaluation['runs'])
    tokens={k:0 for k in ['input_tokens','provider_output_tokens','output_tokens','thought_tokens','cached_tokens','cache_write_tokens','total_tokens']}
    measurable=True;calls=0;known_cost=0.0;models=set();source_hashes=set()
    for audit_id,report in reports.items():
        llm=report['llm'];calls+=sum(bool(c.get('generation_sent')) for c in llm.get('calls',[]))
        measurable=measurable and llm.get('usage_complete',False)
        known_cost+=llm.get('known_cost_estimate_usd',llm.get('cost_estimate_usd') or 0)
        for call in llm.get('calls',[]):
            for key in tokens:
                if isinstance(call.get(key),int):tokens[key]+=call[key]
            if call.get('response_model'):models.add(call['response_model'])
    for a in attempts:
        if a.get('run_path'):source_hashes.add(json.loads((out/a['run_path']/'manifest.json').read_text())['source_sha256'])
    summary={'runs_started':evaluation['runs_started'],'runs_planned':evaluation['runs_planned'],'pairs_eligible':evaluation['pairs_eligible'],
        'formal_cohort_complete':evaluation['formal_cohort_complete'],'pilot':evaluation.get('pilot'),'generation_calls':calls,
        'tokens':tokens,'usage_complete':measurable,'known_cost_estimate_usd':round(known_cost,8),
        'cost_estimate_usd':round(known_cost,8) if measurable else None,'reported_models':sorted(models),'source_hashes':sorted(source_hashes),
        'analysis':evaluation['analysis'],'note':'Cápsula portable revalidada sin llamadas API; cifras son del banco finito, no de producción.'}
    dump(out/'resumen.json',summary)
    lines=['# Evaluación del prototipo con API real','',
        f"Corridas iniciadas: **{evaluation['runs_started']}/{evaluation['runs_planned']}**. Parejas aptas: **{evaluation['pairs_eligible']}**. Cohorte completa: **{evaluation['formal_cohort_complete']}**. Piloto: **{evaluation.get('pilot')}**.",'',
        f"Generaciones API: {calls}; tokens conocidos: {tokens['total_tokens']}; costo conocido estimado: USD {known_cost:.6f}. Uso completo: {measurable}.",'',
        '| Arquitectura | n | TP | FP | FN | TN | Tiempo medio s | Mediana s | Tokens medios |',
        '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for arch in ['single','multiagent']:
        rows=[r for r in evaluation['runs'] if r['architecture']==arch]
        times=[r['elapsed_seconds'] for r in rows if r.get('status')=='complete' and r.get('elapsed_seconds') is not None]
        used=[r['tokens'] for r in rows if r.get('tokens') is not None]
        mean=f'{statistics.mean(times):.3f}' if times else 'no definido'
        median=f'{statistics.median(times):.3f}' if times else 'no definido'
        avg=f'{statistics.mean(used):.1f}' if used else 'no definido'
        lines.append(f"| {arch} | {len(rows)} | {sum(r.get('TP',0) for r in rows)} | {sum(r.get('FP',0) for r in rows)} | {sum(r.get('FN',0) for r in rows)} | {sum(r.get('TN',0) for r in rows)} | {mean} | {median} | {avg} |")
    lines+=['','Los TP acumulados son detecciones repetidas de las mismas condiciones, no vulnerabilidades distintas. La población y las etiquetas se conservan en ground_truth.json y permanecen fuera de los prompts.','',
        '| Indicador | Pares definidos | Media por pareja | IC bootstrap exploratorio 95 % |','| --- | ---: | ---: | --- |']
    for key,stats in evaluation['analysis'].items():
        value=stats['mean'];ci=stats['paired_bootstrap_CI95']
        lines.append(f"| {key} | {stats['n_defined']} | {value if value is not None else 'no definido'} | {ci if ci else 'no estimado'} |")
    lines+=['','La diferencia emparejada de recall es la variable primaria; los indicadores de tiempo y tokens son secundarios. Las metas iniciales son TRTO ≥30 %, IDE ≥20 % y ETV ≥1,10; completar el software no acredita alcanzarlas. Los efectos de confianza NA comparten supuestos del protocolo: el conteo describe condiciones operativas, no nueve CVE o causas demostradas independientes.','',
        '[Resumen de uso y versiones](resumen.json), [evaluación de todos los intentos](evaluation.json), [datos por corrida](runs.csv), [orden predefinido](design.json).','',
        'Cada carpeta de runs conserva solicitud, política, plan, manifiesto, eventos SQLite, evidencias, JSON, HTML y PDF. Los hashes comprueban integridad respecto de las referencias conservadas; no son una firma externa. Los archivos de configuración privada y claves no se incluyen.','',
        'Desde piloto_kali/prototipo puede recalcularse la cápsula sin API con `auditoria evaluar-experimento RUTA_DE_CAPSULA`. La restauración previa se mide por separado. El estudio usa Docker y el kernel compartido de Kali; no certifica sistemas heterogéneos, SEND, RA Guard de hardware o redes de producción.','',
        '[Tarifas oficiales del modelo](https://developers.openai.com/api/docs/models/gpt-6.1-sol). La estimación distingue entrada, salida facturable incluido razonamiento y caché; no sustituye la factura.']
    (out/'README.md').write_text('\n'.join(lines)+'\n')
    hashes={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.json'}
    dump(out/'SHA256SUMS.json',hashes)
    print(json.dumps(summary,ensure_ascii=False))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--entrada',required=True);p.add_argument('--salida',required=True)
    a=p.parse_args();archive(a.entrada,a.salida)
