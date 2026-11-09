from pathlib import Path
import json,hashlib,re,xml.etree.ElementTree as ET
out=Path(__file__).resolve().parent;repo=out.parent/'repo'
passed=skipped=subtests=0;skipreasons=[]
for name in ['python-regresion','python-loopback','python-legacy']:
 t=(out/(name+'.log')).read_text();passed+=int(re.search(r'(\d+) passed',t).group(1));m=re.search(r'(\d+) skipped',t);skipped+=int(m.group(1)) if m else 0;m=re.search(r'(\d+) subtests passed',t);subtests+=int(m.group(1)) if m else 0
 x=ET.parse(out/(name+'.xml'))
 for c in x.findall('.//testcase'):
  assert c.find('failure') is None and c.find('error') is None
  if c.find('skipped') is not None:skipreasons.append({'class':c.get('classname'),'name':c.get('name'),'reason':c.find('skipped').get('message')})
assert (passed,skipped,subtests)==(775,2,59),(passed,skipped,subtests)
inputs=json.loads((out/'fuentes-validadas-sha256.json').read_text());drift=[n for n,h in inputs['files'].items() if hashlib.sha256((repo/n).read_bytes()).hexdigest()!=h];assert not drift,drift
blocked=sum(len(f.read_text().splitlines()) for f in out.glob('network-guard*.log'))
js=(out/'javascript-ui-validated.log').read_text();assert re.search(r'pass 4\b',js) and re.search(r'fail 0\b',js)
summary={'valid':True,'date':'2026-11-09','python_passed':passed,'python_skipped':skipped,'python_subtests_passed':subtests,'javascript_tests_passed':4,'external_connections_permitted':False,'connections_outside_loopback_blocked':blocked,'provider_api_calls':0,'experimental_audits_executed':0,'nmap_fixture_invocations':4,'nmap_scope':'Exact TCP profile on 127.0.0.1 and ::1; two ephemeral fixture ports listening on both families; interface lo','source_files_identical_during_validation':len(inputs['files']),'source_changes_detected':drift,'historical_environment_reproduced':False,'skip_reasons':skipreasons,'note':'The total combines the broad run, separately guarded Nmap loopback case and six legacy stub tests. JS dependency bootstrap failure is preserved separately and was resolved by reusing installed dependencies, without changing product code. Unknown asyncio_mode config warning is preserved in all Python runs.'}
(out/'resumen-validacion.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
(out/'LEEME-pruebas.txt').write_text('''VALIDACIÓN DE LA COPIA INTEGRADA PARA PUBLICACIÓN — 9 DE NOVIEMBRE DE 2026

La regresión se ejecutó contra la copia repo/ integrada desde origin/main y los cambios locales. Se conservaron los comandos, las horas, los códigos de salida, los logs y los XML.

Resultados: 775 pruebas Python aprobadas, dos omitidas y 59 subpruebas aprobadas; cuatro pruebas JavaScript DOM aprobadas. Son comprobaciones de software y de fixtures; no son nuevas corridas de la campaña experimental ni consumieron API.

Se ejecutaron tres grupos Python: 768 aprobadas y 57 subpruebas en la batería amplia; una prueba y dos subpruebas de integración TCP en loopback; seis pruebas del grafo anterior con agentes stub. El grupo amplio excluyó expresamente el caso Nmap para ejecutarlo con una guarda separada. No se suman las cuatro pruebas JavaScript al total de auditorías ni de pruebas Python.

Las conexiones Python se limitaron a loopback y se bloquearon los ejecutables reales de Hydra y Docker. El único Nmap real admitido fue el perfil TCP exacto del arnés contra 127.0.0.1 y ::1, en los dos puertos efímeros que atendían las aplicaciones sintéticas. Se registraron las cuatro invocaciones. Los intentos fuera de loopback fueron bloqueados y se registran en network-guard.log; no se permitieron conexiones externas.

El primer intento JavaScript falló por falta de jsdom y de .venv en la copia limpia; javascript-ui.log conserva ese diagnóstico. El intento final usa el node_modules ya instalado y el entorno Python reproducido, con PYTHONPATH apuntando a la copia integrada. No se modificó código para resolver ese problema ambiental.

Se mantiene el aviso de configuración asyncio_mode desconocida en el entorno sin pytest-asyncio; las pruebas seleccionadas no requieren ejecutar corutinas a través de ese complemento. Las dos omisiones se detallan en resumen-validacion.json.

fuentes-validadas-sha256.json identifica 265 archivos fuente/de pruebas; sus hashes seguían idénticos al cerrar esta validación. No se afirma identidad completa con el entorno experimental de octubre.
''')
print(json.dumps(summary,ensure_ascii=False,indent=2))
