#!/usr/bin/env python3
"""Verifica el suplemento CI con biblioteca estándar, sin red ni herramientas."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,xml.etree.ElementTree as ET

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def file(root,name):
 parts=PurePosixPath(name)
 if not parts.parts or parts.is_absolute() or '..' in parts.parts or '\\' in name or '\x00' in name:raise ValueError('Ruta fuera de alcance')
 path=root/Path(*parts.parts)
 if not path.resolve().is_relative_to(root.resolve()) or any((root/Path(*parts.parts[:i])).is_symlink() for i in range(1,len(parts.parts)+1)) or not path.is_file():raise ValueError('Ruta o enlace no admitido')
 return path

def junit(path,expected=None):
 root=ET.fromstring(path.read_bytes());cases=list(root.iter('testcase'));skip=sum(case.find('skipped') is not None for case in cases);fail=sum(case.find('failure') is not None or case.find('error') is not None for case in cases);total=sum(int(s.attrib['tests']) for s in root.iter('testsuite'));result={'passed':len(cases)-skip,'subtests':total-len(cases),'skipped':skip}
 if fail or expected is not None and tuple(result.values())!=expected:raise ValueError('JUnit no aprobado')
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--solo-paquete',action='store_true');args=parser.parse_args();here=Path(__file__).resolve().parent
 manifest=json.loads((here/'integridad.json').read_text());names=[row['path'] for row in manifest['files']]
 if len(names)!=len(set(names)):raise ValueError('Inventario duplicado')
 actual={p.relative_to(here).as_posix() for p in here.rglob('*') if p.is_file() or p.is_symlink()}
 if actual-set(names)-{'integridad.json','verificacion-publica.json'} or any(p.is_symlink() for p in here.rglob('*')):raise ValueError('Archivo no inventariado o enlace')
 for row in manifest['files']:
  p=file(here,row['path'])
  if p.suffix.lower() in {'.doc','.docx','.docm','.pdf','.pem','.key'} or p.name=='.env':raise ValueError('Archivo privado')
  if p.stat().st_size!=row['bytes'] or sha(p)!=row['sha256']:raise ValueError('Bytes alterados')
 sources=json.loads(file(here,'fuentes-aprobadas.json').read_text())
 for row in sources['files']:
  p=file(here,row['path'])
  if p.stat().st_size!=row['public_bytes'] or sha(p)!=row['public_sha256']:raise ValueError('Proyección alterada')
 status=json.loads(file(here,'estado-suplemento.json').read_text());source=json.loads(file(here,'fuentes-compatibilidad.json').read_text());diagnosis=json.loads(file(here,'recibos/diagnostico-umask-autorizacion.json').read_text());prior=json.loads(file(here,'diagnostico-fallos-ci-previos.json').read_text())
 if status['application_logic_changed'] or not status['hydra_execution_still_blocked'] or status['new_audits']!=0 or status['provider_calls']!=0 or status['new_kpi_campaign']:raise ValueError('Alcance contradictorio')
 if status['subsequent_remote_ci_result']!='not_accredited_by_this_supplement':raise ValueError('Este recibo no acredita CI remota posterior')
 if status['fix_commit']!=source['fix_commit'] or status['baseline_commit']!=source['baseline_commit'] or source['runtime_application_changes'] is not False or source['hydra_execution_still_blocked'] is not True:raise ValueError('Fuente distinta')
 runtime=[row for row in source['files'] if row['path']=='scripts/autorizacion_personal.py'];assert len(runtime)==1
 if runtime[0]['before_sha256']!=runtime[0]['after_sha256'] or runtime[0]['after_sha256']!=diagnosis['source_sha256']:raise ValueError('Control no preservado')
 cases=diagnosis['rows'];combinations={(r['parent_kind'],r['umask'],r['explicit_chmod']) for r in cases};expected={(p,u,c) for p in ['sticky_tmp','private_home'] for u in ['0002','0022','0077'] for c in [False,True]}
 if len(cases)!=12 or combinations!=expected:raise ValueError('Matriz umask incompleta')
 for row in cases:
  mode='0770' if row['explicit_chmod'] or row['umask']=='0002' else '0750' if row['umask']=='0022' else '0700';denied=mode=='0770'
  if row['actual_ancestor_mode']!=mode or row['rejected']!=denied or row['registry_created']==denied or row['reason']!=('authorization_registry_unsafe' if denied else None):raise ValueError('Diagnóstico umask contradictorio')
 if len(prior['failed_cases'])!=7 or sum(r['cause']=='hydra_binary_missing' for r in prior['failed_cases'])!=6 or prior['private_log_copied'] is not False:raise ValueError('Fallo anterior distinto')
 directed=junit(file(here,'recibos/correccion-ci-dirigida.xml'),(43,0,0));full=None
 if status['clean_clone_ci_like_receipt_included']:
  summary=json.loads(file(here,'recibos/clon-ci05/summary.json').read_text())
  if summary['status']!='passed':raise ValueError('Clon local no aprobado')
  full=junit(file(here,'recibos/clon-ci05/prototype-junit.xml'),(1166,112,2))
  if summary['source_commit']!=source['fix_commit'] or summary['commands']!=19 or not summary['fresh_clone'] or not summary['frozen_dependencies'] or summary['production_contacted']:raise ValueError('Clon distinto de la corrección')
  commands=json.loads(file(here,'recibos/clon-ci05/commands.json').read_text())
  if len(commands)!=19 or not all(row['exit_code']==0 for row in commands):raise ValueError('Comandos de clon incompletos')
  if len([row for row in commands if row['name']=='prototype-tests' and 'coverage' in row['argv']])!=1:raise ValueError('Comando de cobertura ausente')
  coverage=json.loads(file(here,'recibos/clon-ci05/coverage.json').read_text());totals=coverage['totals']
  if (totals['covered_lines'],totals['num_statements'],totals['missing_lines'])!=(3392,5382,1990) or totals['percent_covered_display']!='63' or abs(totals['percent_covered']-3392/5382*100)>1e-10 or coverage['meta']['branch_coverage'] is not False:raise ValueError('Cobertura distinta de la aprobada')
  if len(coverage['files'])!=36 or any(not name.startswith('piloto_kali/prototipo/src/auditoria/') for name in coverage['files']):raise ValueError('Ámbito de cobertura distinto')
  junit(file(here,'recibos/clon-ci05/legacy-junit.xml'),(6,0,0))
  browser=json.loads(file(here,'recibos/clon-ci05/browser/summary.json').read_text())
  if browser['status']!='passed' or browser['local_assets_loaded']!=7 or any(browser[k]!=0 for k in ['page_errors','external_requests_attempted','audit_requests_sent','provider_requests_sent']) or browser['private_configuration_used']:raise ValueError('Navegador fuera del alcance')
 preserved=False
 if not args.solo_paquete:
  previous=json.loads(file(here,'conservacion-v4.json').read_text());p=file(here.parents[2],previous['path'])
  if sha(p)!=previous['sha256']:raise ValueError('Manifiesto v4 histórico alterado')
  preserved=True
 print(json.dumps({'integrity_verified':True,'directed_tests':directed,'umask_diagnostic_cases':12,'application_logic_changed':False,'frozen_v4_manifest_preserved':preserved,'local_ci_like_regression':full,'subsequent_remote_ci_pass_claimed':False,'coverage':{'scope':'piloto_kali/prototipo/src/auditoria','covered':3392,'statements':5382,'missing':1990,'percent':63.024897807506505,'scripts_included':False,'branches_measured':False},'phase_counts_are_not_additive':True,'verification_actions':{'network':False,'new_audits':False,'external_tools':False,'archive_extraction':False}},ensure_ascii=False))

if __name__=='__main__':main()
