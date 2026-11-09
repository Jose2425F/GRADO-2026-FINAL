#!/usr/bin/env python3
"""Verifica recibos v4 y sus referencias con biblioteca estándar y sin red."""
from pathlib import Path,PurePosixPath
import argparse,collections,hashlib,json,re,stat,xml.etree.ElementTree as ET,zipfile


def relative(name):
    path=PurePosixPath(name)
    if not path.parts or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
        raise ValueError('Localizador fuera de alcance')
    return path


def local_file(root,name):
    parts=relative(name).parts;path=root/Path(*parts)
    if not path.resolve().is_relative_to(root.resolve()) or any((root/Path(*parts[:n])).is_symlink() for n in range(1,len(parts)+1)):
        raise ValueError('No se admiten enlaces o rutas externas')
    if not path.is_file():raise ValueError('Falta archivo: '+name)
    return path


def sha_file(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):digest.update(block)
    return digest.hexdigest()


def check_junit(path,passed,subtests=0,skipped=0):
    data=ET.fromstring(path.read_bytes());cases=list(data.iter('testcase'));suites=list(data.iter('testsuite'))
    skip=sum(case.find('skipped') is not None for case in cases)
    failed=sum(case.find('failure') is not None or case.find('error') is not None for case in cases)
    count=sum(int(suite.attrib['tests']) for suite in suites)
    if failed or (len(cases)-skip,count-len(cases),skip)!=(passed,subtests,skipped):
        raise ValueError('JUnit no coincide con la fase aprobada: '+str(path.name))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path)
    parser.add_argument('--solo-paquete',action='store_true')
    parser.add_argument('--permitir-pendientes',action='store_true')
    args=parser.parse_args();here=Path(__file__).resolve().parent
    repo=(args.repo or (here if args.solo_paquete else here.parents[2])).resolve()
    manifest=json.loads((here/'integridad-publicacion.json').read_text());names=[row['path'] for row in manifest['files']]
    if len(names)!=len(set(names)):raise ValueError('Inventario duplicado')
    actual={path.relative_to(here).as_posix() for path in here.rglob('*') if path.is_file() or path.is_symlink()}
    if actual-set(names)-{'integridad-publicacion.json','verificacion-publica.json'}:raise ValueError('Archivo no inventariado')
    if any(path.is_symlink() for path in here.rglob('*')):raise ValueError('No se admiten enlaces')
    for row in manifest['files']:
        path=local_file(here,row['path'])
        if path.suffix.lower() in {'.doc','.docx','.docm','.dotx','.dotm','.key','.pem'} or path.name=='.env':raise ValueError('Archivo privado no admitido')
        if path.stat().st_size!=row['bytes'] or sha_file(path)!=row['sha256']:raise ValueError('Archivo alterado: '+row['path'])
    approved=json.loads((here/'fuentes-aprobadas.json').read_text())
    for row in approved['files']:
        path=local_file(here,row['path'])
        if path.stat().st_size!=row['public_bytes'] or sha_file(path)!=row['public_sha256']:raise ValueError('Copia pública alterada')
    status=json.loads((here/'estado-publicacion.json').read_text());phases=status['phases']
    check_junit(local_file(here,phases['operator-panel-unit']['evidence']),56)
    check_junit(local_file(here,phases['installer-unit']['evidence']),43)
    provider=json.loads(local_file(here,phases['provider-unit']['evidence']).read_text())
    if provider['result']!='101 passed in 2.62s' or provider['paid_api_calls']!=0 or len(provider['files'])!=7:
        raise ValueError('Recibo resumido del proveedor distinto')
    for value in phases.values():
        if 'junit' in value:
            junit=value['junit'];check_junit(local_file(here,junit['path']),junit['passed'],junit.get('subtests',0),junit.get('skipped',0))
    if phases['stage']['status']=='accepted_with_explicit_limits':
        stage=json.loads(local_file(here,'recibos/stage03/resumen-instalacion-actual.json').read_text())
        stage_manifest=json.loads(local_file(here,'recibos/stage03/manifest.json').read_text())
        source_map=local_file(here,'recibos/stage03/runtime-source-map.json')
        if len(json.loads(source_map.read_text()))!=341 or sha_file(source_map)!=stage['runtime_source_map_sha256']:
            raise ValueError('Mapa del stage distinto')
        if set(stage_manifest['exact_allowlist'])!={row['path'] for row in stage_manifest['files']}:
            raise ValueError('Proyección stage fuera de allowlist')
        public_origins={row['path']:row for row in approved['files']}
        for row in stage_manifest['files']:
            if public_origins['recibos/stage03/'+row['path']]['origin_sha256']!=row['public_sha256']:
                raise ValueError('Cadena de copia stage alterada')
        acceptance=stage['current_canonical_acceptance'];evaluation=acceptance['assessment']
        if (stage['bootstrap']['containers']!=56 or stage['protected_preflights']['all_passed'] is not True
                or len(stage['protected_preflights']['banks'])!=5 or stage_manifest['provider_role_measured_in_this_single32_cut'] is not False
                or acceptance['banks']!=['integrado'] or acceptance['architecture']!='single'
                or acceptance['tasks']!=32 or acceptance['api_calls']!=0 or acceptance['controller_exit_code']!=0
                or (evaluation['TP'],evaluation['FP'],evaluation['FN'],evaluation['TN'],evaluation['tasks_valid'])!=(13,0,0,11,32)):
            raise ValueError('Alcance stage contradictorio')
    if phases['api']['status']=='accepted_with_explicit_limits':
        shadow=json.loads(local_file(here,'recibos/webshadow/webshadow-02-publico.json').read_text())
        checks={row['check']:row for row in shadow['results']['checks']}
        api=checks['bounded_api_audit_closed'];none=checks['protected_none_audit_closed']
        if shadow['results']['status']!='passed' or not all(row['passed'] for row in checks.values()):
            raise ValueError('Integración web no aprobada')
        if (none['tasks_total'],none['api_calls'],api['generation_calls'],api['known_tokens'],api['accepted_decisions'],api['provider_uid'])!=(32,0,14,11381,14,65530) or api['usage_complete'] is not True:
            raise ValueError('Integración API distinta')
        meta=json.loads(local_file(here,'recibos/webshadow/webshadow-metadatos03-publico.json').read_text())['results']
        if (meta['status']!='passed' or meta['new_audits']!=0 or meta['generation_calls']!=0
                or meta['original_report_file_count']!=179 or meta['original_reports_unchanged'] is not True
                or meta['source_summary_sha256']!=shadow['origin_sha256']):
            raise ValueError('Reapertura de los mismos datos no acreditada')
    if phases['deployment']['status']=='accepted_with_explicit_limits':
        dep=json.loads(local_file(here,'recibos/despliegue/deployment-02-publico.json').read_text())['results']
        https=json.loads(local_file(here,'recibos/despliegue/https-101912-publico.json').read_text())['results']
        before=json.loads(local_file(here,'recibos/despliegue/deployment-intento01-publico.json').read_text())['results']
        expected_web='73022090c5d989012f32cccfbfad554eb92f9501'
        expected_executor='a6b2188330772368bb78ba57d1aea3f7f73793f7'
        ident=dep['web_identity']
        if (dep['status']!='passed' or dep['web_commit']!=expected_web or dep['executor_commit']!=expected_executor
                or dep['original_run_files']!=4239 or dep['users_at_copy']!=2
                or dep['original_run_hashes_still_equal'] is not True or dep['original_data_retained'] is not True
                or dep['original_runs_retained'] is not True or dep['rollback_required'] is not False
                or any(dep[k] for k in ['nginx_changed','global_docker_changed','host_rebooted'])
                or set(ident['Uid'].split())!={'65529'} or set(ident['Gid'].split())!={'65529'}
                or int(ident['CapEff'],16)!=0 or int(ident['CapAmb'],16)!=0 or ident['NoNewPrivs']!='1'):
            raise ValueError('Despliegue final contradictorio')
        if (https['status']!='passed' or https['tls_certificate_verification'] is not True
                or not all(https[k] is True for k in ['anonymous_state_denied','login','admin_role','authenticated_state','idle_at_validation','logout_revokes_session'])
                or https['audit_requests_sent']!=0 or https['provider_requests_sent']!=0
                or len(https['assets'])!=6 or https['existing_runs_visible']!=55
                or len(https['historical_report_checks'])!=2
                or not all(row['status']==200 for row in https['historical_report_checks'])
                or before['status']!='failed' or before['rollback_old_panel_active'] is not True):
            raise ValueError('Comprobación HTTPS o conservación de intento previo distinta')
        source=json.loads(local_file(here,'recibos/web730/cotejo-con-ejecutor.json').read_text())
        web=json.loads(local_file(here,'recibos/despliegue/web-release-730-publico.json').read_text())['results']
        stage_map=json.loads(local_file(here,'recibos/stage03/runtime-source-map.json').read_text())
        delta=set(source['changed_tracked_paths'])
        if (source['source_commit']!=expected_web or source['executor_source_commit']!=expected_executor
                or source['web_files_sha256_matched_git_blobs']!=615 or len(web['files'])!=615
                or source['stage_map_files_identical_to_executor_git']!=337
                or delta!=set(web['delta_from_executor']) or len(delta)!=4
                or any(web['files'][name]!=expected for name,expected in stage_map.items() if name not in delta)
                or source['protected_controller_worker_proxy_filter_installer_changes']):
            raise ValueError('Identidad de componentes contradictoria')
        # The HTTPS asset digest is tied to the final immutable source, rather than
        # accepted solely because a receipt happened to report HTTP200.
        for asset in https['assets']:
            name=asset['url'].split('?',1)[0].lstrip('/')
            if web['files']['scripts/dualstack_ui/'+name]!=asset['sha256']:
                raise ValueError('Recurso HTTPS distinto del corte web final')
        probe=json.loads(local_file(here,'recibos/despliegue/diagnostico-netlink-permisos-publico.json').read_text())['results']['after']
        if (probe['uid']!=65529 or probe['NoNewPrivs']!='1'
                or any(int(probe[k],16) for k in ['CapEff','CapBnd','CapAmb'])
                or probe['ipv6_raw_denied_errno']!=1 or probe['docker_private_denied_errno']!=13):
            raise ValueError('Sondeo de sandbox temporal distinto')
    if phases.get('production-restore-check',{}).get('status')=='passed':
        control=json.loads(local_file(here,'recibos/despliegue/control-https-postdeploy-publico.json').read_text())
        preflight=control['operator_preflight'];checks={row['check']:row for row in control['checks']}
        if (control['status']!='passed' or control['tls_certificate_verification'] is not True
                or control['audit_requests_sent']!=0 or control['provider_requests_sent']!=0
                or control['initial_run_count']!=55 or control['bank']!='integrado'
                or not all(row['passed'] for row in checks.values())
                or checks['protected_bank_ready']['run_count']!=55
                or checks['protected_bank_ready']['audit_run_count_unchanged'] is not True
                or checks['check']['lab_status']!='ready'
                or any(checks[k]['status']!='complete' or checks[k]['global_busy_after'] is not False for k in ['restore','check'])
                or preflight['exit_code']!=0 or preflight['api_calls']!=0 or preflight['catalogue_tasks']!=0
                or preflight['roles_stopped_before_evaluation'] is not True):
            raise ValueError('Control HTTPS posterior contradictorio')
        for role,uid in {'controller':65531,'nmap':65532,'hydra':65533,'broker':0}.items():
            identity=preflight['identities'][role]
            if (set(identity['Uid'].split())!={str(uid)} or identity['Groups']!='' or identity['NoNewPrivs']!='1'
                    or any(int(identity[key],16)!=0 for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])):
                raise ValueError('Identidad de rol posterior distinta')
    for value in phases.values():
        if 'evidence' in value:local_file(here,value['evidence'])
    index=json.loads((here/'indice-kpi-historicos.json').read_text())
    if len(index['corridas'])!=100 or [row['parejas'] for row in index['resultados_registrados']]!=[23,25,23]:raise ValueError('Índice histórico incompleto')
    checked_archives=checked_members=0
    if not args.solo_paquete:
        for row in json.loads((here/'conservacion-anteriores.json').read_text())['files']:
            path=local_file(repo,row['path'])
            if path.stat().st_size!=row['bytes'] or sha_file(path)!=row['sha256']:raise ValueError('Versión anterior alterada: '+row['path'])
            checked_archives+=1
        for row in index['fuentes']:
            path=local_file(repo,row['ruta']);expected=row.get('sha256_original_registrado')
            if expected and sha_file(path)!=expected:raise ValueError('Fuente del índice alterada: '+row['ruta'])
        grouped=collections.defaultdict(dict)
        for run in index['corridas']:
            for family,value in run['familias'].items():
                for item in value if isinstance(value,list) else [value]:
                    name=item['miembro_zip'];relative(name)
                    expected=item['sha256_original_registrado']
                    if name in grouped[run['archivo_zip']] and grouped[run['archivo_zip']][name]!=expected:raise ValueError('Hash contradictorio')
                    grouped[run['archivo_zip']][name]=expected
        for name,rows in grouped.items():
            with zipfile.ZipFile(local_file(repo,name)) as archive:
                infos=archive.infolist();available={info.filename:info for info in infos}
                if len(available)!=len(infos):raise ValueError('ZIP con nombres duplicados')
                for member,expected in rows.items():
                    info=available[member]
                    if info.file_size>32*1024*1024 or stat.S_ISLNK(info.external_attr>>16):raise ValueError('Miembro histórico fuera de alcance')
                    if hashlib.sha256(archive.read(member)).hexdigest()!=expected:raise ValueError('Miembro histórico alterado')
                    checked_members+=1
    pending=[name for name,value in phases.items() if value['status'] not in {'passed','passed_summary_receipt','accepted','accepted_with_explicit_limits'}]
    complete=not pending
    if complete!=status['publication_complete'] or complete!=manifest['publication_complete']:raise ValueError('Cierre contradictorio')
    print(json.dumps({'integrity_verified':True,'publication_complete':complete,'pending':pending,'publication_files':len(names),
        'previous_archives_checked':checked_archives,'historical_members_checked':checked_members,
        'phase_counts_are_not_additive':True,'historical_kpis_recomputed':False,
        'verification_actions':{'new_audits':False,'network':False,'tools_executed':False,'archives_extracted':False}},ensure_ascii=False))
    if pending and not args.permitir_pendientes:raise SystemExit(3)


if __name__=='__main__':main()
