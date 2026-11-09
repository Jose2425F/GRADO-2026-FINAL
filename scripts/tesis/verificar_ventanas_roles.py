"""Cotejo del selftest con registros independientes de broker y trabajadores."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def _read(path,owner=0):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>32_000_000:
            raise ValueError('Archivo de evidencia no admitido: '+str(path))
        with os.fdopen(fd,'rb',closefd=False) as stream:return stream.read()
    finally:os.close(fd)


def verify(base,run_id,output):
    if not re.fullmatch(r'\d{8}T\d{6}Z-(?:integrado|sucursal|comercial|mixto|reforzado)-[0-9a-f]{8}',run_id):
        raise ValueError('Identificador de ejecución no válido.')
    base=Path(base);private=base/'private'/run_id;runroot=base/'runtime'/run_id
    operator_raw=_read(private/'role-negative-operator.json');operator=json.loads(operator_raw)
    controller_raw=_read(runroot/'output/role-negative-controller.json',65531);controller=json.loads(controller_raw)
    descriptor=json.loads(_read(runroot/'descriptor.json'))
    logs={}
    for role,path,owner in [('broker',private/'broker-audit.jsonl',0),('nmap',runroot/'nmap/audit.jsonl',65532),('hydra',runroot/'hydra/audit.jsonl',65533)]:
        logs[role]=[json.loads(line) for line in _read(path,owner).decode().splitlines() if line.strip()]
    forbidden={'admitted','tool_started','tool_finished','tool_identity','child_identity','tool_child_identity'}
    windows={}
    for name,start,end in [('operator',operator['log_window']['started_at'],operator['log_window']['ended_at']),
                           ('principal',controller['started_at'],controller['ended_at'])]:
        selected={role:[r for r in rows if start<=r.get('time',0)<=end] for role,rows in logs.items()}
        windows[name]={'started_at':start,'ended_at':end,'events':selected,
            'counts':{role:dict(Counter(r.get('event') for r in rows)) for role,rows in selected.items()},
            'unexpected_execution_events':[{'role':role,**row} for role,rows in selected.items() for row in rows if row.get('event') in forbidden]}
    tests=controller['tests'];reasons=Counter(t['reason'] for t in tests)
    own=controller['identity'];principal=descriptor['principal']
    identity_ok=(own['pid']==principal['pid'] and own['start_time']==principal['start_time'] and own['netns']==descriptor['audit_netns']
        and own['Uid'].split()==['65531']*4 and own['Gid'].split()==['65531']*4 and not own['Groups']
        and own['NoNewPrivs']=='1' and all(int(own[k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']))
    expected_counts={'broker':5,'nmap':3,'hydra':3}
    log_counts_ok=all(len(windows['principal']['events'][role])==count and
        all(row.get('event')==('rejected' if role=='broker' else 'request_denied') and
            row.get('reason')==('broker_operation_denied' if role=='broker' else 'worker_profile_denied')
            for row in windows['principal']['events'][role]) for role,count in expected_counts.items())
    operator_tests=[row for probe in operator['probes'] for row in probe['tests']]
    saved=next(probe for probe in operator['probes'] if probe['name']=='saved-root-id-with-zero-capabilities')['identity']
    saved_ok=(saved['Uid'].split()==['65531','65531','0','65531'] and saved['Gid'].split()==['65531','65531','0','65531']
        and saved['NoNewPrivs']=='1' and all(int(saved[k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']))
    report={'schema':'centinela-role-window-verification/1','run_id':run_id,'bank':descriptor['bank'],
        'principal_identity':own,'principal_identity_matches_descriptor':identity_ok,
        'principal_negative_tests':len(tests),'principal_rejection_reasons':dict(reasons),
        'principal_negative_cases':[{'name':r['name'],'reason':r['reason'],'passed':r['passed']} for r in tests],
        'principal_log_counts_exact_5_3_3':log_counts_ok,
        'operator_ipc_and_descriptor_tests':len(operator_tests),'operator_missing_gate_test':operator['missing_gate']['passed'],
        'operator_negative_tests_total':len(operator_tests)+1,'operator_saved_root_identity':saved,
        'operator_saved_ids_nonzero_privilege_risk_measured':saved_ok,
        'operator_negative_cases':[{k:r.get(k) for k in ['name','expected','error','errno','passed','response']} for r in operator_tests],
        'windows':windows,'api_calls':0,
        'selftest_sha256':{'operator':hashlib.sha256(operator_raw).hexdigest(),'principal':hashlib.sha256(controller_raw).hexdigest()},
        'evidence_limit':'Cero eventos de admisión o lanzamiento en las rutas instrumentadas durante las ventanas negativas; no es una captura global de syscalls.'}
    report['passed']=(operator.get('passed') is True and controller.get('passed') is True and identity_ok and saved_ok
        and len(operator_tests)==14 and operator['missing_gate']['passed'] and len(tests)==11
        and reasons==Counter({'broker_operation_denied':5,'worker_profile_denied':6}) and log_counts_ok
        and not any(w['unexpected_execution_events'] for w in windows.values()))
    Path(output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--base',required=True,type=Path)
    parser.add_argument('--run-id',required=True);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();report=verify(args.base,args.run_id,args.output)
    print(json.dumps({'passed':report['passed'],'operator_negatives':report['operator_negative_tests_total'],'principal_negatives':report['principal_negative_tests']}))
    if not report['passed']:raise SystemExit(1)
