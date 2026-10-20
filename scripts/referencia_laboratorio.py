"""Referencia privada del evaluador para laboratorios por IP. Nunca entra al LLM."""
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]/'piloto_kali/prototipo/.lab/evaluation_refs'
CONDITIONS={'object_authorization','file_boundary','ipv6_authorization_gap','ssh_default_credential',
            'ftp_default_credential','postgres_default_credential','http_get_default_credential'}


def save_reference(value,root=None):
    from laboratorio_personal import address_scope
    root=root or ROOT
    if not isinstance(value,dict) or set(value)!={'name','cases'}:raise ValueError('Indica nombre y condiciones de referencia.')
    name=value['name'];cases=value['cases']
    if not isinstance(name,str) or not 1<=len(name.strip())<=60 or not all(c.isprintable() for c in name):raise ValueError('El nombre de referencia debe tener entre 1 y 60 caracteres.')
    if not isinstance(cases,list) or not 1<=len(cases)<=128:raise ValueError('Declara entre 1 y 128 condiciones conocidas del laboratorio.')
    normalized=[];seen=set()
    for case in cases:
        if not isinstance(case,dict) or set(case)!={'address','port','condition','expected'}:raise ValueError('Cada caso requiere IP, puerto, prueba y estado esperado.')
        if not isinstance(case['address'],str):raise ValueError('Usa IP literales para las condiciones de referencia.')
        try:address=ip_address(case['address'])
        except (ValueError,TypeError):raise ValueError('Usa IP literales para las condiciones de referencia.') from None
        address_scope(str(address),address.version)
        if type(case['port']) is not int or not 1<=case['port']<=65535:raise ValueError('El puerto debe estar entre 1 y 65535.')
        if not isinstance(case['condition'],str) or not isinstance(case['expected'],str) or case['condition'] not in CONDITIONS or case['expected'] not in {'present','absent'}:raise ValueError('Selecciona una prueba admitida y si la condición está presente o protegida.')
        key=(str(address),case['port'],case['condition'])
        if key in seen:raise ValueError('No repitas la misma IP, puerto y condición.')
        seen.add(key);normalized.append({**case,'address':str(address)})
    record={'version':1,'id':uuid4().hex,'name':name.strip(),'created_at':datetime.now(timezone.utc).isoformat(),
            'cases':sorted(normalized,key=lambda c:(c['address'],c['port'],c['condition']))}
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    data=json.dumps(record,sort_keys=True,ensure_ascii=False).encode()
    descriptor=os.open(root/(record['id']+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as stream:stream.write(data)
    return metadata(record,data)


def metadata(record,data):return {k:record[k] for k in ['id','name','created_at']}|{'cases':len(record['cases']),'sha256':hashlib.sha256(data).hexdigest()}


def load_reference(key,root=None):
    root=root or ROOT
    if not isinstance(key,str) or not re.fullmatch(r'[a-f0-9]{32}',key):raise ValueError('Referencia no disponible.')
    path=root/(key+'.json')
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size>100000:raise ValueError('Referencia no disponible o sin permisos privados.')
    data=path.read_bytes();record=json.loads(data)
    if not isinstance(record,dict) or record.get('id')!=key or record.get('version')!=1 or not isinstance(record.get('cases'),list):raise ValueError('Referencia inválida.')
    return record,metadata(record,data)


def list_references(root=None):
    root=root or ROOT;rows=[]
    def modified(path):
        try:return path.stat().st_mtime
        except OSError:return 0
    for path in sorted(root.glob('*.json'),key=modified,reverse=True)[:50]:
        try:_,row=load_reference(path.stem,root);rows.append(row)
        except (OSError,ValueError,KeyError):continue
    return rows


def observations(directory,request,plan,report):
    """Re-adjudica offline las evidencias; no confía en editar findings de report.json."""
    from aplicaciones_personales import ApplicationTask,adjudicate_application,PROFILE
    from auditoria.contracts import Task,TaskResult,CredentialProfile,LabPolicy,LabSegment,Category
    from auditoria.validation import validate_results
    from auditoria.findings import access_is_verified
    from laboratorio_personal import DEFAULT_CREDENTIALS,SWEEP_ENV
    found=set();checked=set();attempts={};integrity=True;by_id={r.get('task_id'):r for r in report.get('tasks',[]) if isinstance(r,dict)}
    for raw in plan:
        result=by_id.get(raw.get('task_id'))
        if not result:continue
        try:
            result=TaskResult.model_validate(result)
            if raw.get('action_profile')==PROFILE:
                task=ApplicationTask.model_validate(raw);app=request.get('applications',[])[task.application_index]
                findings,validation=adjudicate_application(directory,task,result,app)
                if not validation.get('independent_confirmation'):integrity=False
                for finding in findings:found.add((finding['address'],app['port'],finding['condition']))
                if validation.get('independent_confirmation'):
                    for family,checks in validation.get('checks_by_family',{}).items():
                        for condition,state in checks.items():
                            if state in {'confirmed','not_detected'}:checked.add((app[family],app['port'],condition))
            elif str(raw.get('action_profile','')).startswith('hydra_'):
                task=Task.model_validate(raw);port=task.target.ports[0]
                service=next((s for s in DEFAULT_CREDENTIALS if task.action_profile=='hydra_'+s.replace('-','_')+'_single_v1'),None)
                if service is None or ip_address(task.target.address).version!=4 or len(task.target.ports)!=1:continue
                prefix='default_'+service.replace('-','_')+'_'+str(port)+'_';ref=task.target.credential_ref
                if not isinstance(ref,str) or not ref.startswith(prefix):continue
                index=int(ref.removeprefix(prefix))
                if not 0<=index<len(DEFAULT_CREDENTIALS[service]):continue
                username,_=DEFAULT_CREDENTIALS[service][index]
                profile=CredentialProfile(ref=ref,service=service,port=port,username=username,password_env=SWEEP_ENV,condition='default_credential')
                validation=validate_results(directory,[task],[result])[0]
                if validation.get('evidence_integrity',{}).get('valid') is not True:integrity=False
                policy=LabPolicy(policy_id='personal-credentials',segments=[LabSegment(name='host',network=task.target.address+'/32',interface=task.target.interface,allowed_ports=[port])],allowed_categories=[Category.IPV4_CREDENTIALS],credential_profiles=[profile])
                verified=access_is_verified(directory,policy,task,result,validation)
                key=(task.target.address,port,service.replace('-','_')+'_default_credential')
                if verified:found.add(key);checked.add(key)
                attempts.setdefault(key,{'service':service,'indices':{}})['indices'][index]=bool(result.status.value=='completed_no_findings' and result.authentication and result.authentication.outcome=='rejected' and validation.get('state')!='indeterminate')
        except (OSError,ValueError,KeyError,TypeError,IndexError):
            integrity=False;continue
    for key,value in attempts.items():
        indices=value['indices']
        if set(indices)==set(range(len(DEFAULT_CREDENTIALS[value['service']]))) and all(indices.values()):checked.add(key)
    return found,checked,integrity


def evaluate_reference(directory,request,plan,report,record,meta):
    from laboratorio_personal import scope_hosts
    if request.get('bank')!='personal':raise ValueError('Esta referencia corresponde al modo por IP. Los bancos fijos conservan sus propios evaluadores.')
    addresses={a for _,a in scope_hosts(request.get('personal'))};ports=set(request['personal']['ports'])
    automatic=request['personal'].get('port_mode')=='auto'
    if any(c['address'] not in addresses or type(c['port']) is not int or not 1<=c['port']<=65535 or (not automatic and c['port'] not in ports) for c in record['cases']):raise ValueError('La referencia incluye IP o puertos fuera del alcance de esta pareja.')
    positive={(c['address'],c['port'],c['condition']) for c in record['cases'] if c['expected']=='present'}
    negative={(c['address'],c['port'],c['condition']) for c in record['cases'] if c['expected']=='absent'}
    found,checked,integrity=observations(directory,request,plan,report)
    return {'evaluator_version':'personal-reference-1','evaluator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'ground_truth_sha256':meta['sha256'],'TP':len(found&positive),'FP':len(found&negative),
            'FN':len(positive-found),'TN':len((negative-found)&checked),'evidence_valid':integrity,
            'unknown_negative_controls':len(negative-checked-found),'reference_cases':len(record['cases']),
            'unscored_findings':len(found-positive-negative),'reference_name':record['name']}
