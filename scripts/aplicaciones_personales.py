"""Pruebas HTTP configurables de la tesis, sin catálogo de contenedores ni IA adjudicadora.

Solo GET a IP/puerto autorizados; dos clientes, sin proxies ni redirecciones.
Las sesiones privadas se guardan fuera de las corridas. No se conservan cuerpos.
"""
from __future__ import annotations

import hashlib
import http.client
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, unquote
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener

from pydantic import BaseModel, ConfigDict
from auditoria.contracts import Target, TaskResult, TaskStatus

PROFILE = 'http_application_personal_v1'
SESSION_FILE = Path(__file__).resolve().parents[1]/'piloto_kali/prototipo/.lab/personal_web_sessions.json'
MAX_BODY = 1_048_576
CHECKS = ('object_authorization','file_boundary','ipv6_authorization_gap')


def session_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,40}',value):
        raise ValueError('Usa un nombre de sesión de hasta 40 letras, números, guion o guion bajo.')
    return value


def read_sessions(path=None):
    path=path or SESSION_FILE
    if not path.exists():return {}
    if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_size>100000:
        raise ValueError('El archivo de sesiones debe ser privado (0600), regular y acotado.')
    data=json.loads(path.read_text())
    if not isinstance(data,dict):raise ValueError('Archivo de sesiones inválido.')
    return data


def save_session(value, path=None):
    path=path or SESSION_FILE
    if not isinstance(value,dict) or set(value)!={'name','header','value'}:
        raise ValueError('Indica nombre, tipo y valor de la sesión de prueba.')
    name=session_name(value['name']);header=value['header'];secret=value['value']
    if header not in {'Authorization','Cookie'} or not isinstance(secret,str) or not 1<=len(secret)<=4096 or any(ord(c)<32 or ord(c)>126 for c in secret):
        raise ValueError('La sesión debe ser una cabecera Authorization o Cookie válida, sin saltos de línea.')
    records=read_sessions(path)
    if name not in records and len(records)>=16:raise ValueError('Máximo 16 sesiones guardadas.')
    records[name]={'header':header,'value':secret}
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.web-session-')
    try:
        with os.fdopen(fd,'w') as stream:json.dump(records,stream)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return name


def load_session(name):
    record=read_sessions().get(session_name(name))
    if not isinstance(record,dict) or record.get('header') not in {'Authorization','Cookie'}:
        raise ValueError('web_session_missing')
    value=record.get('value')
    if not isinstance(value,str) or not 1<=len(value)<=4096 or any(ord(c)<32 or ord(c)>126 for c in value):
        raise ValueError('web_session_invalid')
    return {record['header']:value}


def configure_applications(value, config):
    from laboratorio_personal import scope_hosts
    if value is None:return []
    if not isinstance(value,list) or len(value)>16:raise ValueError('Máximo 16 aplicaciones configuradas por corrida.')
    addresses={address for _,address in scope_hosts(config)};out=[];endpoints=set()
    fields={'name','ipv4','ipv6','port','scheme','session','scope_confirmed','own_path','own_marker',
            'foreign_path','foreign_marker','download_path','download_marker','admin_path','admin_marker'}
    for raw in value:
        if not isinstance(raw,dict) or set(raw)-fields:raise ValueError('Configuración de aplicación no admitida.')
        app={}
        name=raw.get('name','Aplicación de prueba')
        if not isinstance(name,str) or not 1<=len(name.strip())<=60 or any(not c.isprintable() for c in name):raise ValueError('Nombre de aplicación inválido.')
        app['name']=name.strip()
        for family,version in [('ipv4',4),('ipv6',6)]:
            text=raw.get(family,'')
            if not isinstance(text,str):raise ValueError('La aplicación requiere IP literales incluidas en el alcance.')
            text=text.strip()
            if text:
                try:address=ip_address(text)
                except ValueError:raise ValueError('La aplicación requiere IP literales.') from None
                if address.version!=version or str(address) not in addresses or address.is_link_local:
                    raise ValueError('Cada IP web debe estar en el alcance de su familia; usa IPv6 ULA/global, no fe80::.')
                text=str(address)
            app[family]=text
        if not app['ipv4'] and not app['ipv6']:raise ValueError('Indica al menos una IP de la aplicación.')
        port=raw.get('port')
        if type(port) is not int or not 1<=port<=65535 or (config.get('port_mode')!='auto' and port not in config['ports']):
            raise ValueError('El puerto web debe pertenecer al alcance TCP. Solo se probará si se descubre abierto y como servicio HTTP compatible.')
        app['port']=port;app['scheme']=raw.get('scheme','http')
        if app['scheme'] not in {'http','https'}:raise ValueError('El protocolo web debe ser HTTP o HTTPS.')
        app['session']=session_name(raw.get('session'))
        if raw.get('scope_confirmed') is not True:raise ValueError('Confirma que los recursos de prueba y sus permisos son conocidos.')
        app['scope_confirmed']=True
        for prefix in ['own','foreign','download','admin']:
            path,marker=raw.get(prefix+'_path',''),raw.get(prefix+'_marker','')
            if not isinstance(path,str) or not isinstance(marker,str):raise ValueError('Rutas y marcadores deben ser texto.')
            if bool(path)!=bool(marker) or (prefix=='own' and not path):raise ValueError('Cada prueba requiere su ruta y marcador; el recurso propio es obligatorio.')
            if path:
                parsed=urlsplit(path)
                if (not path.startswith('/') or path.startswith('//') or parsed.scheme or parsed.netloc or parsed.fragment or '\\' in path
                    or len(path)>1024 or any(ord(c)<33 or ord(c)>126 for c in path)):
                    raise ValueError('Usa rutas relativas al servidor como /documentos/10, sin URL, espacios ni fragmentos.')
                if not 8<=len(marker)<=160 or any(not c.isprintable() for c in marker):raise ValueError('El marcador debe tener entre 8 y 160 caracteres imprimibles de un recurso ficticio.')
            app[prefix+'_path']=path;app[prefix+'_marker']=marker
        decoded=' '.join(app[k+'_path'] for k in ['own','foreign','download','admin'])
        for _ in range(3):decoded=unquote(decoded)
        if any(app[k+'_marker'] and app[k+'_marker'] in decoded for k in ['own','foreign','download','admin']):
            raise ValueError('El marcador debe estar en el contenido ficticio, no en la URL enviada.')
        download=app['download_path']
        for _ in range(3):download=unquote(download)
        if download and '..' not in download:
            raise ValueError('La prueba de límite de descarga requiere una ruta de laboratorio con recorrido ../ y un canario interno conocido.')
        markers=[app[k+'_marker'] for k in ['own','foreign','download','admin'] if app[k+'_marker']]
        if len(set(markers))!=len(markers):raise ValueError('Usa marcadores distintos para recurso propio, ajeno, interno y administrativo.')
        if not any(app[k+'_path'] for k in ['foreign','download','admin']):raise ValueError('Configura al menos una prueba: documento ajeno, descarga o administración.')
        if app['foreign_path']==app['own_path']:raise ValueError('Los recursos propio y ajeno deben tener rutas diferentes.')
        for address in [app['ipv4'],app['ipv6']]:
            if not address:continue
            key=(address,port)
            if key in endpoints:raise ValueError('Un endpoint solo puede pertenecer a una aplicación por corrida.')
            endpoints.add(key)
        out.append(app)
    return out


class ApplicationTask(BaseModel):
    model_config=ConfigDict(extra='forbid')
    task_id:str
    agent_type:str='application_access'
    target:Target
    protocol:str='http'
    action_profile:str=PROFILE
    dependencies:list[str]=[]
    timeout_seconds:int=60
    case_id:None=None
    application_index:int


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def fetch(address,app,path,headers,channel,deadline,interface):
    from laboratorio_personal import resolve_targets
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('web_budget_exhausted')
    version=ip_address(address).version
    resolve_targets({'ipv4':address if version==4 else '', 'ipv6':address if version==6 else '',
                     'ports':[app['port']],'interface':interface},deadline=deadline)
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('web_budget_exhausted')
    timeout=min(3,remaining)
    host='['+address+']' if version==6 else address
    url=f"{app['scheme']}://{host}:{app['port']}{path}"
    response=connection=None
    try:
        if channel=='urllib':
            request=Request(url,headers={**headers,'Accept-Encoding':'identity','Connection':'close'},method='GET')
            try:response=build_opener(ProxyHandler({}),NoRedirects()).open(request,timeout=timeout)
            except HTTPError as exc:response=exc
        else:
            cls=http.client.HTTPSConnection if app['scheme']=='https' else http.client.HTTPConnection
            connection=cls(address,app['port'],timeout=timeout)
            connection.request('GET',path,headers={**headers,'Accept-Encoding':'identity','Connection':'close'})
            response=connection.getresponse()
        chunks=[];size=0
        while True:
            if time.monotonic()>=deadline:raise TimeoutError('web_budget_exhausted')
            block=response.read1(min(65536,MAX_BODY+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
            if size>MAX_BODY:raise ValueError('web_body_too_large')
        body=b''.join(chunks)
        return {'status':response.code if channel=='urllib' else response.status,
                'body_sha256':hashlib.sha256(body).hexdigest(),
                'matches':{name:bool(app[name+'_marker'] and app[name+'_marker'].encode() in body) for name in ['own','foreign','download','admin']}}
    finally:
        if response:response.close()
        if connection:connection.close()


def classify(app,records):
    """Un control incompleto o respuesta ambigua nunca se convierte en ausencia."""
    states={k:'not_requested' for k in CHECKS};families=[f for f in ['ipv4','ipv6'] if app[f]]
    usable={}
    for family in families:
        rows=records.get(family,{})
        usable[family]=(rows.get('own',{}).get('status')==200 and rows['own']['matches'].get('own') is True
                        and rows.get('anonymous',{}).get('status') in {401,403})
    for key,prefix in [('object_authorization','foreign'),('file_boundary','download')]:
        if not app[prefix+'_path']:continue
        observed=[]
        for family in families:
            row=records.get(family,{}).get(prefix,{})
            status=row.get('status')
            observed.append('confirmed' if usable[family] and status==200 and row['matches'].get(prefix) is True else
                            'not_detected' if usable[family] and status in {400,401,403,404} else 'incomplete')
        states[key]='confirmed' if 'confirmed' in observed else 'incomplete' if 'incomplete' in observed else 'not_detected'
    if app['admin_path']:
        if len(families)!=2:states['ipv6_authorization_gap']='not_supported'
        elif not all(usable.values()):states['ipv6_authorization_gap']='incomplete'
        else:
            rows=[records.get(f,{}).get('admin',{}) for f in families]
            statuses=[r.get('status') for r in rows]
            allowed=[r.get('status')==200 and r.get('matches',{}).get('admin') is True for r in rows]
            if any(allowed) and any(s in {401,403} for s in statuses):states['ipv6_authorization_gap']='confirmed'
            elif all(s in {401,403} for s in statuses):states['ipv6_authorization_gap']='not_detected'
            else:states['ipv6_authorization_gap']='incomplete'
    return states


def corroborated_checks(app,first,second):
    by_family={}
    for family in ['ipv4','ipv6']:
        if not app[family]:continue
        single={**app,('ipv6' if family=='ipv4' else 'ipv4'):''}
        a,b=classify(single,first),classify(single,second)
        by_family[family]={k:a[k] if a[k]==b[k] else 'incomplete' for k in CHECKS[:2]}
    checks={}
    for key in CHECKS[:2]:
        values=[row[key] for row in by_family.values()]
        checks[key]='confirmed' if 'confirmed' in values else 'incomplete' if 'incomplete' in values else values[0]
    a,b=classify(app,first),classify(app,second)
    gap=a[CHECKS[2]] if a[CHECKS[2]]==b[CHECKS[2]] else 'incomplete'
    if gap in {'confirmed','not_detected'}:
        for family in by_family:
            for label in ['own','anonymous','admin']:
                x,y=first.get(family,{}).get(label,{}),second.get(family,{}).get(label,{})
                if x.get('status')!=y.get('status') or x.get('matches')!=y.get('matches'):gap='incomplete'
    checks[CHECKS[2]]=gap
    for row in by_family.values():row[CHECKS[2]]=gap
    return checks,by_family


def app_digest(app):return hashlib.sha256(json.dumps(app,sort_keys=True).encode()).hexdigest()


def execute_application(task,app,store,deadline):
    deadline=min(deadline,time.monotonic()+task.timeout_seconds)
    headers=load_session(app['session']);channels={}
    store.event('tool','tool_started',task_id=task.task_id,payload={'tool':'HTTP','profile':PROFILE})
    for channel in ['urllib','http.client']:
        records={}
        for family in ['ipv4','ipv6']:
            if not app[family]:continue
            records[family]={}
            for label,prefix,auth in [('own','own',True),('anonymous','own',False),('foreign','foreign',True),('download','download',True),('admin','admin',True)]:
                if not app[prefix+'_path']:continue
                try:
                    row=fetch(app[family],app,app[prefix+'_path'],headers if auth else {},channel,deadline,task.target.interface)
                except Exception:row={'error':'http_probe_incomplete'}
                records[family][label]=row
                store.event('tool','web_response',task_id=task.task_id,payload={'family':family,'channel':channel,'check':label,'status':row.get('status'),'error':row.get('error')})
        channels[channel]={'task_id':task.task_id,'profile':PROFILE,'application_sha256':app_digest(app),'channel':channel,'records':records}
    evidence,eh=store.evidence(task.task_id+'_http','json',json.dumps(channels['urllib'],sort_keys=True).encode())
    confirmation,ch=store.evidence(task.task_id+'_confirmation','json',json.dumps(channels['http.client'],sort_keys=True).encode())
    checks,by_family=corroborated_checks(app,channels['urllib']['records'],channels['http.client']['records'])
    status=TaskStatus.FAILED if any(v in {'incomplete','not_supported'} for v in checks.values()) else TaskStatus.COMPLETED
    store.event('tool','tool_finished',task_id=task.task_id,payload={'tool':'HTTP','status':status.value})
    return TaskResult(task_id=task.task_id,status=status,reason_code='web_evidence_incomplete' if status==TaskStatus.FAILED else None,
                      evidence_ref=evidence,evidence_sha256=eh,diagnostic_ref=confirmation,diagnostic_sha256=ch,
                      observations={'application_checks':checks,'checks_by_family':by_family})


def assess_application(root,task,result,app):
    from auditoria.validation import _matches
    facts=[]
    for ref,digest,channel in [(result.evidence_ref,result.evidence_sha256,'urllib'),(result.diagnostic_ref,result.diagnostic_sha256,'http.client')]:
        if not _matches(root,ref,digest):raise ValueError('web_evidence_changed')
        data=json.loads((root/ref).read_text())
        if any(data.get(k)!=v for k,v in [('task_id',task.task_id),('profile',PROFILE),('application_sha256',app_digest(app)),('channel',channel)]):raise ValueError('web_evidence_mismatch')
        facts.append(data['records'])
    return corroborated_checks(app,*facts)


def adjudicate_application(root,task,result,app):
    from auditoria.v2_agent import RULES
    record={'task_id':task.task_id,'asset_id':task.target.asset_id,'action_profile':PROFILE,'state':'indeterminate',
            'reason':'web_evidence_incomplete','independent_confirmation':False}
    try:checks,by_family=assess_application(root,task,result,app)
    except (OSError,ValueError,KeyError,TypeError):return [],record
    record.update(state='candidate' if 'confirmed' in checks.values() else 'observed' if 'incomplete' not in checks.values() else 'indeterminate',
                  reason='personal_web_independent_evidence_valid',independent_confirmation=True,checks=checks,checks_by_family=by_family)
    findings=[]
    for key in CHECKS:
        if checks[key]!='confirmed':continue
        families=[f for f in ['ipv4','ipv6'] if app[f] and by_family[f].get(key)=='confirmed']
        if key=='ipv6_authorization_gap':
            primary=json.loads((root/result.evidence_ref).read_text())['records']
            families=[f for f in families if primary[f]['admin']['status']==200]
        for family in families:
            address=app[family]
            findings.append({'asset_id':'objetivo_'+family+'_'+address.replace('.','_').replace(':','_'),'address':address,'defect_key':key+'_tcp_'+str(app['port']),'condition':key,
            'state':'verified','severity':'medium','title':RULES[key][0],'reference':RULES[key][1],'remediation':RULES[key][2],
            'task_id':task.task_id,'evidence_ref':result.evidence_ref,'confirmation_ref':result.diagnostic_ref,
            'independent_confirmation':True,'reproduction':'Dos clientes HTTP independientes, sesión de prueba, control anónimo y marcadores ficticios conocidos.',
            'rule_version':'personal-web-1','scope_note':f"Aplicación {app['name']}, TCP/{app['port']}. Recursos ficticios y permisos declarados; no rastrea toda la aplicación."})
    return findings,record
