"""Inventario explícito IPv4/IPv6 para laboratorios propios, separado del banco v2.

No altera los perfiles congelados. Cada perfil TCP recibe una IP literal y puertos
finitos; el descubrimiento recibe una lista IPv4 acotada. Sin shell ni scripts NSE.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from auditoria.contracts import Target, TaskResult, TaskStatus, Service
from auditoria.dashboard import process_identity
from auditoria.store import RunStore, write_json
from autorizacion_personal import AuthorizationGuard, AuthorizationError

ROOT = Path(__file__).resolve().parents[1]
PROFILE = 'nmap_tcp_services_personal_v1'
NETWORKS = tuple(ip_network(n) for n in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8',
    '169.254.0.0/16','192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','198.18.0.0/15',
    'fc00::/7','fe80::/10','::1/128','2001:db8::/32'])
MAX_HOSTS = 256
MAX_ADDRESS_INPUT = 11000
RUNTIME_SECONDS = 240
# execute_task conserva sus límites: ruta (5 s) y Nmap (65 s).
TASK_RESERVE_SECONDS = 70
AUTOMATIC_PROFILE = 'nmap_tcp_open_ports_personal_v1'
DISCOVERY_PROBES = [21,22,80,443,5432,8080]


def address_scope(raw, version):
    if not isinstance(raw,str) or len(raw)>MAX_ADDRESS_INPUT:
        raise ValueError('La lista de direcciones es demasiado larga.')
    raw=raw.strip()
    if not raw:return '',[]
    if version==4 and '-' in raw:
        try:
            first,last=[ip_address(part.strip()) for part in raw.split('-')]
        except ValueError:
            raise ValueError('Escribe un rango IPv4 como 192.168.56.10-192.168.56.80, sin mezclar listas ni CIDR.') from None
        if first.version!=4 or last.version!=4 or not 1<=int(last)-int(first)+1<=MAX_HOSTS:
            raise ValueError('El rango IPv4 debe ser ascendente y contener como máximo 256 hosts.')
        addresses=[str(ip_address(number)) for number in range(int(first),int(last)+1)]
        # La misma validación de las listas exige que cada IP sea de laboratorio.
        address_scope(','.join(addresses),4)
        return f'{first}-{last}',addresses
    if '/' in raw:
        if version==6:
            raise ValueError('IPv6 solo admite direcciones literales separadas por comas; no prefijos de red.')
        try:network=ip_network(raw,strict=True)
        except ValueError:
            raise ValueError('Escribe un CIDR IPv4 alineado, por ejemplo 192.168.56.0/24; no mezcles CIDR y listas.') from None
        if network.version!=4 or network.prefixlen<24:
            raise ValueError('El CIDR IPv4 debe ser /24 o más pequeño: máximo 256 direcciones.')
        if not any(n.version==4 and network.subnet_of(n) for n in NETWORKS):
            raise ValueError('El CIDR completo debe pertenecer a NETWORKS de laboratorio; no objetivos públicos.')
        return str(network),[str(address) for address in network.hosts()]
    parts=raw.split(',')
    if len(parts)>MAX_HOSTS:
        raise ValueError('Máximo 256 hosts por corrida, sumando IPv4 e IPv6.')
    addresses=[]
    for part in parts:
        try:address=ip_address(part.strip())
        except ValueError:
            raise ValueError(f'Escribe direcciones IPv{version} literales separadas por comas, sin URL ni puerto.') from None
        if address.version!=version or '%' in part or address.is_multicast or address.is_unspecified:
            raise ValueError(f'El campo IPv{version} requiere direcciones unicast de esa familia, sin sufijo de interfaz.')
        if not any(address.version==network.version and address in network for network in NETWORKS):
            raise ValueError('Este modo admite direcciones de laboratorio privadas, locales o de documentación; no objetivos públicos.')
        if str(address) not in addresses:addresses.append(str(address))
    return ','.join(addresses),addresses


def scope_hosts(config):
    """Expansión acotada y pura: no descubre hosts ni consulta rutas."""
    normalized=configuration(config)
    return [(family,address) for family,version in [('ipv4',4),('ipv6',6)]
            for address in address_scope(normalized[family],version)[1]]


def target_for(family,address,config,interface=None):
    return Target(asset_id='objetivo_'+family+'_'+address.replace('.','_').replace(':','_'),
                  address=address,interface=interface or config['interface'],ports=config['ports'])


def configuration(value):
    if not isinstance(value,dict) or set(value)-{'ipv4','ipv6','ports','interface','port_mode'}:
        raise ValueError('Indica IPv4, IPv6, puertos e interfaz en los campos del laboratorio propio.')
    normalized = {}
    count=0
    for key,version in [('ipv4',4),('ipv6',6)]:
        normalized[key],addresses=address_scope(value.get(key,''),version)
        count+=len(addresses)
    if count>MAX_HOSTS:
        raise ValueError('Máximo 256 hosts por corrida, sumando IPv4 e IPv6.')
    if not normalized['ipv4'] and not normalized['ipv6']:
        raise ValueError('Indica al menos una dirección IPv4 o IPv6 de tu laboratorio.')
    mode=value.get('port_mode')
    if mode is not None and (not isinstance(mode,str) or mode not in {'auto','manual'}):
        raise ValueError('Modo de descubrimiento de puertos no admitido.')
    automatic=mode=='auto' or ('ports' not in value and mode is None)
    if automatic:
        if 'ports' in value and value['ports']!=[]:
            raise ValueError('El descubrimiento automático no admite una lista manual de puertos.')
        interface=value.get('interface','auto')
        if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface):
            raise ValueError('La interfaz de red no es válida.')
        return {**normalized,'ports':[],'interface':interface,'port_mode':'auto'}
    ports=value.get('ports','')
    if isinstance(ports,list):
        if not ports or any(type(p) is not int for p in ports):
            raise ValueError('Los puertos deben ser números enteros.')
    elif isinstance(ports,str) and re.fullmatch(r'\s*\d{1,5}(?:\s*,\s*\d{1,5}){0,31}\s*',ports):
        ports=[int(p.strip()) for p in ports.split(',')]
    else:
        raise ValueError('Escribe hasta 32 puertos TCP separados por comas, por ejemplo 22,80,443,8080.')
    if not 1<=len(ports)<=32 or any(p<1 or p>65535 for p in ports) or len(set(ports))!=len(ports):
        raise ValueError('Selecciona de 1 a 32 puertos TCP únicos, entre 1 y 65535.')
    interface=value.get('interface','auto')
    if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface):
        raise ValueError('La interfaz de red no es válida.')
    return {**normalized,'ports':sorted(ports),'interface':interface}


def signature(config):
    return hashlib.sha256(json.dumps(configuration(config),sort_keys=True).encode()).hexdigest()


def require_authorization(authorization, targets=(), *, feature='inventory'):
    """Revalidar el registro del operador antes de cada despacho de red."""
    if not isinstance(authorization, AuthorizationGuard):
        raise AuthorizationError('authorization_required', 'Registra la autorización del alcance antes de ejecutar sondas.')
    receipt = authorization.require_feature(feature)
    if targets:
        receipt = authorization.check_targets(targets)
    return receipt


def resolve_targets(config, *, deadline=None):
    config=configuration(config)
    if not shutil.which('nmap'):
        raise ValueError('Nmap no está disponible en Kali.')
    targets=[]
    for family,address in scope_hosts(config):
        ip=ip_address(address)
        command=['ip', '-6' if ip.version==6 else '-4','-j','route','get',address]
        if ip.is_link_local and ip.version==6:
            if config['interface']=='auto':
                raise ValueError('Para una IPv6 de enlace local (fe80::), selecciona su interfaz de red.')
            command+=['oif',config['interface']]
        try:
            timeout=5 if deadline is None else min(5,deadline-time.monotonic())
            if timeout<=0:raise ValueError('runtime_budget_exhausted')
            result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=timeout)
            routes=json.loads(result.stdout)
            route=routes[0]
        except (OSError,subprocess.SubprocessError,ValueError,IndexError,TypeError):
            raise ValueError(f'Kali no tiene una ruta disponible hacia la dirección {family.upper()}.') from None
        interface=route.get('dev','')
        if route.get('gateway') or route.get('type') in {'unreachable','blackhole','prohibit'}:
            raise ValueError('La dirección debe ser accesible directamente desde una interfaz del laboratorio, sin puerta de enlace.')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface) or (config['interface']!='auto' and interface!=config['interface']):
            raise ValueError('La ruta no coincide con la interfaz de laboratorio seleccionada.')
        targets.append(target_for(family,address,config,interface))
    return targets


def parse_discovery(raw, targets):
    if len(raw)>2_000_000:raise ValueError('Respuesta de descubrimiento demasiado grande.')
    root=ET.fromstring(raw)
    finished=root.find('runstats/finished')
    if finished is None or finished.get('exit')!='success':
        raise ValueError('El descubrimiento no registró un cierre completo.')
    allowed={t.address for t in targets};states={}
    for host in root.findall('host'):
        addresses=[a.get('addr') for a in host.findall('address') if a.get('addrtype') in {'ipv4','ipv6'}]
        status=host.find('status')
        if len(addresses)!=1 or addresses[0] not in allowed or addresses[0] in states or status is None or status.get('state') not in {'up','down'}:
            raise ValueError('El descubrimiento contiene hosts o estados fuera del alcance.')
        states[addresses[0]]=status.get('state')
    # Nmap omite normalmente los hosts sin respuesta en su XML.
    return {t.address:states.get(t.address,'down') for t in targets}


def discover_targets(targets, config, store, deadline, *, authorization=None):
    """Los CIDR y rangos pasan por -sn; las listas explícitas conservan -Pn."""
    require_authorization(authorization, targets)
    if configuration(config) != authorization.scope['personal']:
        raise AuthorizationError('authorization_scope_mismatch', 'El descubrimiento debe usar el alcance registrado por el operador.')
    states={t.address:'not_probed' for t in targets}
    if not any(mark in config['ipv4'] for mark in ['/', '-']):return states
    groups={}
    for target in targets:
        if ip_address(target.address).version==4:groups.setdefault(target.interface,[]).append(target)
    for index,(interface,group) in enumerate(groups.items()):
        # Comprobar otra vez cada ruta justo antes de descubrir este grupo.
        for target in group:
            route_config={**config,'ipv4':target.address,'ipv6':'','interface':interface}
            if resolve_targets(route_config,deadline=deadline)!=[target]:
                raise ValueError('La ruta cambió antes del descubrimiento.')
        timeout=min(60,deadline-time.monotonic())
        if timeout<=0:raise ValueError('runtime_budget_exhausted')
        probes=DISCOVERY_PROBES if config.get('port_mode')=='auto' else config['ports']
        command=['nmap','--unprivileged','-n','-sn','-PS'+','.join(map(str,probes)),
                 '--max-retries','1','--host-timeout','15s','-e',interface,'-oX','-',*[t.address for t in group]]
        require_authorization(authorization, group)
        store.event('controller','discovery_started',payload={'command':command,'host_count':len(group)})
        raw=diagnostic=b''
        try:
            from auditoria.tool_worker import tool_runtime_enabled,run_tool
            result=(run_tool if tool_runtime_enabled() else subprocess.run)(command,capture_output=True,timeout=timeout,check=False)
            raw,diagnostic=result.stdout,result.stderr
            if result.returncode:raise ValueError('discovery_failed')
            discovered=parse_discovery(raw,group)
        except subprocess.TimeoutExpired as exc:
            raw,diagnostic=exc.stdout or b'',exc.stderr or b''
            raise ValueError('discovery_timeout') from None
        finally:
            ref,digest=store.evidence('discovery_'+str(index),'xml',raw[:2_000_000])
            store.evidence('discovery_'+str(index),'txt',diagnostic[:64000])
        states.update(discovered)
        store.event('controller','discovery_finished',payload={'states':discovered,'evidence_ref':ref,'evidence_sha256':digest})
    return states


class InventoryTask(BaseModel):
    model_config=ConfigDict(extra='forbid')
    task_id:str
    agent_type:str
    target:Target
    protocol:str='tcp'
    action_profile:str=PROFILE
    dependencies:list[str]=[]
    timeout_seconds:int=60
    case_id:None=None


def command_for(task):
    if task.action_profile!=PROFILE or task.timeout_seconds!=60 or task.dependencies:
        raise ValueError('Perfil de inventario no admitido.')
    address=ip_address(task.target.address)
    # Revalidar también los campos de un objeto actualizado sin validación de Pydantic.
    configuration({'ipv4':str(address) if address.version==4 else '',
                   'ipv6':str(address) if address.version==6 else '',
                   'ports':task.target.ports,'interface':task.target.interface})
    target=str(address)
    if address.version==6 and address.is_link_local:
        target+='%' + task.target.interface
    return ['nmap',*(['-6'] if address.version==6 else []),'--unprivileged','-n','-Pn','-sT','-sV','--version-light',
            '--max-retries','1','--host-timeout','60s','-e',task.target.interface,'-p',
            ','.join(str(p) for p in task.target.ports),'-oX','-',target]


def parse_inventory(raw,task):
    if len(raw)>2_000_000:
        raise ValueError('Respuesta Nmap demasiado grande.')
    root=ET.fromstring(raw)
    finished=root.find('runstats/finished')
    if finished is None or finished.get('exit')!='success':
        raise ValueError('Nmap no registró un cierre completo.')
    hosts=root.findall('host')
    if len(hosts)!=1 or not any(a.get('addrtype') in {'ipv4','ipv6'} and a.get('addr')==task.target.address for a in hosts[0].findall('address')):
        raise ValueError('El resultado no corresponde al objetivo autorizado.')
    host=hosts[0]
    states={}
    services=[]
    for entry in host.findall('ports/port'):
        port=int(entry.get('portid','0'))
        if port not in task.target.ports or entry.get('protocol')!='tcp':
            raise ValueError('El resultado contiene puertos fuera del alcance.')
        status=entry.find('state')
        state=status.get('state','unknown') if status is not None else 'unknown'
        if state not in {'open','closed','filtered','open|filtered','closed|filtered','unfiltered','unknown'}:
            state='unknown'
        states[port]=state
        if state=='open':
            value=entry.find('service')
            clean=lambda v: ''.join(c for c in v if c.isprintable())[:120] if isinstance(v,str) else None
            services.append(Service(port=port,protocol='tcp',state='open',
                name=clean(value.get('name')) if value is not None else None,
                product=clean(value.get('product')) if value is not None else None,
                version=clean(value.get('version')) if value is not None else None))
    missing=[p for p in task.target.ports if p not in states]
    extra=host.findall('ports/extraports')
    if len(extra)==1 and int(extra[0].get('count','0'))==len(missing) and extra[0].get('state') in {'closed','filtered'}:
        states.update({p:extra[0].get('state') for p in missing})
    return services,[{'port':p,'state':states.get(p,'not_reported')} for p in task.target.ports]


def execute_task(task,store,runner=subprocess.run,*,authorization=None):
    # Comprobar la ruta de nuevo inmediatamente antes del despacho.
    require_authorization(authorization, [task.target])
    config={'ipv4':task.target.address if ip_address(task.target.address).version==4 else '',
            'ipv6':task.target.address if ip_address(task.target.address).version==6 else '',
            'ports':task.target.ports,'interface':task.target.interface}
    if resolve_targets(config)!=[task.target]:
        raise ValueError('El objetivo o la interfaz cambiaron después de comprobarlos.')
    require_authorization(authorization, [task.target])
    command=command_for(task)
    store.event('tool','tool_started',task_id=task.task_id,payload={'tool':'nmap','command':command})
    status=TaskStatus.COMPLETED_NO_FINDINGS;reason=None;services=[];states=[];raw=b'';diagnostic=b''
    try:
        from auditoria.tool_worker import tool_runtime_enabled,run_tool
        result=(run_tool if tool_runtime_enabled() else runner)(command,capture_output=True,timeout=65,check=False)
        raw=result.stdout;diagnostic=result.stderr
        if result.returncode:
            status=TaskStatus.FAILED;reason='nmap_failed'
        else:
            services,states=parse_inventory(raw,task)
    except subprocess.TimeoutExpired as exc:
        raw=exc.stdout or b'';diagnostic=exc.stderr or b'';status=TaskStatus.FAILED;reason='timeout'
    except (OSError,ValueError,ET.ParseError,TypeError):
        status=TaskStatus.FAILED;reason='invalid_inventory'
    reference,digest=store.evidence(task.task_id,'xml',raw[:2_000_000])
    diagnostic_ref,diagnostic_sha=store.evidence(task.task_id+'_diagnostic','txt',diagnostic[:64000])
    store.event('tool','tool_finished',task_id=task.task_id,payload={'tool':'nmap','status':status.value,'reason_code':reason})
    return TaskResult(task_id=task.task_id,status=status,reason_code=reason,services=services,command=command,
                      observations={'port_states':states},evidence_ref=reference,evidence_sha256=digest,
                      diagnostic_ref=diagnostic_ref,diagnostic_sha256=diagnostic_sha)


# Diccionario corto y editable de credenciales por defecto comunes en laboratorios
# didácticos. Autorizado para el alcance indicado; intentos acotados por servicio.
SERVICE_BY_PORT = {22: 'ssh', 21: 'ftp', 5432: 'postgres', 8080: 'http-get', 8088: 'http-get'}
SERVICE_BY_NAME = {'ssh':'ssh','ftp':'ftp','postgres':'postgres','postgresql':'postgres',
                   'http':'http-get','http-proxy':'http-get'}


def supported_services(services):
    """Elegir perfiles por el protocolo observado; el número de puerto no demuestra su tipo."""
    return {s.port:SERVICE_BY_NAME[s.name] for s in services
            if s.protocol=='tcp' and s.state=='open' and s.name in SERVICE_BY_NAME}
DEFAULT_CREDENTIALS = {
    'ssh': [('root', 'toor'), ('root', 'root'), ('admin', 'admin'), ('user', 'user'),
            ('labuser', 'labuser'), ('kali', 'kali'), ('msfadmin', 'msfadmin')],
    'ftp': [('ftp', 'ftp'), ('anonymous', 'anonymous'), ('admin', 'admin'), ('labuser', 'labuser')],
    'postgres': [('postgres', 'postgres'), ('admin', 'admin'), ('labuser', 'labuser')],
    'http-get': [('admin', 'admin'), ('tomcat', 'tomcat'), ('manager', 'manager'), ('admin', 'tomcat')],
}
SWEEP_ENV = 'LAB_SWEEP_PASSWORD'
MAX_SWEEP_ATTEMPTS = 80
CREDENTIAL_RULE = {
    'ssh': ('Credencial SSH por defecto aceptada', 'https://cwe.mitre.org/data/definitions/1392.html'),
    'ftp': ('Credencial FTP por defecto aceptada', 'https://cwe.mitre.org/data/definitions/1392.html'),
    'postgres': ('Credencial PostgreSQL por defecto aceptada', 'https://cwe.mitre.org/data/definitions/521.html'),
    'http-get': ('Credencial de consola HTTP por defecto aceptada', 'https://cwe.mitre.org/data/definitions/1392.html'),
}


def credential_sweep(targets, open_by_address, store, deadline, *, tasks=None, results=None, validations=None, services_by_address=None, authorization=None):
    """Registra cada intento y conserva como incompleta la cobertura que no se ejecutó."""
    require_authorization(authorization, targets, feature='credentials')
    from auditoria.contracts import Task, CredentialProfile, LabPolicy, LabSegment, Category
    from auditoria.agentes.agente_ipv4_credenciales import run_hydra
    from auditoria.validation import validate_results
    from auditoria.findings import access_is_verified
    tasks = tasks if tasks is not None else []
    results = results if results is not None else []
    validations = validations if validations is not None else []
    findings=[]; attempts=0
    old_password=os.environ.get(SWEEP_ENV)
    try:
        for target in targets:
            if ip_address(target.address).version!=4: continue
            selected=services_by_address.get(target.address,{}) if services_by_address is not None else SERVICE_BY_PORT
            for port in [p for p in open_by_address.get(target.address,[]) if p in selected]:
                service=selected[port]
                for index,(username,password) in enumerate(DEFAULT_CREDENTIALS[service]):
                    ref=f'default_{service.replace("-","_")}_{port}_{index}'
                    profile=CredentialProfile(ref=ref,service=service,port=port,username=username,
                                              password_env=SWEEP_ENV,condition='default_credential')
                    task=Task(task_id=f'cred_{target.asset_id}_{port}_{index}',agent_type='ipv4_credentials',
                              target=target.model_copy(update={'ports':[port],'credential_ref':ref,'credential_refs':[]}),
                              protocol='tcp',action_profile=f'hydra_{service.replace("-","_")}_single_v1',timeout_seconds=12)
                    tasks.append(task)
                    write_json(store.root/'plan.json',[t.model_dump(mode='json') for t in tasks])
                    stop='attempt_budget_exhausted' if attempts>=MAX_SWEEP_ATTEMPTS else 'runtime_budget_exhausted' if deadline-time.monotonic()<22 else None
                    if stop:
                        result=TaskResult(task_id=task.task_id,status=TaskStatus.CANCELLED,reason_code=stop)
                    else:
                        attempts+=1;os.environ[SWEEP_ENV]=password
                        store.event('controller','task_admitted',task_id=task.task_id,payload={'profile':task.action_profile})
                        try:
                            result=run_hydra(task,profile,store,timeout_seconds=12,
                                authorize=lambda: require_authorization(authorization, [task.target], feature='credentials'))
                        except AuthorizationError: raise
                        except Exception: result=TaskResult(task_id=task.task_id,status=TaskStatus.FAILED,reason_code='credential_execution_error')
                    record=validate_results(store.root,[task],[result])[0]
                    policy=LabPolicy(policy_id='personal-credentials',segments=[LabSegment(name='host',network=target.address+'/32',
                        interface=target.interface,allowed_ports=[port])],allowed_categories=[Category.IPV4_CREDENTIALS],credential_profiles=[profile])
                    verified=access_is_verified(store.root,policy,task,result,record)
                    record['independent_confirmation']=verified
                    if result.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} and (record['state']=='indeterminate' or (result.authentication and result.authentication.outcome=='accepted' and not verified)):
                        result=result.model_copy(update={'status':TaskStatus.FAILED,'reason_code':'credential_evidence_not_validated'})
                    results.append(result);validations.append(record)
                    store.event('orchestration','task_terminal',task_id=task.task_id,payload={'status':result.status.value,'reason_code':result.reason_code})
                    if verified:
                        title,reference=CREDENTIAL_RULE[service];condition=service.replace('-','_')+'_default_credential'
                        findings.append({'asset_id':target.asset_id,'address':target.address,'defect_key':condition,'condition':condition,
                            'state':'verified','severity':'high','title':title,'reference':reference,
                            'remediation':'Rotar la credencial y restringir el servicio a la red de gestión.',
                            'task_id':task.task_id,'evidence_ref':result.evidence_ref,'confirmation_ref':result.diagnostic_ref,
                            'independent_confirmation':True,'reproduction':'Hydra y cliente independiente, con integridad comprobada.',
                            'rule_version':'personal-1','scope_note':'Prueba de credenciales del laboratorio autorizado.'})
                    if verified or stop: break
    finally:
        if old_password is None:os.environ.pop(SWEEP_ENV,None)
        else:os.environ[SWEEP_ENV]=old_password
    return findings


def coverage_for(targets, tasks, results, findings, host_states, sweep, applications=None):
    """Cobertura por dirección: no convertir una prueba omitida en ausencia de vulnerabilidad."""
    result_by_id={r.task_id:r for r in results};coverage=[]
    for target in targets:
        inventory_tasks=[t for t in tasks if t.target.address==target.address and t.action_profile in {PROFILE,AUTOMATIC_PROFILE}]
        inventory_results=[result_by_id.get(t.task_id) for t in inventory_tasks]
        credentials=[result_by_id[t.task_id] for t in tasks if t.target.address==target.address and t.action_profile.startswith('hydra_') and t.task_id in result_by_id]
        confirmed=sum(f.get('address')==target.address for f in findings)
        inventory_ok=bool(inventory_results) and all(r is not None and r.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} for r in inventory_results)
        compatible=supported_services([s for r in inventory_results if r for s in r.services]) if inventory_ok else {}
        confirmed_credentials=sum(f.get('address')==target.address and f.get('condition','').endswith('_default_credential') for f in findings)
        complete=bool(credentials) and all(r.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} for r in credentials)
        credential_state=('not_requested' if not sweep else 'not_evaluated' if host_states.get(target.address)=='down' or not inventory_ok else
                          'not_supported' if ip_address(target.address).version!=4 else 'not_applicable' if not compatible else
                          'incomplete' if not complete else 'confirmed' if confirmed_credentials else 'not_detected')
        web_tasks=[t for t in tasks if t.action_profile=='http_application_personal_v1' and applications and target.address in [applications[t.application_index][f] for f in ['ipv4','ipv6']]]
        web_results=[result_by_id.get(t.task_id) for t in web_tasks]
        family='ipv'+str(ip_address(target.address).version)
        web_checks={k:'not_configured' for k in ['object_authorization','file_boundary','ipv6_authorization_gap']}
        for result in web_results:
            if result and result.observations.get('checks_by_family',{}).get(family):
                web_checks.update(result.observations['checks_by_family'][family])
            else:web_checks={k:'incomplete' for k in web_checks}
        web_state='not_configured' if not web_tasks else 'incomplete' if any(r is None or r.status not in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} for r in web_results) else 'confirmed' if 'confirmed' in web_checks.values() else 'completed'
        coverage.append({'address':target.address,'web_state':web_state,'web_checks':web_checks,'inventory_state':'completed' if inventory_ok else 'down' if host_states.get(target.address)=='down' else 'incomplete',
            'credentials_state':credential_state,'credential_attempts':sum(r.status not in {TaskStatus.CANCELLED,TaskStatus.BLOCKED} for r in credentials),'confirmed_findings':confirmed,
            'application_checks':web_state if web_tasks else 'requires_application_adapter','ipv6_protocol_checks':'requires_link_observer'})
    return coverage


def run(options,output):
    authorization = AuthorizationGuard(options)
    from auditoria.secure_runtime import require_live_runtime
    require_live_runtime(bank='personal',options=options,output=output)
    if configuration(options['personal']).get('port_mode')=='auto':
        from puertos_personales import run_automatic
        return run_automatic(options,output)
    from aplicaciones_personales import configure_applications, ApplicationTask, PROFILE as WEB_PROFILE, execute_application, adjudicate_application
    config=configuration(options['personal']);applications=configure_applications(options.get('applications',[]),config);audit_id='personal_'+options['architecture']+'_'+uuid4().hex[:12]
    directory=output/(audit_id+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    store=RunStore(directory,audit_id);started=time.monotonic();deadline=started+RUNTIME_SECONDS
    runtime={'status':'running','pid':os.getpid(),'identity':process_identity(os.getpid()),'started_at':datetime.now(timezone.utc).isoformat()}
    write_json(directory/'runtime.json',runtime)
    request={'audit_id':audit_id,'bank':'personal','architecture':options['architecture'], 'token_budget':options['tokens'],
             'llm_mode':'scheduler' if options['ia']=='openai' else 'disabled','personal':config,'applications':applications,'expert_mode':bool(options.get('expert_mode')),'authorization_ref':options['authorization']}
    write_json(directory/'request.json',request)
    write_json(directory/'authorization.json',authorization.verify())
    write_json(directory/'manifest.json',{'bank':'personal','mode':'live','purpose':'network_vulnerability_evaluation' if applications else 'service_inventory_with_default_credentials' if options.get('creds') else 'service_inventory_not_vulnerability_evaluation',
        'source_sha256':__import__('auditoria.cli',fromlist=['source_fingerprint']).source_fingerprint(),
        'adapter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'extensions_sha256':{name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in ['llm_especialistas.py','aplicaciones_personales.py','tesis/llm_contexto.py','tesis/candidatos.py']},'execution_concurrency':2 if options['architecture']=='multiagent' else 1})
    store.event('controller','request_accepted')
    targets=[target_for(family,address,config) for family,address in scope_hosts(config)]
    def plan_for(values):
        return [InventoryTask(task_id=audit_id+'_'+str(i),agent_type='ipv'+str(ip_address(t.address).version)+'_services',target=t)
                for i,t in enumerate(values)]
    tasks=plan_for(targets)
    write_json(directory/'plan.json',[t.model_dump(mode='json') for t in tasks])
    results=[];scheduler=None;error=None;findings=[];validations=[];host_states={t.address:'unknown' for t in targets}
    sweep=bool(options.get('creds'))
    try:
        taint=int(Path('/proc/sys/kernel/tainted').read_text())
        if taint & ((1<<7)|(1<<14)):
            raise ValueError('kernel_failure')
        from aplicaciones_personales import load_session
        for app in applications:load_session(app['session'])
        store.event('controller','authorization_verified',payload=authorization.verify())
        targets=resolve_targets(config,deadline=deadline)
        require_authorization(authorization, targets)
        host_states=discover_targets(targets,config,store,deadline,authorization=authorization)
        tasks=plan_for([t for t in targets if host_states[t.address]!='down'])
        inventory_ids={t.target.address:t.task_id for t in tasks}
        for index,app in enumerate(applications):
            addresses=[app[f] for f in ['ipv4','ipv6'] if app[f]]
            target=next(t for t in targets if t.address==addresses[0])
            tasks.append(ApplicationTask(task_id=audit_id+'_web_'+str(index),target=target,application_index=index,
                dependencies=[inventory_ids[a] for a in addresses if a in inventory_ids]))
        write_json(directory/'plan.json',[t.model_dump(mode='json') for t in tasks])
        store.event('orchestration','plan_created',payload={'task_count':len(tasks)})
        if options['ia']=='openai' and tasks and deadline-time.monotonic()>=TASK_RESERVE_SECONDS:
            from auditoria.openai_provider import OpenAIScheduler,load_openai_config
            load_openai_config(ROOT/'piloto_kali/prototipo/.lab')
            SchedulerClass=OpenAIScheduler
            if options.get('expert_mode'):
                from llm_especialistas import ExpertScheduler
                SchedulerClass=ExpertScheduler
            scheduler=SchedulerClass(store,architecture=options['architecture'],budget=options['tokens'],deadline=deadline-TASK_RESERVE_SECONDS)
            store.event('planner','llm_ready',payload={'model':scheduler.config.model})
        pending=list(tasks);running={}
        with ThreadPoolExecutor(max_workers=2 if options['architecture']=='multiagent' else 1) as pool:
            while pending or running:
                while pending and len(running)<(2 if options['architecture']=='multiagent' else 1):
                    if deadline-time.monotonic()<TASK_RESERVE_SECONDS:break
                    finished={r.task_id:r for r in results}
                    eligible=[]
                    for candidate in list(pending):
                        if candidate.action_profile!=WEB_PROFILE:
                            eligible.append(candidate);continue
                        app=applications[candidate.application_index]
                        addresses=[app[f] for f in ['ipv4','ipv6'] if app[f]]
                        down=any(host_states.get(a)=='down' for a in addresses)
                        if not down and any(d not in finished for d in candidate.dependencies):continue
                        compatible=not down and all(finished[d].status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS}
                            and any(service.port==app['port'] and service.name in {'http','http-proxy','https','ssl/http'} for service in finished[d].services)
                            for d in candidate.dependencies)
                        if compatible:eligible.append(candidate)
                        else:
                            pending.remove(candidate)
                            result=TaskResult(task_id=candidate.task_id,status=TaskStatus.BLOCKED,reason_code='web_inventory_or_service_unavailable')
                            results.append(result)
                            store.event('orchestration','task_terminal',task_id=candidate.task_id,payload={'status':result.status.value,'reason_code':result.reason_code})
                    if not eligible:break
                    eligible.sort(key=lambda t:t.action_profile!=WEB_PROFILE)
                    choice=scheduler.select(eligible,results,tasks) if scheduler else eligible[0]
                    if deadline-time.monotonic()<TASK_RESERVE_SECONDS:break
                    if choice not in eligible:raise ValueError('invalid_selection')
                    require_authorization(authorization,[choice.target],feature='applications' if choice.action_profile==WEB_PROFILE else 'inventory')
                    pending.remove(choice)
                    store.event('controller','task_admitted',task_id=choice.task_id,payload={'profile':choice.action_profile})
                    running[pool.submit(execute_application,choice,applications[choice.application_index],store,deadline,authorization=authorization)
                            if choice.action_profile==WEB_PROFILE else pool.submit(execute_task,choice,store,authorization=authorization)]=choice
                if not running:break
                completed,_=wait(running,return_when=FIRST_COMPLETED)
                for future in completed:
                    task=running.pop(future)
                    try:result=future.result()
                    except AuthorizationError as exc:
                        store.event('controller','authorization_rejected',task_id=task.task_id,payload={'reason_code':exc.reason_code})
                        raise
                    except Exception:result=TaskResult(task_id=task.task_id,status=TaskStatus.FAILED,reason_code='adapter_error')
                    if task.action_profile==WEB_PROFILE:
                        detected,record=adjudicate_application(directory,task,result,applications[task.application_index])
                        findings.extend(detected);validations.append(record)
                        if result.status==TaskStatus.COMPLETED and record['state']=='indeterminate':
                            result=result.model_copy(update={'status':TaskStatus.FAILED,'reason_code':'web_evidence_not_validated'})
                    results.append(result)
                    store.event('orchestration','task_terminal',task_id=task.task_id,payload={'status':result.status.value,'reason_code':result.reason_code})
        for task in pending:
            result=TaskResult(task_id=task.task_id,status=TaskStatus.CANCELLED,reason_code='runtime_budget_exhausted')
            results.append(result);store.event('orchestration','task_terminal',task_id=task.task_id,payload={'status':result.status.value,'reason_code':result.reason_code})
        if sweep:
            # Barrido de credenciales por defecto solo sobre los puertos ABIERTOS descubiertos.
            tasks_by_address={x.target.address:x for x in tasks if x.action_profile==PROFILE}
            open_ports_by_id={r.task_id:[s.port for s in r.services] for r in results}
            live=[];open_by_address={};services_by_address={}
            for t in targets:
                if host_states.get(t.address)=='down':continue
                tk=tasks_by_address.get(t.address)
                ports=open_ports_by_id.get(tk.task_id,[]) if tk else []
                result=next((r for r in results if tk and r.task_id==tk.task_id),None)
                services=supported_services(result.services) if result and result.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} else {}
                if services:
                    open_by_address[t.address]=ports;services_by_address[t.address]=services;live.append(t)
            store.event('orchestration','credential_sweep_started',payload={'hosts':len(live)})
            findings.extend(credential_sweep(live,open_by_address,store,deadline,tasks=tasks,results=results,validations=validations,services_by_address=services_by_address,authorization=authorization))
    except Exception as exc:
        error=exc.reason_code if isinstance(exc,AuthorizationError) else 'preflight_or_configuration_failed'
        if isinstance(exc,AuthorizationError):store.event('controller','authorization_rejected',payload={'reason_code':error})
        recorded={r.task_id for r in results}
        for task in tasks:
            if task.task_id not in recorded:
                result=TaskResult(task_id=task.task_id,status=TaskStatus.BLOCKED,reason_code=error)
                results.append(result)
                store.event('orchestration','task_terminal',task_id=task.task_id,payload={'status':result.status.value,'reason_code':error})
    finally:
        execution_seconds=round(time.monotonic()-started,6)
        if scheduler and options.get('expert_mode') and not error:
            scheduler.deadline=deadline
            scheduler.review(tasks,results,findings)
        if scheduler:scheduler.close()
        llm=scheduler.summary() if scheduler else {'status':'disabled' if options['ia']=='none' else 'not_started','model':None,'known_tokens':0,
            'usage_complete':True,'calls':[],'budget':options['tokens'],'fallbacks':0}
        if scheduler and not llm['calls']:
            llm['status']='not_needed'
            llm['note']='No hubo varias alternativas listas que requirieran una consulta al modelo.'
        complete=bool(targets) and len(results)==len(tasks) and all(r.status in {TaskStatus.COMPLETED,TaskStatus.COMPLETED_NO_FINDINGS} for r in results) and not error
        inventory=[]
        tasks_by_address={t.target.address:t for t in tasks if t.action_profile==PROFILE}
        results_by_id={r.task_id:r for r in results}
        for target in targets:
            task=tasks_by_address.get(target.address)
            result=results_by_id.get(task.task_id) if task else None
            inventory.append({'task_id':task.task_id if task else None,'asset_id':target.asset_id,'address':target.address,
                'family':'IPv'+str(ip_address(target.address).version),'host_state':host_states[target.address],
                'scan_status':result.status.value if result else 'not_scanned',
                'reason_code':result.reason_code if result else 'host_down',
                'ports':result.observations.get('port_states',[]) if result else [],
                'services':[v.model_dump(mode='json') for v in result.services] if result else []})
        report={'audit_id':audit_id,'architecture':options['architecture'],'status':'complete' if complete else 'partial','mode':'live',
            'purpose':'network_vulnerability_evaluation' if applications else 'service_inventory_with_default_credentials' if sweep else 'service_inventory_not_vulnerability_evaluation',
            'findings':findings, 'tasks':[r.model_dump(mode='json') for r in results],
            'inventory':inventory,'llm':llm,'validation':validations,
            'coverage':coverage_for(targets,tasks,results,findings,host_states,sweep,applications),
            'note':('Inventario y pruebas web configuradas con dos clientes independientes. Los perfiles de red IPv6 todavía requieren observador.' if applications else 'Inventario TCP y prueba de credenciales por defecto sobre los servicios abiertos, con corroboración independiente. down significa sin respuesta al descubrimiento.' if sweep else 'Inventario TCP: no confirma vulnerabilidades. down significa sin respuesta al descubrimiento, no necesariamente apagado.'),
            'metrics':{'elapsed_seconds':round(time.monotonic()-started,6),'execution_seconds':execution_seconds,'expert_review_seconds':getattr(scheduler,'review_seconds',0)},'error':error}
        report['cve_candidates']=__import__('tesis.candidatos',fromlist=['for_results']).for_results(tasks,results)
        from auditoria.modulo_reportes import prepare_report, save_report
        report = prepare_report(report, request)
        save_report(directory, report)
        store.event('report','report_saved',payload={'status':report['status'],'tasks_completed':len(results)})
        runtime.update(status='finished',ended_at=datetime.now(timezone.utc).isoformat());write_json(directory/'runtime.json',runtime)
        store.close()
    return 0 if complete else 3


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--job',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    from dualstack_panel import validate_options
    options=validate_options(json.loads(args.job.read_text())['options'])
    if options['scope']!='personal' or options['mode']!='live':raise SystemExit('Perfil no admitido')
    raise SystemExit(run(options,args.output))
