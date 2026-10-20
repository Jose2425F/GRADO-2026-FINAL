"""Proyección de eventos y evidencia para lectura humana; no ejecuta herramientas."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import sqlite3
import xml.etree.ElementTree as ET
from ipaddress import ip_address
from pathlib import Path

from panel_presentacion import AGENT_NAMES, ASSET_NAMES, PROFILE_NAMES, STATUS_NAMES

PROFILE_TOOLS = {
    'nmap_tcp_open_ports_personal_v1':('Nmap · puertos TCP','Búsqueda TCP connect del 1 al 65535. El administrador contrasta el XML y programa reconocimiento únicamente sobre puertos abiertos.'),
    'http_application_personal_v1':('Python HTTP','Dos clientes independientes (urllib y http.client), sesión privada, control anónimo y marcadores configurados; solo GET, sin proxies ni redirecciones.'),
    'nmap_tcp_services_personal_v1':('Nmap IPv4/IPv6','Inventario TCP y reconocimiento de servicios de la IP y puertos indicados por el operador; no confirma vulnerabilidades.'),
    'http_application_dualstack_v2': ('Python HTTP', 'v2_agent.run_task → lab_v2.app_family; urllib.request y http.client independientes, IPv4 e IPv6.'),
    'ipv6_slaac_v2': ('Docker / iproute2', 'lab_v2.wait_receiver: consulta direcciones, rutas y vecinos con ip -j -6; lee el observador del receptor.'),
    'nmap_tcp_services_v1': ('Nmap', 'Inventario TCP y reconocimiento de servicio mediante el perfil Nmap autorizado.'),
}
for _name in ['ra_route', 'ra_mtu', 'na_neighbor', 'dad_na', 'overlap', 'overlap_middle', 'atomic', 'incomplete_chain']:
    PROFILE_TOOLS['ipv6_' + _name + '_v2'] = ('Scapy / Docker / iproute2',
        'lab_v2.probe: emisor Scapy en v2-sender, captura PCAP y contraste del estado del receptor; restauración al cerrar el perfil.')
for _name in ['ra_route','na_neighbor','dad','ra_mtu','overlap_initial','overlap_middle','atomic','incomplete_chain']:
    PROFILE_TOOLS['ipv6_'+_name+'_v1'] = ('Scapy / Docker', 'Perfil IPv6 finito del banco v1; captura y observación de estado según el caso autorizado.')

FAILURE_PHASES = {
    'receiver_readiness':'preparación del receptor IPv6',
    'ipv6_setup':'configuración previa de IPv6', 'ipv6_probe':'sonda IPv6',
    'ipv6_restore':'restauración del receptor IPv6',
    'evidence_persistence':'guardado de evidencia', 'tool_execution':'ejecución de la herramienta',
    'authorization':'comprobación de autorización',
}
FAILURE_REASONS = {
    'execution_error':'La herramienta no pudo completar la tarea',
    'tool_timeout':'Se agotó el tiempo de la tarea',
    'tool_process_failed':'El proceso de la herramienta terminó con error',
    'tool_transport_error':'Falló la comunicación con la herramienta o el objetivo',
    'evidence_write_failed':'No se pudo guardar la evidencia',
    'tool_response_invalid':'La respuesta de la herramienta no tiene el formato esperado',
    'scope_rejected':'El objetivo fue rechazado por la política de autorización',
    'invalid_tool_result':'La herramienta no devolvió un resultado válido para esta tarea',
    'ipv6_receiver_not_ready':'El receptor IPv6 no alcanzó el estado inicial requerido',
    'ipv6_setup_failed':'No se pudo preparar el estado de IPv6 para la prueba',
    'ipv6_probe_failed':'La sonda IPv6 no pudo completar su ejecución',
    'ipv6_restore_failed':'No se pudo restaurar el receptor IPv6',
    'ipv6_capture_not_ready':'La captura IPv6 no quedó preparada',
    'ipv6_capture_invalid':'La captura no acredita una sonda IPv6 válida',
    'ipv6_sender_failed':'El emisor de la sonda IPv6 terminó con error',
    'docker_exec_failed':'Falló la ejecución autorizada dentro del contenedor',
    'docker_restart_failed':'No se pudo reiniciar el contenedor del receptor',
    'docker_inspect_failed':'No se pudo consultar el estado del contenedor',
    'docker_operation_failed':'Falló una operación autorizada del laboratorio',
    'application_control_failed':'El control de acceso permitido de la aplicación falló',
    'application_trace_unverified':'El registro de la aplicación no corroboró las respuestas',
}
EXCEPTION_TYPES = {'TaskExecutionError','LabError','TimeoutExpired','TimeoutError','CalledProcessError',
    'HTTPError','URLError','PolicyError','OSError','ValueError','RuntimeError','Exception'}


def tool_for(profile,bank=None):
    if profile.startswith('hydra_') and profile.endswith('_single_v1'):
        return 'Hydra y cliente independiente', 'Autenticación finita con una credencial autorizada y corroboración independiente si resulta positiva.'
    tool,description=PROFILE_TOOLS.get(profile, ('Perfil del auditor', 'No hay descripción técnica registrada para este perfil.'))
    if bank=='empresa':description=description.replace('v2_agent','empresa_agent').replace('lab_v2','lab_empresa').replace('v2-sender','nova-sender')
    return tool,description


def public_ref(value):
    """Solo referencias relativas a evidencia, nunca rutas privadas ni contenido libre."""
    if isinstance(value, str) and re.fullmatch(r'evidence/[A-Za-z0-9_.-]{1,220}', value):
        return value
    return ''


def recorded_command(command, task):
    """Exhibe únicamente las formas conocidas de Nmap/Hydra, ocultando identidad y archivos."""
    if not isinstance(command, list) or not all(isinstance(x, str) for x in command):
        return ''
    address = task.get('target', {}).get('address', '')
    try:
        ip_address(address)
    except ValueError:
        return ''
    profile = task.get('action_profile', '')
    if profile=='nmap_tcp_open_ports_personal_v1':
        try:
            from puertos_personales import automatic_command
            from laboratorio_personal import InventoryTask
            if command==automatic_command(InventoryTask.model_validate(task)):return shlex.join(command)
        except (ValueError,TypeError,KeyError):pass
        return ''
    if profile=='nmap_tcp_services_personal_v1':
        try:
            from laboratorio_personal import InventoryTask, command_for
            if command==command_for(InventoryTask.model_validate(task)):
                return shlex.join(command)
        except (ValueError,TypeError,KeyError):
            pass
        return ''
    if profile == 'nmap_tcp_services_v1':
        try:
            from auditoria.agentes.agente_ipv4_servicios import nmap_command
            from auditoria.contracts import Task
            if command == nmap_command(Task.model_validate(task)):
                return shlex.join(command)
        except (ValueError, TypeError, KeyError):
            pass
    if profile.startswith('hydra_') and profile.endswith('_single_v1') and len(command) in {20, 21}:
        # El resultado conserva una orden pública con archivos opacos. No mostrar el usuario.
        fixed = {0:'hydra',1:'-l',3:'-P',5:'-o',7:'-b',8:'json',9:'-t',10:'1',11:'-f',12:'-I',13:'-4',14:'-w',15:'5',16:'-s'}
        if any(command[i] != value for i,value in fixed.items()):
            return ''
        if command[18] != address or command[19] not in {'ssh','ftp','postgres','http-get'}:
            return ''
        if not command[17].isdigit() or int(command[17]) not in task.get('target',{}).get('ports',[]):
            return ''
        if profile != f"hydra_{command[19].replace('-','_')}_single_v1":
            return ''
        if (command[19]=='http-get' and command[20:]!=['/manager/html']) or (command[19]!='http-get' and len(command)!=20):
            return ''
        public = list(command)
        public[2],public[4],public[6] = '[usuario oculto]','[archivo privado]','[resultado privado]'
        return shlex.join(public)
    return ''


def event_rows(path, root, limit=1000):
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        return []
    connection = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=.2)
        rows = connection.execute('SELECT rowid,timestamp,component,kind,task_id,payload_json FROM events ORDER BY rowid DESC LIMIT ?', (limit,)).fetchall()
        result = []
        for seq, stamp, component, kind, task, raw in reversed(rows):
            try:
                payload = json.loads(raw)
                if isinstance(payload, dict):
                    result.append((seq, stamp, component, kind, task, payload))
            except (ValueError, TypeError):
                continue
        return result
    except (OSError, sqlite3.Error):
        return []
    finally:
        if connection is not None:
            connection.close()


def http_path(value):
    # Estas son las rutas cerradas del fixture; no proyectar consultas, cookies o cuerpos arbitrarios.
    if value == '/admin' or (isinstance(value, str) and re.fullmatch(r'/objects/[0-9a-f]{12}', value)):
        return value
    allowed = {'/download?name=..%2Fprivate%2Faudit_marker.txt', '/download?name=%252e%252e%252fprivate%252faudit_marker.txt'}
    return value if value in allowed else '[ruta no publicada]'


def inspect_run(directory, root, run, report, plan, read_file):
    tasks = {t.get('task_id'):t for t in plan if isinstance(t, dict)}
    results = {t.get('task_id'):t for t in report.get('tasks', []) if isinstance(t, dict)}
    rows = event_rows(directory / 'events.sqlite3', root)
    lines, evidence_by_task, starts = [], {}, {}
    validations = {v.get('task_id'):v for v in report.get('validation',[]) if isinstance(v,dict)}

    def add(seq, stamp, kind, tool, text, source, task_id=None, level='info'):
        task = tasks.get(task_id, {})
        asset = task.get('target', {}).get('asset_id', '')
        lines.append({'id':f'{seq}:{len(lines)}', 'time':stamp, 'kind':kind, 'tool':tool, 'text':text,
                      'source':source, 'task_id':task_id, 'asset':ASSET_NAMES.get(asset, asset), 'level':level,
                      'address':task.get('target',{}).get('address','')})

    def evidence(task_id):
        if task_id in evidence_by_task:
            return evidence_by_task[task_id]
        result = results.get(task_id, {})
        ref = public_ref(result.get('evidence_ref')) or public_ref(f'evidence/{task_id}_state.json')
        raw = read_file(directory / ref) if ref else None
        try:
            value = json.loads(raw) if raw else {}
            value = value if isinstance(value, dict) else {}
        except (ValueError, TypeError):
            value = {}
        expected = result.get('evidence_sha256')
        integrity = hashlib.sha256(raw).hexdigest() == expected if raw and isinstance(expected, str) else None
        evidence_by_task[task_id] = (ref, value, integrity)
        return evidence_by_task[task_id]

    for seq,stamp,component,kind,task_id,payload in rows:
        task = tasks.get(task_id, {})
        profile = task.get('action_profile', '')
        tool, description = tool_for(profile,run.get('bank'))
        if component=='orchestration' and kind=='tool_execution_failed' and payload.get('engine')=='langgraph':
            stage=payload.get('stage');code=payload.get('reason_code');exception=payload.get('exception_type')
            stage=stage if isinstance(stage,str) and stage in FAILURE_PHASES else 'tool_execution'
            code=code if isinstance(code,str) and code in FAILURE_REASONS else 'execution_error'
            exception=exception if isinstance(exception,str) and exception in EXCEPTION_TYPES else None
            text=f"Fallo en {FAILURE_PHASES[stage]}: {FAILURE_REASONS[code]}."
            if exception:text+=f' Tipo: {exception}.'
            ref=public_ref(payload.get('diagnostic_ref'))
            digest=payload.get('diagnostic_sha256')
            digest=digest if isinstance(digest,str) and re.fullmatch(r'[a-f0-9]{64}',digest) else ''
            raw=read_file(directory/ref) if ref and digest and payload.get('diagnostic_persisted') is True else None
            verified=bool(raw and hashlib.sha256(raw).hexdigest()==digest)
            if verified:text+=f' Diagnóstico: {ref} · SHA-256 {digest}.'
            add(seq,stamp,'FALLO',tool,text,'Evento saneado de fallo; no acredita un hallazgo',task_id,'error')
            lines[-1].update(failure_stage=stage,failure_phase=FAILURE_PHASES[stage],reason_code=code,
                            exception_type=exception,diagnostic_ref=ref if verified else '',
                            diagnostic_sha256=digest if verified else '')
        elif component=='orchestration' and kind in {'receiver_recovery_started','receiver_recovery_finished'}:
            # Una recuperación previa prepara el receptor; nunca equivale a una
            # prueba enviada ni a la confirmación de una vulnerabilidad.
            if (payload.get('stage')!='receiver_readiness' or type(payload.get('attempt')) is not int
                or payload['attempt']!=1 or payload.get('probe_sent') is not False):continue
            if kind=='receiver_recovery_started':
                text='Recuperando el estado inicial del receptor IPv6 antes de enviar la sonda. No confirma un hallazgo.'
                level='warning'
            elif payload.get('status')=='recovered':
                text='Estado inicial del receptor IPv6 recuperado. La sonda todavía no se ha enviado; no confirma un hallazgo.'
                level='info'
            elif payload.get('status')=='failed':
                text='No se pudo recuperar el estado inicial del receptor IPv6. No se envió la sonda ni se confirmó un hallazgo.'
                level='error'
            else:continue
            add(seq,stamp,'RECUPERACIÓN','Preparación del receptor IPv6',text,
                'Recuperación previa acotada a un intento; evento '+kind,task_id,level)
        elif component=='orchestration' and kind in {'graph_node_started','graph_node_finished','graph_node_failed'}:
            labels={'preflight':'Comprobar laboratorio y autorización','admission':'Admitir tareas autorizadas',
                    'execution':'Ejecutar herramientas','validation':'Validar evidencia',
                    'review':'Revisar resultados con el LLM','close':'Guardar informes y cerrar',
                    'abort':'Detener de forma controlada'}
            node=payload.get('node')
            if payload.get('engine')=='langgraph' and node in labels:
                action={'graph_node_started':'Inicio','graph_node_finished':'Fin','graph_node_failed':'Fallo'}[kind]
                add(seq,stamp,'LANGGRAPH','LangGraph',action+': '+labels[node]+'.','Transición real del grafo registrada',level='error' if kind=='graph_node_failed' else 'info')
        elif kind=='discovery_started' and run['mode']=='live':
            # Reconstruir la forma cerrada a partir del alcance, nunca publicar una orden libre.
            try:
                from laboratorio_personal import configuration,scope_hosts,DISCOVERY_PROBES
                request=json.loads(read_file(directory/'request.json') or b'{}')
                config=configuration(request.get('personal'))
                allowed={address for _,address in scope_hosts(config)}
                command=payload.get('command')
                assert isinstance(command,list) and 14<=len(command)<=269
                assert all(isinstance(v,str) for v in command)
                probes=DISCOVERY_PROBES if config.get('port_mode')=='auto' else config['ports']
                assert command[:10]==['nmap','--unprivileged','-n','-sn','-PS'+','.join(map(str,probes)),'--max-retries','1','--host-timeout','15s','-e']
                assert re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',command[10]) and command[11:13]==['-oX','-']
                assert all(ip_address(v).version==4 and v in allowed for v in command[13:])
                assert len(set(command[13:]))==len(command[13:])
                add(seq,stamp,'DESCUBRIMIENTO','Nmap',f"Buscando respuesta en {len(command[13:])} {'dirección' if len(command[13:])==1 else 'direcciones'} IPv4.",'Evento discovery_started')
                add(seq,stamp,'COMANDO','Nmap',shlex.join(command),'Invocación solicitada; evento discovery_started')
            except (ValueError,TypeError,KeyError,AssertionError):
                pass
        elif kind=='discovery_finished' and run['mode']=='live':
            states=payload.get('states',{})
            if isinstance(states,dict) and len(states)<=256 and all(isinstance(v,str) and v in {'up','down'} for v in states.values()):
                add(seq,stamp,'DESCUBRIMIENTO','Nmap',f"Descubrimiento cerrado: {sum(v=='up' for v in states.values())} con respuesta; {sum(v=='down' for v in states.values())} sin respuesta.",'Evento discovery_finished')
        elif component=='administrator' and kind=='open_ports_reported':
            try:
                from puertos_personales import parse_open_ports
                from laboratorio_personal import InventoryTask
                ref=public_ref(payload.get('evidence_ref'));raw=read_file(directory/ref) if ref else None
                if not raw or hashlib.sha256(raw).hexdigest()!=payload.get('evidence_sha256'):continue
                ports=parse_open_ports(raw,InventoryTask.model_validate(task))
                if ports!=payload.get('open_ports'):continue
                listing=', '.join(map(str,ports[:32])) or 'ninguno'
                suffix=f' (se muestran 32 de {len(ports)})' if len(ports)>32 else ''
                add(seq,stamp,'ADMINISTRADOR','Descubrimiento → administrador',f'Puertos TCP abiertos verificados: {listing}{suffix}.','Entrega registrada con XML íntegro; solo estos puertos pueden generar reconocimiento',task_id)
            except (OSError,ValueError,TypeError,ET.ParseError):pass
        elif component=='administrator' and kind=='open_service_plan_created':
            count=payload.get('tasks')
            if type(count) is int and 0<=count<=256:add(seq,stamp,'ADMINISTRADOR','Plan de servicios',f'{count} lotes de reconocimiento programados sobre puertos abiertos.','Evento open_service_plan_created',task_id)
        elif component=='tool' and kind=='tool_started':
            command=recorded_command(payload.get('command'),task)
            if command:add(seq,stamp,'COMANDO',tool,command,'Invocación solicitada; evento tool_started',task_id)
        elif component=='tool' and kind=='tool_finished':
            label='Inventario completado' if profile=='nmap_tcp_services_personal_v1' and payload.get('status')=='completed_no_findings' else STATUS_NAMES.get(payload.get('status'),'Cierre de herramienta')
            add(seq,stamp,'HERRAMIENTA',tool,label,
                'Evento tool_finished',task_id,'error' if payload.get('status')=='failed' else 'info')
        elif kind == 'task_admitted':
            starts[task_id]=stamp
            add(seq,stamp,'INICIO',tool,PROFILE_NAMES.get(profile, profile), 'Evento task_admitted', task_id)
            if run['mode'] == 'live':
                add(seq,stamp,'PERFIL',tool,description, 'Descripción del código; no es una traza de cada subcomando',task_id)
        elif kind == 'task_terminal':
            status = payload.get('status')
            reason = payload.get('reason_code')
            reason = reason if isinstance(reason,str) and re.fullmatch(r'[a-z0-9_:-]{1,80}',reason) else None
            label='Inventario completado' if profile=='nmap_tcp_services_personal_v1' and status=='completed_no_findings' else STATUS_NAMES.get(status,'Cierre registrado')
            add(seq,stamp,'CIERRE',tool,label + (f' · {reason}' if reason else ''),
                'Evento task_terminal',task_id,'error' if status in {'failed','blocked','cancelled'} else 'info')
            if task_id in starts:
                from datetime import datetime
                try:
                    elapsed=(datetime.fromisoformat(stamp)-datetime.fromisoformat(starts[task_id])).total_seconds()
                    if elapsed>=0:lines[-1]['text']+=f' · {elapsed:.2f} s'
                except (TypeError,ValueError):pass
            if run['mode'] != 'live' or status not in {'completed','completed_no_findings'}:
                continue
            command = recorded_command(results.get(task_id,{}).get('command'), task)
            if command:
                add(seq,stamp,'COMANDO',tool,command,'Orden conservada en el resultado; no se ejecuta desde esta consola',task_id)
            ref, data, integrity = evidence(task_id)
            if integrity is True:
                services=results.get(task_id,{}).get('services',[])
                for service in (services if isinstance(services,list) else [])[:32]:
                    if not isinstance(service,dict) or service.get('state')!='open' or service.get('port') not in task.get('target',{}).get('ports',[]):continue
                    name=service.get('name','')
                    name=name if isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,40}',name) else 'sin identificar'
                    add(seq,stamp,'SERVICIO',tool,f"TCP {service['port']} abierto · {name}",'Resultado conservado; disponible al cierre, no salida en streaming',task_id)
            if integrity is True and not data:
                add(seq,stamp,'EVIDENCIA','Archivo',ref+' · SHA-256 coincide','Artefacto de la tarea',task_id)
            if not data or integrity is False:
                if integrity is False:add(seq,stamp,'VALIDACIÓN','Integridad','La evidencia no coincide con su SHA-256. No interpretar este artefacto.','Contraste local del archivo',task_id,'error')
                continue
            if integrity is True:
                authentication=results.get(task_id,{}).get('authentication') or {}
                if isinstance(authentication,dict) and authentication.get('outcome') in {'accepted','rejected','indeterminate','transport_error'}:
                    labels={'accepted':'Credencial aceptada por la herramienta','rejected':'Credencial rechazada','indeterminate':'Autenticación sin resultado concluyente','transport_error':'Error de conexión al autenticar'}
                    add(seq,stamp,'AUTENTICACIÓN',tool,labels[authentication['outcome']],'Resultado de herramienta; no confirma por sí solo un hallazgo',task_id)
                validation=validations.get(task_id,{})
                if validation.get('independent_confirmation') is True:
                    add(seq,stamp,'VALIDACIÓN','Cliente independiente','Corroboración independiente registrada.','Registro de validación del informe final',task_id)
            families = data.get('families',{})
            for family,facts in (families.items() if isinstance(families,dict) else []):
                if family not in {'ipv4','ipv6'} or not isinstance(facts,dict):
                    continue
                for record in facts.get('records',[])[:20]:
                    if not isinstance(record,dict) or type(record.get('status')) is not int:
                        continue
                    add(seq,stamp,'HTTP','urllib.request',f"{family.upper()} GET {http_path(record.get('path'))} → HTTP {record['status']}",
                        'Respuesta conservada; visible al cerrar la tarea, sin hora individual',task_id)
            for field in ['probe','control_probe']:
                proof = data.get(field,{})
                if not isinstance(proof,dict) or not public_ref(proof.get('pcap_ref')):
                    continue
                count = proof.get('packet_count')
                if type(count) is int and 1 <= count <= 3:
                    add(seq,stamp,'PAQUETES','Scapy',f"Captura de {'control' if field=='control_probe' else 'prueba'}: {count} paquetes · {public_ref(proof['pcap_ref'])}",
                        'Metadatos de captura conservados',task_id)
            if ref and data:
                add(seq,stamp,'EVIDENCIA','Archivo',ref + (' · SHA-256 coincide' if integrity else ''), 'Artefacto de la tarea',task_id)
        elif component == 'llm' and kind == 'request_started':
            review=payload.get('phase')=='specialist_review'
            add(seq,stamp,'IA','Revisor LLM' if review else 'Planificador API','Revisando observaciones para el informe.' if review else 'Seleccionando la siguiente prueba del catálogo.','Evento request_started')
        elif component == 'llm' and kind == 'decision':
            accepted = payload.get('status') == 'accepted'
            tokens = payload.get('total_tokens')
            tokens_text = f'{tokens} tokens medidos' if type(tokens) is int else 'uso sin medición completa'
            add(seq,stamp,'IA','Revisor LLM' if payload.get('phase')=='specialist_review' else 'Planificador API',('Respuesta aceptada' if accepted else 'Respuesta no aceptada')+' · '+tokens_text,
                'Evento decision',level='info' if accepted else 'warning')
        elif kind == 'web_response':
            if payload.get('family') in {'ipv4','ipv6'} and payload.get('channel') in {'urllib','http.client'} and payload.get('check') in {'own','anonymous','foreign','download','admin'}:
                status=payload.get('status');status=status if type(status) is int and 100<=status<=599 else 'sin respuesta válida'
                add(seq,stamp,'HTTP',payload['channel'],payload['family']+' · '+payload['check']+' · '+str(status),'Respuesta registrada; cabeceras de sesión y cuerpo ocultos',task_id)
        elif kind == 'report_saved':
            add(seq,stamp,'INFORME','Validador y reportes','Informe y resultados publicados; explicación técnica y ejecutiva disponibles.','Evento report_saved')
        elif kind in {'request_accepted','plan_created','llm_ready','llm_fallback','provider_retry'}:
            labels = {'request_accepted':'Solicitud admitida dentro de la política.', 'plan_created':'Catálogo de tareas preparado.',
                      'llm_ready':'Planificador IA preparado.', 'llm_fallback':'Planificación de respaldo activada.', 'provider_retry':'Reintento del proveedor registrado.'}
            add(seq,stamp,'CONTROL','Controlador',labels[kind],'Evento '+kind,level='warning' if kind in {'llm_fallback','provider_retry'} else 'info')

    technical = []
    for task in run.get('tasks',[]):
        original = tasks.get(task['id'],{})
        result = results.get(task['id'],{})
        validation = validations.get(task['id'],{})
        ref, data, integrity = evidence(task['id'])
        tool, description = tool_for(task.get('profile',''),run.get('bank'))
        technical.append({'id':task['id'], 'profile':task.get('profile',''), 'address':task.get('address',''),
                          'tool':tool, 'description':description, 'evidence':ref if data or integrity is not None else '', 'hash_matches':integrity,
                          'confirmation':public_ref(result.get('diagnostic_ref')), 'command':recorded_command(result.get('command'),original),
                          'corroborated':validation.get('independent_confirmation') is True,
                          'validation':validation.get('reason') if validation.get('reason') in {'v2_independent_evidence_valid','independent_authentication_valid','empresa_independent_evidence_valid'} else '',
                          'state':STATUS_NAMES.get(task.get('status'),task.get('status',''))})
    return {'console':{'lines':lines, 'events_read':len(rows), 'limited':len(rows)>=1000,
                       'note':'Consola de lectura de eventos y evidencia. No admite comandos. Los subcomandos internos no tienen telemetría individual; la descripción de un perfil no acredita su ejecución completa.'},
            'technical':technical}
