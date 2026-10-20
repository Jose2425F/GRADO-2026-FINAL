"""Selección editorial de evidencia: lo accionable primero, detalle completo aparte."""
from collections import Counter

INACTIVE = {'not_requested', 'not_configured', 'not_supported', 'not_applicable'}
OWNERS = {'object_authorization': 'Aplicaciones', 'file_boundary': 'Aplicaciones',
          'ipv6_authorization_gap': 'Aplicaciones y redes',
          'untrusted_router_advertisement': 'Redes', 'neighbor_override': 'Redes', 'dad_interference': 'Redes'}


SUCCESS = {'completed', 'completed_no_findings'}
TERMINAL = SUCCESS | {'failed', 'blocked', 'cancelled', 'skipped'}
STAGES = [('discovery', 'Descubrimiento de puertos'), ('services', 'Identificación de servicios'),
          ('credentials', 'Comprobación de credenciales'), ('applications', 'Pruebas de aplicaciones'),
          ('other', 'Otras comprobaciones')]


def task_stage(profile):
    profile = profile if isinstance(profile, str) else ''
    if profile == 'nmap_tcp_open_ports_personal_v1': return 'discovery'
    if profile in {'nmap_tcp_services_personal_v1','nmap_tcp_services_v1'}: return 'services'
    if profile.startswith('hydra_'): return 'credentials'
    if profile == 'http_application_personal_v1' or profile.startswith('personal_web_') or 'authorization' in profile or 'file_boundary' in profile: return 'applications'
    return 'other'


def execution_progress(run, brief):
    tasks = brief.get('tasks', [])
    states = Counter(t.get('status') for t in tasks)
    total = max(len(tasks), run.get('total', 0))
    closed = sum(states[s] for s in TERMINAL)
    stages = []
    for key, label in STAGES:
        selected = [t for t in tasks if task_stage(t.get('profile', '')) == key]
        if not selected: continue
        count = Counter(t.get('status') for t in selected)
        stages.append({'key': key, 'label': label, 'total': len(selected),
                       'closed': sum(count[s] for s in TERMINAL),
                       'successful': sum(count[s] for s in SUCCESS),
                       'issues': sum(count[s] for s in ['failed', 'blocked', 'cancelled']),
                       'skipped': count['skipped'],
                       'no_detection': count['completed_no_findings'] if key == 'credentials' else None,
                       'findings': sum(c.get('task_id') in {t.get('id') for t in selected} for c in brief.get('cards', []))})
    automatic = brief.get('automatic_ports') or any(t.get('profile') == 'nmap_tcp_open_ports_personal_v1' for t in tasks)
    return {'total': total, 'closed': closed, 'successful': sum(states[s] for s in SUCCESS),
            'issues': sum(states[s] for s in ['failed', 'blocked', 'cancelled']),
            'skipped': states['skipped'], 'remaining': max(0, total-closed),
            'percent': round(100*closed/total, 1) if total else 0,
            'stages': stages, 'dynamic': bool(automatic),
            'explanation': ('El total cuenta operaciones del alcance autorizado. En rangos, primero se comprueba qué direcciones responden y se preparan tareas solo para ellas. Después el plan crece al descubrir servicios: se añaden tareas de identificación y, si se solicitaron, intentos de credenciales y pruebas web. Cada intento cuenta como una tarea; no es una vulnerabilidad distinta.'
                            if automatic else 'Cada tarea corresponde a una operación del plan. Una tarea cerrada puede haber terminado correctamente, fallado, quedado bloqueada u omitida.')}


INCIDENTS = {
    'credential_evidence_not_validated': ('Evidencia de autenticación no validada',
        'La comprobación no produjo evidencia que el validador pudiera aceptar. Este intento no confirma una credencial válida ni descarta una debilidad.',
        'Revisar el diagnóstico y la corroboración del intento; comprobar que el servicio responde con el mecanismo de autenticación esperado y repetir la prueba autorizada.'),
    'runtime_budget_exhausted': ('Límite de tiempo alcanzado', 'La tarea quedó sin ejecutar dentro del presupuesto de tiempo.',
        'Repetir con un alcance menor o revisar el presupuesto de ejecución.'),
    'timeout': ('Tiempo de espera agotado', 'La herramienta no terminó dentro del tiempo permitido.',
        'Comprobar conectividad y respuesta del servicio antes de repetir.'),
    'web_inventory_or_service_unavailable': ('Servicio web sin requisitos verificados', 'No se verificó el inventario o el servicio necesario para ejecutar esta prueba.',
        'Revisar el inventario y la configuración de la aplicación antes de repetir.')}


def report_view(run, brief, technical, assistance, plan=None, results=None):
    progress = execution_progress(run, brief)
    ports_by_task = {t.get('task_id'): [port for port in t.get('target', {}).get('ports', [])
                                      if type(port) is int and 1 <= port <= 65535] if t.get('action_profile','').startswith(('hydra_','http_')) else [] for t in (plan or [])}
    for result in results or []:
        task_id=result.get('task_id');auth=result.get('authentication')
        if isinstance(auth,dict) and type(auth.get('port')) is int and auth['port'] in ports_by_task.get(task_id,[]):
            ports_by_task[task_id]=[auth['port']]
    findings = [{**card, 'ports': ports_by_task.get(card.get('task_id'), [])} for card in brief.get('cards', [])]
    incident_groups = {}
    for issue in brief.get('issues', []):
        reason = issue.get('reason') or 'not_recorded'
        key = (issue.get('address') or issue.get('asset_name', 'Objetivo'), issue.get('profile'), reason)
        if key not in incident_groups:
            title, meaning, next_step = INCIDENTS.get(reason, ('Comprobación sin resultado válido',
                'Esta operación no aportó una comprobación válida. Su resultado no acredita que el control sea seguro.',
                'Revisar la bitácora y la evidencia técnica de la tarea antes de repetirla.'))
            incident_groups[key] = {'address': key[0], 'label': issue.get('label', 'Comprobación'),
                'reason': reason, 'title': title, 'meaning': meaning, 'next_step': next_step, 'count': 0, 'ports': []}
        group = incident_groups[key]; group['count'] += 1
        group['ports'] = sorted(set(group['ports']) | set(ports_by_task.get(issue.get('id'), [])))
    exposures = []
    for item in brief.get('inventory', []):
        ports = [p for p in item.get('ports', []) if p.get('state') == 'open']
        # Una línea de servicio no sustituye al estado de puerto registrado.
        if not ports or item.get('host_state') == 'down':
            continue
        services = []
        for port in ports:
            service = next((s for s in item.get('services', []) if s.get('port') == port['port']), {})
            services.append({'port': port['port'], 'name': service.get('name') or 'Sin identificar',
                             'version': ' '.join(str(service.get(k) or '') for k in ['product', 'version']).strip()})
        exposures.append({**item, 'open_services': services})
    down = sum(i.get('host_state') == 'down' for i in brief.get('inventory', []))
    closed = sum(p.get('state') == 'closed' for i in brief.get('inventory', []) for p in i.get('ports', []))
    cards = findings
    groups = {}
    for card in cards:
        condition = card.get('condition') or card['title']
        key = 'default_credentials' if condition in {'ssh_default_credential','ftp_default_credential','postgres_default_credential','http_get_default_credential'} else condition
        if key not in groups:
            groups[key] = {'title': 'Eliminar las credenciales por defecto de los servicios' if key=='default_credentials' else card['title'], 'fix': card['fix'], 'impact': card['impact'],
                           'owner': OWNERS.get(key, 'Sistemas'), 'targets': [], 'count': 0,
                           'severity': card.get('severity', 'unknown'), 'observations': [], 'endpoints': [],
                           'verification': ('Repetir la prueba autorizada: la credencial conocida debe ser rechazada, una cuenta válida debe seguir funcionando y la evidencia independiente debe confirmar el resultado.'
                                            if key=='default_credentials' else 'Repetir el caso que confirmó el hallazgo y su control protegido; conservar ambas evidencias antes de cerrar la acción.')}
        card['verification'] = groups[key]['verification']
        target = card.get('address') or card.get('asset') or 'Objetivo'
        if target not in groups[key]['targets']:
            groups[key]['targets'].append(target)
        groups[key]['endpoints'].append({'address': target, 'ports': card['ports'], 'title': card['title']})
        groups[key]['count'] += 1
        if card['title'] not in groups[key]['observations']:
            groups[key]['observations'].append(card['title'])
        ranks={'critical':0,'high':1,'medium':2,'low':3,'unknown':4}
        if ranks.get(card.get('severity'),4)<ranks.get(groups[key]['severity'],4):
            groups[key]['severity']=card['severity']
    priorities = sorted(groups.values(), key=lambda g: {'critical':0,'high':1,'medium':2,'low':3}.get(g['severity'],4))
    for index, group in enumerate(priorities, 1):
        group['order'] = index
    service_count = sum(len(i['open_services']) for i in exposures)
    if run.get('mode') != 'live' or not brief.get('final'):
        headline = brief['summary']
    elif cards:
        headline = f"{len(cards)} hallazgos confirmados en {brief['affected']} {'objetivo' if brief['affected']==1 else 'objetivos'}. Plan de corrección: {len(priorities)} {'acción' if len(priorities)==1 else 'acciones'}."
    elif brief.get('is_inventory'):
        headline = f"{service_count} servicios TCP abiertos en {len(exposures)} direcciones. El resultado es un inventario de exposición, sin pruebas de vulnerabilidad."
    else:
        headline = 'No se confirmaron hallazgos en las pruebas ejecutadas.'
    issue_count = len(brief.get('issues', []))
    if issue_count and brief.get('final'):
        headline += f' Hay {issue_count} tareas con incidencias que requieren revisión.'
    reviews = [r for r in assistance.get('reviews', []) if r.get('status') == 'accepted' and r.get('interpretation')]
    coverage = []
    for item in brief.get('coverage', []):
        if item.get('inventory_state') == 'down':
            continue
        checks = []
        if item.get('credentials_state') not in INACTIVE:
            checks.append(('Credenciales', item.get('credentials_state', 'not_evaluated')))
        for name, state in item.get('web_checks', {}).items():
            if state not in INACTIVE:
                checks.append(({'object_authorization': 'Documento ajeno', 'file_boundary': 'Límite de descarga',
                                'ipv6_authorization_gap': 'Permisos IPv4/IPv6'}.get(name, name), state))
        if checks:
            coverage.append({'address': item['address'], 'checks': checks})
    hosts = []
    host_rows=list(exposures)
    if run.get('bank')=='empresa':
        addresses={item['address'] for item in host_rows}
        for task in brief.get('tasks',[]):
            address=task.get('address')
            if address and address not in addresses:
                host_rows.append({'address':address,'open_services':[]});addresses.add(address)
    for item in host_rows:
        address = item['address']
        confirmed = [f for f in findings if f.get('address') == address]
        issues = [g for g in incident_groups.values() if g['address'] == address]
        hosts.append({'address': address, 'services': item['open_services'], 'findings': len(confirmed),
                      'issues': sum(g['count'] for g in issues),
                      'activity': ('Aplicación dual-stack instrumentada' if any(t.get('address')==address and t.get('agent')=='application_access' for t in brief.get('tasks',[])) else 'Controles IPv6 instrumentados' if any(t.get('address')==address and t.get('agent') in {'ipv6_ndp','ipv6_fragmentation'} for t in brief.get('tasks',[])) else 'Sin servicio TCP abierto confirmado'),
                      'conclusion': ('Hallazgo confirmado · revisión pendiente' if confirmed and issues else
                                     'Hallazgo confirmado' if confirmed else 'Comprobación incompleta' if issues else
                                     'Sin hallazgos confirmados en las pruebas realizadas')})
    states = Counter(t.get('status') for t in brief.get('tasks', []))
    return {'progress': progress, 'findings': findings, 'hosts': hosts, 'incident_groups': list(incident_groups.values()),
            'severity_counts': dict(Counter(f.get('severity','unknown') for f in findings)),
            'headline': headline, 'priorities': priorities, 'exposures': exposures,
            'service_count': service_count, 'exposed_hosts': len(exposures), 'down_count': down,
            'closed_ports': closed, 'issues': brief.get('issues', []), 'reviews': reviews,
            'coverage': coverage, 'task_states': dict(states),
            'diagnostics': technical, 'scope_count': max(len(brief.get('inventory', [])), brief.get('assets', 0))}
