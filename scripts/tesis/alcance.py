"""Contrato visible del alcance académico y sus criterios de aceptación."""
CAPABILITIES = [
 {'id':'services','title':'Servicios IPv4','tool':'Nmap','detail':'Puertos, producto y versión. Candidatos CVE del catálogo local, sin confirmarlos por banner.','state':'implemented'},
 {'id':'credentials','title':'Credenciales IPv4','tool':'Hydra + cliente independiente','detail':'SSH, FTP, PostgreSQL y HTTP Basic: intentos finitos y corroboración.','state':'implemented'},
 {'id':'ipv6','title':'NDP y SLAAC IPv6','tool':'Scapy + observador','detail':'Anuncios de router, vecinos, DAD y MTU con restauración del receptor.','state':'implemented'},
 {'id':'fragmentation','title':'Fragmentación IPv6','tool':'Scapy + observador','detail':'Solapamientos, fragmento atómico y cadena incompleta. La conformidad también se registra.','state':'implemented'},
]
ROLES = [
 {'id':'administrator','name':'Administrador','kind':'Orquestación','action':'Selecciona tareas autorizadas, aplica dependencias y controla recursos.'},
 {'id':'network','name':'Servicios IPv4','kind':'Especialista LLM','action':'Relaciona inventario, referencias y limitaciones de identificación.'},
 {'id':'credentials','name':'Credenciales IPv4','kind':'Especialista LLM','action':'Interpreta acceso corroborado, rechazos e incidencias de autenticación.'},
 {'id':'ipv6','name':'NDP / SLAAC','kind':'Especialista LLM','action':'Interpreta cambios de ruta, vecinos y direcciones frente a la política del enlace.'},
 {'id':'fragmentation','name':'Fragmentación IPv6','kind':'Especialista LLM','action':'Distingue recepción conforme, descarte y observación insuficiente.'},
 {'id':'applications','name':'Acceso a aplicaciones','kind':'Extensión documentada','action':'Revisa permisos de recursos y diferencias de autorización dual-stack en los escenarios del banco.'},
]


def summary(active_runs, archive_list, study, api_available, readiness=None):
    result={'architecture':'Monolito modular', 'capabilities':CAPABILITIES,'roles':ROLES,
        'bank':{'id':'empresa','name':'NovaFlow · banco integrado','targets':10,'tasks':32,'containers':12,
                'state':'requires_acceptance','note':'Banco existente para preparar el cierre. Su disponibilidad no equivale a una certificación experimental.'},
        'active_runs':len(active_runs),'archived_runs':sum(a.get('runs_count') or 0 for a in archive_list),
        'archives':archive_list,'api_configured':bool(api_available),
        'gates':[
            {'id':'software','title':'Código y alcance','state':'implemented','detail':'Cuatro áreas académicas, validadores, eventos e informes. La aceptación se comprueba con pruebas.'},
            {'id':'lab','title':'Aceptar el laboratorio','state':'pending','detail':'Verificar controles positivos y protegidos, restauración y referencia del evaluador antes del piloto.'},
            {'id':'freeze','title':'Congelar la versión','state':'pending','detail':'El protocolo histórico es incompatible con los cambios actuales. Preparar una nueva identidad de código, banco y prompts.'},
            {'id':'pilot','title':'Piloto y presupuesto','state':'pending','detail':'Comprobar el flujo real de ambas arquitecturas y medir consumo antes de fijar la muestra.'},
            {'id':'study','title':'Evaluación comparativa','state':'pending','detail':'15 parejas / 30 corridas previstas como estudio exploratorio; conservar fallos y resultados desfavorables.'},
            {'id':'document','title':'Documento y sustentación','state':'pending','detail':'Actualizar resultados y decisiones en el principal (máximo 80 páginas), detalle con referencias a anexos.'}],
        'study':{'status':'preparing','pairs':15,'runs':30,'budget_usd':20,'formal_runs':0,
                 'note':'La nueva etapa está vacía. Las prácticas manuales no se convierten automáticamente en muestra experimental.'}}
    result['readiness']=readiness or {}
    acceptance=(readiness or {}).get('acceptance',{})
    if acceptance.get('acceptance_passed') is True:
        result['gates'][1].update(state='validated',detail=f"{acceptance.get('tasks_valid')} / {acceptance.get('tasks_checked')} perfiles válidos en la aceptación funcional del banco; falta congelar imágenes y versión para el estudio.")
        result['bank']['state']='functional_acceptance_passed'
    elif acceptance.get('acceptance_passed') is False:
        result['gates'][1].update(state='issues',detail=f"Aceptación con incidencias: {acceptance.get('tasks_valid')} / {acceptance.get('tasks_checked')} perfiles válidos. Revisar la evidencia antes de medir KPI.")
    from tesis.estudio import public_status
    progress=public_status()
    if progress:
        result['study'].update(progress,formal_runs=progress.get('formal_runs',0),pairs=progress.get('pairs_planned',30),runs=progress.get('runs_planned',60),note=progress.get('message',''))
        result['gates'][4].update(state='validated' if progress.get('status')=='complete' else 'pending',detail=f"{progress.get('formal_runs',0)} / {progress.get('runs_planned',60)} posiciones formales registradas; {progress.get('pilot_runs',0)} corridas de piloto separadas. Finalizar posiciones no acredita ausencia de fallos.")
    return result


def preparation(repository):
    import json
    def read(path):
        try:
            if path.is_symlink() or path.stat().st_size>1_000_000:return {}
            value=json.loads(path.read_text());return value if isinstance(value,dict) else {}
        except (OSError,ValueError):return {}
    acceptance=read(repository/'piloto_kali/prototipo/.verificacion/cierre-tesis/aceptacion.json')
    api=read(repository/'docs/cierre-tesis/comprobacion-api.json')
    return {'acceptance':{k:acceptance.get(k) for k in ['acceptance_passed','tasks_checked','tasks_valid','created_at','source_sha256']},
            'api':{k:api.get(k) for k in ['status','model','known_tokens','usage_complete','generations','type']}}
