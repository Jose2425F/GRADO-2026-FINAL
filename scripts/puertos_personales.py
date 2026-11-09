"""Descubrimiento TCP automático y entrega al administrador; fuera de los bancos fijos."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET
from uuid import uuid4

import laboratorio_personal as P
from auditoria.contracts import Service, TaskResult, TaskStatus
from auditoria.dashboard import process_identity
from auditoria.store import RunStore, write_json

PROFILE = P.AUTOMATIC_PROFILE
MAX_SERVICE_TASKS = 256
SUCCESS = {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}


def automatic_command(task):
    if task.action_profile!=PROFILE or task.timeout_seconds!=60 or task.dependencies or task.target.ports:
        raise ValueError('Perfil automático de puertos no admitido.')
    address=ip_address(task.target.address)
    P.configuration({'ipv4':str(address) if address.version==4 else '',
                     'ipv6':str(address) if address.version==6 else '',
                     'port_mode':'auto','interface':task.target.interface})
    target=str(address)+('%'+task.target.interface if address.version==6 and address.is_link_local else '')
    return ['nmap',*(['-6'] if address.version==6 else []),'--unprivileged','-n','-Pn','-sT',
            '--max-retries','1','--host-timeout','50s','-e',task.target.interface,'-p','1-65535','-oX','-',target]


def parse_open_ports(raw,task):
    if len(raw)>2_000_000:raise ValueError('open_port_response_too_large')
    root=ET.fromstring(raw);finished=root.find('runstats/finished');info=root.findall('scaninfo')
    if finished is None or finished.get('exit')!='success' or len(info)!=1 or info[0].get('type')!='connect' or info[0].get('protocol')!='tcp' or info[0].get('numservices')!='65535' or info[0].get('services')!='1-65535':
        raise ValueError('incomplete_tcp_discovery')
    hosts=root.findall('host')
    if len(hosts)!=1 or hosts[0].get('timedout') not in {None,'false'}:raise ValueError('incomplete_host_discovery')
    host=hosts[0]
    status=host.find('status')
    if status is None or status.get('state')!='up':raise ValueError('host_not_confirmed_for_port_scan')
    addresses=[a.get('addr') for a in host.findall('address') if a.get('addrtype') in {'ipv4','ipv6'}]
    if addresses!=[task.target.address]:raise ValueError('unexpected_discovery_target')
    entries={};opened=[]
    for entry in host.findall('ports/port'):
        port=int(entry.get('portid','0'));state=entry.find('state')
        if entry.get('protocol')!='tcp' or not 1<=port<=65535 or port in entries or state is None or state.get('state') not in {'open','closed','filtered','unfiltered','open|filtered','closed|filtered'}:
            raise ValueError('invalid_tcp_port_state')
        entries[port]=state.get('state')
        if state.get('state')=='open':opened.append(port)
    extra=0
    for item in host.findall('ports/extraports'):
        count=int(item.get('count','-1'))
        if count<0 or item.get('state') not in {'closed','filtered','unfiltered','open|filtered','closed|filtered'}:raise ValueError('invalid_aggregate_state')
        extra+=count
    if len(entries)+extra!=65535:raise ValueError('incomplete_tcp_port_accounting')
    return sorted(opened)


def execute_open_task(task,store,deadline,runner=subprocess.run,*,authorization=None):
    P.require_authorization(authorization, [task.target])
    if authorization.scope['personal'].get('port_mode')!='auto':
        raise P.AuthorizationError('authorization_ports_denied', 'El permiso no incluye el descubrimiento TCP automático.')
    command=automatic_command(task)
    config={'ipv4':task.target.address if ip_address(task.target.address).version==4 else '',
            'ipv6':task.target.address if ip_address(task.target.address).version==6 else '',
            'port_mode':'auto','interface':task.target.interface}
    if P.resolve_targets(config,deadline=deadline)!=[task.target]:raise ValueError('discovery_route_changed')
    P.require_authorization(authorization, [task.target])
    raw=diagnostic=b'';opened=[];status=TaskStatus.COMPLETED_NO_FINDINGS;reason=None
    store.event('tool','tool_started',task_id=task.task_id,payload={'tool':'nmap','command':command})
    try:
        timeout=min(65,deadline-time.monotonic())
        if timeout<=0:raise ValueError('runtime_budget_exhausted')
        from auditoria.tool_worker import tool_runtime_enabled,run_tool
        result=(run_tool if tool_runtime_enabled() else runner)(command,capture_output=True,timeout=timeout,check=False)
        raw=result.stdout;diagnostic=result.stderr
        if result.returncode:status=TaskStatus.FAILED;reason='tcp_discovery_failed'
        else:opened=parse_open_ports(raw,task)
    except subprocess.TimeoutExpired as exc:
        raw=exc.stdout or b'';diagnostic=exc.stderr or b'';status=TaskStatus.FAILED;reason='tcp_discovery_timeout'
    except (OSError,ValueError,TypeError,ET.ParseError):status=TaskStatus.FAILED;reason='invalid_open_port_inventory'
    ref,digest=store.evidence(task.task_id,'xml',raw[:2_000_000]);diagnostic_ref,diagnostic_sha=store.evidence(task.task_id+'_diagnostic','txt',diagnostic[:64000])
    store.event('tool','tool_finished',task_id=task.task_id,payload={'tool':'nmap','status':status.value,'reason_code':reason})
    return TaskResult(task_id=task.task_id,status=status,reason_code=reason,command=command,
        services=[Service(port=p,protocol='tcp',state='open') for p in opened],
        observations={'open_ports':opened,'tcp_range':'1-65535','scan_complete':status in SUCCESS},
        evidence_ref=ref,evidence_sha256=digest,diagnostic_ref=diagnostic_ref,diagnostic_sha256=diagnostic_sha)


def validated_result(directory,task,result):
    """El administrador contrasta evidencia antes de admitir puertos o servicios."""
    if result.task_id!=task.task_id:raise ValueError('unexpected_task_result')
    if result.status not in SUCCESS:return result
    ref=result.evidence_ref
    if ref!='evidence/'+task.task_id+'.xml':raise ValueError('unexpected_evidence_reference')
    path=directory/ref
    if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):raise ValueError('invalid_evidence_path')
    if path.stat().st_size>2_000_000:raise ValueError('evidence_too_large')
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=result.evidence_sha256:raise ValueError('invalid_evidence_integrity')
    if task.action_profile==PROFILE:
        ports=parse_open_ports(raw,task)
        if ports!=result.observations.get('open_ports') or result.services!=[Service(port=p,protocol='tcp',state='open') for p in ports]:raise ValueError('discovery_evidence_mismatch')
    else:
        services,states=P.parse_inventory(raw,task)
        if services!=result.services or states!=result.observations.get('port_states'):raise ValueError('service_evidence_mismatch')
    return result


def run_automatic(options,output):
    authorization = P.AuthorizationGuard(options)
    from auditoria.secure_runtime import require_live_runtime
    require_live_runtime(bank='personal',options=options,output=output)
    from aplicaciones_personales import configure_applications,load_session,ApplicationTask,execute_application,adjudicate_application,PROFILE as WEB_PROFILE
    config=P.configuration(options['personal']);applications=configure_applications(options.get('applications',[]),config)
    audit_id='personal_'+options['architecture']+'_'+uuid4().hex[:12];directory=output/(audit_id+'_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    store=RunStore(directory,audit_id);started=time.monotonic();deadline=started+P.RUNTIME_SECONDS
    runtime={'status':'running','pid':P.os.getpid(),'identity':process_identity(P.os.getpid()),'started_at':datetime.now(timezone.utc).isoformat()}
    write_json(directory/'runtime.json',runtime)
    purpose='network_vulnerability_evaluation' if applications else 'service_inventory_with_default_credentials' if options.get('creds') else 'service_inventory_not_vulnerability_evaluation'
    request={'audit_id':audit_id,'bank':'personal','architecture':options['architecture'],'token_budget':options['tokens'],
        'llm_mode':'scheduler' if options['ia']=='openai' else 'disabled','personal':config,'applications':applications,
        'expert_mode':bool(options.get('expert_mode')),'authorization_ref':options['authorization']}
    write_json(directory/'request.json',request)
    write_json(directory/'authorization.json',authorization.verify())
    workers=2 if options['architecture']=='multiagent' else 1
    write_json(directory/'manifest.json',{'bank':'personal','mode':'live','purpose':purpose,'port_discovery':'tcp_1_65535',
        'source_sha256':__import__('auditoria.cli',fromlist=['source_fingerprint']).source_fingerprint(),
        'adapter_sha256':hashlib.sha256(Path(P.__file__).read_bytes()).hexdigest(),
        'extensions_sha256':{name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in ['puertos_personales.py','llm_especialistas.py','aplicaciones_personales.py','tesis/llm_contexto.py','tesis/candidatos.py']},
        'execution_concurrency':workers,'maximum_runtime_seconds':P.RUNTIME_SECONDS,'maximum_service_tasks':MAX_SERVICE_TASKS})
    targets=[P.target_for(f,a,config) for f,a in P.scope_hosts(config)]
    def port_tasks(values):return [P.InventoryTask(task_id=audit_id+'_ports_'+str(i),agent_type='ipv'+str(ip_address(t.address).version)+'_services',target=t,action_profile=PROFILE) for i,t in enumerate(values)]
    tasks=port_tasks(targets);results=[];findings=[];validations=[];scheduler=None;error=None
    states={t.address:'unknown' for t in targets};discovery_ids={};opened_by_address={}
    def save_plan():write_json(directory/'plan.json',[t.model_dump(mode='json') for t in tasks])
    def terminal(task,result):
        results.append(result);store.event('orchestration','task_terminal',task_id=task.task_id,payload={'status':result.status.value,'reason_code':result.reason_code})
    def dispatch(initial):
        pending=list(initial);running={}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while pending or running:
                while pending and len(running)<workers and deadline-time.monotonic()>=P.TASK_RESERVE_SECONDS:
                    ready=sorted(pending,key=lambda t:t.action_profile==PROFILE)
                    # El plan crece con los puertos observados. El planificador congelado
                    # solo crea alias una vez: ampliar aquí sin alterar sus decisiones.
                    if scheduler:
                        for item in tasks:
                            if item.task_id not in scheduler.aliases:scheduler.aliases[item.task_id]=f't{len(scheduler.aliases):03d}'
                            if item.target.asset_id not in scheduler.asset_aliases:scheduler.asset_aliases[item.target.asset_id]=f'a{len(scheduler.asset_aliases):03d}'
                    choice=scheduler.select(ready,results,tasks) if scheduler else ready[0]
                    if choice not in ready:raise ValueError('invalid_selection')
                    if deadline-time.monotonic()<P.TASK_RESERVE_SECONDS:break
                    P.require_authorization(authorization,[choice.target],feature='applications' if choice.action_profile==WEB_PROFILE else 'inventory')
                    pending.remove(choice);store.event('controller','task_admitted',task_id=choice.task_id,payload={'profile':choice.action_profile})
                    if choice.action_profile==PROFILE:future=pool.submit(execute_open_task,choice,store,deadline,authorization=authorization)
                    elif choice.action_profile==P.PROFILE:future=pool.submit(P.execute_task,choice,store,authorization=authorization)
                    else:future=pool.submit(execute_application,choice,applications[choice.application_index],store,deadline,authorization=authorization)
                    running[future]=choice
                if not running:break
                completed,_=wait(running,return_when=FIRST_COMPLETED)
                for future in completed:
                    task=running.pop(future)
                    try:
                        result=future.result()
                        if not isinstance(result,TaskResult) or result.task_id!=task.task_id:raise ValueError('invalid_task_result')
                        if task.action_profile in {PROFILE,P.PROFILE}:result=validated_result(directory,task,result)
                        else:
                            detected,record=adjudicate_application(directory,task,result,applications[task.application_index]);findings.extend(detected);validations.append(record)
                            if result.status==TaskStatus.COMPLETED and record['state']=='indeterminate':result=result.model_copy(update={'status':TaskStatus.FAILED,'reason_code':'web_evidence_not_validated'})
                    except P.AuthorizationError as exc:
                        store.event('controller','authorization_rejected',task_id=task.task_id,payload={'reason_code':exc.reason_code})
                        raise
                    except Exception:result=TaskResult(task_id=task.task_id,status=TaskStatus.FAILED,reason_code='automatic_inventory_or_evidence_invalid')
                    if task.action_profile==PROFILE and result.status in SUCCESS:
                        ports=result.observations['open_ports'];opened_by_address[task.target.address]=ports
                        store.event('administrator','open_ports_reported',task_id=task.task_id,payload={'receiver':'agente_administrador','open_ports':ports,
                            'address':task.target.address,'evidence_ref':result.evidence_ref,'evidence_sha256':result.evidence_sha256,'tcp_range':'1-65535'})
                        chunks=[ports[i:i+32] for i in range(0,len(ports),32)]
                        used=sum(t.action_profile==P.PROFILE for t in tasks)
                        if used+len(chunks)>MAX_SERVICE_TASKS:
                            result=result.model_copy(update={'status':TaskStatus.FAILED,'reason_code':'service_task_budget_exhausted'})
                        else:
                            children=[P.InventoryTask(task_id=task.task_id+'_services_'+str(i),agent_type=task.agent_type,
                                target=task.target.model_copy(update={'ports':chunk})) for i,chunk in enumerate(chunks)]
                            tasks.extend(children);pending.extend(children);save_plan()
                            store.event('administrator','open_service_plan_created',task_id=task.task_id,payload={'tasks':len(children),'open_ports_count':len(ports)})
                    terminal(task,result)
        for task in pending:terminal(task,TaskResult(task_id=task.task_id,status=TaskStatus.CANCELLED,reason_code='runtime_budget_exhausted'))
    save_plan();store.event('controller','request_accepted')
    try:
        if int(Path('/proc/sys/kernel/tainted').read_text()) & ((1<<7)|(1<<14)):raise ValueError('kernel_failure')
        for app in applications:load_session(app['session'])
        store.event('controller','authorization_verified',payload=authorization.verify())
        targets=P.resolve_targets(config,deadline=deadline)
        P.require_authorization(authorization,targets)
        states=P.discover_targets(targets,config,store,deadline,authorization=authorization)
        tasks=port_tasks([t for t in targets if states[t.address]!='down']);discovery_ids={t.target.address:t.task_id for t in tasks};save_plan()
        store.event('orchestration','plan_created',payload={'task_count':len(tasks),'port_discovery':'tcp_1_65535'})
        if options['ia']=='openai' and tasks and deadline-time.monotonic()>=P.TASK_RESERVE_SECONDS:
            from auditoria.openai_provider import OpenAIScheduler,load_openai_config
            load_openai_config(P.ROOT/'piloto_kali/prototipo/.lab');Scheduler=OpenAIScheduler
            if options.get('expert_mode'):
                from llm_especialistas import ExpertScheduler
                Scheduler=ExpertScheduler
            scheduler=Scheduler(store,architecture=options['architecture'],budget=options['tokens'],deadline=deadline-P.TASK_RESERVE_SECONDS)
            store.event('planner','llm_ready',payload={'model':scheduler.config.model})
        dispatch(list(tasks))
        by_id={r.task_id:r for r in results};services_by_address={}
        for target in targets:
            services_by_address[target.address]=[s for t in tasks if t.action_profile==P.PROFILE and t.target.address==target.address
                for r in [by_id.get(t.task_id)] if r and r.status in SUCCESS for s in r.services if s.state=='open']
        web=[]
        for i,app in enumerate(applications):
            addresses=[app[f] for f in ['ipv4','ipv6'] if app[f]];target=next(t for t in targets if t.address==addresses[0])
            dependencies=[t.task_id for t in tasks if t.action_profile in {PROFILE,P.PROFILE} and t.target.address in addresses]
            task=ApplicationTask(task_id=audit_id+'_web_'+str(i),target=target.model_copy(update={'ports':[app['port']]}),application_index=i,dependencies=dependencies)
            tasks.append(task)
            compatible=all(states.get(a)!='down' and app['port'] in opened_by_address.get(a,[]) and
                any(s.port==app['port'] and s.name in {'http','http-proxy','https','ssl/http'} for s in services_by_address[a]) for a in addresses)
            if compatible and all(by_id.get(d) and by_id[d].status in SUCCESS for d in dependencies):web.append(task)
            else:terminal(task,TaskResult(task_id=task.task_id,status=TaskStatus.BLOCKED,reason_code='web_inventory_or_service_unavailable'))
        save_plan();dispatch(web)
        if options.get('creds'):
            compatible={a:P.supported_services(s) if all(by_id.get(t.task_id) and by_id[t.task_id].status in SUCCESS
                for t in tasks if t.target.address==a and t.action_profile in {PROFILE,P.PROFILE}) else {} for a,s in services_by_address.items()}
            live=[t for t in targets if compatible[t.address]]
            store.event('orchestration','credential_sweep_started',payload={'hosts':len(live)})
            findings.extend(P.credential_sweep(live,{a:list(s) for a,s in compatible.items()},store,deadline,
                tasks=tasks,results=results,validations=validations,services_by_address=compatible,authorization=authorization))
    except Exception as exc:
        error=exc.reason_code if isinstance(exc,P.AuthorizationError) else 'preflight_or_configuration_failed';finished={r.task_id for r in results}
        if isinstance(exc,P.AuthorizationError):store.event('controller','authorization_rejected',payload={'reason_code':error})
        for task in tasks:
            if task.task_id not in finished:terminal(task,TaskResult(task_id=task.task_id,status=TaskStatus.BLOCKED,reason_code=error))
    finally:
        execution_seconds=round(time.monotonic()-started,6)
        if scheduler and options.get('expert_mode') and not error:scheduler.deadline=deadline;scheduler.review(tasks,results,findings)
        if scheduler:scheduler.close()
        llm=scheduler.summary() if scheduler else {'status':'disabled' if options['ia']=='none' else 'not_started','model':None,'known_tokens':0,'usage_complete':True,'calls':[],'budget':options['tokens'],'fallbacks':0}
        if scheduler and not llm['calls']:llm['status']='not_needed'
        inventory=[];by_id={r.task_id:r for r in results}
        for target in targets:
            group=[t for t in tasks if t.target.address==target.address and t.action_profile in {PROFILE,P.PROFILE}]
            done=[by_id.get(t.task_id) for t in group];ok=bool(done) and all(r and r.status in SUCCESS for r in done)
            source=next((t for t in group if t.action_profile==PROFILE),None)
            ports={p:'open' for p in opened_by_address.get(target.address,[])};services={p:Service(port=p,protocol='tcp',state='open') for p in ports}
            for t in group:
                r=by_id.get(t.task_id)
                if t.action_profile!=P.PROFILE or not r or r.status not in SUCCESS:continue
                for row in r.observations.get('port_states',[]):
                    ports[row['port']]=row['state']
                    if row['state']!='open':services.pop(row['port'],None)
                for service in r.services:services[service.port]=service
            inventory.append({'task_id':source.task_id if source else None,'source_task_ids':[t.task_id for t in group],
                'asset_id':target.asset_id,'address':target.address,'family':'IPv'+str(ip_address(target.address).version),'host_state':states[target.address],
                'port_mode':'auto','tcp_range':'1-65535','scan_status':'completed_no_findings' if ok else 'not_scanned' if states[target.address]=='down' else 'incomplete',
                'reason_code':None if ok else 'host_down' if states[target.address]=='down' else 'port_or_service_scan_incomplete',
                'ports':[{'port':p,'state':s} for p,s in sorted(ports.items())],'services':[s.model_dump(mode='json') for s in services.values()]})
        complete=bool(targets) and len(results)==len(tasks) and all(r.status in SUCCESS for r in results) and not error
        report={'audit_id':audit_id,'architecture':options['architecture'],'status':'complete' if complete else 'partial','mode':'live','purpose':purpose,
            'port_mode':'auto','tcp_range':'1-65535','findings':findings,'tasks':[r.model_dump(mode='json') for r in results],
            'inventory':inventory,'llm':llm,'validation':validations,'coverage':P.coverage_for(targets,tasks,results,findings,states,bool(options.get('creds')),applications),
            'note':'Descubrimiento TCP 1-65535. El administrador programa reconocimiento en lotes de hasta 32 puertos observados abiertos y aplica únicamente perfiles compatibles. Una búsqueda incompleta no acredita ausencia.',
            'metrics':{'elapsed_seconds':round(time.monotonic()-started,6),'execution_seconds':execution_seconds,'expert_review_seconds':getattr(scheduler,'review_seconds',0)},'error':error}
        report['cve_candidates']=__import__('tesis.candidatos',fromlist=['for_results']).for_results(tasks,results)
        from auditoria.modulo_reportes import prepare_report, save_report
        report = prepare_report(report, request)
        save_report(directory, report)
        store.event('report','report_saved',payload={'status':report['status'],'tasks_completed':len(results)})
        runtime.update(status='finished',ended_at=datetime.now(timezone.utc).isoformat());write_json(directory/'runtime.json',runtime);store.close()
    return 0 if complete else 3
