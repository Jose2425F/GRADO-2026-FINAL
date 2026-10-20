import json
import shutil
from pathlib import Path

import pytest
from auditoria.contracts import TaskResult,TaskStatus
from auditoria.policy import authorize_request,PolicyError
from auditoria.store import RunStore
from auditoria import v2_agent

CERT=Path(__file__).resolve().parents[3]/'docs/resultados-laboratorio-v2-2026-10-12/certificacion'


def test_v2_plan_and_policy_are_closed_and_do_not_load_evaluator_labels(monkeypatch):
    req=v2_agent.request('test',llm=False)
    authorize_request(req,v2_agent.policy())
    tasks=v2_agent.build_plan(req)
    assert len(tasks)==22
    assert len({t.task_id for t in tasks})==22
    assert sum(t.agent_type=='application_access' for t in tasks)==4
    with pytest.raises(PolicyError):
        authorize_request(req.model_copy(update={'targets':req.targets[:-1]}),v2_agent.policy())
    with pytest.raises(PolicyError):
        authorize_request(req,v2_agent.policy().model_copy(update={'max_token_budget':100000}))


def artifact_task(store,task,records):
    case=task.target.asset_id+'_same_resource' if task.agent_type=='application_access' else task.target.asset_id+'_'+task.action_profile.removeprefix('ipv6_').removesuffix('_v2')
    record=next(r for r in records if r['case_id']==case)
    source=json.loads((CERT/record['evidence_ref']).read_text())
    data={'asset_id':task.target.asset_id,'target':task.target.address,'profile':task.action_profile}
    if task.agent_type=='application_access':
        data['families']={f:source[f]['primary'] for f in ('ipv4','ipv6')}
        confirmation={**data,'families':{f:source[f]['confirmation'] for f in ('ipv4','ipv6')},'channel':'independent_http_client'}
    else:
        if task.action_profile=='ipv6_slaac_v2':data.update(before=source,after=source,restored=source)
        else:data.update({k:v for k,v in source.items() if k in ['before','after','restored','probe','control','control_probe']})
        if 'variant_probe' in source:data['probe']=source['variant_probe']
        confirmation={**data,'channel':'packet_observer_and_kernel_state'}
    er,eh=store.evidence(task.task_id,'json',json.dumps(data).encode())
    cr,ch=store.evidence(task.task_id+'_confirmation','json',json.dumps(confirmation).encode())
    return TaskResult(task_id=task.task_id,status=TaskStatus.COMPLETED,evidence_ref=er,evidence_sha256=eh,diagnostic_ref=cr,diagnostic_sha256=ch)


@pytest.mark.skipif(not CERT.exists() and not CERT.is_symlink(), reason='Fixture histórico privado no distribuido; regresión no ejecutada en el paquete público')
def test_archived_independent_evidence_revalidates_all_profiles_and_deduplicates(tmp_path):
    store=RunStore(tmp_path/'run','test')
    for p in (CERT/'evidence').glob('*.pcap'):shutil.copy2(p,store.root/'evidence'/p.name)
    records=json.loads((CERT/'certificate.json').read_text())['checks']
    found=set()
    try:
        for task in v2_agent.build_plan(v2_agent.request('test',llm=False)):
            result=artifact_task(store,task,records)
            assert v2_agent.validation_record(store.root,task,result)['evidence_integrity']['valid'] is True, task.task_id
            found.update((f['asset_id'],f['defect_key']) for f in v2_agent.adjudicate(store.root,task,result))
        assert len(found)==9
        assert not any(a in {'app_d','receiver_b'} for a,k in found)
        (store.root/result.evidence_ref).write_text('{}')
        assert v2_agent.validation_record(store.root,task,result)['evidence_integrity']['valid'] is False
        assert v2_agent.adjudicate(store.root,task,result)==[]
    finally:store.close()


@pytest.mark.skipif(not CERT.exists() and not CERT.is_symlink(), reason='Fixture histórico privado no distribuido; regresión no ejecutada en el paquete público')
def test_v2_access_demo_cancels_every_pending_task_after_verified_access(tmp_path,monkeypatch):
    from auditoria.agentes.agente_administrador import build_graph
    from auditoria.contracts import TaskStatus
    store=RunStore(tmp_path/'demo','test')
    records=json.loads((CERT/'certificate.json').read_text())['checks']
    invoked=[]
    def adapter(task,store):
        invoked.append(task.task_id)
        return artifact_task(store,task,records)
    monkeypatch.setattr(v2_agent,'run_task',adapter)
    try:
        req=v2_agent.request('test',llm=False,stop=True)
        state=build_graph(store,live=True).invoke({'request':req,'policy':v2_agent.policy(),'tasks':[],'results':[],'report':{}})
        assert len(invoked)==1
        assert state['report']['execution_control']['stopped'] is True
        assert state['report']['execution_control']['execution_concurrency']==1
        assert sum(r.status==TaskStatus.CANCELLED for r in state['results'])==21
        assert len(state['report']['findings'])==3
    finally:store.close()


def test_scheduler_passes_only_allowed_boolean_observations_to_model():
    from auditoria.scheduler import Scheduler
    tasks=v2_agent.build_plan(v2_agent.request('test',llm=False))
    scheduler=Scheduler.__new__(Scheduler)
    scheduler.aliases={};scheduler.asset_aliases={};scheduler.architecture='single'
    contexts=[]
    scheduler.decide=lambda choices,context,role: contexts.append(context) or choices[0]
    result=TaskResult(task_id=tasks[0].task_id,status=TaskStatus.COMPLETED,
        observations={'state_changed':True,'restored':'SECRET_SCRIPT','secret':'SECRET_KEY','raw_ip':'192.0.2.9'})
    scheduler.select(tasks[1:3],[result],tasks)
    assert contexts[0]['previous'][0]['observations']=={'state_changed':True}
    assert 'SECRET' not in json.dumps(contexts)
    assert '192.0.2.9' not in json.dumps(contexts)


def test_comparison_context_includes_fixture_seed(tmp_path):
    from auditoria.metrics import comparison_context
    from auditoria.store import write_json
    write_json(tmp_path/'request.json',v2_agent.request('test',llm=False).model_dump(mode='json'))
    manifest={'policy_sha256':'policy','tools':{},'lab':{'fixture_seed_sha256':'seed-a','targets':[]}}
    write_json(tmp_path/'manifest.json',manifest)
    before=comparison_context(tmp_path)
    manifest['lab']['fixture_seed_sha256']='seed-b'
    write_json(tmp_path/'manifest.json',manifest)
    assert before!=comparison_context(tmp_path)


def test_generic_v2_execution_requires_preflight_before_store_or_network(tmp_path,monkeypatch):
    from auditoria.cli import run_request
    req=v2_agent.request('test',llm=False)
    pol=v2_agent.policy()
    monkeypatch.setattr(v2_agent.lab,'docker',lambda *a,**k:pytest.fail('no network without preflight'))
    with pytest.raises(PolicyError,match='preflight'):
        run_request(req,pol,tmp_path/'out',live=True,request_bytes=req.model_dump_json().encode(),policy_bytes=pol.model_dump_json().encode())
    assert not (tmp_path/'out').exists()
