from pathlib import Path
import sys

sys.path[:0]=[str(Path(__file__).resolve().parents[1]),str(Path(__file__).resolve().parents[2]/"piloto_kali/prototipo/src")]
from auditoria import empresa_agent,lab_empresa
from auditoria.contracts import Service,TaskResult
from tesis.inventario import credential_block,build_inventory


def fixture():
    tasks=empresa_agent.build_plan(empresa_agent.request("LAB-PROPIO",llm=False,tokens=0))
    auth=next(t for t in tasks if t.agent_type=="ipv4_credentials")
    discovery=next(t for t in tasks if t.task_id==auth.dependencies[0])
    service=lab_empresa.CREDENTIALS[auth.target.asset_id]["services"][0]
    return tasks,auth,discovery,service


def test_each_credential_depends_on_its_own_asset_discovery():
    tasks,*_=fixture()
    by_id={t.task_id:t for t in tasks}
    for task in tasks:
        if task.agent_type=="ipv4_credentials":
            assert len(task.dependencies)==1
            predecessor=by_id[task.dependencies[0]]
            assert predecessor.action_profile=="nmap_tcp_services_v1"
            assert predecessor.target==task.target


def test_authentication_requires_validated_open_compatible_protocol():
    _,task,discovery,(name,port)=fixture()
    assert credential_block(task,{},lab_empresa) is not None
    result=TaskResult(task_id=discovery.task_id,status="completed",services=[Service(
        port=port,protocol="tcp",state="open",name=name)])
    assert credential_block(task,{discovery.task_id:result},lab_empresa) is None
    for changes in [{"name":"unrecognized"},{"state":"closed"},{"port":port+1},{"protocol":"udp"}]:
        altered=result.model_copy(update={"services":[result.services[0].model_copy(update=changes)]})
        assert credential_block(task,{discovery.task_id:altered},lab_empresa).reason_code=="credential_service_not_discovered"
    failed=result.model_copy(update={"status":"failed"})
    assert credential_block(task,{discovery.task_id:failed},lab_empresa) is not None


def test_inventory_links_validated_services_to_attempt_and_evidence():
    tasks,_,discovery,(name,port)=fixture()
    result=TaskResult(task_id=discovery.task_id,attempt_id="a"*32,status="completed",evidence_ref="evidence/discovery.xml",
        evidence_sha256="b"*64,services=[Service(port=port,protocol="tcp",state="open",name=name)])
    inventory=build_inventory(tasks,[result])
    entry=next(x for x in inventory if x["asset_id"]==discovery.target.asset_id)
    assert entry["discovery_status"]=="completed"
    assert entry["services"][0]["port"]==port
    assert entry["discovery_tasks"][0]["attempt_id"]=="a"*32
    assert entry["discovery_tasks"][0]["evidence_sha256"]=="b"*64
    assert any(x["discovery_status"]=="not_requested" for x in inventory)
    assert any(x["discovery_status"]=="incomplete" for x in inventory)


def test_inventory_keeps_both_families_of_dualstack_applications():
    request=empresa_agent.request('LAB-PROPIO',llm=False,tokens=0)
    tasks=empresa_agent.build_plan(request)
    inventory=build_inventory(tasks,[],targets=request.targets)
    assert {(x['asset_id'],x['address']) for x in inventory}=={(t.asset_id,t.address) for t in request.targets}
    assert len([x for x in inventory if x['asset_id']=='app_crm'])==2
