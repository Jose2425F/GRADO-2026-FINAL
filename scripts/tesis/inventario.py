"""Inventario derivado de resultados validados y admisión de credenciales."""
from auditoria.contracts import TaskResult, TaskStatus

SUCCESS = {TaskStatus.COMPLETED, TaskStatus.COMPLETED_NO_FINDINGS}
SERVICE_NAMES = {"ssh":{"ssh"}, "ftp":{"ftp"}, "postgres":{"postgres", "postgresql"},
                 "http-get":{"http", "http-proxy"}}


def credential_block(task, completed, bank):
    if task.agent_type != "ipv4_credentials":
        return None
    service = task.action_profile.removeprefix("hydra_").removesuffix("_single_v1").replace("_", "-")
    ports = [port for name,port in bank.CREDENTIALS[task.target.asset_id]["services"] if name==service]
    records = [completed.get(dep) for dep in task.dependencies]
    observed = [s for result in records if result is not None and result.status in SUCCESS for s in result.services]
    if (not task.dependencies or len(ports)!=1 or not records or
        any(result is None or result.status not in SUCCESS for result in records) or
        not any(s.protocol=="tcp" and s.state=="open" and s.port==ports[0] and
                s.name in SERVICE_NAMES.get(service,set()) for s in observed)):
        return TaskResult(task_id=task.task_id,status=TaskStatus.BLOCKED,
            reason_code="credential_service_not_discovered",
            observations={"discovery_task_ids":list(task.dependencies)})
    return None


def build_inventory(tasks, results, *, targets=None):
    by_id = {r.task_id:r for r in results}
    assets = {}
    for target in (targets if targets is not None else [t.target for t in tasks]):
        key = (target.asset_id,target.address)
        assets.setdefault(key,{"asset_id":key[0],"address":key[1],"interface":target.interface,
            "discovery_status":"not_requested","discovery_tasks":[],"services":[]})
    for task in tasks:
        key = (task.target.asset_id,task.target.address)
        item = assets[key]
        if task.action_profile != "nmap_tcp_services_v1":
            continue
        result = by_id.get(task.task_id)
        valid = result is not None and result.status in SUCCESS
        item["discovery_status"] = "completed" if valid else "incomplete"
        item["discovery_tasks"].append({"task_id":task.task_id,
            "attempt_id":result.attempt_id if result else None,
            "evidence_ref":result.evidence_ref if result else None,
            "evidence_sha256":result.evidence_sha256 if result else None})
        if valid:
            item["services"].extend(service.model_dump(mode="json") for service in result.services)
    return list(assets.values())
