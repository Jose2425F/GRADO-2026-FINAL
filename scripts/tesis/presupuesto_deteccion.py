"""Contrato verificable de cobertura parcial; sin proveedores ni verdad reservada."""

GOOD = {'completed', 'completed_no_findings'}
ROLES = {'ipv4_services': 'network', 'ipv6_services': 'network',
         'ipv4_credentials': 'credentials', 'application_access': 'applications',
         'ipv6_ndp': 'ipv6', 'ipv6_fragmentation': 'fragmentation'}


def budget_omission(task):
    return task.get('status') == 'skipped' and task.get('reason_code') == 'task_budget_not_selected'


def budget_record_valid(value):
    """Comprueba el presupuesto registrado, aunque alguna tarea haya fallado."""
    manifest = value.get('manifest', {}).get('detection_budget', {})
    report = value.get('report', {})
    measured = report.get('detection_budget', {})
    plan = value.get('plan', [])
    results = report.get('tasks', [])
    if (not isinstance(plan,list) or not isinstance(results,list)
        or any(not isinstance(t,dict) or not isinstance(t.get('task_id'),str) for t in [*plan,*results])):
        return False
    n = len(plan)
    limit = n * 3 // 5
    if (not isinstance(manifest,dict) or not isinstance(measured,dict) or not n
        or any(b.get('applied') is not True
               or type(b.get('catalogue_size')) is not int or b['catalogue_size'] != n
               or type(b.get('task_limit')) is not int or b['task_limit'] != limit
               or b.get('policy') != 'floor_60_percent_catalogue'
               or type(b.get('fraction')) not in {int,float} or b['fraction'] != .6
               for b in (manifest, measured))):
        return False
    ids = [t.get('task_id') for t in plan]
    result_ids = [t.get('task_id') for t in results]
    if len(set(ids)) != n or len(results) != n or set(result_ids) != set(ids):
        return False
    admitted = measured.get('admitted_task_ids')
    if (not isinstance(admitted,list) or any(not isinstance(item,str) for item in admitted)
        or len(set(admitted))!=len(admitted)
        or not set(admitted)<=set(ids)
        or manifest.get('admitted_task_ids')!=admitted):
        return False
    return (0<len(admitted)<=limit
        and all(type(b.get('executed_tasks')) is int and b['executed_tasks']==len(admitted)
                for b in (manifest,measured))
        and all(t.get('status') in GOOD|{'failed','blocked','cancelled'} if t['task_id'] in admitted else
                budget_omission(t) or (t.get('status')=='blocked' and t.get('reason_code')=='dependency_failed')
                for t in results))


def partial_budget_valid(value):
    """Sólo admite omisiones intencionales con todas las admisiones válidas."""
    if not budget_record_valid(value):return False
    return all(t.get('status') in GOOD or budget_omission(t) for t in value['report']['tasks'])


def expected_review_roles(value):
    """Los revisores cubren los dominios ejecutados, no tareas omitidas."""
    if not budget_record_valid(value):
        return {'generalist'} if value['run']['architecture'] == 'single' else set(ROLES.values())
    if value['run']['architecture'] == 'single':
        return {'generalist'}
    selected = set(value['report']['detection_budget']['admitted_task_ids'])
    return {ROLES[t['agent_type']] for t in value['plan']
            if t.get('task_id') in selected and t.get('agent_type') in ROLES}
