"""No omitir fallos reales al comparar el catálogo parcial confirmado."""
from copy import deepcopy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesis.presupuesto_deteccion import partial_budget_valid,expected_review_roles,budget_record_valid


def fixture():
    plan=[{'task_id':f't{i}','agent_type':'ipv4_services'} for i in range(25)]
    results=[{'task_id':t['task_id'],'status':'completed' if i<15 else 'skipped',
              'reason_code':None if i<15 else 'task_budget_not_selected'} for i,t in enumerate(plan)]
    budget={'applied':True,'catalogue_size':25,'task_limit':15,'executed_tasks':15,
            'fraction':.6,'policy':'floor_60_percent_catalogue','admitted_task_ids':[f't{i}' for i in range(15)]}
    return {'plan':plan,'run':{'architecture':'multiagent'},'manifest':{'detection_budget':deepcopy(budget)},
            'report':{'detection_budget':budget,'tasks':results}}


def test_intentionally_unselected_are_normal_and_only_executed_roles_need_review():
    value=fixture()
    assert partial_budget_valid(value)
    assert expected_review_roles(value)=={'network'}
    value['run']['architecture']='single'
    assert expected_review_roles(value)=={'generalist'}


def test_failures_forged_omissions_missing_tasks_and_budget_overrun_are_not_eligible():
    mutations=[lambda v:v['report']['tasks'][0].update(status='failed'),
               lambda v:v['report']['tasks'][-1].update(reason_code='dependency_failed'),
               lambda v:v['report']['tasks'].pop(),
               lambda v:v['report']['detection_budget'].update(executed_tasks=16),
               lambda v:v['manifest']['detection_budget'].update(task_limit=16),
               lambda v:v['manifest']['detection_budget'].update(executed_tasks=999),
               lambda v:v['manifest']['detection_budget'].update(policy='other'),
               lambda v:v['report']['detection_budget'].update(policy='other'),
               lambda v:v['manifest']['detection_budget'].update(fraction=.9),
               lambda v:v['report']['detection_budget'].update(fraction=.9),
               lambda v:v['manifest']['detection_budget'].update(executed_tasks=15.0),
               lambda v:v['report']['tasks'][-1].update(task_id='t0')]
    for mutate in mutations:
        value=fixture();mutate(value)
        assert not partial_budget_valid(value)


def test_valid_budget_is_not_reported_missing_when_a_tool_and_its_dependencies_fail():
    value=fixture()
    value['report']['tasks'][0].update(status='failed',reason_code='ipv6_receiver_not_ready')
    value['report']['tasks'][-1].update(status='blocked',reason_code='dependency_failed')
    assert budget_record_valid(value)
    assert not partial_budget_valid(value)
