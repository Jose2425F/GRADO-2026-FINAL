import sys
from pathlib import Path
from types import SimpleNamespace as O
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.validacion_presupuesto import minimum_positive_cost


def task(name,conditions=(),dependencies=()):
    return O(task_id=name,target=O(asset_id='a'),conditions=conditions,dependencies=dependencies)


def test_atomic_web_task_and_transitive_dependencies_count_once():
    tasks=[task('discover'),task('credentials',['p'],['discover']),
           task('web',['q','r']),task('conformity')]
    result=minimum_positive_cost(tasks,{('a','p'),('a','q'),('a','r')},lambda t:t.conditions)
    assert result['minimum_tasks']==3
    assert set(result['task_ids'])=={'discover','credentials','web'}


def test_overlap_alternatives_and_unreachable_positive():
    tasks=[task('x',['p']),task('y',['p','q']),task('z',['q'])]
    assert minimum_positive_cost(tasks,{('a','p'),('a','q')},lambda t:t.conditions)['minimum_tasks']==1
    assert minimum_positive_cost(tasks,{('a','missing')},lambda t:t.conditions)['covers_all_present'] is False


def test_invalid_dependency_is_rejected_instead_of_faking_a_bound():
    for tasks in [[task('x',['p'],['absent'])],[task('x',['p'],['y']),task('y',[],['x'])]]:
        with pytest.raises(ValueError):minimum_positive_cost(tasks,{('a','p')},lambda t:t.conditions)
