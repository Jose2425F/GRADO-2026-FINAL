from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import hashlib
import json
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from auditoria import empresa_agent
from auditoria.lab import LabError
from auditoria.policy import PolicyError
from tesis.orquestacion_langgraph import TaskExecutionError
from tesis.protocolo_ipv6 import execute_protocol,instrument_protocol


def fixture(profile='na_neighbor'):
    tasks=empresa_agent.build_plan(empresa_agent.request('LAB-PROPIO',llm=False,tokens=0))
    task=next(t for t in tasks if t.target.asset_id=='receiver_a' and t.action_profile=='ipv6_'+profile+'_v2')
    state={'observer':{'udp_deliveries':[]}}
    bank=SimpleNamespace(RECEIVERS={'receiver_a':{'container':'owned-receiver'}},SENDER='fd00::10',SENDER_MAC='02:00:00:00:00:10',
        wait_receiver=Mock(return_value=state),reset_receiver=Mock(return_value=state),
        snapshot=Mock(return_value=state),docker=Mock(),nd_effect=Mock(return_value=True),
        probe=Mock(return_value=(state,{'nonce':'nonce'})))
    engine=SimpleNamespace(targets=lambda:[task.target],ND=empresa_agent.ND,FRAG=empresa_agent.FRAG,
        _run_protocol=Mock())
    payloads={}
    def evidence(name,ext,data):
        payloads[name]=json.loads(data)
        return 'evidence/'+name+'.'+ext,hashlib.sha256(data).hexdigest()
    store=SimpleNamespace(event=Mock(),evidence=evidence)
    return task,bank,engine,store,payloads


def test_success_preserves_single_probe_and_independent_evidence_structure():
    task,bank,engine,store,data=fixture()
    result=execute_protocol(task,store,engine,bank)
    assert result.status.value=='completed' and result.observations['readiness_recovery'] is False
    bank.probe.assert_called_once_with(bank.RECEIVERS['receiver_a'],'na_neighbor',store,task.task_id)
    bank.reset_receiver.assert_called_once()
    assert data[task.task_id+'_confirmation']['channel']=='packet_observer_and_kernel_state'
    assert data[task.task_id+'_state']['profile']==task.action_profile


def test_known_readiness_failure_recovers_once_before_probe_and_records_it():
    task,bank,engine,store,_=fixture()
    bank.wait_receiver.side_effect=LabError('receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto')
    result=execute_protocol(task,store,engine,bank)
    assert result.observations['readiness_recovery'] is True
    assert bank.reset_receiver.call_count==2  # Recuperación previa y cierre de la sonda.
    assert bank.probe.call_count==1
    assert [c.args[1] for c in store.event.call_args_list]==['receiver_recovery_started','receiver_recovery_finished']
    assert all(c.kwargs['payload']['probe_sent'] is False for c in store.event.call_args_list)


def test_failed_recovery_never_transmits_probe_or_retries_recovery():
    task,bank,engine,store,_=fixture()
    bank.wait_receiver.side_effect=LabError('receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto')
    bank.reset_receiver.side_effect=LabError('not ready')
    with pytest.raises(TaskExecutionError) as caught:execute_protocol(task,store,engine,bank)
    assert caught.value.stage=='receiver_readiness'
    assert bank.reset_receiver.call_count==1 and bank.probe.call_count==0


def test_probe_error_is_not_retried_and_cleanup_still_runs():
    task,bank,engine,store,_=fixture()
    bank.probe.side_effect=TimeoutError('PRIVATE CONTENT')
    with pytest.raises(TaskExecutionError) as caught:execute_protocol(task,store,engine,bank)
    assert caught.value.stage=='ipv6_probe' and caught.value.reason_code=='ipv6_probe_failed'
    assert bank.probe.call_count==1 and bank.reset_receiver.call_count==1
    assert 'PRIVATE CONTENT' not in str(caught.value)


def test_unknown_readiness_failure_does_not_modify_or_probe_lab():
    task,bank,engine,store,_=fixture()
    bank.wait_receiver.side_effect=PermissionError('private')
    with pytest.raises(TaskExecutionError):execute_protocol(task,store,engine,bank)
    bank.reset_receiver.assert_not_called();bank.probe.assert_not_called()


def test_adapter_and_original_dispatch_are_restored_even_after_failure():
    task,bank,engine,store,_=fixture()
    original=engine._run_protocol
    with pytest.raises(RuntimeError):
        with instrument_protocol(engine,bank):
            assert engine._run_protocol(task,store).status.value=='completed'
            raise RuntimeError()
    assert engine._run_protocol is original


def test_scope_rejection_precedes_all_network_operations():
    task,bank,engine,store,_=fixture()
    engine.targets=lambda:[]
    with pytest.raises(PolicyError):execute_protocol(task,store,engine,bank)
    bank.wait_receiver.assert_not_called();bank.probe.assert_not_called()
