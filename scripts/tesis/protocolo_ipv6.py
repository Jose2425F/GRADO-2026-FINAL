"""Adaptador del banco cerrado: etapas observables y recuperación previa acotada.

Conserva las sondas y el adjudicador originales. Nunca repite una sonda fallida;
una recuperación del receptor sólo puede ocurrir antes de transmitirla.
"""
from __future__ import annotations

import json
import time
from contextlib import contextmanager

from auditoria.contracts import TaskResult, TaskStatus
from auditoria.lab import LabError
from auditoria.policy import PolicyError
from .orquestacion_langgraph import TaskExecutionError


@contextmanager
def instrument_protocol(engine,bank):
    """Sustituye sólo el adaptador en memoria y conserva el despachador autorizado."""
    original=engine._run_protocol
    engine._run_protocol=lambda task,store:execute_protocol(task,store,engine,bank)
    try:
        yield
    finally:
        engine._run_protocol=original


def execute_protocol(task, store, engine, bank):
    if task.target not in engine.targets():
        raise PolicyError('empresa_target_denied', 'Activo fuera del banco autorizado.')
    profile=task.action_profile.removeprefix('ipv6_').removesuffix('_v2')
    if profile not in {'slaac',*engine.ND,*engine.FRAG} or task.target.asset_id not in bank.RECEIVERS:
        raise PolicyError('empresa_profile_denied', 'Perfil fuera del catálogo autorizado.')
    receiver=bank.RECEIVERS[task.target.asset_id]
    deadline=time.monotonic()+task.timeout_seconds

    def call(stage,code,action,*args,**kwargs):
        if stage!='ipv6_restore' and time.monotonic()>=deadline:
            raise TaskExecutionError(stage=stage,reason_code='tool_timeout')
        try:
            value=action(*args,**kwargs)
        except Exception as exc:
            raise TaskExecutionError(stage=stage,reason_code=code) from exc
        if time.monotonic()>deadline:
            raise TaskExecutionError(stage=stage,reason_code='tool_timeout')
        return value

    recovered=False
    try:
        before=call('receiver_readiness','ipv6_receiver_not_ready',bank.wait_receiver,receiver,
                    seconds=min(45,max(1,int(deadline-time.monotonic()))))
    except TaskExecutionError as exc:
        original=exc.__cause__
        # Sólo la condición conocida de estado inicial; no reintentar rechazos,
        # comandos, capturas ni excepciones arbitrarias.
        if (not isinstance(original,LabError) or not original.args
            or original.args[0]!='receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto'):
            raise
        store.event('orchestration','receiver_recovery_started',task_id=task.task_id,
                    payload={'stage':'receiver_readiness','attempt':1,'probe_sent':False})
        before=call('receiver_readiness','ipv6_receiver_not_ready',bank.reset_receiver,receiver)
        recovered=True
        store.event('orchestration','receiver_recovery_finished',task_id=task.task_id,
                    payload={'stage':'receiver_readiness','attempt':1,'probe_sent':False,'status':'recovered'})

    payload={'asset_id':task.target.asset_id,'target':task.target.address,
             'profile':task.action_profile,'before':before,'readiness_recovery':recovered}
    if profile=='slaac':
        payload.update(after=before,restored=before)
    else:
        try:
            if profile=='na_neighbor':
                call('ipv6_setup','ipv6_setup_failed',bank.docker,'exec',receiver['container'],
                     'ip','-6','neigh','replace',bank.SENDER,'lladdr',bank.SENDER_MAC,'nud',
                     'permanent' if task.target.asset_id=='receiver_b' else 'reachable','dev','eth0')
                payload['before']=call('ipv6_setup','ipv6_setup_failed',bank.snapshot,receiver)
            if profile in engine.ND:
                payload['after'],payload['probe']=call('ipv6_probe','ipv6_probe_failed',bank.probe,
                                                       receiver,profile,store,task.task_id)
            else:
                control,_=engine.FRAG[profile]
                payload['control'],payload['control_probe']=call('ipv6_probe','ipv6_probe_failed',
                    bank.probe,receiver,control,store,task.task_id+'_control')
                payload['after'],payload['probe']=call('ipv6_probe','ipv6_probe_failed',
                    bank.probe,receiver,profile,store,task.task_id+'_variant')
        finally:
            payload['restored']=call('ipv6_restore','ipv6_restore_failed',bank.reset_receiver,receiver)
    corroboration={**payload,'channel':'packet_observer_and_kernel_state'}
    evidence,eh=call('evidence_persistence','evidence_write_failed',store.evidence,
                    task.task_id+'_state','json',json.dumps(payload,sort_keys=True).encode())
    diagnostic,dh=call('evidence_persistence','evidence_write_failed',store.evidence,
                      task.task_id+'_confirmation','json',json.dumps(corroboration,sort_keys=True).encode())
    summary={'restored':True,'bank':'empresa','readiness_recovery':recovered}
    if profile in engine.ND:
        summary['state_changed']=bool(bank.nd_effect(profile,payload['before'],payload['after'],receiver,payload['probe']))
    elif profile in engine.FRAG:
        summary['control_received']=any(x['nonce']==payload['control_probe']['nonce'] for x in payload['control']['observer']['udp_deliveries'])
        summary['variant_udp_delivered']=any(x['nonce']==payload['probe']['nonce'] for x in payload['after']['observer']['udp_deliveries'])
    return TaskResult(task_id=task.task_id,status=TaskStatus.COMPLETED,evidence_ref=evidence,
                      evidence_sha256=eh,diagnostic_ref=diagnostic,diagnostic_sha256=dh,observations=summary)
