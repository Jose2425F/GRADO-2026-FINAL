"""Herramienta bloqueada real, SIGKILL y recuperación de SQLite; no hay red/API."""
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import time

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]
from tesis.procesos import wait_bounded,terminate_group
from tesis.segmentos import SegmentGuard,SegmentQuarantined
from auditoria import empresa_agent


def test_blocked_graph_is_killed_within_bound_and_preserves_quarantine(tmp_path):
    code='''
import signal,sys,time
from pathlib import Path
from auditoria import empresa_agent
from auditoria.store import RunStore
from tesis.segmentos import SegmentGuard
from tesis.orquestacion_langgraph import LangGraphOrchestrator
signal.signal(signal.SIGTERM,signal.SIG_IGN)
root=Path(sys.argv[1]);store=RunStore(root/'run','bounded_process')
task=next(t for t in empresa_agent.build_plan(empresa_agent.request('LAB-PROPIO',llm=False,tokens=0)) if t.agent_type=='ipv6_ndp')
guard=SegmentGuard(root/'locks',store)
def worker(task):
 store.event('tool','blocked_tool_started',task_id=task.task_id)
 print('blocked',flush=True)
 while True:time.sleep(1)
LangGraphOrchestrator(tasks=[task],workers=1,deadline=time.monotonic()+600,store=store,
 prepare=lambda:None,execute=worker,terminal=lambda t,r:r,close=lambda c:None,segments=guard).invoke()
'''
    env={**os.environ,'PYTHONPATH':str(ROOT/'scripts')+os.pathsep+str(ROOT/'piloto_kali/prototipo/src')}
    child=subprocess.Popen([sys.executable,'-c',code,str(tmp_path)],env=env,start_new_session=True,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            assert selector.select(10),'graph did not start'
        assert child.stdout.readline().strip()=='blocked'
        started=time.monotonic()
        result,timed_out=wait_bounded(child,.2,grace_seconds=.2)
        assert result==124 and timed_out and child.poll() is not None
        assert time.monotonic()-started<5
        with sqlite3.connect(tmp_path/'run/events.sqlite3') as db:
            assert db.execute('pragma integrity_check').fetchone()[0]=='ok'
            assert db.execute("select count(*) from events where kind='blocked_tool_started'").fetchone()[0]==1
        task=next(t for t in empresa_agent.build_plan(empresa_agent.request('LAB-PROPIO',llm=False,tokens=0)) if t.agent_type=='ipv6_ndp')
        with pytest.raises(SegmentQuarantined):SegmentGuard(tmp_path/'locks').acquire(task)
    finally:
        if child.poll() is None:terminate_group(child,grace_seconds=.2)


def test_normal_process_returns_without_timeout():
    child=subprocess.Popen([sys.executable,'-c','pass'],start_new_session=True)
    assert wait_bounded(child,10)==(0,False)
