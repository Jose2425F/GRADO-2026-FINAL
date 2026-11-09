"""RF08/RF26: locks reales, fallos simulados y persistencia entre procesos; sin red."""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "piloto_kali/prototipo/src")]
from auditoria import empresa_agent
from auditoria.contracts import TaskResult, TaskStatus
from auditoria.store import RunStore
from tesis.orquestacion_langgraph import LangGraphOrchestrator, TaskExecutionError
from tesis.segmentos import SegmentBusy, SegmentGuard, SegmentQuarantined


def tasks():
    return empresa_agent.build_plan(empresa_agent.request("LAB-PROPIO", llm=False, tokens=0))


def test_shared_readers_both_families_and_exclusive_ipv6(tmp_path):
    task = tasks()[0]
    peer = task.model_copy(update={"task_id": "peer", "target": task.target.model_copy(update={"address": "fd00::1"})})
    intrusive = task.model_copy(update={"task_id": "ndp", "agent_type": "ipv6_ndp"})
    one, two = SegmentGuard(tmp_path), SegmentGuard(tmp_path)
    one.acquire(task)
    two.acquire(peer)
    with pytest.raises(SegmentBusy):
        SegmentGuard(tmp_path).acquire(intrusive)
    one.release(task)
    two.release(peer)
    one.acquire(intrusive)
    with pytest.raises(SegmentBusy):
        two.acquire(peer)
    one.release(intrusive)
    with pytest.raises(SegmentQuarantined):
        two.acquire(peer)


def test_quarantine_blocks_a_new_guard_until_fresh_recovery_passes(tmp_path):
    task = next(t for t in tasks() if t.agent_type == "ipv6_ndp")
    guard = SegmentGuard(tmp_path)
    guard.acquire(task)
    guard.release(task)
    new = SegmentGuard(tmp_path)
    with pytest.raises(SegmentQuarantined):
        new.acquire(task)
    with pytest.raises(RuntimeError):
        new.recover([task.target.interface], lambda: (_ for _ in ()).throw(RuntimeError("failed baseline")))
    with pytest.raises(SegmentQuarantined):
        new.acquire(task)
    with pytest.raises(ValueError):
        new.recover([task.target.interface], lambda: True)
    new.recover([task.target.interface], lambda: {"simulated_baseline": "verified"})
    new.acquire(task)
    new.release(task)


def test_recovery_cannot_race_a_running_reader(tmp_path):
    task = tasks()[0]
    guard = SegmentGuard(tmp_path)
    guard.acquire(task)
    called = []
    with pytest.raises(SegmentBusy):
        SegmentGuard(tmp_path).recover([task.target.interface], lambda: called.append(True))
    assert not called
    guard.release(task)


def test_killed_process_leaves_quarantine_after_kernel_releases_lock(tmp_path):
    code = """
import json,sys,time
from auditoria import empresa_agent
from tesis.segmentos import SegmentGuard
task=next(t for t in empresa_agent.build_plan(empresa_agent.request('LAB-PROPIO',llm=False,tokens=0)) if t.agent_type=='ipv6_ndp')
SegmentGuard(sys.argv[1]).acquire(task)
print('locked',flush=True)
time.sleep(30)
"""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "scripts") + os.pathsep + str(ROOT / "piloto_kali/prototipo/src")}
    proc = subprocess.Popen([sys.executable, "-c", code, str(tmp_path)], env=env, stdout=subprocess.PIPE, text=True)
    try:
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), "child did not acquire its lock"
        assert proc.stdout.readline().strip() == "locked"
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        task = next(t for t in tasks() if t.agent_type == "ipv6_ndp")
        with pytest.raises(SegmentQuarantined):
            SegmentGuard(tmp_path).acquire(task)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_real_graph_never_dispatches_same_segment_after_restore_failure(tmp_path):
    request = empresa_agent.request("LAB-PROPIO", llm=False, tokens=0)
    catalog = empresa_agent.build_plan(request)
    store = RunStore(tmp_path / "run", "segment_acceptance")
    guard = SegmentGuard(tmp_path / "locks", store)
    ran = []
    failed = []
    def execute(task):
        ran.append(task)
        if task.target.asset_id == "receiver_a" and "ra_route" in task.action_profile:
            failed.append(task)
            raise TaskExecutionError(stage="ipv6_restore", reason_code="ipv6_restore_failed")
        if task.agent_type in {"ipv6_ndp", "ipv6_fragmentation"}:
            guard.restored(task, {"simulated_baseline": True})
        return TaskResult(task_id=task.task_id, status="completed_no_findings")
    controller = LangGraphOrchestrator(tasks=catalog, workers=2, deadline=time.monotonic()+600,
        store=store, prepare=lambda: None, execute=execute, terminal=lambda task, result: result,
        close=lambda controller: None, segments=guard,
        authorize=lambda task: empresa_agent.authorize_empresa(request, empresa_agent.policy(), task=task))
    try:
        controller.invoke()
        assert len(failed) == 1
        failure_index = ran.index(failed[0])
        assert not [t for t in ran[failure_index+1:] if t.target.interface == failed[0].target.interface]
        denied = [r for r in controller.completed.values() if r.reason_code == "segment_quarantined"]
        assert denied and all(r.status == TaskStatus.BLOCKED for r in denied)
        with sqlite3.connect(store.root / "events.sqlite3") as db:
            kinds = [r[0] for r in db.execute("select kind from events")]
        assert {"segment_lock_acquired", "segment_restoration_verified", "segment_quarantined", "segment_admission_denied"} <= set(kinds)
    finally:
        store.close()


def test_successful_restore_receipt_allows_next_task(tmp_path):
    task = next(t for t in tasks() if t.agent_type == "ipv6_ndp")
    store = RunStore(tmp_path / "run", "receipt_test")
    guard = SegmentGuard(tmp_path / "locks", store)
    try:
        guard.acquire(task)
        guard.restored(task, {"simulated_baseline": True})
        guard.release(task)
        other = SegmentGuard(tmp_path / "locks")
        other.acquire(task)
        other.release(task)
        receipt = json.loads((store.root / "evidence" / (task.task_id + "_restoration.json")).read_text())
        assert receipt["segment"] == task.target.interface
    finally:
        store.close()
