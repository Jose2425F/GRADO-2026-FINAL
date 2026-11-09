"""Aceptación del grafo real, con herramientas y proveedor simulados: cero tráfico."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sqlite3
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.usefixtures("simulated_protected_runtime", "simulated_bank_restoration")

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "piloto_kali/prototipo/src")]

import laboratorio_empresa as company
from auditoria.contracts import TaskResult, TaskStatus
from auditoria.store import RunStore
from tesis.orquestacion_langgraph import LangGraphOrchestrator, NODES, TaskExecutionError, engine_metadata


def task_set(count=3):
    tasks = company.agent.build_plan(company.agent.request("LAB-PROPIO", llm=False))
    result = [task.model_copy(update={"task_id": "graph_task_" + str(i), "dependencies": []})
              for i, task in enumerate(tasks[:count])]
    return result


def events(root):
    with sqlite3.connect(root / "events.sqlite3") as connection:
        return [(kind, task_id, json.loads(payload)) for kind, task_id, payload in
                connection.execute("SELECT kind,task_id,payload_json FROM events ORDER BY rowid")]


def execute_graph(tmp_path, tasks, *, prepare=lambda: None, worker=None, authorize=None,
                  clock=lambda: 0, deadline=1000, terminal=None, task_limit=None):
    records = []
    closed = []
    store = RunStore(tmp_path / "run", "graph_test")

    def record(task, result):
        records.append(result)
        return terminal(task, result) if terminal else result

    def close(controller):
        closed.append({"error": controller.error, "transitions": list(controller.transitions)})

    controller = LangGraphOrchestrator(tasks=tasks, workers=2, deadline=deadline, store=store,
        prepare=prepare, execute=worker or (lambda task: TaskResult(task_id=task.task_id, status="completed_no_findings")),
        terminal=record, close=close, authorize=authorize, clock=clock, task_limit=task_limit)
    try:
        state = controller.invoke()
    finally:
        store.close()
    return controller, state, records, closed, events(store.root)


def test_compiled_stategraph_controls_each_phase_and_validated_dependency(tmp_path):
    tasks = task_set(2)
    tasks[1] = tasks[1].model_copy(update={"dependencies": [tasks[0].task_id]})
    admitted = []
    validated = []

    def worker(task):
        if task is tasks[1]:
            assert tasks[0].task_id in validated
        admitted.append(task.task_id)
        return TaskResult(task_id=task.task_id, status="completed_no_findings")

    def validate(task, result):
        validated.append(task.task_id)
        return result

    controller, state, records, closed, trace = execute_graph(tmp_path, tasks, worker=worker, terminal=validate)
    assert set(NODES) <= set(controller.compiled.get_graph().nodes)
    assert controller.transitions == ["preflight", "admission", "execution", "validation",
                                      "admission", "execution", "validation", "admission", "review", "close"]
    assert admitted == validated == [task.task_id for task in tasks]
    assert state["closed"] and not state["pending"] and not state["running"]
    assert len(records) == len(tasks) and len(closed) == 1
    assert [payload["node"] for kind, _, payload in trace if kind == "graph_node_started"] == controller.transitions
    assert [payload["node"] for kind, _, payload in trace if kind == "graph_node_finished"] == controller.transitions
    metadata = engine_metadata()
    assert metadata["engine"] == "langgraph" and metadata["version"]
    assert len(metadata["source_sha256"]) == 64


def test_preflight_denial_routes_through_abort_without_worker_or_provider(tmp_path):
    calls = []

    def preflight():
        raise company.LabError("controlled_preflight_failure")

    controller, state, results, closed, _ = execute_graph(tmp_path, task_set(), prepare=preflight,
                                                        worker=lambda task: calls.append(task))
    assert not calls
    assert controller.transitions == ["preflight", "abort", "review", "close"]
    assert state["closed"] and closed[0]["error"] == "lab_not_ready_or_kernel"
    assert all(result.status == TaskStatus.BLOCKED for result in results)


def test_revalidates_before_every_dispatch_and_closes_already_active_work(tmp_path):
    tasks = task_set(3)
    # Activos distintos para permitir que el segundo se admita durante el primero.
    tasks[1] = tasks[1].model_copy(update={"target": tasks[1].target.model_copy(update={"asset_id": "other_lab_asset"})})
    checked = []

    def authorize(task):
        checked.append(task.task_id)
        if task.task_id == tasks[1].task_id:
            raise ValueError("scope_changed")

    controller, state, results, closed, _ = execute_graph(tmp_path, tasks, authorize=authorize)
    assert checked == [tasks[0].task_id, tasks[1].task_id]
    assert "abort" in controller.transitions and state["closed"]
    assert len(results) == 3 and len({result.task_id for result in results}) == 3
    assert results[0].status == TaskStatus.COMPLETED_NO_FINDINGS
    assert all(result.status == TaskStatus.BLOCKED for result in results[1:])


def test_deadline_rechecked_after_provider_selection_cancels_unstarted_work(tmp_path):
    now = [0]

    class Scheduler:
        def select(self, ready, previous, tasks):
            now[0] = 900
            return ready[0]

    ran = []
    _, state, results, _, _ = execute_graph(tmp_path, task_set(), prepare=Scheduler,
        worker=lambda task: ran.append(task), clock=lambda: now[0])
    assert not ran and state["closed"]
    assert all(result.status == TaskStatus.CANCELLED for result in results)


def test_invalid_llm_choice_cannot_dispatch_a_task(tmp_path):
    class Scheduler:
        def select(self, *args):
            return object()

    ran = []
    controller, state, results, closed, _ = execute_graph(tmp_path, task_set(), prepare=Scheduler,
                                                       worker=lambda task: ran.append(task))
    assert not ran and state["closed"]
    assert "abort" in controller.transitions and closed[0]["error"]
    assert all(result.status == TaskStatus.BLOCKED for result in results)


class FakeExpert:
    fail_review = False
    fail_close = False
    fail_summary = False

    def __init__(self, store, **options):
        self.config = SimpleNamespace(model="simulated-no-api")
        self.calls = []
        self.review_seconds = 0

    def select(self, ready, previous, tasks):
        self.calls.append({"status": "accepted", "total_tokens": 1})
        return ready[0]

    def review(self, tasks, results, findings):
        assert len(results) == len(tasks)
        if self.fail_review:
            raise RuntimeError("simulated_review_failure")

    def close(self):
        if self.fail_close:
            raise RuntimeError("simulated_close_failure")

    def summary(self):
        if self.fail_summary:
            raise RuntimeError("simulated_summary_failure")
        return {"status": "accepted", "calls": self.calls, "model": self.config.model,
                "known_tokens": len(self.calls), "usage_complete": True, "fallbacks": 0}


@pytest.mark.usefixtures("healthy_kernel")
@pytest.mark.parametrize("failure", ["fail_review", "fail_close", "fail_summary", None])
def test_panel_persists_terminal_report_runtime_and_events_if_review_or_provider_close_fails(tmp_path, failure):
    from dualstack_panel import validate_options
    options = validate_options({"name": "LangGraph simulated acceptance", "authorization": "LAB-PROPIO",
                                "scope": "empresa", "architecture": "multiagent", "ia": "openai",
                                "tokens": 6000, "expert_mode": True})
    class Provider(FakeExpert):
        pass
    if failure:
        setattr(Provider, failure, True)
    with patch.object(company.lab, "load_auditor_environment"), patch.object(company.lab, "preflight", return_value={}), \
         patch.object(company.agent, "run_task", side_effect=lambda task, store: TaskResult(task_id=task.task_id, status="completed_no_findings")), \
         patch.object(company, "validation_for", return_value=({"state": "observed"}, [])), \
         patch("auditoria.openai_provider.load_openai_config"), patch("llm_especialistas.ExpertScheduler", Provider):
        code = company.run_panel(options, tmp_path)
    root = next(tmp_path.glob("*/report.json")).parent
    report = json.loads((root / "report.json").read_text())
    manifest = json.loads((root / "manifest.json").read_text())
    assert code == (3 if failure else 0)
    assert len(report["tasks"]) == 32
    assert report["status"] == ("partial" if failure else "complete")
    assert json.loads((root / "runtime.json").read_text())["status"] == "finished"
    assert (root / "evaluation.json").exists()
    assert manifest["orchestration"]["engine"] == report["orchestration"]["engine"] == "langgraph"
    assert manifest["extensions_sha256"]["tesis/orquestacion_langgraph.py"] == manifest["orchestration"]["source_sha256"]
    assert report["orchestration"]["transitions"][-2:] == ["review", "close"]
    assert report["orchestration"]["transition_count"] == len(report["orchestration"]["transitions"])
    assert any(kind == "graph_completed" for kind, _, _ in events(root))
    if failure == "fail_summary":
        assert report["llm"]["usage_complete"] is False and report["llm"]["known_tokens"] is None


@pytest.mark.usefixtures("healthy_kernel")
def test_four_variant_bank_contexts_use_the_same_actual_graph(tmp_path):
    from dualstack_panel import validate_options
    from tesis.laboratorios import Context, catalog
    for scenario in catalog():
        for architecture in ("single", "multiagent"):
            options = validate_options({"name": "Simulated variant", "authorization": "LAB-PROPIO",
                                        "scope": "empresa", "scenario": scenario['id'], "architecture": architecture})
            # El panel valida estas etiquetas; el motor comprueba también su contrato.
            options['manual_context'] = {'study_id': 'langgraph_manual_20261018', 'pair': 1}
            context = Context(scenario['id'], state_root=tmp_path / 'states')
            context.validation = lambda *args: ({"state": "observed"}, [])
            output = tmp_path / scenario['id'] / architecture
            with patch.object(context.lab, "load_auditor_environment"), patch.object(context.lab, "preflight", return_value={}), \
                 patch.object(context.agent, "run_task", side_effect=lambda task, store: TaskResult(task_id=task.task_id, status="completed_no_findings")), \
                 patch('tesis.restauracion_manual.assert_run_claim',return_value={'simulation_only':True}):
                assert company.run_panel(options, output, bank_context=context) == 0
            root = next(output.glob("*/report.json")).parent
            manifest = json.loads((root / "manifest.json").read_text())
            report = json.loads((root / "report.json").read_text())
            assert manifest["scenario"]["id"] == scenario['id']
            assert manifest["orchestration"]["engine"] == "langgraph"
            assert manifest['manual_context'] == report['manual_context'] == {
                'study_id': 'langgraph_manual_20261018', 'pair': 1, 'scenario': scenario['id'], 'architecture': architecture}
            assert len(report['tasks']) == scenario['tasks']
            assert report['detection_budget']['applied'] is False
            assert report['detection_budget']['task_limit'] is None
            assert report['detection_budget']['executed_tasks'] == scenario['tasks']
            assert any(kind == "graph_node_started" and payload["node"] == "execution" for kind, _, payload in events(root))


@pytest.mark.usefixtures("healthy_kernel")
def test_transient_terminal_event_failure_preserves_first_result_once_without_reexecution(tmp_path):
    from dualstack_panel import validate_options
    options = validate_options({"name": "Simulated SQLite failure", "authorization": "LAB-PROPIO", "scope": "empresa"})
    original_event = RunStore.event
    failed_task = []
    executed = []

    def event(store, component, kind, **kwargs):
        if kind == 'task_terminal' and not failed_task:
            failed_task.append(kwargs['task_id'])
            raise sqlite3.OperationalError('simulated transient event write failure')
        return original_event(store, component, kind, **kwargs)

    def worker(task, store):
        executed.append(task.task_id)
        return TaskResult(task_id=task.task_id, status='completed_no_findings')

    with patch.object(company.lab, "load_auditor_environment"), patch.object(company.lab, "preflight", return_value={}), \
         patch.object(company.agent, "run_task", side_effect=worker), \
         patch.object(company, "validation_for", return_value=({"state": "observed"}, [])), \
         patch.object(RunStore, 'event', event):
        assert company.run_panel(options, tmp_path) == 3
    root = next(tmp_path.glob('*/report.json')).parent
    report = json.loads((root / 'report.json').read_text())
    assert report['status'] == 'partial' and report['error'] == 'execution_or_configuration_error'
    assert len(report['tasks']) == len({task['task_id'] for task in report['tasks']}) == 32
    assert len(report['validation']) == 32
    first = [task for task in report['tasks'] if task['task_id'] == failed_task[0]]
    assert len(first) == 1 and first[0]['status'] == 'completed_no_findings'
    assert len(executed) == len(set(executed))
    assert json.loads((root / 'runtime.json').read_text())['status'] == 'finished'
    assert any(kind == 'graph_completed' and payload['status'] == 'partial' for kind, _, payload in events(root))


@pytest.mark.usefixtures("healthy_kernel")
@pytest.mark.parametrize('persistent', [False, True])
def test_close_trace_failure_rewrites_partial_without_repeating_tools_or_provider(tmp_path, persistent):
    from dualstack_panel import validate_options
    options = validate_options({"name": "Simulated close trace failure", "authorization": "LAB-PROPIO", "scope": "empresa",
                                "ia": "openai", "tokens": 6000, "expert_mode": True})
    original_event = RunStore.event
    failed = []
    executed = []

    class Provider(FakeExpert):
        instances = []
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.review_calls = self.close_calls = self.summary_calls = 0
            self.instances.append(self)
        def review(self, *args):
            self.review_calls += 1
            return super().review(*args)
        def close(self):
            self.close_calls += 1
            return super().close()
        def summary(self):
            self.summary_calls += 1
            return super().summary()

    def event(store, component, kind, **kwargs):
        if (kind == 'graph_node_finished' and kwargs.get('payload', {}).get('node') == 'close') or (persistent and failed):
            failed.append(kind)
            raise sqlite3.OperationalError('simulated close event failure')
        return original_event(store, component, kind, **kwargs)

    def worker(task, store):
        executed.append(task.task_id)
        return TaskResult(task_id=task.task_id, status='completed_no_findings')

    with patch.object(company.lab, "load_auditor_environment"), patch.object(company.lab, "preflight", return_value={}), \
         patch.object(company.agent, "run_task", side_effect=worker), \
         patch.object(company, "validation_for", return_value=({"state": "observed"}, [])), \
         patch("auditoria.openai_provider.load_openai_config"), patch("llm_especialistas.ExpertScheduler", Provider), \
         patch.object(RunStore, 'event', event):
        assert company.run_panel(options, tmp_path) == 3
    root = next(tmp_path.glob('*/report.json')).parent
    report = json.loads((root / 'report.json').read_text())
    assert report['status'] == 'partial' and report['error'] == 'graph_trace_error'
    assert report['orchestration']['trace_complete'] is False
    assert len(report['tasks']) == len({task['task_id'] for task in report['tasks']}) == 32
    assert len(executed) == len(set(executed)) == 19
    assert len(Provider.instances) == 1
    assert Provider.instances[0].review_calls == Provider.instances[0].close_calls == Provider.instances[0].summary_calls == 1
    assert len(report['llm']['calls']) == len(Provider.instances[0].calls)
    assert json.loads((root / 'runtime.json').read_text())['status'] == 'finished'


@pytest.mark.usefixtures("healthy_kernel")
@pytest.mark.parametrize('mismatch', [None, 'missing', 'unexpected', 'duplicate', 'invalid_digest'])
def test_original_bank_records_exact_image_and_fixture_identity_before_provider(tmp_path, mismatch):
    from dualstack_panel import validate_options
    options = validate_options({"name": "Simulated image identity", "authorization": "LAB-PROPIO", "scope": "empresa",
                                "ia": "openai", "tokens": 6000, "expert_mode": True})
    state = tmp_path/'state'
    state.mkdir()
    fixture = b'LAB_FIXTURE_SEED=simulated-private-fixture\n'
    (state/'lab.env').write_bytes(fixture)
    segments = {network: sorted(members) for network, (_, _, members) in company.lab.NETWORKS.items()}
    names = sorted({name for members in segments.values() for name in members})
    images = {name: 'sha256:' + hashlib.sha256(name.encode()).hexdigest() for name in names}
    lines = [f'/{name} {image}' for name, image in images.items()]
    if mismatch == 'missing':
        lines.pop()
    elif mismatch == 'unexpected':
        lines.append('/foreign-container sha256:' + 'f'*64)
    elif mismatch == 'duplicate':
        lines.append(lines[0])
    elif mismatch == 'invalid_digest':
        lines[0] = '/' + names[0] + ' unverified-tag'
    initialized = []

    class Provider(FakeExpert):
        def __init__(self, store, **kwargs):
            manifest = json.loads((store.root/'manifest.json').read_text())
            assert manifest['scenario'] == {'id': 'integrado', 'version': company.lab.VERSION,
                'source_sha256': 'd'*64, 'images': images,
                'fixture_sha256': hashlib.sha256(fixture).hexdigest()}
            initialized.append(True)
            super().__init__(store, **kwargs)

    with patch.object(company, 'STATE', state), patch.object(company.lab, "load_auditor_environment"), \
         patch.object(company.lab, "preflight", return_value={'segments': segments, 'source_sha256': 'd'*64}), \
         patch.object(company.lab, 'docker', return_value='\n'.join(lines) + '\n') as docker, \
         patch.object(company.agent, "run_task", side_effect=lambda task, store: TaskResult(task_id=task.task_id, status='completed_no_findings')), \
         patch.object(company, "validation_for", return_value=({"state": "observed"}, [])), \
         patch("auditoria.openai_provider.load_openai_config"), patch("llm_especialistas.ExpertScheduler", Provider):
        code = company.run_panel(options, tmp_path/'runs')
    docker.assert_called_once_with('inspect', '--format', '{{.Name}} {{.Image}}', *names)
    root = next((tmp_path/'runs').glob('*/report.json')).parent
    report = json.loads((root/'report.json').read_text())
    if mismatch:
        assert code == 3 and not initialized
        assert report['error'] == 'lab_not_ready_or_kernel'
        assert all(task['status'] == 'blocked' for task in report['tasks'])
        assert report['llm']['status'] == 'not_started'
    else:
        assert code == 0 and initialized == [True]
        assert json.loads((root/'manifest.json').read_text())['scenario']['images'] == images


def test_dispatch_budget_counts_failed_tools_and_preserves_every_catalogue_entry(tmp_path):
    tasks = task_set(5)
    for i, task in enumerate(tasks):
        tasks[i] = task.model_copy(update={'target': task.target.model_copy(update={'asset_id': 'isolated_' + str(i)})})
    ran = []
    def worker(task):
        ran.append(task.task_id)
        return TaskResult(task_id=task.task_id, status='failed' if task is tasks[0] else 'completed_no_findings')
    controller, state, results, _, trace = execute_graph(tmp_path, tasks, worker=worker, task_limit=3)
    assert state['closed'] and len(ran) == len(set(ran)) == 3
    assert len(controller.admitted_task_ids) == 3 and set(controller.admitted_task_ids) == set(ran)
    assert len(results) == len({result.task_id for result in results}) == 5
    skipped = [result for result in results if result.status == TaskStatus.SKIPPED]
    assert len(skipped) == 2 and all(result.reason_code == 'task_budget_not_selected' for result in skipped)
    assert all(result.observations['selection_state'] == 'not_selected' for result in skipped)
    admitted = [payload for kind, _, payload in trace if kind == 'task_admitted']
    assert [payload['executed_tasks'] for payload in admitted] == [1, 2, 3]
    assert all(payload['task_limit'] == 3 for payload in admitted)


@pytest.mark.usefixtures('healthy_kernel')
@pytest.mark.parametrize('architecture,workers', [('single', 1), ('multiagent', 2)])
def test_real_api_practice_uses_floor_sixty_percent_in_each_lab_without_network(tmp_path, architecture, workers):
    from dualstack_panel import validate_options
    from tesis.laboratorios import Context, catalog
    from tesis.llm_contexto import ROLE_MAP
    for scenario in [None, *catalog()]:
        context = Context(scenario['id'], state_root=tmp_path/'states') if scenario else None
        engine = context.agent if context else company.agent
        bank = context.lab if context else company.lab
        name = scenario['id'] if scenario else 'integrado'
        options = validate_options({'name': 'Simulated bounded practice', 'scope': 'empresa', 'authorization': 'LAB-PROPIO',
            'architecture': architecture, 'ia': 'openai', 'tokens': 6000, 'expert_mode': True,
            **({'scenario':name} if scenario else {})})
        catalogue = engine.build_plan(engine.request('LAB-PROPIO', architecture=architecture))
        expected_limit = len(catalogue)*3//5
        active = []
        peak = [0]
        ran = []
        reviewed = []
        lock = threading.Lock()
        first_pair_started = threading.Event()
        def worker(task, store):
            manifest = json.loads((store.root/'manifest.json').read_text())
            assert task.task_id in manifest['detection_budget']['admitted_task_ids']
            assert manifest['executed_tasks'] <= expected_limit
            with lock:
                assert task.target.asset_id not in [item.target.asset_id for item in active]
                if task.agent_type in {'ipv6_ndp','ipv6_fragmentation'}:
                    assert not any(item.agent_type in {'ipv6_ndp','ipv6_fragmentation'} for item in active)
                active.append(task);ran.append(task);peak[0]=max(peak[0],len(active))
                first_worker = len(ran) == 1
                if len(active) == 2:
                    first_pair_started.set()
            # Mantener la primera tarea hasta observar la segunda: 3 ms no
            # garantizan solapamiento en equipos lentos ni con disco ocupado.
            if workers == 2 and first_worker:
                assert first_pair_started.wait(timeout=5), 'No se despacharon dos tareas independientes'
            time.sleep(.003)
            with lock:active.remove(task)
            return TaskResult(task_id=task.task_id, status='completed_no_findings')
        class Provider(FakeExpert):
            def select(self, ready, previous, tasks):
                assert self.detection_budget == {'catalogue_size':len(catalogue),'task_limit':expected_limit,
                    'admitted_tasks':len(self.calls),'remaining_slots':expected_limit-len(self.calls)}
                return super().select(ready, previous, tasks)
            def review(self, tasks, results, findings):
                assert len(tasks) == len(results) == expected_limit
                assert all(result.status != TaskStatus.SKIPPED for result in results)
                assert len(self.catalogue_tasks) == len(catalogue)
                reviewed.extend(tasks)
        if context:
            context.validation = lambda *args: ({'state':'observed'}, [])
        with patch.object(bank, 'load_auditor_environment'), patch.object(bank, 'preflight', return_value={}), \
             patch.object(engine, 'run_task', side_effect=worker), patch.object(company, 'validation_for', return_value=({'state':'observed'}, [])), \
             patch('auditoria.openai_provider.load_openai_config'), patch('llm_especialistas.ExpertScheduler', Provider), \
             patch('tesis.evaluacion.score', return_value={'evidence_valid':True}):
            assert company.run_panel(options,tmp_path/name,bank_context=context) == 0
        root = next((tmp_path/name).glob('*/report.json')).parent
        report = json.loads((root/'report.json').read_text())
        manifest = json.loads((root/'manifest.json').read_text())
        assert peak[0] == workers and len(ran) == len(reviewed) == expected_limit
        assert len(report['tasks']) == len(catalogue)
        assert sum(result['status'] == 'skipped' for result in report['tasks']) == len(catalogue)-expected_limit
        assert report['status'] == 'complete'
        assert report['detection_budget'] == manifest['detection_budget']
        assert report['detection_budget']['applied'] is True
        assert report['task_limit'] == manifest['task_limit'] == expected_limit
        assert report['executed_tasks'] == manifest['executed_tasks'] == expected_limit
        assert set(report['detection_budget']['admitted_task_ids']) == {task.task_id for task in ran}
        actual_plan = json.loads((root/'plan.json').read_text())
        expected_roles = ['generalist'] if architecture == 'single' else list(dict.fromkeys(ROLE_MAP[task['agent_type']] for task in actual_plan if task['task_id'] in {task.task_id for task in ran}))
        assert report['llm']['specialist_reviews_expected_roles'] == expected_roles
        from tesis.presupuesto_deteccion import partial_budget_valid, expected_review_roles
        value={'manifest':manifest,'report':report,'plan':actual_plan,'run':{'architecture':architecture}}
        assert partial_budget_valid(value)
        assert expected_review_roles(value) == set(expected_roles)


def test_specialist_filter_keeps_catalogue_aliases_and_only_executed_roles():
    from llm_especialistas import ExpertScheduler
    catalogue = company.agent.build_plan(company.agent.request('LAB-PROPIO'))
    tasks = [catalogue[4], catalogue[-1]]
    results = [TaskResult(task_id=task.task_id,status='completed_no_findings') for task in tasks]
    scheduler = object.__new__(ExpertScheduler)
    scheduler.catalogue_tasks = catalogue
    scheduler.architecture = 'multiagent'
    scheduler.used = 0
    contexts = []
    with patch.object(scheduler,'_review',side_effect=lambda role,context,used: contexts.append((role,context))):
        scheduler.review(tasks,results,[])
    assert set(scheduler.specialist_reviews_expected_roles) == {'credentials','fragmentation'}
    assert set(role for role, _ in contexts) == {'credentials','fragmentation'}
    refs = {ref for _, context in contexts for ref in context['evidence_tasks']}
    assert refs == {'t004','t031'}
    assert all(context['tasks_total'] == 1 for _, context in contexts)


@pytest.mark.usefixtures('healthy_kernel')
@pytest.mark.parametrize('failure', ['admission_event', 'admission_manifest'])
def test_admission_persistence_failure_consumes_reservation_and_never_runs_tools(tmp_path, failure):
    from dualstack_panel import validate_options
    original_event = RunStore.event
    original_write = company.write_json
    failed = []
    ran = []
    def event(store, component, kind, **kwargs):
        if failure == 'admission_event' and kind == 'task_admitted':
            failed.append(kind)
            raise sqlite3.OperationalError('simulated admission event failure')
        return original_event(store, component, kind, **kwargs)
    def write(path, value):
        if failure == 'admission_manifest' and path.name == '.manifest.json.tmp' and value.get('executed_tasks',0):
            failed.append(path.name)
            raise OSError('simulated persistent manifest update failure')
        return original_write(path, value)
    options = validate_options({'name':'Simulated reservation failure','scope':'empresa','authorization':'LAB-PROPIO'})
    with patch.object(company.lab,'load_auditor_environment'), patch.object(company.lab,'preflight',return_value={}), \
         patch.object(company.agent,'run_task',side_effect=lambda task,store:ran.append(task)), \
         patch.object(company,'validation_for',return_value=({'state':'observed'}, [])), \
         patch.object(RunStore,'event',event), patch.object(company,'write_json',write):
        assert company.run_panel(options,tmp_path) == 3
    report = json.loads(next(tmp_path.glob('*/report.json')).read_text())
    assert failed and not ran
    assert report['status'] == 'partial' and report['error']
    assert report['executed_tasks'] == len(report['detection_budget']['admitted_task_ids']) == 1
    assert len(report['tasks']) == len({task['task_id'] for task in report['tasks']}) == 32
    assert all(task['status'] == 'blocked' for task in report['tasks'])
    assert json.loads(next(tmp_path.glob('*/runtime.json')).read_text())['status'] == 'finished'


@pytest.mark.parametrize('architecture',['single','multiagent'])
def test_planner_prompt_receives_only_public_task_budget_numbers(tmp_path, architecture):
    from auditoria.openai_provider import OpenAIScheduler
    config=SimpleNamespace(model='gpt-6.1-sol',api_key='simulated-key',reasoning_effort='low',max_output_tokens=2048)
    store=RunStore(tmp_path/'prompt','simulated_budget_prompt')
    class Transport:
        def __init__(self):self.inputs=[]
        def post(self, endpoint, body, *, timeout):
            self.inputs.append(body['input'])
            if endpoint.endswith('input_tokens'):return {'input_tokens':10}
            choice=body['text']['format']['schema']['properties']['choice']['enum'][0]
            return {'model':'gpt-6.1-sol','status':'completed','id':'simulated',
                'usage':{'input_tokens':10,'output_tokens':5,'total_tokens':15},
                'output':[{'type':'message','content':[{'type':'output_text','text':json.dumps({'choice':choice})}]}]}
    try:
        with patch('auditoria.openai_provider.OpenAIConfig.from_environment',return_value=config):
            scheduler=OpenAIScheduler(store,architecture=architecture,budget=6000,deadline=time.monotonic()+60)
        transport=Transport();scheduler.transport=transport
        public={'catalogue_size':32,'task_limit':19,'admitted_tasks':3,'remaining_slots':16}
        scheduler.detection_budget={**public,'reserved_ground_truth':'DO_NOT_SEND','cookie':'DO_NOT_SEND'}
        tasks=company.agent.build_plan(company.agent.request('LAB-PROPIO'))
        ready=[task for task in tasks if not task.dependencies]
        assert scheduler.select(ready,[],tasks) in ready
        assert transport.inputs
        for prompt in transport.inputs:
            value=json.loads(prompt.split('\n',1)[1])
            assert value['context']['detection_budget'] == public
            assert 'DO_NOT_SEND' not in prompt and 'reserved_ground_truth' not in prompt
        assert scheduler.summary()['known_tokens']>0
    finally:store.close()


@pytest.mark.parametrize('failure,expected_type,expected_stage,expected_code', [
    (lambda: company.LabError('receptor NovaFlow sin SLAAC, anuncio legítimo o estado inicial correcto'),
     'LabError','receiver_readiness','ipv6_receiver_not_ready'),
    (lambda: __import__('subprocess').TimeoutExpired(['tool','PRIVATE_EXECUTION_VALUE'],45),
     'TimeoutExpired','tool_execution','tool_timeout'),
    (lambda: RuntimeError('PRIVATE_EXECUTION_VALUE'),
     'RuntimeError','tool_execution','execution_error'),
    (lambda: company.LabError('unexpected PRIVATE_EXECUTION_VALUE'),
     'LabError','tool_execution','execution_error'),
])
def test_tool_failure_persists_safe_private_diagnostic_without_retry(
        tmp_path, failure, expected_type, expected_stage, expected_code):
    tasks=task_set(2)
    executed=[]
    def worker(task):
        executed.append(task.task_id)
        raise failure()
    controller,state,results,closed,trace=execute_graph(tmp_path,tasks,worker=worker,task_limit=1)
    assert executed == controller.admitted_task_ids == [tasks[0].task_id]
    assert state['closed'] and len(closed) == 1
    result=next(item for item in results if item.task_id == tasks[0].task_id)
    assert result.status == TaskStatus.FAILED and result.reason_code == expected_code
    assert result.observations == {'failure_stage':expected_stage,'exception_type':expected_type,
                                   'diagnostic_persisted':True}
    assert next(item for item in results if item.task_id == tasks[1].task_id).reason_code == 'task_budget_not_selected'
    path=tmp_path/'run'/result.diagnostic_ref
    payload=path.read_bytes()
    diagnostic=json.loads(payload)
    assert path.stat().st_mode & 0o777 == 0o600
    assert hashlib.sha256(payload).hexdigest() == result.diagnostic_sha256
    assert diagnostic['exception_type'] == expected_type and diagnostic['stage'] == expected_stage
    assert diagnostic['reason_code'] == expected_code and diagnostic['admission_index'] == 1
    assert diagnostic['task_limit'] == 1 and diagnostic['catalogue_size'] == 2
    event=next(payload for kind,task_id,payload in trace
               if kind == 'tool_execution_failed' and task_id == result.task_id)
    assert event['reason_code'] == expected_code and event['stage'] == expected_stage
    assert event['diagnostic_sha256'] == result.diagnostic_sha256
    for value in [payload.decode(),json.dumps(trace),result.model_dump_json()]:
        assert 'PRIVATE_EXECUTION_VALUE' not in value


def test_typed_adapter_failure_keeps_stage_and_sanitizes_original_cause(tmp_path):
    from subprocess import TimeoutExpired
    def worker(task):
        try:
            raise TimeoutExpired(['PRIVATE_COMMAND'],45,output='PRIVATE_STDOUT',stderr='PRIVATE_STDERR')
        except TimeoutExpired as exc:
            raise TaskExecutionError(stage='ipv6_restore',reason_code='ipv6_restore_failed') from exc
    _,state,results,_,trace=execute_graph(tmp_path,task_set(1),worker=worker)
    assert state['closed'] and len(results) == 1
    result=results[0]
    assert result.reason_code == 'ipv6_restore_failed'
    diagnostic=json.loads((tmp_path/'run'/result.diagnostic_ref).read_text())
    assert diagnostic['stage'] == 'ipv6_restore'
    assert diagnostic['exception_chain'] == [
        {'exception_type':'TaskExecutionError','stage':'ipv6_restore','reason_code':'ipv6_restore_failed'},
        {'exception_type':'TimeoutExpired','stage':'tool_execution','reason_code':'tool_timeout'}]
    serialized=json.dumps([diagnostic,trace,result.model_dump(mode='json')])
    assert 'PRIVATE_' not in serialized


@pytest.mark.parametrize('persistence_failure',['evidence','event'])
def test_diagnostic_persistence_failure_preserves_tool_failure_and_consumed_slot(tmp_path,persistence_failure):
    original_event=RunStore.event
    attempts=[]
    def event(store,component,kind,**kwargs):
        if persistence_failure == 'event' and kind == 'tool_execution_failed':
            raise sqlite3.OperationalError('PRIVATE_DATABASE_FAILURE')
        return original_event(store,component,kind,**kwargs)
    def worker(task):
        attempts.append(task.task_id)
        raise TaskExecutionError(stage='receiver_readiness',reason_code='ipv6_receiver_not_ready')
    with patch.object(RunStore,'event',event):
        if persistence_failure == 'evidence':
            with patch.object(RunStore,'evidence',side_effect=OSError('PRIVATE_STORAGE_FAILURE')):
                controller,state,results,closed,trace=execute_graph(tmp_path,task_set(2),worker=worker,task_limit=1)
        else:
            controller,state,results,closed,trace=execute_graph(tmp_path,task_set(2),worker=worker,task_limit=1)
    assert attempts == controller.admitted_task_ids and len(attempts) == 1
    assert state['closed'] and len(closed) == 1 and len(results) == 2
    result=next(item for item in results if item.status == TaskStatus.FAILED)
    assert result.reason_code == 'ipv6_receiver_not_ready'
    if persistence_failure == 'evidence':
        assert result.diagnostic_ref is result.diagnostic_sha256 is None
        assert result.observations['diagnostic_persisted'] is False
        event=next(payload for kind,_,payload in trace if kind == 'tool_execution_failed')
        assert event['diagnostic_persisted'] is False
    else:
        assert result.diagnostic_ref and result.diagnostic_sha256
        assert result.observations['diagnostic_event_saved'] is False
    assert 'PRIVATE_' not in json.dumps([trace,result.model_dump(mode='json')])


def test_invalid_tool_result_has_safe_diagnostic_and_labels_reject_free_text(tmp_path):
    with pytest.raises(ValueError,match='invalid_execution_failure_label'):
        TaskExecutionError(stage='PRIVATE_STAGE',reason_code='execution_error')
    with pytest.raises(ValueError,match='invalid_execution_failure_label'):
        TaskExecutionError(stage='tool_execution',reason_code='PRIVATE_ERROR')
    _,state,results,_,_=execute_graph(tmp_path,task_set(1),worker=lambda task:None)
    assert state['closed'] and results[0].reason_code == 'invalid_tool_result'
    assert results[0].diagnostic_ref and results[0].diagnostic_sha256
