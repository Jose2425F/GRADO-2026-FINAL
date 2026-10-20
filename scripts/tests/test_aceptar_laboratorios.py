from pathlib import Path
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'piloto_kali/prototipo/src')]
import aceptar_laboratorios as acceptance


GRAPH = {'engine':'langgraph','version':'test','graph':'test','source_sha256':'a'*64}


def configure(monkeypatch, tmp_path, fail=None):
    pilot = tmp_path / 'pilot'
    monkeypatch.setattr(acceptance, 'PILOT', pilot)
    monkeypatch.setattr(acceptance, 'STATE', pilot / '.lab-suite')
    monkeypatch.setattr(acceptance, 'RECEIPT', pilot / '.lab-suite/acceptance-five.json')
    monkeypatch.setattr(acceptance, 'OUTPUT', pilot / 'corridas/acceptance_five')
    monkeypatch.setattr(acceptance, 'engine_metadata', lambda: dict(GRAPH))
    monkeypatch.setattr(acceptance, 'process_identity', lambda _: 'synthetic-process')
    monkeypatch.setattr(acceptance.suite, 'kernel_ok', lambda: None)
    invoked = []

    def guarded(command, _log, timeout):
        assert timeout == 2700
        assert '--slot' in command and '--openai' not in command
        output = Path(command[-1]);spec = json.loads((output / 'slot.json').read_text())
        options = spec['options']
        assert options == acceptance.acceptance_options()
        assert options['ia'] == 'none' and options['tokens'] == 0
        assert 'manual_context' not in options and not options['expert_mode']
        invoked.append(spec['scenario'])
        expected = next(row['tasks'] for row in acceptance.laboratory_catalog() if row['id'] == spec['scenario'])
        directory = output / 'synthetic_run';directory.mkdir()
        valid = spec['scenario'] != fail
        data = {'report':{'status':'complete' if valid else 'partial', 'llm':{'status':'disabled','known_tokens':0,'total_tokens':0,'calls':[]}},
                'request':{'token_budget':0,'llm_mode':'disabled'},
                'plan':[{'task_id':str(i)} for i in range(expected)],
                'manifest':{'orchestration':dict(GRAPH),'detection_budget':{'catalogue_size':expected,'task_limit':None,'applied':False}},
                'evaluation':{'tasks_checked':expected,'tasks_valid':expected if valid else 0,'acceptance_passed':valid,'evidence_valid':valid,'TP':1,'FP':0,'FN':0,'TN':1}}
        for name, value in data.items():
            (directory / (name + '.json')).write_text(json.dumps(value))
        return 0 if valid else 3

    monkeypatch.setattr('ejecutar_estudio_novaflow.guarded', guarded)
    return invoked


def test_accepts_exactly_five_full_catalogues_without_api_or_manual_positions(tmp_path, monkeypatch):
    invoked = configure(monkeypatch, tmp_path)
    assert acceptance.accept_all() == 0
    assert invoked == list(acceptance.IDS)
    receipt = acceptance.public_status()
    assert receipt['accepted'] is True and receipt['completed_labs'] == 5
    assert receipt['known_tokens'] == receipt['new_api_generations'] == 0
    assert sum(row['expected_tasks'] for row in receipt['scenarios']) == 154
    assert all(row['full_catalogue'] and row['zero_api'] for row in receipt['scenarios'])


def test_failure_preserves_attempt_and_stops_remaining_labs(tmp_path, monkeypatch):
    invoked = configure(monkeypatch, tmp_path, fail='comercial')
    assert acceptance.accept_all() == 3
    receipt = acceptance.public_status()
    assert invoked == ['integrado','sucursal','comercial']
    assert receipt['accepted'] is False and receipt['status'] == 'stopped'
    assert receipt['completed_labs'] == 2
    assert receipt['scenarios'][2]['status'] == 'failed'
    assert receipt['scenarios'][3]['status'] == 'pending'


def test_old_or_incomplete_receipt_never_accredits_five_labs(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    acceptance.accept_all()
    saved = json.loads(acceptance.RECEIPT.read_text())
    saved['scenarios'][0]['full_catalogue'] = False
    acceptance.RECEIPT.write_text(json.dumps(saved))
    assert acceptance.public_status()['accepted'] is False
    assert acceptance.public_status()['status'] == 'invalidated'


def test_kernel_guard_precedes_any_worker_or_receipt(tmp_path, monkeypatch):
    invoked = configure(monkeypatch, tmp_path)
    monkeypatch.setattr(acceptance.suite, 'kernel_ok', lambda: (_ for _ in ()).throw(ValueError('kernel_failure')))
    with pytest.raises(ValueError, match='kernel_failure'):
        acceptance.accept_all()
    assert invoked == [] and not acceptance.RECEIPT.exists()


def test_slot_cannot_enable_api_or_enter_a_manual_position(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    slot = tmp_path / 'slot';slot.mkdir()
    options = acceptance.acceptance_options() | {'ia':'openai','tokens':60000}
    (slot / 'slot.json').write_text(json.dumps({'parent_pid':__import__('os').getppid(),
        'parent_identity':'synthetic-process','scenario':'integrado','options':options}))
    with pytest.raises(ValueError, match='no autorizado'):
        acceptance.run_slot(slot)
    assert json.loads((slot / 'worker_failure.json').read_text())['reason'] == 'execution_failed'


def test_missing_images_have_explicit_failure_without_build_or_pull(tmp_path, monkeypatch):
    calls = []
    def inspect(command, **_):
        calls.append(command)
        return type('Result', (), {'returncode':1})()
    monkeypatch.setattr('subprocess.run', inspect)
    with pytest.raises(ValueError, match='lab_images_missing'):
        acceptance.ensure_images_available({'services':{'web':{'image':'owned-local-image'}}})
    assert calls == [['docker','image','inspect','owned-local-image']]


def test_original_acceptance_uses_the_same_pinned_restoration_as_panel(tmp_path, monkeypatch):
    configure(monkeypatch, tmp_path)
    import laboratorio_empresa as cli
    from tesis import restauracion_banco as pinned
    output = tmp_path / 'slot'; output.mkdir()
    (output / 'slot.json').write_text(json.dumps({'parent_pid':__import__('os').getppid(),
        'parent_identity':'synthetic-process','scenario':'integrado',
        'options':acceptance.acceptance_options(),'receipt':str(acceptance.RECEIPT)}))
    calls = []
    monkeypatch.setattr(cli, 'STATE', tmp_path / 'original')
    monkeypatch.setattr(cli.lab, 'prepare', lambda _: calls.append('fixture'))
    monkeypatch.setattr(pinned, 'prepare_images', lambda _: calls.append('pin-local-images'))
    monkeypatch.setattr(pinned, 'down_pinned', lambda _: calls.append('down-pinned'))
    monkeypatch.setattr(pinned, 'restore_pinned', lambda _: calls.append('restore-pinned'))
    monkeypatch.setattr(acceptance, 'clear_owned_suite_banks', lambda: calls.append('clear-suite'))
    monkeypatch.setattr(acceptance, 'update_phase', lambda _path, _scenario, phase: calls.append(phase))
    monkeypatch.setattr('ejecutar_estudio_novaflow.wait_preflight', lambda _: calls.append('preflight'))
    monkeypatch.setattr(cli, 'run_panel', lambda options, _output: calls.append(('audit',options)) or 0)
    assert acceptance._execute_slot(output) == 0
    assert calls == ['restoring','fixture','pin-local-images','clear-suite','down-pinned',
        'restore-pinned','checking','preflight','running',('audit',acceptance.acceptance_options()),
        'closing','down-pinned']
