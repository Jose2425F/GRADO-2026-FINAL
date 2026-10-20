"""Diseño reproducible y orden de posiciones; cero API, herramientas o Docker."""
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import random
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesis.protocolo_manual import (MODEL, SCENARIOS, SEED, STUDY_ID, next_slot,
                                    protocol, schedule, validate_next, write_protocol)


def test_schedule_has_exact_fifty_positions_and_twenty_five_paired_comparisons():
    rows = schedule()
    assert len(rows) == 50
    assert [row['sequence'] for row in rows] == list(range(1, 51))
    assert all(row['sequence'] == row['slot'] for row in rows)
    assert len({(row['scenario'], row['pair'], row['architecture']) for row in rows}) == 50
    assert Counter(row['scenario'] for row in rows) == Counter({scenario: 10 for scenario in SCENARIOS})
    for i in range(0, len(rows), 2):
        first, second = rows[i:i+2]
        assert (first['scenario'], first['pair']) == (second['scenario'], second['pair'])
        assert {first['architecture'], second['architecture']} == {'single', 'multiagent'}
        assert first['first_architecture'] == second['first_architecture'] == first['architecture']
        assert first['pair_position'] == 1 and second['pair_position'] == 2
        assert first['restore_required'] is second['restore_required'] is True
        assert first['preflight_required'] is second['preflight_required'] is True


def test_seeded_randomization_is_stratified_three_two_and_thirteen_twelve():
    firsts = [row for row in schedule() if row['pair_position'] == 1]
    assert Counter(row['architecture'] for row in firsts) == {'single': 13, 'multiagent': 12}
    for scenario in SCENARIOS:
        counts = Counter(row['architecture'] for row in firsts if row['scenario'] == scenario)
        assert sorted(counts.values()) == [2, 3]
    before = schedule()
    previous_random_state = random.getstate()
    try:
        random.seed(993)
        for _ in range(100):
            random.random()
        assert schedule() == before
    finally:
        random.setstate(previous_random_state)
    assert protocol()['seed'] == SEED


def test_protocol_hash_is_canonical_and_authorized_limit_is_applied():
    value = protocol()
    assert value == protocol()
    digest = value.pop('protocol_sha256')
    assert value.pop('sha256') == digest
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assert hashlib.sha256(raw).hexdigest() == digest
    assert value['planned_runs'] == 50 and value['planned_pairs'] == 25
    assert value['status'] == 'frozen' and value['task_limit_status'] == 'confirmed'
    assert value['state'] == 'confirmed'
    assert value['task_limit'] is value['proposed_task_limit'] is None
    assert value['task_limits'] == value['proposed_task_limits']
    assert value['protocol_version'] == '3'
    assert value['proposed_task_fraction'] == .6
    assert value['proposed_task_limits'] == {'integrado': 19, 'sucursal': 15, 'comercial': 16, 'mixto': 19, 'reforzado': 22}
    assert all(value['proposed_task_limits'][name] == count * 3 // 5 for name, count in value['catalog_task_counts'].items())
    assert value['structural_validation']['satisfied'] is False
    minimums = value['structural_validation']['minimum_tasks_for_all_present_conditions']
    assert minimums == {'integrado': 12, 'sucursal': 9, 'comercial': 10, 'mixto': 10, 'reforzado': 3}
    assert all(minimums[name] <= cap for name, cap in value['proposed_task_limits'].items())
    assert value['task_limit_applied'] is value['execution_enabled'] is True
    assert value['model'] == MODEL == 'gpt-6.1-sol'
    assert value['tokens'] == 60000 and value['max_cost_usd'] == 2.0
    assert value['max_runtime_seconds'] == value['limits']['max_runtime_seconds_per_run'] == 2400
    assert value['limits']['audit_request_contract_ceiling_seconds'] == 3600
    assert value['limits']['runtime_limit_applied_by_this_module'] is False
    assert value['limits']['cost_limit_applied_by_this_module'] is False


def test_callers_cannot_modify_future_schedule_or_protocol():
    rows = schedule()
    rows[0]['architecture'] = 'changed'
    value = protocol()
    value['schedule'].clear()
    assert schedule()[0]['architecture'] != 'changed'
    assert len(protocol()['schedule']) == 50


def test_every_first_attempt_consumes_a_position_even_failed_or_interrupted():
    rows = schedule()
    first = {**rows[0], 'status': 'failed'}
    second = {**rows[1], 'status': 'interrupted'}
    assert next_slot() == rows[0]
    assert next_slot([first]) == rows[1]
    assert next_slot([first, second]) == rows[2]
    assert next_slot([first, first, second]) == rows[2]
    assert next_slot(rows) is None
    assert next_slot(range(1, 51)) is None


def test_nested_contexts_and_unrelated_studies_do_not_replace_first_attempts():
    rows = schedule()
    first = rows[0]
    run = {'manual_context': {key: first[key] for key in ['study_id', 'scenario', 'pair', 'architecture']},
           'status': 'partial'}
    other = {**rows[1], 'study_id': 'historical-other-study'}
    assert next_slot([run, other]) == rows[1]
    plain = {key: first[key] for key in ['scenario', 'pair', 'architecture']}
    assert next_slot([plain]) == rows[1]


@pytest.mark.parametrize('records', [[2], [1, 3], [True], [0], [51], ['1'],
    [{'scenario': 'other', 'pair': 1, 'architecture': 'single'}]])
def test_out_of_order_or_invalid_positions_are_rejected(records):
    with pytest.raises(ValueError):
        next_slot(records)


def panel_options(row):
    return {'scope': 'empresa', 'scenario': '' if row['scenario'] == 'integrado' else row['scenario'],
            'architecture': row['architecture'], 'manual_context': {'study_id': STUDY_ID, 'pair': row['pair']}}


def test_validate_next_matches_panel_empty_original_scenario_and_exact_order():
    rows = schedule()
    assert validate_next(panel_options(rows[0])) == rows[0]
    assert validate_next(panel_options(rows[1]), [rows[0]]) == rows[1]
    with pytest.raises(ValueError, match='siguiente posición'):
        validate_next(panel_options(rows[1]))
    with pytest.raises(ValueError, match='50 posiciones'):
        validate_next(panel_options(rows[-1]), rows)
    with pytest.raises(ValueError):
        validate_next({'scope': 'empresa'})


def test_json_and_csv_are_deterministic_proposals_with_fifty_data_rows(tmp_path):
    receipt = write_protocol(tmp_path)
    assert receipt['status'] == 'frozen' and receipt['rows'] == 50
    source = (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.json').read_bytes()
    table = (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.csv').read_bytes()
    assert write_protocol(tmp_path) == receipt
    assert (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.json').read_bytes() == source
    assert (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.csv').read_bytes() == table
    value = json.loads(source)
    records = list(csv.DictReader(table.decode('utf-8').splitlines()))
    assert len(records) == 50
    assert len({(r['scenario'], r['pair']) for r in records}) == 25
    assert all(r['protocol_sha256'] == value['protocol_sha256'] for r in records)
    assert all(r['restore_required'] == r['preflight_required'] == 'True' for r in records)
    assert all(r['model'] == MODEL and r['tokens'] == '60000' for r in records)
    assert all(r['status'] == 'frozen' and r['task_limit_status'] == 'confirmed' and r['task_limit_applied']=='True' for r in records)
    # Una propuesta distinta se conserva para revisión, no se pisa silenciosamente.
    (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.json').write_text('{"different":true}\n')
    with pytest.raises(FileExistsError):
        write_protocol(tmp_path)
    assert (tmp_path/'PROTOCOLO_MANUAL_LANGGRAPH.csv').read_bytes() == table
