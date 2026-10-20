"""Paquete verificable con dos primeras corridas y 48 posiciones no iniciadas."""
from copy import deepcopy
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tesis.exportacion_manual import FIELDS, export_csv, export_zip, verify_export
from tesis.protocolo_manual import protocol


def fixture():
    proposal = protocol()
    rows = []
    for slot in proposal['schedule']:
        row = {key: None for key in FIELDS}
        row.update(sequence=slot['sequence'], scenario=slot['scenario'], laboratory='Laboratorio ' + slot['scenario'],
                   pair=slot['pair'], architecture=slot['architecture'], status='not_started', recorded=False,
                   protocol_sha256=proposal['protocol_sha256'], exclusion_reasons=[])
        if slot['sequence'] <= 2:
            single = slot['architecture'] == 'single'
            row.update(status='complete', recorded=True, run_id='panel/job/' + slot['architecture'],
                seconds=10 if single else 8, input_tokens=600 if single else 500,
                output_tokens=400 if single else 300, provider_output_tokens=400 if single else 300,
                text_output_tokens=300 if single else 250, reasoning_tokens=100 if single else 50,
                total_tokens=1000 if single else 800, known_tokens=1000 if single else 800,
                usage_complete=True, token_usage_complete=True, cost_estimate_usd=.001 if single else .0008,
                known_cost_estimate_usd=.001 if single else .0008, cost_limit_usd=2.0,
                token_budget=60000, max_runtime_seconds=2400, TP=2 if single else 3, FP=0, FN=1 if single else 0,
                TN=2, unknown_negative_controls=0, negative_conditions_total=2, eligible_pair=True, model='gpt-6.1-sol',
                reported_models=['gpt-6.1-sol'], source_sha256='a'*64, graph_sha256='b'*64,
                ground_truth_sha256='c'*64, restoration_id='restore_' + slot['architecture'], scope_sha256='d'*64,
                recorded_protocol_sha256=proposal['protocol_sha256'],
                scenario_source_sha256='e'*64, images_sha256='f'*64, fixture_sha256='0'*64,
                adapter_sha256='1'*64, extensions_sha256={'tesis/orquestacion_langgraph.py': 'b'*64},
                graph_version='novaflow-langgraph-1', langgraph_version='1.2.12',
                api_generations=3 if single else 7, fallbacks=0,
                specialist_reviews_accepted=1 if single else 5, specialist_reviews_expected=1 if single else 5,
                evidence_valid=True, task_limit=19, catalogue_size=32, executed_tasks=19, task_limit_applied=True)
        rows.append(row)
    return {'records': rows, 'records_extra': []}, proposal


def unpack(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def repack(payloads, *, refresh_manifest=False):
    if refresh_manifest:
        manifest = json.loads(payloads['manifest.json'])
        for name in manifest['files']:
            if name in payloads:
                manifest['files'][name] = {'sha256': hashlib.sha256(payloads[name]).hexdigest(), 'bytes': len(payloads[name])}
        payloads['manifest.json'] = json.dumps(manifest).encode()
    target = io.BytesIO()
    with zipfile.ZipFile(target, 'w') as archive:
        for name, data in payloads.items():
            archive.writestr(name, data)
    return target.getvalue()


def test_round_trip_deterministic_and_independent_metrics_without_state_mutation():
    summary, proposal = fixture()
    before = deepcopy((summary, proposal))
    data = export_zip(summary, proposal)
    assert data == export_zip(summary, proposal)
    assert (summary, proposal) == before
    result = verify_export(data)
    assert result['valid'], result['errors']
    assert result['counts'] == {'planned_runs': 50, 'planned_pairs': 25, 'recorded_runs': 2,
        'not_started_runs': 48, 'extra_attempts': 0, 'eligible_pairs': 1}
    assert result['analysis']['TRTO_percent']['mean'] == pytest.approx(20)
    assert result['analysis']['IDE_percent']['mean'] == pytest.approx(50)
    assert result['analysis']['ETV_ratio']['mean'] == pytest.approx(1.875)
    assert result['scenarios'][0]['analysis']['TRTO_percent']['n'] == 1
    assert all(group['analysis']['TRTO_percent']['n'] == 0 for group in result['scenarios'][1:])


def test_csv_has_fifty_positions_and_missing_measurements_are_empty_not_zero():
    summary, _ = fixture()
    raw = export_csv(summary)
    rows = list(csv.DictReader(io.StringIO(raw.decode())))
    assert len(rows) == 50
    for row in rows[2:]:
        for key in ['seconds', 'input_tokens', 'output_tokens', 'reasoning_tokens', 'total_tokens', 'cost_estimate_usd', 'TP', 'FP', 'FN', 'TN']:
            assert row[key] == ''
    assert rows[0]['output_tokens'] == '400'
    assert rows[0]['reasoning_tokens'] == '100'
    # Ya están incluidos en los 400 facturables, no se vuelven a sumar.
    assert rows[0]['total_tokens'] == '1000'


def test_partial_catalogue_keeps_unchecked_negatives_visible_and_reviews_actual_domains():
    summary,proposal=fixture()
    single,multi=summary['records'][:2]
    single.update(TN=1,unknown_negative_controls=1)
    multi.update(TN=0,unknown_negative_controls=2,specialist_reviews_accepted=2,specialist_reviews_expected=2)
    result=verify_export(export_zip(summary,proposal))
    assert result['valid'],result['errors']
    assert result['counts']['eligible_pairs']==1


def test_private_unknown_fields_are_dropped_and_no_raw_summary_is_exported():
    summary, proposal = fixture()
    summary['api_key'] = 'SECRET_API_KEY'
    summary['raw_prompt'] = 'SECRET_PROMPT'
    summary['records'][0]['cookie'] = 'SECRET_COOKIE'
    summary['records'][0]['provider_response'] = 'SECRET_BODY'
    proposal['unlisted_prompt'] = 'SECRET_PROTOCOL_PROMPT'
    data = export_zip(summary, proposal)
    all_text = b'\n'.join(unpack(data).values())
    for value in [b'SECRET_API_KEY', b'SECRET_PROMPT', b'SECRET_COOKIE', b'SECRET_BODY', b'SECRET_PROTOCOL_PROMPT']:
        assert value not in all_text
    assert verify_export(data)['valid']


@pytest.mark.parametrize('unsafe', ['https://private.example/path', 'Bearer private-token', 'api_key=secret-value', '=HYPERLINK("x")'])
def test_no_urls_credentials_or_csv_formulas_in_allowed_text(unsafe):
    summary, proposal = fixture()
    summary['records'][0]['laboratory'] = unsafe
    with pytest.raises(ValueError):
        export_zip(summary, proposal)


def test_hash_tampering_and_missing_file_are_rejected():
    summary, proposal = fixture()
    payloads = unpack(export_zip(summary, proposal))
    payloads['runs.json'] = payloads['runs.json'].replace(b'1000', b'9999', 1)
    assert verify_export(repack(payloads))['valid'] is False
    payloads.pop('runs.csv')
    assert verify_export(repack(payloads))['valid'] is False
    assert verify_export(b'not-a-zip')['valid'] is False


@pytest.mark.parametrize('change', ['model', 'limits', 'scope', 'restoration', 'usage', 'tokens_double_counted', 'unknown_controls'])
def test_claimed_apt_pair_must_have_compatible_public_data(change):
    summary, proposal = fixture()
    row = summary['records'][1]
    if change == 'model': row['reported_models'] = ['different-real-model']
    elif change == 'limits': row['cost_limit_usd'] = 20
    elif change == 'scope': row['scope_sha256'] = '9'*64
    elif change == 'restoration': row['restoration_id'] = summary['records'][0]['restoration_id']
    elif change == 'usage': row['usage_complete'] = False
    elif change == 'tokens_double_counted': row['total_tokens'] += row['reasoning_tokens']
    elif change == 'unknown_controls': row['unknown_negative_controls'] = 1
    result = verify_export(export_zip(summary, proposal))
    assert result['valid'] is False and result['counts']['eligible_pairs'] == 0
    assert result['analysis']['TRTO_percent']['n'] == 0


def test_duplicate_attempt_is_separate_and_does_not_replace_first_result():
    summary, proposal = fixture()
    extra = deepcopy(summary['records'][0])
    extra.update(run_id='panel/retry/' + extra['architecture'], status='failed', eligible_pair=False,
                 exclusion_reasons=['Intento adicional; no reemplaza el primer resultado.'])
    summary['records_extra'] = [extra]
    result = verify_export(export_zip(summary, proposal))
    assert result['valid'] and result['counts']['extra_attempts'] == 1
    assert result['counts']['recorded_runs'] == 2 and result['counts']['eligible_pairs'] == 1


def test_duplicate_main_slot_and_duplicate_zip_member_are_rejected():
    summary, proposal = fixture()
    summary['records'][1]['sequence'] = summary['records'][0]['sequence']
    with pytest.raises(ValueError):
        export_zip(summary, proposal)
    summary, proposal = fixture()
    payloads = unpack(export_zip(summary, proposal))
    target = io.BytesIO()
    with zipfile.ZipFile(target, 'w') as archive:
        for name, data in payloads.items(): archive.writestr(name, data)
        with pytest.warns(UserWarning): archive.writestr('runs.json', payloads['runs.json'])
    assert verify_export(target.getvalue())['valid'] is False


def test_rehashing_a_modified_aggregate_still_fails_independent_recalculation():
    summary, proposal = fixture()
    payloads = unpack(export_zip(summary, proposal))
    aggregate = json.loads(payloads['summary.json'])
    aggregate['analysis']['TRTO_percent']['mean'] = 99
    payloads['summary.json'] = json.dumps(aggregate).encode()
    result = verify_export(repack(payloads, refresh_manifest=True))
    assert result['valid'] is False
    assert any('recálculo' in reason for reason in result['errors'])
