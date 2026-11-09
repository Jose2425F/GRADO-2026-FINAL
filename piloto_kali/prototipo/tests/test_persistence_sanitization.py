import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from auditoria.store import RunStore,write_json
from auditoria.sanitization import sanitize,VERSION


def test_nested_secrets_and_terminal_sequences_removed_before_disk(tmp_path,monkeypatch):
    secret='synthetic-private-fixture-2026'
    monkeypatch.setenv('LAB_NOVA_PASSWORD',secret)
    store=RunStore(tmp_path/'run','clean')
    try:
        raw={'nested':[{'password':'short','banner':'\x1b]8;;http://bad\x07hello\x1b[31m\x00\u202e'+secret}],
             'token_budget':6000,'count':0}
        ref,digest=store.evidence('task','json',json.dumps(raw).encode())
        saved=(store.root/ref).read_bytes()
        assert secret.encode() not in saved and b'short' not in saved
        assert digest==hashlib.sha256(saved).hexdigest()
        data=json.loads(saved)
        assert data['token_budget']==6000 and data['count']==0
        assert data['nested'][0]['banner']=='hello[REDACTED]'
        event=store.event('tool','message',payload=raw)
        assert event.payload['_sanitization']['omitted_values_retained'] is False
        write_json(store.root/'report.json',raw)
        assert secret not in (store.root/'sanitization.jsonl').read_text()
        with sqlite3.connect(store.root/'events.sqlite3') as db:
            rows=[r[0] for r in db.execute('select payload_json from events')]
        assert rows and all(secret not in row and 'short' not in row for row in rows)
    finally:store.close()


def test_plain_evidence_and_binary_captures_keep_exact_bytes(tmp_path,monkeypatch):
    store=RunStore(tmp_path/'run','binary')
    try:
        for extension,data in [('json',b'{ "count": 1 }'),('xml',b'<nmaprun/>'),('pcap',b'\xd4\xc3\xb2\xa1\x00\x1b\x7f')]:
            ref,digest=store.evidence('task_'+extension,extension,data)
            assert (store.root/ref).read_bytes()==data
        monkeypatch.setenv('OPENAI_API_KEY','synthetic-secret-canary-123456')
        with pytest.raises(ValueError,match='unsafe_or_invalid_evidence'):
            store.evidence('blocked','pcap',b'prefix synthetic-secret-canary-123456 suffix')
        assert not (store.root/'evidence/blocked.pcap').exists()
    finally:store.close()


@pytest.mark.parametrize('value',['password=short','Bearer abcdefghijklmnop','sk-proj-abcdefghijklmnopqrstuvwxyz',
                                  'api_key: abcdefghijk'])
def test_unknown_credentials_in_common_forms_are_redacted(value):
    clean,counts=sanitize(value,secrets=[])
    assert '[REDACTED]' in clean and counts


def test_controls_splitting_a_known_secret_cannot_bypass_redaction():
    clean,counts=sanitize('abc\x1b[0mdefghij',secrets=['abcdefghij'])
    assert clean=='[REDACTED]' and counts['known_secret']==1


def test_key_collision_is_rejected_instead_of_losing_a_measurement():
    with pytest.raises(ValueError,match='sanitization_key_collision'):
        sanitize({'a':1,'a\x00':2},secrets=[])
