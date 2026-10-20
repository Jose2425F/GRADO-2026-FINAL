import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.restauracion_manual import RestorationBook,assert_run_claim


def test_fresh_restore_check_single_use_and_reboot(tmp_path):
    book=RestorationBook(tmp_path/'receipts.json',boot_id='boot1')
    assert not book.public('integrado')['restored']
    book.checked('integrado')
    assert not book.public('integrado')['restored']
    book.restored('integrado','restore1')
    assert not book.public('integrado')['restored']
    book.checked('integrado')
    assert book.public('integrado')['restored']
    receipt=book.claim('integrado','run1')
    assert book.verify_claim('integrado','run1',receipt['id'])
    assert book.activate('integrado','run1',receipt['id'])
    with pytest.raises(ValueError,match='ya fue utilizado'):
        book.activate('integrado','run1',receipt['id'])
    with pytest.raises(ValueError):book.claim('integrado','run2')
    book.restored('integrado','restore2');book.checked('integrado')
    assert not RestorationBook(book.path,boot_id='boot2').public('integrado')['restored']
    with pytest.raises(ValueError):book.verify_claim('integrado','run1',receipt['id'])


def test_check_never_restores_invalidated_or_other_scenario(tmp_path):
    book=RestorationBook(tmp_path/'receipts.json',boot_id='boot1')
    book.restored('sucursal','r');book.checked('sucursal')
    assert not book.public('comercial')['restored']
    book.invalidate('sucursal');book.checked('sucursal')
    assert not book.public('sucursal')['restored']


def test_pending_design_cannot_start_a_registered_child(tmp_path,monkeypatch):
    monkeypatch.setattr('tesis.protocolo_manual.protocol',lambda:{'status':'pending_confirmation'})
    with pytest.raises(ValueError,match='pendiente de confirmación'):
        assert_run_claim(tmp_path,{'ia':'openai','tokens':60000,'expert_mode':True},tmp_path/'receipts.json')


def test_confirmed_protocol_still_requires_real_panel_job_before_api(tmp_path):
    with pytest.raises(ValueError,match='Trabajo manual no admitido'):
        assert_run_claim(tmp_path,{'ia':'openai','tokens':60000,'expert_mode':True},tmp_path/'receipts.json')
