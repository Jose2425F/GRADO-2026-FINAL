"""El botón de aceptación es una operación sin configuración ni proveedor."""
from pathlib import Path
import sys
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dualstack_panel import Operations


def test_acceptance_all_preserves_kernel_guard_before_spawn(tmp_path):
    operations=Operations(tmp_path/'corridas',popen=Mock())
    with patch.object(operations,'snapshot',return_value={'busy':False}),\
         patch('dualstack_panel.study_summary',return_value={'active':False}),\
         patch('dualstack_panel.collect_state',return_value={'runs':[]}),\
         patch('dualstack_panel.kernel_warning',return_value='Reinicia Kali'):
        with pytest.raises(ValueError,match='Reinicia Kali'):
            operations.start('acceptance_all',{})
    operations.popen.assert_not_called()


def test_acceptance_cannot_receive_ai_or_paid_audit_options(tmp_path):
    operations=Operations(tmp_path/'corridas',popen=Mock())
    with patch.object(operations,'snapshot',return_value={'busy':False}),\
         patch('dualstack_panel.study_summary',return_value={'active':False}),\
         patch('dualstack_panel.collect_state',return_value={'runs':[]}):
        with pytest.raises(ValueError,match='no recibe configuración'):
            operations.start('acceptance_all',{'ia':'openai','tokens':60000})
    operations.popen.assert_not_called()


def test_paid_registered_sample_requires_five_labs_accepted_before_spawn(tmp_path):
    from tesis.protocolo_manual import STUDY_ID
    root=tmp_path/'corridas';root.mkdir()
    operations=Operations(root,popen=Mock())
    with patch.object(operations,'snapshot',return_value={'busy':False}),\
         patch('dualstack_panel.study_summary',return_value={'active':False}),\
         patch('dualstack_panel.collect_state',return_value={'runs':[]}),\
         patch('aceptar_laboratorios.public_status',return_value={'accepted':False}):
        with pytest.raises(ValueError,match='aceptación sin IA de los cinco'):
            operations.start('audit',{'scope':'empresa','authorization':'LAB-PROPIO','architecture':'single',
                'ia':'openai','expert_mode':True,'tokens':60000,'manual_context':{'study_id':STUDY_ID,'pair':1}})
    operations.popen.assert_not_called()


def test_acceptance_worker_command_is_fixed_and_invalidates_old_restores(tmp_path):
    operations=Operations(tmp_path/'corridas',popen=Mock())
    fake_thread=Mock()
    with patch.object(operations,'snapshot',return_value={'busy':False}),\
         patch('dualstack_panel.study_summary',return_value={'active':False}),\
         patch('dualstack_panel.collect_state',return_value={'runs':[]}),\
         patch('dualstack_panel.kernel_warning',return_value=''),\
         patch('dualstack_panel.threading.Thread',return_value=fake_thread),\
         patch.object(operations.restorations,'invalidate') as invalidate:
        job=operations.start('acceptance_all',{})
        assert job['action']=='acceptance_all' and job['options']=={}
        assert {call.args[0] for call in invalidate.call_args_list}=={'integrado','sucursal','comercial','mixto','reforzado'}
        fake_thread.start.assert_called_once()
    assert not job.get('manual_protocol')
