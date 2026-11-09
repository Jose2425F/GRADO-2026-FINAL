"""El permiso se exige en las entradas y se vuelve a comprobar al despachar."""
from datetime import datetime, timedelta, timezone
from contextlib import closing
import json
from pathlib import Path
import sys
from unittest.mock import Mock, patch

import pytest

import laboratorio_personal as P
import puertos_personales as A
from aplicaciones_personales import ApplicationTask, configure_applications, execute_application
from autorizacion_personal import AuthorizationError, revoke_authorization
from auditoria.contracts import Target, Task, CredentialProfile
from auditoria.store import RunStore
from authorization_fixture import personal_authorization, scope_options


def config(**changes):
    return P.configuration({'ipv4':'127.0.0.1','ipv6':'::1','ports':[22,80],
                            'interface':'lo',**changes})


def options(**changes):
    return {'scope':'personal','name':'Prueba local','authorization':'LAB-PROPIO',
            'personal':config(),'creds':False,'applications':[],
            'architecture':'single','ia':'none','tokens':0,**changes}


@pytest.mark.parametrize('entry',[P.run,A.run_automatic])
def test_missing_permission_stops_before_routes_tools_or_provider(tmp_path,monkeypatch,entry):
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE',str(tmp_path/'private'/'missing.json'))
    value=options()
    if entry is A.run_automatic:
        value['personal']=P.configuration({'ipv4':'127.0.0.1','ipv6':'::1',
                                           'port_mode':'auto','interface':'lo'})
    with (patch.object(P,'resolve_targets') as routes,patch.object(P.subprocess,'run') as network,
            patch('auditoria.openai_provider.OpenAIScheduler') as provider):
        with pytest.raises(AuthorizationError):entry(value,tmp_path/'runs')
    routes.assert_not_called();network.assert_not_called();provider.assert_not_called()
    assert not (tmp_path/'runs').exists()


@pytest.mark.parametrize('address',['127.0.0.1','::1'])
def test_revocation_during_route_check_prevents_inventory_dispatch(tmp_path,address):
    value=options()
    target=Target(asset_id='local',address=address,interface='lo',ports=[80])
    task=P.InventoryTask(task_id='inventory',agent_type='ipv4_services',target=target)
    runner=Mock()
    with personal_authorization(value) as guard,closing(RunStore(tmp_path/'run','inventory')) as store:
        def route(*args,**kwargs):
            revoke_authorization(guard.path,guard.reference)
            return [target]
        with patch.object(P,'resolve_targets',side_effect=route):
            with pytest.raises(AuthorizationError,match='revocada'):
                P.execute_task(task,store,runner=runner,authorization=guard)
    runner.assert_not_called()


def test_direct_inventory_entry_without_guard_never_emits_a_probe(tmp_path):
    task=P.InventoryTask(task_id='inventory',agent_type='ipv4_services',
        target=Target(asset_id='local',address='127.0.0.1',interface='lo',ports=[80]))
    runner=Mock()
    with closing(RunStore(tmp_path/'run','inventory')) as store,patch.object(P,'resolve_targets') as route:
        with pytest.raises(AuthorizationError):P.execute_task(task,store,runner=runner)
    route.assert_not_called();runner.assert_not_called()


def test_http_authorization_rejection_is_not_swallowed_or_retried(tmp_path):
    app=configure_applications([{'name':'Aplicación local','ipv4':'127.0.0.1','ipv6':'::1',
        'port':80,'session':'sesion-fixture','scope_confirmed':True,
        'own_path':'/own','own_marker':'PROPIO-FIXTURE',
        'foreign_path':'/foreign','foreign_marker':'AJENO-FIXTURE'}],config())[0]
    value=options(applications=[app])
    task=ApplicationTask(task_id='web',target=Target(asset_id='app',address='127.0.0.1',
        interface='lo',ports=[80]),application_index=0)
    with (personal_authorization(value) as guard,closing(RunStore(tmp_path/'run','web')) as store,
            patch('aplicaciones_personales.load_session',return_value={}),
            patch('aplicaciones_personales.fetch',side_effect=AuthorizationError('authorization_revoked','revocada')) as fetch):
        with pytest.raises(AuthorizationError):execute_application(task,app,store,10**15,authorization=guard)
    assert fetch.call_count==1


def test_hydra_rechecks_permission_after_route_and_before_process(tmp_path,monkeypatch):
    from auditoria.agentes.agente_ipv4_credenciales import run_hydra
    value=options(creds=True)
    target=Target(asset_id='local',address='127.0.0.1',interface='lo',ports=[22],credential_ref='test')
    task=Task(task_id='credential',agent_type='ipv4_credentials',target=target,
              protocol='tcp',action_profile='hydra_ssh_single_v1',timeout_seconds=12)
    profile=CredentialProfile(ref='test',service='ssh',port=22,username='fixture',
                              password_env='CENTINELA_TEST_PASSWORD',condition='default_credential')
    monkeypatch.setenv('CENTINELA_TEST_PASSWORD','fixture-only-not-a-real-account')
    with personal_authorization(value) as guard,closing(RunStore(tmp_path/'run','credential')) as store:
        def revoke(*args,**kwargs):revoke_authorization(guard.path,guard.reference)
        with (patch('auditoria.agentes.agente_ipv4_credenciales.check_route',side_effect=revoke),
                patch('auditoria.agentes.agente_ipv4_credenciales.subprocess.run') as runner):
            with pytest.raises(AuthorizationError):
                run_hydra(task,profile,store,timeout_seconds=12,
                    authorize=lambda:P.require_authorization(guard,[target],feature='credentials'))
    runner.assert_not_called()


def test_operator_cli_issues_and_revokes_without_account_password_prompt(tmp_path,monkeypatch,capsys):
    import administrar_centinela as cli
    monkeypatch.delenv('CENTINELA_AUTHORIZATIONS_FILE',raising=False)
    scope=tmp_path/'scope.json';scope.write_text(json.dumps(scope_options(config())))
    data=tmp_path/'data'
    argv=['administrar_centinela.py','--data-dir',str(data),'autorizar-alcance','LAB-PROPIO',
          '--solicitud',str(scope),'--responsable','Operador de prueba',
          '--soporte','acta-fixture','--vence',(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()]
    with patch.object(sys,'argv',argv),patch.object(cli.getpass,'getpass') as password:
        cli.main()
    password.assert_not_called()
    assert json.loads(capsys.readouterr().out)['authorization']['reference']=='LAB-PROPIO'
    assert (data/'authorizations.json').stat().st_mode&0o777==0o600
    with patch.object(sys,'argv',['administrar_centinela.py','--data-dir',str(data),
                                'revocar-alcance','LAB-PROPIO']):cli.main()
    assert json.loads(capsys.readouterr().out)['authorization']['revoked'] is True


@pytest.mark.parametrize('payload',[{'interface':'lo'},
    {'interface':'lo','authorization':'LAB-PROPIO','registry_path':'/tmp/forged.json'}])
def test_http_discovery_cannot_omit_reference_or_select_a_registry(tmp_path,payload):
    import threading
    from urllib.error import HTTPError
    from urllib.request import Request,urlopen
    from dualstack_panel import Panel,make_server
    panel=Panel(tmp_path/'runs');server=make_server(panel,0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_port}'
    request=Request(origin+'/api/lab/personal/discover',json.dumps(payload).encode(),
        {'Content-Type':'application/json','Origin':origin,'X-CSRF-Token':panel.csrf},method='POST')
    try:
        with patch('descubrimiento_red.discover') as discover:
            with pytest.raises(HTTPError) as error:urlopen(request,timeout=3)
            assert error.value.code==400
            discover.assert_not_called()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)


def test_panel_preflight_rejects_unregistered_private_targets_before_starting_a_job(tmp_path,monkeypatch):
    from dualstack_panel import Operations
    monkeypatch.setenv('CENTINELA_AUTHORIZATIONS_FILE',str(tmp_path/'private'/'missing.json'))
    operations=Operations(tmp_path/'runs')
    with (patch.object(operations,'snapshot',return_value={'busy':False}),
          patch('dualstack_panel.study_summary',return_value={'active':False}),
          patch('dualstack_panel.collect_state',return_value={'runs':[]}),
          patch('dualstack_panel.resolve_targets') as routes,
          patch('dualstack_panel.threading.Thread') as thread):
        with pytest.raises(AuthorizationError):operations.start('personal_check',options(mode='live'))
    routes.assert_not_called();thread.assert_not_called();assert operations.jobs==[]
