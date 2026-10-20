import json
import sys
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dualstack_panel import validate_options
from tesis.evaluacion_manual import STUDY_ID,ensure_empty_position,summary
from tesis.protocolo_manual import protocol


def read(path,default):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return default


def recorded(root,architecture,pair=1,status='complete',graph_hash='c'*64):
    key=f'{pair}-{architecture}'
    directory=root/key;directory.mkdir()
    context={'study_id':STUDY_ID,'pair':pair,'scenario':'integrado','architecture':architecture}
    graph={'engine':'langgraph','version':'1.2.12','graph':'novaflow-langgraph-1','source_sha256':graph_hash}
    roles=['generalist'] if architecture=='single' else ['network','credentials','applications','ipv6','fragmentation']
    configured=protocol()
    slot=next(slot for slot in configured['schedule'] if (slot['scenario'],slot['pair'],slot['architecture'])==('integrado',pair,architecture))
    report={'llm':{'provider':'openai','model':configured['model'],'known_tokens':1000,'total_tokens':1000,
        'usage_complete':True,'cost_estimate_usd':.01,'known_cost_estimate_usd':.01,
        'cost_limit_usd':2.,'configuration':{'cost_limit_usd':2.},
        'calls':[{'generation_sent':True,'status':'accepted','response_model':configured['model']}],
        'specialist_reviews':[{'role':role,'status':'accepted'} for role in roles]}}
    unique=slot['sequence']
    records={'request':{'bank':'empresa','token_budget':60000,'max_runtime_seconds':2400},'plan':[],
        'manifest':{'source_sha256':'a'*64,'auditor_source_sha256':'a'*64,'adapter_sha256':'b'*64,'orchestration':graph,'manual_context':context,
            'maximum_runtime_seconds':2400,
            'manual_protocol':{'protocol_sha256':configured['protocol_sha256'],'sequence':slot['sequence'],
                'restoration':{'id':f'{unique:032x}','activation_id':f'{unique+100:032x}'}},
            'scenario':{'id':'integrado','version':'fixture','source_sha256':'a'*64,
                        'fixture_sha256':'b'*64,'images':{'fixture':'sha256:'+'f'*64}}},
        'report':report,'evaluation':{'evidence_valid':True,'ground_truth_sha256':'d'*64,
         'TP':2,'FP':0,'FN':0,'TN':2,'unknown_negative_controls':0}}
    categories=['ipv4_services','ipv4_credentials','application_access','ipv6_ndp','ipv6_fragmentation']
    records['plan']=[{'task_id':f't{i}','agent_type':categories[i%5]} for i in range(32)]
    report['tasks']=[{'task_id':f't{i}','status':'completed' if i<19 else 'skipped',
        'reason_code':None if i<19 else 'task_budget_not_selected'} for i in range(32)]
    budget={'applied':True,'catalogue_size':32,'task_limit':19,'executed_tasks':19,
            'fraction':.6,'policy':'floor_60_percent_catalogue','admitted_task_ids':[f't{i}' for i in range(19)]}
    records['manifest']['detection_budget']=budget.copy();report['detection_budget']=budget.copy()
    records['evaluation']['negative_conditions_total']=2
    for name,value in records.items():(directory/(name+'.json')).write_text(json.dumps(value))
    return {'key':key,'manual_context':context,'orchestration':graph,'architecture':architecture,
        'bank':'empresa','mode':'live','status':status,'seconds':10 if architecture=='single' else 8,
        'tasks':[{'status':'completed'}],'llm':{'model':configured['model'],'known_tokens':1000,
            'usage_complete':True,'fallbacks':0},'started_at':'2026-10-18T00:00:00+00:00'}


def test_manual_context_requires_openai_review_and_bounded_pair():
    options={'scope':'empresa','authorization':'LAB-PROPIO','ia':'openai','expert_mode':True,
        'manual_context':{'study_id':STUDY_ID,'pair':1}}
    assert validate_options(options)['manual_context']==options['manual_context']
    for override in [{'ia':'none'},{'expert_mode':False},
        *[{'manual_context':{'study_id':STUDY_ID,'pair':v}} for v in [0,6,True,'1']],
        {'manual_context':{'study_id':'other','pair':1}}]:
        with pytest.raises(ValueError):validate_options({**options,**override})


def test_registered_start_rejects_changed_tokens_before_process_creation(tmp_path):
    from dualstack_panel import Operations
    from unittest.mock import Mock,patch
    root=tmp_path/'runs';root.mkdir()
    popen=Mock(side_effect=AssertionError('No debe crear un proceso de auditoría.'))
    operations=Operations(root,popen=popen)
    # La aceptación real del usuario puede estar activa en otro proceso; esta
    # prueba sólo verifica el rechazo del presupuesto antes de crear un hijo.
    with patch.object(operations,'snapshot',return_value={'busy':False}), \
         patch('dualstack_panel.study_summary',return_value={'active':False}), \
         patch('dualstack_panel.collect_state',return_value={'runs':[]}), \
         pytest.raises(ValueError,match='60.000 tokens'):
            operations.start('audit',{'scope':'empresa','authorization':'LAB-PROPIO','ia':'openai',
                'expert_mode':True,'tokens':30000,'manual_context':{'study_id':STUDY_ID,'pair':1}})
    popen.assert_not_called()


def test_only_complete_matching_langgraph_api_pair_has_metrics():
    with TemporaryDirectory() as folder:
        root=Path(folder);runs=[recorded(root,'single'),recorded(root,'multiagent')]
        result=summary(runs,root,read)
        assert result['planned_runs']==50 and result['planned_pairs']==25
        assert result['completed_runs']==2 and result['completed_pairs']==1
        assert result['scenarios'][0]['pairs'][0]['metrics']['TRTO_percent']==20
        assert result['scenarios'][0]['analysis']['ETV_ratio']['n']==1
        assert result['scenarios'][1]['analysis']['TRTO_percent']['n']==0
        # Cambiar la identidad real del grafo invalida la pareja aunque la API funcionó.
        path=root/'1-multiagent/manifest.json';manifest=read(path,{})
        manifest['orchestration']['source_sha256']='e'*64;path.write_text(json.dumps(manifest))
        invalid=summary(runs,root,read)
        assert invalid['completed_pairs']==0
        assert invalid['scenarios'][0]['pairs'][0]['metrics']['TRTO_percent'] is None


def test_failed_attempt_and_missing_review_remain_visible_without_kpi():
    with TemporaryDirectory() as folder:
        root=Path(folder);runs=[recorded(root,'single',status='partial'),recorded(root,'multiagent')]
        result=summary(runs,root,read)
        assert result['failed_runs']==1 and result['recorded_runs']==2
        assert result['completed_pairs']==0
        runs[0]['status']='complete'
        path=root/'1-single/report.json';report=read(path,{})
        report['llm']['specialist_reviews']=[];path.write_text(json.dumps(report))
        assert summary(runs,root,read)['completed_pairs']==0


@pytest.mark.parametrize('change',['different_model','missing_model','different_truth','unknown_controls','missing_bank','different_images','different_auditor'])
def test_api_success_does_not_hide_model_or_truth_incompatibility(change):
    with TemporaryDirectory() as folder:
        root=Path(folder);runs=[recorded(root,'single'),recorded(root,'multiagent')]
        if change in {'different_model','missing_model'}:
            path=root/'1-multiagent/report.json';value=read(path,{})
            value['llm']['calls'][0]['response_model']='different-real' if change=='different_model' else None
        elif change in {'different_truth','unknown_controls'}:
            path=root/'1-multiagent/evaluation.json';value=read(path,{})
            if change=='different_truth':value['ground_truth_sha256']='e'*64
            else:value['unknown_negative_controls']=1
        else:
            path=root/'1-multiagent/manifest.json';value=read(path,{})
            if change=='missing_bank':value['scenario'].pop('images')
            elif change=='different_images':value['scenario']['images']['fixture']='sha256:'+'e'*64
            else:value['auditor_source_sha256']='e'*64
        path.write_text(json.dumps(value))
        result=summary(runs,root,read)
        assert result['completed_pairs']==0
        assert result['scenarios'][0]['pairs'][0]['reasons']


def test_old_unregistered_runs_and_reruns_do_not_replace_first_attempt():
    with TemporaryDirectory() as folder:
        root=Path(folder);first=recorded(root,'single',status='partial')
        second=deepcopy(first);second['status']='complete';second['started_at']='2026-10-18T01:00:00+00:00'
        old=deepcopy(second);old.pop('manual_context')
        result=summary([old,second,first],root,read)
        assert result['total_attempts']==2 and result['recorded_runs']==1
        assert result['duplicate_attempts']==1 and result['failed_runs']==1
        (root/'panel_job.json').write_text(json.dumps({'options':{'scope':'empresa','architecture':'single',
            'manual_context':{'study_id':STUDY_ID,'pair':1}}}))
        with pytest.raises(ValueError,match='ya tiene un intento'):
            ensure_empty_position(root,{'architecture':'single','manual_context':{'study_id':STUDY_ID,'pair':1}})
        ensure_empty_position(root,{'architecture':'multiagent','manual_context':{'study_id':STUDY_ID,'pair':1}})


def test_reserved_position_without_manifest_is_visible_as_failed_attempt():
    with TemporaryDirectory() as folder:
        root=Path(folder);job=root/'panel'/'failed-start';job.mkdir(parents=True)
        (job/'panel_job.json').write_text(json.dumps({'name':'Falló antes del motor',
            'created_at':'2026-10-18T00:00:00+00:00','options':{'architecture':'single',
            'manual_context':{'study_id':STUDY_ID,'pair':1}}}))
        (job/'panel_status.json').write_text(json.dumps({'status':'failed'}))
        result=summary([],root,read)
        assert result['recorded_runs']==1 and result['failed_runs']==1
        assert result['scenarios'][0]['pairs'][0]['single']['status']=='interrupted'
        assert result['completed_pairs']==0


@pytest.mark.parametrize('change',[
    'missing_protocol','wrong_protocol','wrong_sequence','missing_restoration','missing_activation',
    'reused_restoration','reused_activation','wrong_model_both','wrong_tokens_both',
    'wrong_cost_cap_both','cost_exceeded','cost_unknown','cost_incomplete','cost_nan',
    'wrong_runtime_both','runtime_exceeded','unknown_policy_both','wrong_fraction_both',
    'manifest_execution_count',
])
def test_captured_protocol_and_restoration_gates_reject_incomplete_or_changed_records(tmp_path,change):
    runs=[recorded(tmp_path,'single'),recorded(tmp_path,'multiagent')]
    values=[]
    for run in runs:
        directory=tmp_path/run['key']
        values.append({name:read(directory/(name+'.json'),{}) for name in ['manifest','report','request']})
    first,second=values
    if change=='missing_protocol':second['manifest']['manual_protocol']=None
    elif change=='wrong_protocol':second['manifest']['manual_protocol']['protocol_sha256']='e'*64
    elif change=='wrong_sequence':second['manifest']['manual_protocol']['sequence']=50
    elif change=='missing_restoration':second['manifest']['manual_protocol']['restoration']={}
    elif change=='missing_activation':second['manifest']['manual_protocol']['restoration'].pop('activation_id')
    elif change in {'reused_restoration','reused_activation'}:
        key='id' if change=='reused_restoration' else 'activation_id'
        second['manifest']['manual_protocol']['restoration'][key]=first['manifest']['manual_protocol']['restoration'][key]
    elif change=='wrong_model_both':
        for run,value in zip(runs,values):
            run['llm']['model']=value['report']['llm']['model']='other-model'
            value['report']['llm']['calls'][0]['response_model']='other-model'
    elif change=='wrong_tokens_both':
        for value in values:value['request']['token_budget']=30000
    elif change=='wrong_cost_cap_both':
        for value in values:
            value['report']['llm']['cost_limit_usd']=3.
            value['report']['llm']['configuration']['cost_limit_usd']=3.
    elif change=='cost_exceeded':
        second['report']['llm'].update(cost_estimate_usd=2.01,known_cost_estimate_usd=2.01)
    elif change=='cost_unknown':second['report']['llm']['cost_estimate_usd']=None
    elif change=='cost_incomplete':second['report']['llm']['usage_complete']=False
    elif change=='cost_nan':
        second['report']['llm'].update(cost_estimate_usd=float('nan'),known_cost_estimate_usd=float('nan'))
    elif change=='wrong_runtime_both':
        for value in values:
            value['manifest']['maximum_runtime_seconds']=3600
            value['request']['max_runtime_seconds']=3600
    elif change=='runtime_exceeded':runs[1]['seconds']=2401
    elif change in {'unknown_policy_both','wrong_fraction_both'}:
        for value in values:
            for name in ['manifest','report']:
                value[name]['detection_budget'].update(**({'policy':'other'} if change=='unknown_policy_both' else {'fraction':.9}))
    elif change=='manifest_execution_count':second['manifest']['detection_budget']['executed_tasks']=999
    for run,value in zip(runs,values):
        for name,document in value.items():(tmp_path/run['key']/(name+'.json')).write_text(json.dumps(document))
    result=summary(runs,tmp_path,read)
    row=result['scenarios'][0]['pairs'][0]
    assert result['recorded_runs']==2 and result['completed_runs']==2
    assert result['completed_pairs']==0 and row['reasons']
    assert all(metric is None for metric in row['metrics'].values())
