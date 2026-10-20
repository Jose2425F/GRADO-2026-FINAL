'use strict';
// Presentación del alcance académico. No ejecuta herramientas ni consulta modelos.
let workspaceSignature='';
function renderWorkspace(){
 const value=state.thesis;if(!value)return;
 const signature=JSON.stringify([value, page,state.scenario_catalog,state.suite_acceptance,state.acceptance_five,state.suite_progress,state.manual_evaluation,state.runs]);if(signature===workspaceSignature)return;workspaceSignature=signature;
 renderScenarioCards();
 const icons=['v4','key','v6','<>'];$('thesis-capabilities').replaceChildren();
 value.capabilities.forEach((cap,index)=>{const card=el('article',undefined,'capability');card.append(el('span',icons[index],'cap-icon'),el('h3',cap.title),el('p',cap.detail),el('small',cap.tool.toUpperCase()));$('thesis-capabilities').append(card);});
 const manual=state.manual_evaluation,acceptance=state.acceptance_five;
 const gates=manual?[
  {title:'Código y alcance',state:'implemented',detail:'LangGraph, herramientas autorizadas, validadores, evidencia e informes. La aceptación funcional comprueba los cinco bancos.'},
  {title:'Aceptar los cinco laboratorios',state:acceptance?.accepted?'validated':acceptance?.status==='stopped'?'issues':'pending',detail:acceptance?.accepted?'Cinco catálogos completos comprobados sin IA y con cero tokens.':acceptance?.status==='invalidated'?'La aceptación anterior corresponde a otra versión. Repite la comprobación para esta versión.':`${acceptance?.completed_labs||0} de 5 aceptados para la versión actual. Consulta Laboratorio.`},
  {title:'Protocolo experimental',state:manual.protocol?.status==='frozen'?'implemented':'pending',detail:`${manual.planned_pairs||25} parejas y ${manual.planned_runs||50} posiciones, semilla ${manual.protocol?.seed||'pendiente'}. Mismo modelo y límites por arquitectura; restauración antes de cada posición.`},
  {title:'Corridas registradas',state:manual.failed_runs?'issues':manual.recorded_runs?'implemented':'pending',detail:`${manual.recorded_runs||0} intentos registrados; ${manual.failed_runs||0} con incidencias. Los fallos se conservan y no se reemplazan.`},
  {title:'Evaluación comparativa',state:manual.completed_pairs===manual.planned_pairs?'validated':'pending',detail:`${manual.completed_pairs||0} de ${manual.planned_pairs||25} parejas aptas. Resultados por laboratorio; las parejas incompatibles quedan excluidas.`},
  {title:'Documento y sustentación',state:'pending',detail:'Consolidar los resultados verificables y las incidencias de la evaluación en el documento y los anexos.'}
 ]:value.gates;
 $('thesis-gates').replaceChildren();gates.forEach((gate,index)=>{const card=el('article',undefined,'gate-card'),body=el('div');body.append(el('h3',gate.title),badge(['implemented','validated'].includes(gate.state)?'complete':gate.state==='issues'?'partial':'pending',gate.state==='validated'?'Comprobado':gate.state==='implemented'?'Implementado':gate.state==='issues'?'Con incidencias':'Pendiente'),el('p',gate.detail));card.append(el('span',String(index+1).padStart(2,'0'),'gate-number'),body);$('thesis-gates').append(card);});
 $('model-role-cards').replaceChildren();for(const role of value.roles){const card=el('article',undefined,'role-card');card.append(el('small',role.kind.toUpperCase()),el('h3',role.name),el('p',role.action));$('model-role-cards').append(card);}
 $('archive-count').textContent=`${num(value.archived_runs)} corridas archivadas`;$('archive-list').replaceChildren();
 for(const item of value.archives){const row=el('div',undefined,'archive-entry'),copy=el('div');copy.append(el('strong',item.label),el('p',`${num(item.runs_count)} registros · ${num(item.files_count)} archivos · ${new Date(item.created_at).toLocaleDateString('es')}`));const link=el('a','Consultar archivo ↗','button');link.href='/archive?id='+encodeURIComponent(item.id);link.target='_blank';link.rel='noopener';row.append(copy,link);$('archive-list').append(row);}
 if(!value.archives.length)$('archive-list').append(el('p','No hay archivos de corridas en este entorno.','field-note'));
 $('thesis-next-step').textContent=`${num(value.active_runs)} corridas en el historial activo. La nueva evaluación requiere cinco parejas por cada uno de los cinco laboratorios. Restaura y comprueba el banco antes de cada corrida.`;
 $('study-title').textContent='Nueva etapa · preparar y aceptar el banco';$('study-message').textContent=value.study.note;
 const accepted=state.acceptance_five?state.acceptance_five.accepted===true:value.readiness?.acceptance?.acceptance_passed===true;
 $('thesis-next-title').textContent=accepted?'Preparar las corridas manuales del nuevo estudio.':'Aceptar el laboratorio antes de medir.';
 if(accepted)$('study-title').textContent='Nueva etapa · congelar versión y preparar el piloto';
 $('lab-stage-badge').className='pill '+(accepted?'green':'amber');
 $('lab-stage-badge').textContent=accepted?'Aceptación funcional registrada':'Pendiente de aceptación final';
 $('study-cert').textContent=accepted?'Funcional comprobada':'Pendiente';
 const api=value.readiness?.api;$('api-contract-status').textContent=api?.status==='accepted'?`Contrato real de API comprobado con ${api.model}: ${num(api.generations)} revisiones y ${num(api.known_tokens)} tokens medidos sobre observaciones sintéticas de desarrollo. No es una auditoría ni parte de la muestra.`:'API '+(value.api_configured?'configurada. Su acceso y uso real se verifican durante una comprobación registrada.':'sin configurar. El panel no solicita claves ni llama al proveedor al abrirse.');$('study-calls').textContent=String(value.study.formal_runs);
 if(value.study.id){$('study-title').textContent='Estudio NovaFlow · '+({preparing:'Preparación',acceptance:'Aceptación sin IA',restoring:'Restauración',pilot:'Piloto con API',formal:'Evaluación con API',pilot_complete:'Piloto completado',complete:'Posiciones finalizadas',stopped:'Detenido',interrupted:'Interrumpido'}[value.study.status]||value.study.status);$('study-message').textContent=value.study.message;$('planned-runs').textContent=String(value.study.runs);$('planned-pairs').textContent=value.study.pairs+' parejas · una ejecución por arquitectura';$('thesis-next-title').textContent=value.study.active?'Piloto y evaluación en ejecución.':'Revisar el registro del estudio.';$('thesis-next-step').textContent=value.study.pilot_runs+' corridas piloto y '+value.study.formal_runs+' formales registradas. Gasto conocido acumulado (mínimo): USD '+Number(value.study.known_cost_total_usd??value.study.known_cost_usd??0).toFixed(4)+'. Comprometido con reservas: USD '+Number(value.study.budget_committed_usd??((value.study.known_cost_usd||0)+(value.study.held_usd||0))).toFixed(4)+' de '+Number(value.study.budget_usd||20).toFixed(2)+'.'+(value.study.predecessor_id?' Incluye la cohorte anterior y su consumo pendiente de conciliar.':'');}

 if(!$('thesis-kpi-scores')){const box=el('div',undefined,'kpi-scorecards');box.id='thesis-kpi-scores';document.querySelector('#page-kpi .stats').after(box);}
 $('thesis-kpi-scores').replaceChildren();
 for(const [title,goal,note] of [['TRTO','≥ 30 %','Reducción de tiempo frente al agente único.'],['IDE','≥ 20 %','Mejora de verdaderos positivos; requiere referencia.'],['ETV','≥ 1,10','Eficiencia de tokens por condición confirmada.']]){const stats=state.manual_evaluation?null:value.study.analysis?.metrics?.[{TRTO:'TRTO_percent',IDE:'IDE_percent',ETV:'ETV_ratio'}[title]],card=el('article',undefined,'kpi-score');const measured=Number.isFinite(stats?.mean);card.append(el('span',title),el('strong',measured?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(stats.mean)+(title==='ETV'?' ×':' %'):'—'),el('p','Meta '+goal+' · '+(stats?.n||0)+' parejas con indicador calculable'),el('small',note));$('thesis-kpi-scores').append(card);}
 if(state.manual_evaluation){
  $('thesis-next-title').textContent=accepted?'Continuar las posiciones del protocolo.':'Aceptar los cinco laboratorios antes de medir.';
  $('thesis-next-step').textContent=accepted?`${manual.recorded_runs||0} de 50 intentos registrados y ${manual.completed_pairs||0} de 25 parejas aptas. Sigue Preparar siguiente posición en Evaluación y KPI; restaura y comprueba antes de cada corrida.`:'En Laboratorio pulsa Aceptar los cinco laboratorios sin IA. Los cambios del motor requieren comprobar de nuevo la versión actual; los resultados anteriores se conservan.';
  $('architecture-details').hidden=true;document.querySelector('.historical-kpi').hidden=true;
  document.querySelector('.archive-card').hidden=!(value.archives||[]).length;
 }
 if(typeof renderManualPlan==='function')renderManualPlan();
} 
function chooseBench(scope){
 document.querySelector(`input[name=scope][value="${scope}"]`).checked=true;
 updateOptions();showSetupStep(1);renderState();showPage('new');
}
$('launch-thesis').addEventListener('click',()=>chooseBench('empresa'));
$('launch-personal').addEventListener('click',()=>chooseBench('personal'));
$('launch-v2').addEventListener('click',()=>chooseBench('v2'));
$('launch-applications').addEventListener('click',()=>{chooseBench('personal');showSetupStep(2);$('web-settings').open=true;});
for(const button of document.querySelectorAll('[data-own-lab]'))button.addEventListener('click',()=>chooseBench('personal'));
renderWorkspace();

function renderScenarioCards(){
 if(!$('suite-labs')){const section=el('section',undefined,'card');section.id='suite-labs';section.style.marginTop='24px';section.append(el('h2','Cuatro escenarios adicionales'),el('p','Casos y referencias separados. La dificultad describe carga y mezcla de controles; no añade tipos de explotación. Activa uno por vez.','field-note'));const progress=el('p',undefined,'notice');progress.id='suite-live-note';const grid=el('div',undefined,'role-grid');grid.id='suite-lab-grid';section.append(progress,grid);$('page-lab').append(section);}
 const accepted=state.acceptance_five||state.suite_acceptance||{},active=state.suite_progress?.active||state.acceptance_five?.active;
 $('suite-live-note').textContent=active?'Aceptación u operación de escenarios en curso. Cero API durante la aceptación.':accepted.status==='accepted'?'Los cuatro escenarios aprobaron su aceptación funcional sin IA. Falta preparar y congelar la evaluación con API.':accepted.status==='running'?'La aceptación aún no tiene cierre confirmado; consulta el estado antes de auditar.':accepted.status==='stopped'?'Aceptación detenida con incidencias: revisar antes de medir KPI.':'Escenarios preparados; la aceptación funcional se registra por separado.';
 $('suite-lab-grid').replaceChildren();
 for(const item of state.scenario_catalog||[]){const card=el('article',undefined,'suite-card card'),check=(accepted.scenarios||[]).find(x=>x.id===item.id);card.append(el('small',item.difficulty),el('h3',item.name),el('p',`${item.targets} objetivos · ${item.tasks} tareas · ${item.containers} contenedores`),el('p',item.detail));if(check)card.append(el('p',check.status==='accepted'?`Aceptación: ${check.evaluation.tasks_valid}/${check.expected_tasks} válidas; TP ${check.evaluation.TP}, FP ${check.evaluation.FP}, FN ${check.evaluation.FN}, TN ${check.evaluation.TN}.`:check.status==='running'?'Aceptación en curso, sin IA.':'Estado de aceptación: '+check.status,'field-note'));const button=el('button','Configurar este escenario','button');button.type='button';button.addEventListener('click',()=>{chooseBench('empresa');$('scenario').value=item.id;updateOptions();});card.append(button);$('suite-lab-grid').append(card);}
}
