'use strict';
const $ = id => document.getElementById(id);
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const form = $('audit-form');
let state = {runs:[],jobs:[],lab:{status:'unknown'},busy:false};
let selectedKey = null, detail = null, page = 'new', tab = 'findings', connected = false;
let detailFresh = false;
let posting = false, followJob = null, pendingAudit = false, previousKeys = new Set();
let eventBaseline = null, eventRun = null, recordedUntil = 0, pickerSignature = '';
let consolePaused=false, consoleSignature='', consoleRun=null;
let openCards = new Set(), cardsRun = null, personalCheckKey=null, personalChecking=null;
const statuses = {running:'En curso',pending:'Pendiente',complete:'Finalizada',partial:'Con incidencias',interrupted:'Interrumpida',dry_run:'Simulación',completed:'Completada',completed_no_findings:'Sin hallazgos',failed:'Fallida',blocked:'Bloqueada',cancelled:'Cancelada',skipped:'Omitida'};
const severities = {critical:'Crítica',high:'Alta',medium:'Media',low:'Baja',unknown:'Sin clasificación'};
const num = value => Number.isFinite(value) ? new Intl.NumberFormat('es').format(value) : '—';
const time = value => Number.isFinite(value) ? value < 60 ? `${Math.floor(value)} s` : `${Math.floor(value/60)} min ${Math.floor(value%60)} s` : '—';
function el(tag, text, className) { const node = document.createElement(tag); if(text !== undefined && text !== null) node.textContent = text; if(className) node.className = className; return node; }
function badge(status, label) { const kind = ['complete','completed','completed_no_findings','ready'].includes(status) ? 'green' : ['failed','interrupted','error'].includes(status) ? 'red' : ['partial','blocked','cancelled','dry_run','preliminary','stopping'].includes(status) ? 'amber' : 'subtle'; return el('span',label || statuses[status] || status,'pill '+kind); }
function empty(title, description) { const node = el('div',undefined,'empty-state'); node.append(el('strong',title),el('p',description)); return node; }
function showError(message) { $('error-banner').textContent = message; $('error-banner').hidden = false; }
function clearError() { $('error-banner').hidden = true; }
let setupStep=1;
function renderSetupHelp(){
  const scope=options().scope, personal=scope==='personal', empresa=scope==='empresa';
  const future=!empresa;
  $('scope-options').hidden=!future;$('scope-options').dataset.exploratory=String(future);
  $('audit-track-note').textContent=future?'Desarrollo futuro · práctica exploratoria, separada de la muestra final.':'Nueva evaluación manual. Cada corrida se registra con su laboratorio, pareja y arquitectura.';
  document.querySelector('#page-new .intro-panel .eyebrow').textContent=future?'DESARROLLO FUTURO / PRÁCTICA EXPLORATORIA':'TESIS / PREPARAR AUDITORÍA';
  $('setup-description').textContent=personal?'Evalúa tus equipos por IP o rango. El inventario es automático; las pruebas de acceso y aplicaciones se activan en el siguiente paso.':empresa?'Elige uno de los cinco laboratorios y el número de pareja. Después selecciona arquitectura, comprueba el banco e inicia tú la corrida.':'Reproduce el catálogo fijo del banco v2 histórico. Sus resultados se conservan separados del banco de tesis.';
  const guides=personal?{
    1:['Una red, un alcance claro.','Introduce las direcciones autorizadas. IPv4 admite rangos; IPv6 requiere una lista de direcciones conocidas.'],
    2:['Elige qué comprobar.','El inventario está incluido. Activa credenciales o configura recursos web si preparaste esos escenarios.'],
    3:['Revisa antes de iniciar.','Comprueba rutas e interfaz. El presupuesto de 240 segundos es compartido: los equipos pendientes no cuentan como evaluados.']
  }:{
    1:['Un banco con objetivos conocidos.',empresa?`${scenarioInfo()?.name||'NovaFlow'} tiene ${scenarioInfo()?.targets||10} objetivos definidos. Aquí no debes introducir IP; para tus equipos usa Mi red por IP.`:'El banco histórico tiene 6 objetivos fijos. Para direcciones propias elige Mi red por IP.'],
    2:['Un catálogo reproducible.',empresa?`El catálogo contiene ${scenarioInfo()?.tasks||32} tareas sobre servicios, credenciales, aplicaciones y protocolos IPv6. La IA prioriza dentro del límite de esta corrida.`:'Se ejecutan las 22 tareas del catálogo v2. No se amplía a otros equipos desde este banco.'],
    3:['Comprueba el estado actual.','Una aceptación anterior no garantiza disponibilidad ahora. Comprueba el banco y revisa agentes, IA y presupuesto.']
  };
  $('setup-guide-title').textContent=guides[setupStep][0];$('setup-guide-text').textContent=guides[setupStep][1];
}
function showSetupStep(next,validate=false){
  if(validate&&next>setupStep){
    if(setupStep===1&&options().scope==='personal'&&!$('personal-ipv4').value.trim()&&!$('personal-ipv6').value.trim()){showError('Indica una IPv4, un rango o una IPv6 para tu laboratorio.');$('personal-ipv4').focus();return;}
    if(setupStep===2&&!validateApplicationSelection())return;
  }
  const changed=setupStep!==next;setupStep=next;clearError();
  for(const number of [1,2,3])$('setup-step-'+number).hidden=number!==next;
  for(const node of document.querySelectorAll('[data-setup-step]')){const n=Number(node.dataset.setupStep);node.classList.toggle('is-complete',n<next);if(n===next)node.setAttribute('aria-current','step');else node.removeAttribute('aria-current');}
  renderSetupHelp();$('readiness-card').hidden=next!==3;$('review-card').hidden=next!==3;$('start-audit').hidden=next!==3;updateButtons();
  if(changed&&page==='new')document.querySelector('.wizard-nav').scrollIntoView({block:'start'});
}
for(const node of document.querySelectorAll('[data-setup-step]'))node.addEventListener('click',()=>showSetupStep(Number(node.dataset.setupStep),true));
for(const node of document.querySelectorAll('[data-step-next]'))node.addEventListener('click',()=>showSetupStep(Number(node.dataset.stepNext),true));
for(const node of document.querySelectorAll('[data-step-back]'))node.addEventListener('click',()=>showSetupStep(Number(node.dataset.stepBack)));
function options(mode='live') { const data = new FormData(form);const value={name:data.get('name'),authorization:data.get('authorization'),architecture:data.get('architecture'),ia:data.get('ia'),tokens:Number(data.get('tokens')),mode,scope:data.get('scope')||'v2'};if(value.scope==='empresa'&&$('scenario').value)value.scenario=$('scenario').value;if(value.scope==='personal'){value.personal={ipv4:data.get('ipv4'),ipv6:data.get('ipv6'),port_mode:'auto',interface:data.get('interface')};value.creds=$('personal-creds').checked;if($('personal-web').checked)value.applications=applicationOptions();}if(value.ia==='openai'&&value.scope!=='v2'&&$('expert-mode').checked)value.expert_mode=true;if(value.scope==='empresa'&&$('manual-evaluation').checked)value.manual_context={study_id:manualStudyId(),pair:Number($('manual-pair').value)};return value; }
function renderAcceptanceFive(){
  const receipt=state.acceptance_five||{},accepted=receipt.accepted===true,active=receipt.active===true;
  const labels={pending:'Pendiente',running:'En curso · sin IA',accepted:'Cinco laboratorios aceptados',stopped:'Detenida · revisar incidencia',interrupted:'Interrumpida · revisar',invalidated:'Repetir aceptación de esta versión'};
  $('acceptance-five-status').textContent=accepted?'Aceptación completa · 5/5 laboratorios':labels[receipt.status]||'Pendiente';$('acceptance-five-status').className='pill '+(accepted?'green':active?'subtle':'amber');
  $('acceptance-five-progress').textContent=`${receipt.completed_labs||0} / 5 laboratorios aceptados · ${num(receipt.known_tokens??0)} tokens`;
  $('acceptance-five-note').textContent=state.execution_guard?.blocked?state.execution_guard.message:accepted?'Aceptación completa de los cinco bancos, sin IA. Ahora sigue el orden del protocolo en Evaluación y KPI para tus corridas registradas.':active?'Aceptación en curso. Espera a que terminen los cinco bancos; puedes revisar los estados de abajo. No inicies otras auditorías ni operaciones Docker.':['stopped','interrupted','invalidated'].includes(receipt.status)?'La aceptación no está completa o corresponde a otra versión. Revisa la incidencia y el estado del kernel antes de repetirla.':'Después de reiniciar Kali, usa este botón y espera el recibo de los cinco laboratorios. Esta aceptación no ocupa posiciones de las 50 corridas con IA.';
  const failure=(receipt.scenarios||[]).find(row=>row.status==='failed'),reasons={lab_images_missing:'Faltan imágenes locales del laboratorio. Prepara las imágenes antes de repetir la aceptación; esta comprobación no las descarga ni reconstruye.',restoration_failed:'No se pudo restaurar el laboratorio. Revisa Docker y las imágenes locales.',preflight_failed:'La comprobación de disponibilidad no aprobó. Revisa los servicios, las rutas y la configuración del banco.',cleanup_failed:'No se pudo cerrar el banco al finalizar. Revisa Docker antes de activar otro laboratorio.',operation_timeout:'Una operación superó su tiempo máximo. Revisa la fase indicada antes de repetirla.',kernel_failure:'El kernel registró un fallo. Reinicia Kali y repite la aceptación.',execution_failed:'La ejecución del catálogo se detuvo. Revisa el registro local para identificar la prueba afectada.',acceptance_evidence_incomplete:'El catálogo no terminó con toda su evidencia válida. Revisa las pruebas funcionales de este laboratorio.',report_not_unique:'No se produjo un informe completo de aceptación.'};
  const failurePhase=({restoring:'preparación y restauración',checking:'comprobación de disponibilidad',running:'ejecución del catálogo',closing:'cierre del laboratorio',preparing:'preparación'})[failure?.failure_phase||failure?.phase]||'sin confirmar';
  if(failure&&!state.execution_guard?.blocked)$('acceptance-five-note').textContent=`${failure.name||manualScenarioName(failure.id)}: ${reasons[failure.reason]||'La aceptación se detuvo.'} Fase: ${failurePhase}. Registro local: piloto_kali/prototipo/.lab-suite/acceptance-five.log`;
  $('acceptance-five-labs').replaceChildren();
  const phases={pending:'Pendiente',restoring:'Preparando y restaurando',checking:'Comprobando disponibilidad',running:'Ejecutando catálogo completo',closing:'Cerrando el laboratorio',finished:'Finalizada',stopped:'Detenida'};
  for(const lab of manualLaboratories()){const measured=(receipt.scenarios||[]).find(row=>row.id===lab.id),row=el('article',undefined,'acceptance-lab-row'),copy=el('div');copy.append(el('strong',measured?.name||lab.name),el('small',measured?.expected_tasks?`${measured.evaluation?.tasks_valid??0} / ${measured.expected_tasks} tareas válidas · ${phases[measured.phase]||'Pendiente'}`:'Catálogo completo · pendiente'));row.append(copy,badge(measured?.status==='accepted'&&receipt.status!=='invalidated'?'complete':measured?.status==='failed'?'failed':'pending',measured?.status==='accepted'&&receipt.status!=='invalidated'?'Aceptado':measured?.status==='failed'?'Revisar incidencia':phases[measured?.phase]||'Pendiente'));$('acceptance-five-labs').append(row);}
}
function manualStudyId(){return state.manual_evaluation?.study_id||'langgraph_manual_20261018';}
function manualContextEnabled(){return options().scope==='empresa'&&$('manual-evaluation').checked;}
function manualTaskLimit(scenario=options().scenario||'integrado'){const protocol=state.manual_evaluation?.protocol;return protocol?.task_limits?.[scenario]??protocol?.task_limit??null;}
function manualProtocolFrozen(){const protocol=state.manual_evaluation?.protocol,limit=manualTaskLimit();return protocol?.status==='frozen'&&protocol.task_limit_status!=='pending_confirmation'&&Number.isInteger(limit)&&limit>0;}
function manualConfigurationError(){
  if(!manualContextEnabled())return '';
  const manual=state.manual_evaluation||{},protocol=manual.protocol;
  if(!manualProtocolFrozen())return manual.message||'El protocolo está pendiente de confirmación. El límite propuesto no se aplica y no se puede registrar una auditoría todavía.';
  if(options().ia!=='openai')return 'La evaluación manual requiere OpenAI. Para comprobar sin IA, desactiva Registrar en la nueva evaluación.';
  if(!$('expert-mode').checked)return 'Activa la revisión LLM para conservar la misma configuración en agente único y multiagente.';
  if(Number.isInteger(protocol.tokens)&&options().tokens!==protocol.tokens)return `Usa el límite de ${num(protocol.tokens)} tokens definido en el protocolo congelado.`;
  if(state.acceptance_five?.accepted!==true)return 'Completa la aceptación sin IA de los cinco laboratorios en Laboratorio antes de registrar las corridas.';
  if(manual.ready===false)return manual.message||'La nueva evaluación todavía no está preparada en este equipo.';
  const value=options(),entry=manual.scenarios?.find(item=>item.id===(value.scenario||'integrado'))?.pairs?.find(item=>item.pair===value.manual_context.pair)?.[value.architecture];
  if(entry)return 'Esta posición ya tiene un intento registrado. Consérvalo aunque haya fallado; para practicar de nuevo, desactiva Registrar en la nueva evaluación.';
  const next=nextManualPosition();if(!next)return 'No hay una posición pendiente habilitada en el protocolo.';if((value.scenario||'integrado')!==next.scenario||value.manual_context.pair!==next.pair||value.architecture!==next.architecture)return 'La selección no coincide con la siguiente posición del protocolo. Pulsa Usar siguiente posición del protocolo para cargarla.';
  if(currentLab().restored!==true)return 'Pulsa Restaurar y después Comprobar antes de esta corrida registrada. La restauración debe ser nueva y no haberse usado.';
  return '';
}
function manualArchitectureName(value){return value==='single'?'Agente único':value==='multiagent'?'Multiagente':'Sin definir';}
function manualScenarioName(value){return manualLaboratories().find(item=>item.id===value)?.name||value;}
function nextManualPosition(){return state.manual_evaluation?.next_slot||null;}
function renderManualProtocol(){
  const manual=state.manual_evaluation||{},protocol=manual.protocol||{},frozen=manualProtocolFrozen(),next=nextManualPosition();
  $('manual-protocol-status').textContent=frozen?'Protocolo congelado':'Pendiente de confirmación';$('manual-protocol-status').className='pill '+(frozen?'green':'amber');
  $('manual-protocol-message').textContent=frozen?'El protocolo está congelado. Sigue el orden registrado y restaura el laboratorio antes de cada posición.':manual.message||'La propuesta no está aplicada. El registro de corridas permanece bloqueado hasta confirmar el límite y congelar el protocolo.';
  $('manual-protocol-values').replaceChildren();
  const values=[['Modelo',protocol.model||'Por definir'],['Tokens por corrida',Number.isInteger(protocol.tokens)?num(protocol.tokens):'Por definir'],['Límite de tareas',frozen?protocol.task_limits?'Por laboratorio · ver detalle':num(protocol.task_limit)+' tareas':protocol.proposed_task_limits?'60 % propuesto · sin aplicar':Number.isInteger(protocol.proposed_task_limit)?num(protocol.proposed_task_limit)+' tareas propuestas · sin aplicar':'Pendiente de confirmación'],['Semilla del orden',protocol.seed??'Por definir'],['Tope de costo por corrida',Number.isFinite(protocol.max_cost_usd)?'USD '+new Intl.NumberFormat('es',{minimumFractionDigits:2,maximumFractionDigits:2}).format(protocol.max_cost_usd):'Por definir'],['Estado del registro',frozen?'Habilitable tras restaurar y comprobar':'Bloqueado · falta confirmación']];
  for(const [label,text] of values){const item=el('div');item.append(el('dt',label),el('dd',text));$('manual-protocol-values').append(item);}
  $('manual-cost-limit').textContent=Number.isFinite(protocol.max_cost_usd)?'USD '+new Intl.NumberFormat('es',{minimumFractionDigits:2,maximumFractionDigits:2}).format(protocol.max_cost_usd):'Por definir';
  $('manual-protocol-limits').replaceChildren();
  const limits=frozen?protocol.task_limits:protocol.proposed_task_limits;
  if(limits){$('manual-protocol-limits').append(el('strong',frozen?'Límites congelados por laboratorio':'Propuesta del 60 % del catálogo · todavía sin aplicar'));const list=el('ul');for(const lab of manualLaboratories()){const count=limits[lab.id],catalog=lab.id==='integrado'?32:(state.scenario_catalog||[]).find(item=>item.id===lab.id)?.tasks;if(Number.isInteger(count))list.append(el('li',`${lab.name}: ${count} de ${catalog??'—'} tareas${frozen?'':' · propuesta'}`));}$('manual-protocol-limits').append(list);if(!frozen)$('manual-protocol-limits').append(el('p',typeof protocol.configuration_statusdetail==='string'?protocol.configuration_statusdetail:'El 60 % no impide cubrir todos los positivos; está pendiente decidir el diseño. Los límites continúan sin aplicar.','field-note'));else if(protocol.structural_validation?.satisfied===false)$('manual-protocol-limits').append(el('p','El límite se aprobó como presupuesto parcial, aunque sigue siendo estructuralmente posible cubrir todos los positivos. Los resultados dependerán de la selección y la ejecución reales.','field-note'));}
  $('manual-protocol-hash').textContent=protocol.sha256||'Sin congelar';
  $('manual-next-position').textContent=next?`${frozen?'Siguiente posición':'Posición propuesta, aún bloqueada'} ${next.sequence||next.slot}/50: ${manualScenarioName(next.scenario)} · pareja ${next.pair}/5 · ${manualArchitectureName(next.architecture)}.`:frozen?'No hay otra posición pendiente en el protocolo.':'La siguiente posición se habilitará después de confirmar y congelar el protocolo.';
  const rows=new Map();for(const entry of protocol.schedule||[]){const key=entry.scenario+'/'+entry.pair;if(!rows.has(key))rows.set(key,[]);rows.get(key).push(entry);}
  $('manual-protocol-order').replaceChildren();
  for(const entries of [...rows.values()].sort((a,b)=>(a[0].sequence||a[0].slot)-(b[0].sequence||b[0].slot))){entries.sort((a,b)=>(a.sequence||a.slot)-(b.sequence||b.slot));const first=entries[0],row=el('tr');if(next&&entries.some(entry=>(entry.sequence||entry.slot)===(next.sequence||next.slot)))row.className='is-next';for(const text of [manualScenarioName(first.scenario),String(first.pair),manualArchitectureName(first.architecture),manualArchitectureName(entries[1]?.architecture),entries.map(entry=>String(entry.sequence||entry.slot)).join(' y ')])row.append(el('td',text));$('manual-protocol-order').append(row);}
  if(!rows.size){const row=el('tr'),cell=el('td','El orden todavía no está disponible.');cell.colSpan=5;row.append(cell);$('manual-protocol-order').append(row);}
}
function prepareNextManualPosition(){
  const next=nextManualPosition();if(!manualProtocolFrozen()||!next)return;
  form.querySelector('input[name=scope][value=empresa]').checked=true;$('manual-evaluation').checked=true;
  $('scenario').value=next.scenario==='integrado'?'':next.scenario;$('manual-pair').value=String(next.pair);form.querySelector(`input[name=architecture][value="${next.architecture}"]`).checked=true;
  updateOptions();showSetupStep(1);renderState();showPage('new');
}
function renderManualControls(){
  const enabled=manualContextEnabled(),pair=Number($('manual-pair').value),scenario=scenarioInfo();
  $('manual-context-fields').hidden=options().scope!=='empresa';$('manual-pair-fields').hidden=!enabled;$('manual-pair').disabled=!enabled;
  const protocol=state.manual_evaluation?.protocol,schedule=(protocol?.schedule||[]).filter(item=>item.scenario===(options().scenario||'integrado')&&item.pair===pair).sort((a,b)=>(a.sequence||a.slot)-(b.sequence||b.slot));$('manual-order-note').textContent=schedule.length?'Orden del protocolo para esta pareja: '+schedule.map(item=>manualArchitectureName(item.architecture)+' (posición '+(item.sequence||item.slot)+')').join(' → ')+'.':'El orden debe proceder del protocolo congelado; no se deduce del número de pareja.';
  const proposed=protocol?.proposed_task_limits?.[options().scenario||'integrado'];
  $('manual-limit-preview').textContent=manualProtocolFrozen()?`Límite congelado para este laboratorio: ${manualTaskLimit()} tareas.`:Number.isInteger(proposed)?`Propuesta para este laboratorio: ${proposed} de ${scenario?.tasks||32} tareas (60 % redondeado hacia abajo). Sigue sin aplicarse; el registro permanece bloqueado.`:'';
  $('review-manual-row').hidden=!enabled;$('review-manual').textContent=`${scenario?.name||'Banco integrado'} · pareja ${pair}/5`;
  $('manual-restoration-note').hidden=!enabled;
  $('manual-practice-budget-note').hidden=options().scope!=='empresa';
  $('manual-context-note').textContent=state.manual_evaluation?.message||'Se conserva el primer intento de cada arquitectura y pareja, incluso si falla. Para repetir como práctica, desactiva el registro. No inicia corridas automáticamente.';
}
function runOrchestration(run){return run?.orchestration||null;}
function langGraphConfirmed(run){return runOrchestration(run)?.engine==='langgraph';}
function renderRunProvenance(){
  const run=detail?.run,proof=runOrchestration(run),confirmed=langGraphConfirmed(run),context=run?.manual_context;
  $('run-orchestration').hidden=!proof;$('run-orchestration').textContent=confirmed?'LangGraph confirmado'+(proof.version?' · '+proof.version:''):'Motor registrado: '+(proof?.engine||'sin identificar');$('run-orchestration').className='pill '+(confirmed?'green':'subtle');
  $('run-manual-context').hidden=!context;$('run-manual-context').textContent=context?`Evaluación manual · pareja ${context.pair}/5 · ${run.architecture==='single'?'Agente único':'Multiagente'}`:'';
}
function manualLaboratories(){return [{id:'integrado',name:'Banco integrado'},...(state.scenario_catalog||[]).map(item=>({id:item.id,name:item.name}))];}
function renderManualPlan(){
  renderManualProtocol();
  const manual=state.manual_evaluation||{},runs=state.runs.filter(run=>run.manual_context?.study_id===manualStudyId()),labs=manualLaboratories();
  let completed=0;$('manual-run-matrix').replaceChildren();
  for(const lab of labs){
    const measured=(manual.scenarios||[]).find(item=>item.id===lab.id),row=el('tr');row.append(el('th',measured?.label||lab.name));
    for(let pair=1;pair<=5;pair++){
      const record=measured?.pairs?.find(item=>item.pair===pair),cell=el('td'),slot=el('div',undefined,'manual-slot');
      for(const architecture of ['single','multiagent']){
        const attempts=runs.filter(run=>run.manual_context.pair===pair&&(run.manual_context.scenario||run.scenario||'integrado')===lab.id&&run.architecture===architecture),recorded=record?.[architecture],closed=recorded?recorded.status==='complete':attempts[0]?.status==='complete'&&langGraphConfirmed(attempts[0]),active=recorded?['running','pending'].includes(recorded.status):['running','pending'].includes(attempts[0]?.status),issue=Boolean(recorded||attempts.length)&&!closed&&!active;
        if(closed)completed++;
        const label=(architecture==='single'?'U: ':'M: ')+(closed?'completada':active?'en curso':issue?'revisar intento':'pendiente');slot.append(el('span',label,closed?'slot-complete':active?'slot-running':issue?'slot-issue':''));
      }
      if(record?.complete)slot.append(el('strong','Pareja apta','slot-complete'));
      else if(record?.reasons?.length){const issues=el('details',undefined,'manual-pair-issues');issues.append(el('summary','Revisar pareja'));const list=el('ul');for(const reason of record.reasons)list.append(el('li',reason));issues.append(list);slot.append(issues);}
      cell.append(slot);row.append(cell);
    }
    $('manual-run-matrix').append(row);
  }
  $('manual-kpi-results').replaceChildren();
  for(const lab of labs){
    const measured=(manual.scenarios||[]).find(item=>item.id===lab.id),row=el('tr');row.append(el('th',measured?.label||lab.name),el('td',`${measured?.completed_pairs||0} / 5`));
    for(const [key,suffix] of [['TRTO_percent',' %'],['IDE_percent',' %'],['ETV_ratio',' ×']]){const metric=measured?.analysis?.[key],cell=el('td');cell.append(el('strong',metric?.n>0&&Number.isFinite(metric.mean)?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(metric.mean)+suffix:'Pendiente'));if(metric?.n>0)cell.append(el('small',`${metric.n} parejas`));row.append(cell);}
    $('manual-kpi-results').append(row);
  }
  const planned=manual.planned_runs||labs.length*10,pairs=manual.planned_pairs||labs.length*5;
  $('manual-plan-count').textContent=Number.isInteger(manual.completed_pairs)?`${manual.completed_pairs} / ${pairs} parejas aptas`:`${completed} / ${planned} posiciones completadas`;
  $('manual-plan-note').textContent=`${manual.total_attempts??runs.length} intentos registrados${Number.isInteger(manual.failed_runs)?' · '+manual.failed_runs+' con incidencias':''}. La aptitud de cada pareja se determina desde su evidencia y configuración; conserva todos los intentos.`;
  $('planned-runs').textContent=String(planned);$('planned-pairs').textContent=`${pairs} parejas · 5 por laboratorio`;
  $('study-title').textContent='Evaluación manual con LangGraph';$('study-message').textContent=manual.message||manual.note||'Tú inicias cada corrida desde Preparar auditoría. Conserva el mismo catálogo, modelo y presupuesto dentro de cada pareja.';$('study-calls').textContent=String(manual.recorded_runs??runs.length);
}
let applicationSequence=0;
function validateApplicationSelection(){if(options().scope==='personal'&&$('personal-web').checked&&!$('web-applications').children.length){showError('Añade al menos una aplicación o desactiva las pruebas web.');return false;}return true;}
function applicationOptions() {
  return [...$('web-applications').children].map(card=>{
    const app={};for(const input of card.querySelectorAll('[data-field]'))app[input.dataset.field]=input.type==='checkbox'?input.checked:input.dataset.field==='port'?Number(input.value):input.value.trim();return app;
  });
}
function addApplication() {
  if($('web-applications').children.length>=16){showError('Máximo 16 aplicaciones por corrida.');return;}
  const card=el('section',undefined,'card');card.append(el('h3','Aplicación y recursos de prueba'));const index=++applicationSequence;
  const field=(key,label,placeholder='',value='')=>{const id='web-app-'+index+'-'+key,input=el('input');input.id=id;input.dataset.field=key;input.value=value;input.placeholder=placeholder;input.maxLength=key.endsWith('_path')?1024:key.endsWith('_marker')?160:60;input.autocomplete='off';const caption=el('label',label);caption.htmlFor=id;card.append(caption,input);return input;};
  field('name','Nombre de la aplicación','Portal de documentos','Aplicación '+index);
  const ips=el('div',undefined,'option-grid');card.append(ips);
  for(const [key,label,placeholder] of [['ipv4','IPv4 de esta aplicación','192.168.56.20'],['ipv6','IPv6 del mismo servicio · opcional','fd00:56::20']]){const box=el('div');const input=field(key,label,placeholder);box.append(input.previousSibling,input);ips.append(box);}
  field('port','Puerto de la aplicación · se verifica al descubrir','8080','8080').type='number';
  const scheme=el('select');scheme.dataset.field='scheme';scheme.id='web-app-'+index+'-scheme';for(const value of ['http','https']){const o=el('option',value.toUpperCase());o.value=value;scheme.append(o);}const schemeLabel=el('label','Protocolo');schemeLabel.htmlFor=scheme.id;card.append(schemeLabel,scheme);
  field('session','Nombre de la sesión guardada','cuenta-prueba','cuenta-prueba');
  card.append(el('p','Control obligatorio: un documento privado que la cuenta de prueba sí puede leer. Sin sesión debe devolver 401 o 403.','field-note'));
  field('own_path','Ruta del documento propio','/documentos/10');field('own_marker','Texto único dentro del documento propio','DOCUMENTO_ANA_2026');
  for(const [title,prefix,path,marker] of [['Acceso a un documento ajeno','foreign','/documentos/20','DOCUMENTO_PEDRO_2026'],['Descarga fuera del directorio permitido','download','/descargar?archivo=../interno/canario.txt','ARCHIVO_INTERNO_2026'],['Permisos administrativos entre IPv4 e IPv6','admin','/administracion','ADMINISTRACION_2026']]){const group=el('details');group.append(el('summary',title+' · opcional'));card.append(group);const a=field(prefix+'_path','Ruta de prueba',path),b=field(prefix+'_marker','Texto único del recurso que debería estar prohibido',marker);group.append(a.previousSibling,a,b.previousSibling,b);}
  const label=el('label',undefined,'check'),check=el('input');check.type='checkbox';check.dataset.field='scope_confirmed';check.style.width='auto';label.append(check,document.createTextNode(' Confirmo que son recursos ficticios autorizados y que esta cuenta no debe acceder a los recursos ajeno, interno o administrativo configurados.'));card.append(label);
  const remove=el('button','Quitar aplicación','secondary');remove.type='button';remove.addEventListener('click',()=>{card.remove();updateOptions();});card.append(remove);$('web-applications').append(card);updateOptions();
}
$('add-web-application').addEventListener('click',addApplication);
$('personal-web').addEventListener('change',()=>{if($('personal-web').checked&&!$('web-applications').children.length)addApplication();updateOptions();});
$('save-web-session').addEventListener('click',async()=>{const result=await post('/api/web-session',{name:$('web-session-name').value.trim(),header:$('web-session-header').value,value:$('web-session-value').value});if(result){$('web-session-value').value='';$('web-session-note').textContent=result.message;}});
function personalConfigurationKey(){const value=options();return JSON.stringify({personal:value.personal,applications:value.applications||[]});}
function scenarioInfo(){return (state.scenario_catalog||[]).find(x=>x.id===options().scenario)||null;}
function currentLab() {const sc=options().scope;if(sc==='empresa'&&options().scenario)return state.scenario_labs?.[options().scenario]||{status:'unknown',message:'Activa este escenario con Restaurar y compruébalo antes de iniciar.'};if(sc==='empresa')return state.empresa_lab||{status:'unknown',message:'Comprueba NovaFlow antes de iniciar sus 32 tareas.'};if(sc!=='personal')return state.lab;const lab=state.personal_lab||{status:'unknown',message:'Indica tus IP y comprueba las rutas.'};return lab.status==='ready'&&personalCheckKey!==personalConfigurationKey()?{status:'unknown',message:'Comprueba las IP y la interfaz actuales antes de iniciar.'}:lab;}

function personalHostCount(value) {
  const raw=value.ipv4.trim(),cidr=raw.includes('/')||raw.includes('-');
  const listCount=text=>new Set(text.split(',').map(s=>s.trim()).filter(Boolean)).size;
  const match=raw.match(/^\d{1,3}(?:\.\d{1,3}){3}\/(\d{1,2})$/);
  const prefix=match?Number(match[1]):-1;
  const range=raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/);
  const ipNumber=ip=>ip.split('.').every(p=>Number(p)<=255)?ip.split('.').reduce((n,p)=>n*256+Number(p),0):NaN;
  const size=range?ipNumber(range[2])-ipNumber(range[1])+1:NaN;
  const ipv4=range?(Number.isFinite(size)&&size>0?size:null):cidr?(prefix>=24&&prefix<=32?2**(32-prefix)-(prefix<31?2:0):null):listCount(raw);
  return {count:ipv4===null?null:ipv4+listCount(value.ipv6),cidr};
}


function renderContext() {
  const personal=page==='live'?detail?.run.bank==='personal':page==='new'&&options().scope==='personal';
  const empresa=page==='live'?detail?.run.bank==='empresa':page==='new'&&options().scope==='empresa';
  $('scope-name').textContent=empresa?'Empresa NovaFlow S.A.S.':personal?'Mi laboratorio':'Empresa Andina Demo';
  const selectedScenario=empresa&&page==='new'?scenarioInfo():null;
  $('scope-description').textContent=empresa?(page==='live'?'Laboratorio instrumentado NovaFlow. El seguimiento muestra los activos y las tareas de esta corrida.':`Laboratorio instrumentado NovaFlow. Cinco capacidades; ${selectedScenario?.targets||10} objetivos en ${selectedScenario?.containers||12} contenedores.`):personal?'Red definida por el operador. Pruebas y cobertura por equipo.':'Escenario empresarial simulado. Pruebas controladas por IPv4 e IPv6.';
  $('footer-scope').textContent=empresa?'DualStack · Empresa NovaFlow (detección)':personal?'DualStack · Mi laboratorio por IP':'DualStack · Escenario empresarial simulado';
  if(!['new','live'].includes(page))$('footer-scope').textContent=page==='future'?'NovaFlow Labs · Desarrollo futuro y archivo':'NovaFlow Labs · Investigación dual-stack';
  $('result-help').textContent=options().scope==='personal'&&!$('personal-creds').checked&&!$('personal-web').checked?'Los estados de tus puertos y los servicios reconocidos, con consola y dos informes. No se confirman vulnerabilidades en este modo.':'Una explicación de cada problema, el objetivo afectado, su riesgo y los pasos para corregirlo. Puedes guardar o imprimir el informe.';
}
function showPage(next,historyMode='push') {
  const [route,query='']=next.split('?');next=route;
  const requestedScope=new URLSearchParams(query).get('scope');
  if(next==='new'&&['empresa','personal','v2'].includes(requestedScope)&&requestedScope!==options().scope){
    form.querySelector(`input[name=scope][value="${requestedScope}"]`).checked=true;personalCheckKey=null;updateOptions();showSetupStep(1);
  }
  if(!['thesis','lab','models','future','new','live','history','kpi'].includes(next)) next = 'thesis';
  const changed=page!==next;
  page = next;
  for(const id of ['thesis','lab','models','future','new','live','history','kpi']) $('page-'+id).hidden = id !== page;
  for(const node of document.querySelectorAll('nav [data-page]')) node.classList.toggle('selected',node.dataset.page===page);
  for(const node of document.querySelectorAll('.workspace-switch [data-page]'))node.classList.toggle('selected',node.dataset.page===(page==='future'||(page==='new'&&options().scope!=='empresa')?'future':'thesis'));
  const hash='#'+page+(page==='new'&&options().scope!=='empresa'?'?scope='+options().scope:'');
  if(historyMode==='replace')history.replaceState(null,'',hash);
  else if(historyMode!=='none'&&location.hash!==hash)history.pushState(null,'',hash);
  if(page==='live') renderDetail();
  if(page==='history') renderHistory();
  if(['kpi','future'].includes(page)) renderStudy();
  drawHalos();renderContext();if(typeof renderWorkspace==='function')renderWorkspace();
  if(changed)window.scrollTo(0,0);
}
function selectTab(next) {
  tab = next;
  for(const name of ['findings','agents','activity','console','architecture']) $('tab-'+name).hidden = name !== tab;
  for(const node of document.querySelectorAll('[data-tab]')) {const chosen=node.dataset.tab===tab;node.classList.toggle('selected',chosen);node.setAttribute('aria-selected',String(chosen));}
  renderMap(); drawHalos(); if(tab==='console')renderConsole();if(tab==='agents')renderAgents();
}
function updateOptions() {
  const selectedScope=options().scope,limit=selectedScope==='empresa'?80000:20000;
  for(const item of $('tokens').options)item.disabled=Number(item.value)>limit;
  if($('tokens').dataset.scope!==selectedScope){
    const previous=$('tokens').dataset.scope;
    if(selectedScope==='empresa'&&previous!==undefined)$('tokens').value='60000';
    else if(Number($('tokens').value)>limit)$('tokens').value=String(limit);
    $('tokens').dataset.scope=selectedScope;
  }
  const value = options(),scenario=scenarioInfo();
  $('scenario-description').textContent=scenario?`${scenario.difficulty} · ${scenario.targets} objetivos · ${scenario.tasks} tareas. ${scenario.detail}`:'Banco original NovaFlow: 10 objetivos y 32 tareas. Los escenarios adicionales se conservan por separado.';
  $('close-scenario').hidden=value.scope!=='empresa';
  $('review-architecture').textContent = value.architecture === 'multiagent' ? 'Agentes especializados' : 'Agente único';
  $('review-ia').textContent = value.ia === 'openai' ? 'OpenAI · planificación y revisión' : 'Desactivada';
  $('review-tokens').textContent = value.ia === 'openai' ? num(value.tokens) : '0';
  const personal=value.scope==='personal';
  const web=personal&&$('personal-web').checked;
  const empresa=value.scope==='empresa';
  const creds=personal&&$('personal-creds').checked;
  const defaultNames={v2:'Evaluación de seguridad · Empresa Andina Demo',personal:'Auditoría de red · IP entregadas',empresa:'Auditoría · NovaFlow S.A.S.'};
  if(Object.values(defaultNames).includes($('audit-name').value))$('audit-name').value=defaultNames[value.scope];
  $('v2-targets').hidden=personal||empresa;$('personal-fields').hidden=!personal;$('simulation-options').hidden=personal||empresa;$('empresa-fields').hidden=!empresa;
  $('personal-tests').hidden=!personal;$('fixed-tests').hidden=personal;
  $('fixed-tests').textContent=empresa?`${scenario?.name||'NovaFlow'} dispone de ${scenario?.tasks||32} tareas de catálogo: servicios, credenciales, permisos web y controles IPv6. No requiere configurar rutas web en este formulario.`:'El banco v2 ejecuta 22 tareas: permisos de aplicaciones dual-stack y controles de protocolo IPv6. Conserva su catálogo y protocolo congelados.';
  $('expert-mode').disabled=!personal&&!empresa;
  $('expert-mode-note').textContent=value.scope==='v2'?'v2 conserva su planificador y protocolo anteriores. La revisión ampliada está disponible para tu red y NovaFlow.':value.architecture==='single'?'Un agente LLM generalista revisa el resumen completo. Hasta 40 % del límite compartido; no se garantiza una consulta si no queda presupuesto.':'Cada rol revisa solo las observaciones de su área. Hasta 40 % del límite compartido; los roles sin presupuesto quedan señalados.';
  const roles=personal?['Descubrimiento IPv4/IPv6',...(creds?['Acceso']:[]),...(web?['Aplicaciones']:[])]:empresa?['Descubrimiento','Acceso','Aplicaciones','Red IPv6','Fragmentación']:['Aplicaciones','Red IPv6','Fragmentación'];$('agent-preview').replaceChildren();for(const name of value.architecture==='single'?['Agente generalista']:roles)$('agent-preview').append(el('span',name));

  const hosts=personal?personalHostCount(value.personal):{count:6,cidr:false};
  $('review-scope').textContent=empresa?(scenario?.name||'NovaFlow · banco integrado'):personal?'Red autorizada por IP o rango':'Laboratorio v2 completo';
  $('review-objectives').textContent=empresa?`${scenario?.targets||10} objetivos · ${scenario?.containers||12} contenedores`:personal?`${hosts.count===null?'Revisar rango':hosts.count+' hosts candidatos'} · máximo 256`:'6 equipos';
  $('review-tasks').textContent=empresa?`${scenario?.tasks||32} tareas de catálogo${manualContextEnabled()&&manualProtocolFrozen()?' · tope '+manualTaskLimit():''} · 5 capacidades`:personal?('Descubrimiento TCP → administrador → servicios abiertos'+(creds?' + credenciales por defecto':'')+(web?' + pruebas web configuradas':'')):'22 pruebas del catálogo';
  $('execution-badge').textContent=empresa?'DETECCIÓN REAL · 5 CAPACIDADES':personal?(web?'INVENTARIO + PRUEBAS WEB':creds?'INVENTARIO + CREDENCIALES POR DEFECTO':'INVENTARIO REAL · PUERTOS TCP'):'PRUEBAS REALES · 22 TAREAS';
  $('budget-settings').hidden = value.ia !== 'openai';
  $('start-audit').textContent = `Iniciar ${empresa?'detección':personal?((creds||web)?'detección':'inventario'):'auditoría'} real ${value.ia==='openai'?'con IA':'sin IA'} →`;
  renderManualControls();renderSetupHelp();updateButtons();renderContext();
}
function updateButtons() {
  const busy = posting || state.busy;
  const guard=state.execution_guard?.blocked===true;
  const manualError=manualConfigurationError();
  $('acceptance-five-start').disabled=!connected||busy||guard||state.acceptance_five?.active===true;
  const nextAvailable=manualProtocolFrozen()&&Boolean(nextManualPosition());for(const id of ['prepare-manual-next','use-manual-next'])$(id).disabled=!nextAvailable||busy;
  $('start-audit').disabled = !connected || busy || guard || Boolean(manualError) || currentLab().status !== 'ready';
  const withAI = options().ia === 'openai';
  $('simulate').disabled = !connected || busy || withAI || options().scope!=='v2';
  $('simulation-note').textContent = withAI ? 'Tienes IA seleccionada. Usa Iniciar auditoría real con IA. Para simular, selecciona Sin IA.' : 'Esta opción solo demuestra la interfaz y muestra tareas omitidas.';
  $('check-lab').disabled = !connected || busy || guard;
  $('close-scenario').disabled = !connected || busy || guard;
  $('restore-lab').disabled = !connected || busy || guard || options().scope==='personal';
  $('start-note').textContent = !connected ? 'Esperando conexión con el panel.' : busy ? 'Espera a que termine la operación actual.' : options().scope==='empresa' ? (currentLab().status==='ready'?`Catálogo de ${scenarioInfo()?.tasks||32} tareas${manualContextEnabled()&&manualProtocolFrozen()?' · tope '+manualTaskLimit()+' por corrida':''} ${withAI?'con OpenAI':'sin IA'}. Agente único en serie; multiagente hasta dos tareas independientes. Las pruebas IPv6 se aíslan.`:`Pulsa Comprobar para verificar los ${scenarioInfo()?.containers||12} contenedores y las rutas del escenario.`) : currentLab().status === 'ready' ? (options().scope==='personal' ? ($('personal-web').checked ? 'Inventario y pruebas web configuradas con dos clientes independientes. 240 s compartidos; lo pendiente queda incompleto.' : $('personal-creds').checked ? 'Máximo 256 hosts y 240 s. Inventaría servicios y probará credenciales por defecto con corroboración; una credencial aceptada es un hallazgo real.' : 'Máximo 256 hosts y 240 s. Inventaría servicios; no confirma vulnerabilidades. Los pendientes por tiempo quedan sin evaluar.') : withAI ? `Ejecutará las 22 tareas reales con OpenAI. Límite compartido: ${num(options().tokens)} tokens.` : 'Ejecutará las 22 tareas reales sin IA, con cero tokens.') : options().scope==='personal' ? 'Comprueba las rutas de todos tus objetivos para iniciar. Este modo no restaura tus equipos.' : 'Comprueba o restaura el laboratorio para iniciar.';
  const active = state.jobs.find(job=>job.action==='audit'&&job.status==='running'&&job.run_key===selectedKey);
  $('stop-audit').hidden = !active || detail?.run.status !== 'running';
  $('stop-audit').disabled = busy && posting;
  if(connected&&guard)$('start-note').textContent=state.execution_guard.message;
  else if(connected&&!busy&&manualError)$('start-note').textContent=manualError;
  else if(connected&&!busy&&currentLab().status==='error')$('start-note').textContent=currentLab().message;
}
async function post(path, body) {
  if(posting) return null;
  posting = true; updateButtons(); clearError();
  try {
    const response = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
    const data = await response.json();
    if(!response.ok) throw new Error(data.error || 'La operación no pudo iniciarse.');
    return data;
  } catch(error) {showError(error.message==='Failed to fetch' ? 'No hay conexión con el panel. Vuelve a abrirlo e intenta otra vez.' : error.message); return null;}
  finally {posting=false;updateButtons();}
}
async function start(mode) {
  if(setupStep!==3){showSetupStep(3,true);return;}
  if(!validateApplicationSelection()||!form.reportValidity()) return;
  const manualError=manualConfigurationError();if(mode==='live'&&manualError){showError(manualError);return;}
  previousKeys = new Set(state.runs.map(run=>run.key));
  const response = await post('/api/audit',options(mode));
  if(response) {
    followJob = response.job.id; pendingAudit = true; selectedKey = null; detail = null;
    showPage('live'); selectTab('activity');
    $('job-message').hidden=false; $('job-message').textContent=mode==='live' ? 'Iniciando la auditoría y comprobando el alcance. Las tareas aparecerán aquí.' : 'Preparando una simulación. Esta operación no ejecuta pruebas de red.';
  }
}
function renderState() {
  renderAcceptanceFive();
  const guard=state.execution_guard;
  $('runtime-blocker').hidden=!guard?.blocked;
  $('runtime-message').textContent=guard?.message||'';
  const bank=state.empresa_lab||{status:'unknown',message:'Comprueba el banco antes de iniciar.'};
  $('lab-current-badge').replaceWith(Object.assign(badge(bank.status,{ready:'Disponible ahora',checking:'Comprobando',restoring:'Restaurando',error:'Bloqueado ahora',unknown:'Por comprobar'}[bank.status]||'Por comprobar'),{id:'lab-current-badge'}));
  $('lab-current-message').textContent=bank.message;
  if(personalChecking) {
    const check=state.jobs.find(job=>job.id===personalChecking.id);
    if(check&&['complete','failed'].includes(check.status)) {if(check.status==='complete')personalCheckKey=personalChecking.key;personalChecking=null;}
  }
  const lab = currentLab();
  $('lab-heading').textContent=options().scope==='personal'?'Estado de mis objetivos':options().scope==='empresa'?'Banco NovaFlow':'Estado del laboratorio';
  $('check-lab').textContent=options().scope==='personal'?'Comprobar objetivos':'Comprobar';
  if($('personal-interface').options.length===1)for(const name of (state.interfaces||[]).filter(name=>!name.startsWith('veth'))){const option=el('option',name);option.value=name;$('personal-interface').append(option);}

  const label = {unknown:'Por comprobar',checking:'Comprobando',restoring:'Restaurando',ready:'Listo',error:'Necesita atención'}[lab.status] || 'Por comprobar';
  $('lab-badge').replaceWith(Object.assign(badge(lab.status,label),{id:'lab-badge'}));
  $('lab-message').textContent = lab.message;
  const iaOption=form.querySelector('input[name="ia"][value="openai"]');
  iaOption.disabled=!state.openai_available;
  iaOption.closest('label').title=state.openai_available?'Utiliza la configuración privada existente.':'Configura el proveedor local antes de utilizar IA. Puedes auditar sin IA.';
  iaOption.closest('label').querySelector('small').textContent=state.openai_available?'El modelo prioriza pruebas del catálogo autorizado.':'IA no configurada. Puedes ejecutar las pruebas sin IA.';
  if(!state.openai_available&&iaOption.checked){form.querySelector('input[name="ia"][value="none"]').checked=true;updateOptions();}
  if(!$('catalog').children.length) for(const target of state.catalog || []) {
    const item=el('div',undefined,'catalog-item');item.append(el('strong',target.name),el('span',target.ipv4),el('span',target.ipv6));item.title=target.tests;$('catalog').append(item);
  }
  const job = state.jobs.find(job=>job.id===followJob);
  if(job?.run_key && state.runs.some(run=>run.key===job.run_key)) {
    if(selectedKey!==job.run_key) {selectedKey=job.run_key; detail=null;}
    pendingAudit=false;
  } else if(pendingAudit) {
    const created = state.runs.find(run=>!previousKeys.has(run.key));
    if(created) {selectedKey=created.key;detail=null;pendingAudit=false;}
  }
  if(!selectedKey && !pendingAudit && !followJob) selectedKey=(state.runs.find(run=>run.status==='running') || state.runs.find(run=>run.mode==='live'&&run.status==='complete') || state.runs[0])?.key || null;
  const signature=JSON.stringify(state.runs.map(run=>[run.key,run.status,run.name]));
  if(signature!==pickerSignature) {
    $('run-select').replaceChildren();
    for(const run of state.runs) {const option=el('option',`${run.name} · ${run.status_name} · ${run.id.slice(-8)}`);option.value=run.key;$('run-select').append(option);}
    pickerSignature=signature;
  }
  $('run-select').value=selectedKey||'';
  $('job-message').hidden = !job;
  if(job) $('job-message').textContent=job.message;
  if(job&&['failed','interrupted'].includes(job.status)) $('job-message').className='notice error'; else $('job-message').className='notice';
  if(job&&['failed','partial','complete','interrupted'].includes(job.status)) pendingAudit=false;
  updateButtons();
  renderManualControls();
  if(page==='live'&&!selectedKey)renderDetail();
  if(page==='history') renderHistory();
  if(typeof renderWorkspace==='function')renderWorkspace();
}
function renderDetectionBudget(){
  const run=detail?.run,budget=detail?.detection_budget||run?.detection_budget;
  const node=$('detection-budget-note');node.hidden=budget?.applied!==true;
  if(node.hidden){node.textContent='';return;}
  const notSelected=Number.isInteger(budget.not_selected_tasks)&&budget.not_selected_tasks>=0?budget.not_selected_tasks:null;
  const executed=Number.isInteger(budget.executed_tasks)?num(budget.executed_tasks):'—',catalogue=Number.isInteger(budget.catalogue_size)?num(budget.catalogue_size):'—';
  node.textContent=`${executed} ejecutadas de ${catalogue} tareas del catálogo · límite ${num(budget.task_limit)}${notSelected?' · '+notSelected+' no seleccionadas por el límite':''}. Las operaciones cerradas pueden incluir tareas no seleccionadas; no equivalen a pruebas ejecutadas ni acreditan seguridad.`;
}
function renderDetail() {
  renderDetectionBudget();
  renderRunProvenance();
  if(!detail || detail.run.key!==selectedKey) {
    const failed=state.jobs.some(job=>job.id===followJob&&job.status==='failed');
    $('run-title').textContent = failed ? 'La auditoría no se inició' : pendingAudit ? 'Preparando tu auditoría…' : 'Seguimiento y resultados';
    $('run-subtitle').textContent = failed ? 'Revisa el mensaje de la operación y vuelve a comprobar el laboratorio.' : pendingAudit ? 'La comprobación inicial puede tardar unos segundos.' : 'Elige una ejecución del historial o inicia una nueva auditoría.';
    $('run-status').replaceWith(Object.assign(badge('pending',failed?'No iniciada':pendingAudit?'Preparando':'En espera'),{id:'run-status'}));
    $('executive-summary').textContent = failed ? 'No se generó un resultado nuevo. Las auditorías anteriores siguen disponibles en el historial.' : 'Aquí aparecerá el resultado explicado a partir de la evidencia.';
    for(const id of ['stat-progress','stat-findings','stat-time','stat-tokens']) $(id).textContent='—';
    $('stat-progress-note').textContent='Esperando una auditoría';$('stat-findings-note').textContent='Sin resultado nuevo';$('stat-mode').textContent='Sin ejecución seleccionada';$('stat-budget').textContent='Reporte: 0 tokens adicionales';$('usage-note').textContent='';$('findings-count').textContent='0';
    $('progress-fill').style.width='0%'; $('report-link').hidden=true;$('executive-report-link').hidden=true;$('console-output').textContent='Sin auditoría seleccionada.';
    $('findings').replaceChildren(empty('Todavía no hay resultados','Las pruebas y sus observaciones aparecerán cuando el auditor inicie.'));
    $('tasks').replaceChildren();$('events').replaceChildren();$('incidents').hidden=true;
    $('progress-explanation').hidden=true;$('result-insights').hidden=true;$('inventory-toggle').hidden=true;renderExecution();renderMap();renderAgents();return;
  }
  const {run,brief}=detail;renderContext();
  $('run-title').textContent=run.name;
  $('run-subtitle').textContent=`${run.architecture==='multiagent'?'Agentes especializados':'Agente único'} · ${run.bank==='personal'?'Red y pruebas configuradas':run.mode==='live'?'Pruebas reales de laboratorio':'Simulación sin pruebas de red'} · ${run.id}`;
  $('run-status').replaceWith(Object.assign(badge(run.status,run.status_name),{id:'run-status'}));
  const progress=detail.report_view?.progress;
  $('stat-progress').textContent=`${num(progress?.closed ?? run.finished)} / ${num(progress?.total ?? run.total)}`;
  $('stat-progress-note').textContent=run.mode!=='live' ? 'La simulación omite las pruebas' : `${num(progress?.successful ?? brief.checked)} correctas · ${num(progress?.issues ?? brief.issues.length)} con incidencias${progress?.skipped ? ` · ${num(progress.skipped)} omitidas` : ''}`;
  $('progress-fill').style.width=`${Math.max(0,Math.min(100,Number(progress?.percent ?? run.progress)||0))}%`;
  $('progress-explanation').hidden=!progress;
  if(progress){
    $('progress-outcome').textContent=brief.final?'Plan final':progress.dynamic?'Plan en construcción':'Plan de operaciones';
    $('progress-explanation-text').textContent=progress.explanation;
    $('progress-stages').replaceChildren();
    for(const stage of progress.stages){
      const item=el('article',undefined,'progress-stage');
      item.append(el('strong',`${num(stage.total)}`),el('span',stage.label),
        el('small',`${num(stage.successful)} correctas${stage.no_detection!==null && stage.no_detection!==undefined ? ` (${num(stage.no_detection)} sin detección)` : ''}${stage.issues ? ` · ${num(stage.issues)} con incidencias` : ''}${stage.skipped ? ` · ${num(stage.skipped)} omitidas` : ''}${stage.total>stage.closed ? ` · ${num(stage.total-stage.closed)} por cerrar` : ''}`));
      if(stage.issues)item.classList.add('has-issues');
      $('progress-stages').append(item);
    }
  }
  $('findings-tab-title').textContent=brief.is_inventory?'Servicios y cobertura':'Hallazgos';
  $('stat-findings-label').textContent=brief.is_inventory?'Servicios TCP abiertos':brief.final?'Hallazgos confirmados':'Observaciones preliminares';
  $('stat-findings').textContent=num(brief.is_inventory?brief.service_count:brief.cards.length);
  $('stat-findings-note').textContent=brief.is_inventory?'Vulnerabilidades: no evaluadas':run.mode!=='live'?'No demuestra detecciones reales':brief.final?`${brief.affected} objetivos afectados`:'Pendientes del cierre de la auditoría';
  $('stat-time').textContent=time(run.seconds);$('stat-mode').textContent=run.status_name;
  $('stat-tokens').textContent=(run.llm.usage_complete ? '' : '≥ ')+num(run.llm.known_tokens);
  $('stat-budget').textContent=`Límite: ${num(run.llm.budget)} · Reporte: 0 adicionales`;
  $('executive-summary').textContent=detail.report_view?.headline||brief.summary;
  renderExecution();renderInsights();
  $('inventory-toggle').hidden=!brief.inventory?.length;
  $('summary-title').textContent=brief.final?'Lo que significa el resultado':run.mode!=='live'?'Esto fue una simulación':'Lo que sabemos hasta ahora';
  const notes=[];
  if(!run.llm.usage_complete) notes.push(run.status==='running'?'El consumo es provisional mientras la auditoría está en curso.':run.status==='interrupted'?'La interrupción puede haber dejado consumo del proveedor sin registrar. Se muestra el mínimo conocido.':'El proveedor no informó todo el uso. El consumo mostrado es parcial.');
  if(run.llm.fallbacks) notes.push(`${run.llm.fallbacks} incidencias de planificación o revisión: decisiones de respaldo o respuestas rechazadas. Consulta el detalle de IA.`);
  if(Number.isFinite(run.llm.cost)&&run.llm.cost>0) notes.push(`Costo registrado estimado: USD ${run.llm.cost.toFixed(4)}. No es la factura del proveedor.`);
  $('usage-note').textContent=notes.join(' ');
  $('report-link').hidden=!brief.final;
  $('report-link').href='/report?audience=technical&key='+encodeURIComponent(run.key);
  $('executive-report-link').hidden=!brief.final;
  $('executive-report-link').href='/report?audience=executive&key='+encodeURIComponent(run.key);
  $('findings-count').textContent=num(brief.is_inventory?brief.service_count:brief.cards.length);
  $('architecture-details').hidden=false;
  renderFindings();renderTasks();renderEvents();renderMap();renderAgents();updateButtons();if(tab==='console')renderConsole();if(tab==='agents')renderAgents();
}
function renderFindings() {
  if(!detail) return;
  const {run,brief}=detail;
  if(brief.is_inventory){renderInventory();renderCandidates();renderIncidents();return;}
  if(cardsRun!==run.key) {openCards=new Set(brief.cards.slice(0,1).map(card=>card.id));cardsRun=run.key;}
  const query=$('finding-search').value.trim().toLocaleLowerCase('es');
  const filtered=(detail.report_view?.findings||brief.cards).filter(card=>[card.title,card.asset,card.address,card.meaning].join(' ').toLocaleLowerCase('es').includes(query));
  $('findings').replaceChildren();
  for(const card of filtered) {
    const item=el('details',undefined,'finding');item.open=openCards.has(card.id);
    item.addEventListener('toggle',()=>{if(item.open)openCards.add(card.id);else openCards.delete(card.id);});
    const heading=el('summary');const symbol=el('span','!','finding-symbol '+card.severity);
    const title=el('div',undefined,'finding-heading');title.append(el('strong',card.title),el('small',`${card.address}${card.ports?.length?' · TCP '+card.ports.join(', '):''} · ${card.asset}`));
    heading.append(symbol,title,badge(card.preliminary?'preliminary':'complete',card.preliminary?'Preliminar':'Confirmado'));
    const content=el('div',undefined,'finding-content');
    const sections=el('div',undefined,'finding-sections');
    for(const [label,text] of [['Qué ocurrió',card.meaning],['Por qué importa',card.impact]]) {const section=el('section');section.append(el('h3',label),el('p',text));sections.append(section);}
    const fix=el('section',undefined,'finding-fix');fix.append(el('h3','Qué hacer para corregirlo'),el('p',card.fix));
    const evidence=el('details',undefined,'evidence-details');evidence.append(el('summary','Cómo se comprobó y alcance de la evidencia'),el('p',card.confirmation),el('p',`Clasificación del auditor: ${severities[card.severity]||'Sin clasificación'}.`),el('p',card.scope));
    if(card.evidence)evidence.append(el('p','Evidencia conservada: '+card.evidence));
    if(card.confirmation_ref)evidence.append(el('p','Corroboración: '+card.confirmation_ref));
    content.append(sections,fix,evidence);item.append(heading,content);$('findings').append(item);
  }
  if((brief.has_credentials||brief.has_web||run.bank==='empresa')&&brief.inventory.length)renderInventory(false);
  if(!filtered.length) {
    const title=query?'No hay coincidencias':run.mode!=='live'?'Esta simulación no ejecutó pruebas':brief.final?'No se confirmaron hallazgos':run.status==='interrupted'?'La auditoría se interrumpió':'Las primeras observaciones aparecerán aquí';
    const text=query?'Prueba otro objetivo o palabra.':run.mode!=='live'?'Para obtener resultados reales, inicia una auditoría con el laboratorio listo.':brief.final?'Revisa la cobertura y las incidencias. Este resultado se limita a las pruebas realizadas.':run.status==='interrupted'?'No existe un informe final de esta ejecución. Revisa las tareas y comprueba o restaura el laboratorio antes de otra prueba.':'El auditor está recogiendo evidencia. Las observaciones preliminares se publican después de que termine cada tarea y se revisan al cierre.';
    $('findings').append(empty(title,text));
  }
  renderCandidates();renderIncidents();
}
function renderCandidates(){
  const values=detail?.cve_candidates||[];if(!values.length)return;
  const box=el('details',undefined,'candidate-card');box.append(el('summary',`${values.length} candidatos CVE · pendientes de contrastar`),el('p','Catálogo local acotado: una coincidencia producto/versión no confirma la vulnerabilidad. Estos candidatos no cuentan como hallazgos ni como TP de los KPI.'));
  for(const value of values){const section=el('section');section.append(el('h3',`${value.cve} · ${value.address}:${value.port}`),el('p',value.observed_product+' '+value.observed_version),el('p',value.limitation),el('p',value.next_step));const source=el('a','Aviso del fabricante ↗');source.href=value.url;source.target='_blank';source.rel='noopener';section.append(source);box.append(section);}
  $('findings').append(box);
}
function renderIncidents(){
  const issues=detail?.brief.issues||[],groups=detail?.report_view?.incident_groups||[];
  $('incidents').replaceChildren();$('incidents').hidden=!issues.length;if(!issues.length)return;
  const box=el('div',undefined,'incident-box');box.append(el('h3',`${issues.length} operaciones requieren atención`),el('p','Estas comprobaciones no aportaron un resultado válido. Los hallazgos confirmados se conservan; las incidencias requieren revisión.'));
  for(const group of groups){
    const section=el('section',undefined,'panel-incident');
    section.append(el('h4',`${group.address}${group.ports.length?' · TCP '+group.ports.join(', '):''} · ${group.count} ${group.count===1?'intento':'intentos'}`),el('strong',group.title),el('p',group.meaning),el('p','Siguiente paso: '+group.next_step));
    const reason=el('details');reason.append(el('summary','Ver motivo registrado'),el('code',group.reason));section.append(reason);box.append(section);
  }
  if(!groups.length)for(const task of issues)box.append(el('p',`${task.asset_name}: ${task.label} · ${task.status_name}`));
  $('incidents').append(box);
}

function renderInventory(clear=true) {
  if(clear){$('findings').replaceChildren();$('incidents').hidden=true;}
  const query=$('finding-search').value.trim().toLocaleLowerCase('es');
  const inventory=detail.brief.inventory||[], showAll=$('inventory-all').checked;
  const exposed=inventory.filter(i=>i.host_state!=='down'&&i.ports.some(p=>p.state==='open'));
  const visible=(showAll?inventory:exposed).filter(i=>!query||[i.address,i.asset,...i.services.map(s=>[s.name,s.product,s.version].join(' '))].join(' ').toLocaleLowerCase('es').includes(query));
  let target=$('findings');
  if(!clear){const section=el('details',undefined,'inventory-section');section.append(el('summary',`Servicios expuestos · ${exposed.length} direcciones`));const body=el('div');section.append(body);target.append(section);target=body;}
  for(const item of visible) {
    const card=el('section',undefined,'card inventory-host');const heading=el('div',undefined,'card-top');heading.append(el('h2',item.address),badge('complete',item.host_state==='down'?'Sin respuesta':`${item.ports.filter(p=>p.state==='open').length} puertos abiertos`));card.append(heading);
    if(item.host_state==='down'){heading.lastChild.replaceWith(badge('pending','Sin respuesta'));card.append(el('p','No respondió al descubrimiento; puertos sin escanear.','field-note'));target.append(card);continue;}
    renderCoverage(card,item.coverage);
    const ports=showAll?item.ports:item.ports.filter(p=>p.state==='open');
    if(ports.length){const table=el('table'),header=el('tr');for(const name of ['Puerto TCP','Estado','Servicio reconocido'])header.append(el('th',name));const head=el('thead');head.append(header);table.append(head);const body=el('tbody');
      for(const port of ports){const row=el('tr'),service=item.services.find(s=>s.port===port.port);const names={open:'Abierto',closed:'Cerrado',filtered:'Filtrado',not_reported:'Sin estado individual'};row.append(el('td',port.port),el('td',names[port.state]||port.state),el('td',service?[service.name,service.product,service.version].filter(Boolean).join(' · '):'—'));body.append(row);}table.append(body);const scroll=el('div',undefined,'table-scroll');scroll.append(table);card.append(scroll);}
    target.append(card);
  }
  if(!visible.length&&clear)target.append(empty(query?'No hay coincidencias':detail.brief.final?'Sin servicios abiertos registrados':'Recogiendo evidencia de red',query?'Cambia la búsqueda o activa el detalle de estados.':'La consola conserva las operaciones y sus incidencias. La ausencia de exposición registrada no demuestra seguridad.'));
  if(clear&&inventory.length&&!showAll){const excluded=inventory.length-exposed.length;target.append(el('p',`${exposed.length} direcciones con servicios abiertos. ${excluded} sin exposición registrada agrupadas en el detalle. Un puerto abierto no es una vulnerabilidad.`, 'inventory-note'));}
  if(clear&&detail.brief.issues.length){const issues=el('details',undefined,'inventory-section');issues.append(el('summary',`${detail.brief.issues.length} tareas requieren revisión`),el('p','Revisa Pruebas y actividad o filtra Incidencias en la consola. Una prueba incompleta no acredita un control seguro.','field-note'));target.append(issues);}
}
function renderCoverage(card,coverage) {
  if(!coverage)return;
  const notes=[];
  const labels={confirmed:'Confirmada con evidencia',not_detected:'Sin detección en la prueba',incomplete:'Incompleta',not_evaluated:'Sin evaluación válida'};
  if(labels[coverage.credentials_state])notes.push(`Credenciales: ${labels[coverage.credentials_state]} · ${coverage.credential_attempts} intentos`);
  const names={object_authorization:'Documento ajeno',file_boundary:'Límite de descarga',ipv6_authorization_gap:'Permisos IPv4/IPv6'};
  for(const [key,value] of Object.entries(coverage.web_checks||{}))if(labels[value])notes.push(`${names[key]||key}: ${labels[value]}`);
  if(notes.length){const section=el('details',undefined,'coverage-details');section.append(el('summary','Pruebas aplicadas a este equipo'));notes.forEach(text=>section.append(el('p',text,'field-note')));card.append(section);}
}
function renderExecution(){
  const tasks=detail?.brief.tasks.filter(t=>t.status==='running')||[],active=connected&&detailFresh&&detail?.run.status==='running';
  $('execution-strip').classList.toggle('is-running',Boolean(active));
  $('execution-title').textContent=active?tasks.length?`${tasks.length} ${tasks.length===1?'operación activa':'operaciones activas'}`:'Preparando la siguiente operación':detail?'Corrida '+detail.run.status_name.toLocaleLowerCase('es'):'Sin operación activa';
  $('execution-detail').textContent=active?tasks.length?tasks.map(t=>`${t.address||t.asset_name} · ${t.label}`).join(' / '):'Consulta la consola para ver el último evento registrado.':detail?'Consulta los hallazgos y la bitácora conservada.':'Inicia una auditoría o abre una del historial.';
  $('execution-phase').textContent=active?'EN EJECUCIÓN':detail?'REGISTRO CONSERVADO':'EN ESPERA';
}
function renderInsights(){
  const box=$('result-insights'),reviews=(detail?.assistance?.reviews||[]).filter(r=>r.status==='accepted'&&r.interpretation);box.hidden=!reviews.length;box.replaceChildren();
  for(const review of reviews){const section=el('section');section.append(el('small','ANÁLISIS DEL LLM · INTERPRETACIÓN'),el('p',review.interpretation),el('strong','Siguiente paso'),el('p',review.next_step));for(const action of review.prioritized_actions||[]){const row=el('div',undefined,'structured-action');row.append(el('h4',action.title+' · '+action.addresses.join(', ')),el('p',action.why),el('strong','Verificación de cierre'),el('p',action.verification));section.append(row);}box.append(section);}
}
function renderTasks() {
  $('tasks').replaceChildren();
  for(const task of detail.brief.tasks) {const row=el('div',undefined,'task');const description=el('div');description.append(el('strong',task.label),el('small',`${task.asset_name} · ${task.agent_name}`));row.append(description,badge(task.status,task.status_name));$('tasks').append(row);}
}
function renderEvents() {
  $('events').replaceChildren();
  for(const event of detail.brief.events) {const row=el('li',undefined,event.issue?'issue':'');const date=new Date(event.time);row.append(el('span',event.label),el('time',Number.isNaN(date.getTime())?'':date.toLocaleTimeString('es',{hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'America/New_York'})));$('events').append(row);}
  if(!detail.brief.events.length)$('events').append(el('li','Todavía no hay eventos para esta auditoría.'));
  const keys=new Set(detail.run.events.map(event=>JSON.stringify([event.time,event.kind,event.task,event.status])));
  if(eventRun===detail.run.key&&eventBaseline&&[...keys].some(key=>!eventBaseline.has(key)))recordedUntil=performance.now()+900;
  eventRun=detail.run.key;eventBaseline=keys;
}
function activity() {
  const running=connected&&detailFresh&&detail?.run.key===selectedKey&&detail.run.status==='running'&&state.runs.some(run=>run.key===selectedKey&&run.status==='running');
  const tasks=running?detail.brief.tasks.filter(task=>task.status==='running'):[];
  return {running,apps:tasks.filter(task=>task.agent==='application_access'||task.agent==='ipv4_services'||task.agent==='ipv4_credentials').length,ipv6:tasks.filter(task=>task.agent==='ipv6_ndp'||task.agent==='ipv6_fragmentation'||task.agent==='ipv6_services').length,recorded:connected&&performance.now()<recordedUntil};
}
function renderMap() {
  const current=activity();$('activity-map').replaceChildren();
  const nodes=[['◎','Coordinación',current.running?'Corrida activa':'En espera',current.running,false],['▤',detail?.brief.is_inventory?'Servicios IPv4':'Aplicaciones',current.apps?`${current.apps} tareas activas`:'Sin tareas activas',current.apps,false],['◇',detail?.brief.is_inventory?'Servicios IPv6':'Red IPv6',current.ipv6?`${current.ipv6} tareas activas`:'Sin tareas activas',current.ipv6,false],['≡','Registro',current.recorded?'Nuevo evento observado':'Evidencia local',false,current.recorded]];
  for(const [icon,title,note,active,recorded] of nodes){const node=el('div',undefined,'map-node'+(active?' active':'')+(recorded?' recorded':''));node.append(el('span',icon),el('strong',title),el('small',note));$('activity-map').append(node);}
}
function drawHalos() {
  $('halos').replaceChildren();
  const frame=$('diagram');
  if(page!=='live'||tab!=='architecture'||!$('architecture-details').open||!frame.contentDocument) return;
  const current=activity(),nodes=[];
  if(current.running)nodes.push(['controlador','Corrida activa',false]);
  if(current.apps+current.ipv6)nodes.push(['perfiles',`${current.apps+current.ipv6} tareas activas`,false]);
  if(current.recorded)nodes.push(['registro','Evento observado',true]);
  for(const [id,label,recorded] of nodes) {
    const node=frame.contentDocument.getElementById('node-'+id);if(!node)continue;
    const rect=node.getBoundingClientRect();if(!rect.width||!rect.height)continue;
    const halo=el('div',undefined,'halo'+(recorded?' recorded':''));halo.dataset.node=id;
    Object.assign(halo.style,{left:`${rect.left-5}px`,top:`${rect.top-5}px`,width:`${rect.width+10}px`,height:`${rect.height+10}px`});halo.append(el('span',label));$('halos').append(halo);
  }
}
function filteredConsoleLines(){
  const query=$('console-search').value.trim().toLocaleLowerCase('es'),category=$('console-category').value;
  const categories={commands:['COMANDO'],network:['DESCUBRIMIENTO','SERVICIO','HTTP','PAQUETES','AUTENTICACIÓN','VALIDACIÓN','ADMINISTRADOR'],ai:['IA'],administrator:['ADMINISTRADOR'],orchestration:['LANGGRAPH','GRAFO','ORQUESTACIÓN']};
  return (detail?.console?.lines||[]).filter(line=>(category==='all'||category==='issues'&&['error','warning'].includes(line.level)||categories[category]?.includes(line.kind))&&(!query||[line.kind,line.tool,line.asset,line.address,line.task_id,line.text,line.source].join(' ').toLocaleLowerCase('es').includes(query)));
}
function lineTime(line){const stamp=new Date(line.time);return Number.isNaN(stamp.getTime())?'sin hora':stamp.toLocaleTimeString('es',{hour12:false,timeZone:'America/New_York'});}
function consoleText(){return filteredConsoleLines().map(line=>`[${lineTime(line)}] [${line.kind}] [${line.tool}] ${line.address||line.asset||''} ${line.text}\n    Origen: ${line.source}${line.task_id?' · Tarea: '+line.task_id:''}`).join('\n\n');}
function renderConsole() {
  if(!detail)return;
  if(consoleRun!==detail.run.key){consoleRun=detail.run.key;consolePaused=false;$('console-pause').textContent='Pausar vista';$('console-pause').setAttribute('aria-pressed','false');}
  if(consolePaused)return;
  $('console-note').textContent=(detail.console?.note||'No hay bitácora disponible para esta ejecución.')+(detail.console?.limited?' Se muestran los últimos 1.000 eventos.':'');
  const filtered=filteredConsoleLines(),lines=filtered.slice(-300),output=$('console-output');
  $('console-count').textContent=`${filtered.length} / ${detail.console?.lines?.length||0} operaciones${filtered.length>300?' · vista: últimas 300':''}`;
  const signature=JSON.stringify([detail.run.key,lines]);if(signature===consoleSignature)return;consoleSignature=signature;
  const previous=output.scrollTop;output.replaceChildren();
  for(const line of lines){const row=el('article',undefined,'console-line '+line.level),meta=el('div',undefined,'console-line-meta');meta.append(el('time',lineTime(line)),el('span',line.kind,'console-kind'),el('strong',line.tool));if(line.address||line.asset)meta.append(el('span',line.address||line.asset,'console-target'));row.append(meta);if(line.kind==='COMANDO'&&line.text.length>300){const command=el('details',undefined,'command-details');command.append(el('summary',line.text.slice(0,150)+'… · ver comando completo'),el('code',line.text));row.append(command);}else row.append(el(line.kind==='COMANDO'?'code':'p',line.text));const source=el('details');source.append(el('summary','Origen y tarea'),el('p',line.source+(line.task_id?' · '+line.task_id:'')));row.append(source);output.append(row);}
  if(!lines.length)output.append(el('p','Sin operaciones que coincidan con el filtro.','console-empty'));
  output.scrollTop=$('console-follow').checked?output.scrollHeight:previous;
}
function renderHistory() {
  const query=$('history-search').value.trim().toLocaleLowerCase('es');
  const runs=state.runs.filter(run=>[run.name,run.id].join(' ').toLocaleLowerCase('es').includes(query));
  $('history-count').textContent=`${runs.length} ejecuciones`;$('history').replaceChildren();
  for(const run of runs) {
    const row=el('tr'),name=el('td');name.append(el('strong',run.name),el('small',`${run.mode==='live'?'Prueba real':'Simulación'} · ${run.id}`));
    const date=new Date(run.started_at);const status=el('td');status.append(badge(run.status,run.status_name));
    const action=el('td'),button=el('button','Ver resultados →','button');button.addEventListener('click',()=>{selectedKey=run.key;detail=null;followJob=null;pendingAudit=false;$('run-select').value=selectedKey;showPage('live');selectTab('findings');loadDetail(selectedKey);window.scrollTo({top:0,behavior:'smooth'});});action.append(button);
    row.append(name,el('td',Number.isNaN(date.getTime())?'—':date.toLocaleString('es',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',timeZone:'America/New_York'})),status,el('td',num(run.findings)),el('td',(run.llm.usage_complete?'':'≥ ')+num(run.llm.known_tokens)),action);$('history').append(row);
  }
  if(!runs.length){const row=el('tr'),cell=el('td',query?'No hay auditorías que coincidan con la búsqueda.':'No hay auditorías en esta etapa. Empieza preparando el laboratorio.');cell.colSpan=6;row.append(cell);$('history').append(row);}
}
async function loadDetail(key) {
  if(!key)return;
  try {
    const response=await fetch('/api/run?key='+encodeURIComponent(key),{cache:'no-store',signal:AbortSignal.timeout(6000)});
    if(!response.ok)throw new Error('El resultado todavía no está disponible.');
    const next=await response.json();
    if(key!==selectedKey)return;
    detail=next;detailFresh=true;if(page==='live')renderDetail();
  } catch(error) {if(key===selectedKey)detailFresh=false;if(page==='live'&&key===selectedKey&&connected)showError(error.message);}
}
async function poll() {
  try {
    const response=await fetch('/api/state',{cache:'no-store',signal:AbortSignal.timeout(6000)});
    if(!response.ok)throw new Error('offline');
    state=await response.json();connected=true;
    $('connection').textContent='Conectado · actualización automática';$('connection').classList.remove('offline');
    renderState();if(['kpi','future'].includes(page))renderStudy();if(selectedKey&&page==='live')await loadDetail(selectedKey);
  } catch(_) {connected=false;$('connection').textContent='Sin conexión · actividad no disponible';$('connection').classList.add('offline');updateButtons();renderMap();drawHalos();}
  setTimeout(poll,1000);
}
const expertNames={network:'Descubrimiento',credentials:'Acceso y credenciales',applications:'Aplicaciones',ipv6:'Red IPv6',fragmentation:'Fragmentación',generalist:'Agente único'};
const expertRoles={ipv4_services:'network',ipv6_services:'network',ipv4_credentials:'credentials',application_access:'applications',ipv6_ndp:'ipv6',ipv6_fragmentation:'fragmentation'};
let rosterSignature='',expertQuestions={};
function renderAgents(force=false){
  const current=detail?.run.key===selectedKey?detail:null;
  const signature=JSON.stringify([current?.run.tasks,current?.run.llm,current?.assistance]);if(!force&&signature===rosterSignature)return;rosterSignature=signature;
  $('agent-roster').replaceChildren();$('agent-decisions').replaceChildren();
  if(!current){$('agent-mode').textContent='Sin auditoría';$('agent-explanation').textContent='Aquí verás los roles, las consultas registradas y las revisiones del modelo cuando ejecutes una auditoría.';return;}
  const {run,assistance={}}=current;const withAI=run.llm.status!=='disabled'&&!!run.llm.model;
  $('agent-mode').textContent=withAI?(assistance.expert_mode?'Planificación + revisión LLM':'Planificación LLM'):'Sin LLM';
  $('agent-explanation').textContent=withAI?'Son roles del modelo configurado, con contexto por especialidad. Los textos del LLM son interpretaciones; los validadores confirman los hallazgos. Las consultas comparten el límite de tokens.':'Las herramientas y validadores siguen ejecutando las pruebas. No se muestran respuestas de IA cuando no hubo consultas al modelo.';
  const groups={};for(const task of run.tasks){const role=run.architecture==='single'?'generalist':expertRoles[task.agent]||'network';(groups[role]??=[]).push(task);}
  for(const [role,tasks] of Object.entries(groups)){
    const card=el('article',undefined,'expert-card'),head=el('div',undefined,'expert-head'),name=el('div'),done=tasks.filter(t=>['completed','completed_no_findings'].includes(t.status)).length,active=tasks.filter(t=>t.status==='running').length;
    name.append(el('h3',expertNames[role]),el('small',`${done} de ${tasks.length} pruebas completadas${active?' · '+active+' activas':''}`));head.append(el('span',role==='ipv6'?'v6':role==='generalist'?'01':expertNames[role].slice(0,1),'expert-avatar'),name);card.append(head);
    const review=(assistance.reviews||[]).find(r=>r.role===role);
    if(review?.status==='accepted'){
      card.append(el('p','Interpretación registrada del LLM · contrastar con la evidencia.','field-note'));
      const questions=el('div',undefined,'expert-questions'),selected=expertQuestions[role]||'interpretation';
      for(const [key,label] of [['interpretation','Qué observó'],['limitation','Qué falta'],['next_step','Siguiente paso']]){const button=el('button',label,key===selected?'selected':'');button.type='button';button.addEventListener('click',()=>{expertQuestions[role]=key;renderAgents(true);});questions.append(button);}
      card.append(questions,el('p',review[selected],'expert-answer'));
      card.append(el('small',`Basado en ${(review.evidence_tasks||[]).length} referencias de tareas · leerlo no genera otra consulta`,'field-note'));
    }else{
      const reasons={review_budget_exhausted:'El límite reservado no alcanzó para esta revisión.',review_time_exhausted:'No quedó tiempo para consultar este rol.',provider_or_usage_unavailable:'El proveedor o su medición de uso no están disponibles.',usage_unavailable:'El proveedor no informó todo el consumo.',invalid_specialist_response:'La respuesta no cumplió el contrato de revisión.',invalid_review_text:'El texto no cumplió la longitud o el formato permitido.',invalid_review_evidence:'La revisión citó referencias no admitidas.',invalid_action_evidence:'Una acción citó evidencia que no corresponde al equipo.',invalid_action_text:'La descripción de una acción no cumplió el formato permitido.',invalid_action_scope:'Una acción quedó fuera del alcance permitido.',invalid_review_json:'La respuesta no pudo interpretarse como JSON.',response_incomplete:'El proveedor devolvió una respuesta incompleta.'};
      card.append(el('p',review?(reasons[review.reason]||'La revisión no estuvo disponible; revisa el registro de IA.'):!withAI?'Este rol ejecuta sus perfiles sin asistencia LLM.':assistance.expert_mode?'La revisión se publica al cerrar las pruebas, si hay presupuesto y tiempo.':'Esta corrida utilizó el planificador clásico; no pidió revisión de observaciones.'));
    }
    $('agent-roster').append(card);
  }
  for(const row of (assistance.decisions||[]).slice(-12).reverse()){
    const item=el('div',undefined,'decision-row'),role=expertNames[expertRoles[row.role]||row.role]||(row.role==='administrator'?'Coordinación':'Planificación');item.append(el('span',role),badge(row.status,row.status==='accepted'?'Respuesta aceptada':row.status==='fallback'?'Respaldo registrado':'No enviada'),el('small',Number.isFinite(row.tokens)?num(row.tokens)+' tokens':'Uso sin medir'));$('agent-decisions').append(item);
  }
  if(!$('agent-decisions').children.length)$('agent-decisions').append(el('p','No hay decisiones de planificación registradas para esta corrida.','field-note'));
}
function renderStudy() {
  const study=state.kpi_study||{}, old=study.previous||{}, cert=study.certification||{};
  $('study-title').textContent=({awaiting_recharge:'Preparado · pendiente de recarga',checking_api:'Comprobando acceso a la API',running:'Estudio en ejecución',complete:'Estudio finalizado',stopped:'Estudio detenido',interrupted:'Estudio interrumpido'})[study.status]||'Preparación pendiente';
  $('study-message').textContent='Empresa Andina Demo es un escenario simulado con seis objetivos y 22 tareas por auditoría. El plan prevé 15 comparaciones emparejadas; conserva fallos y separa pilotos y estudios anteriores.';
  if(study.source_compatible===false){$('study-title').textContent='Revisar protocolo antes de iniciar';$('study-message').textContent=study.readiness_note;}
  $('study-cert').textContent=cert.integrity_valid?`${num(cert.checks_passed)} / ${num(cert.checks_total)}`:'Pendiente';
  $('study-calls').textContent=num(study.api_calls_started);
  $('study-previous').textContent=`Estudio v2 anterior: ${num(old.runs_started||0)} de 30 ejecuciones iniciadas. Se interrumpió por una incidencia de plataforma; se conserva por separado.`;
  const format=(key,suffix='')=>Number.isFinite(old.analysis?.[key]?.mean)?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(old.analysis[key].mean)+suffix:'—';
  $('study-results').replaceChildren();
  const fresh=(state.experiments||[]).find(exp=>exp.key.startsWith('kpi_v2_api/'));
  const freshValue=(key,suffix='')=>Number.isFinite(fresh?.analysis?.[key]?.mean)?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(fresh.analysis[key].mean)+suffix:'Pendiente';
  for(const cells of [['V2 anterior · 12 de octubre',num(old.pairs_eligible||0),format('TRTO_percent',' %'),format('IDE_percent',' %'),format('ETV_ratio'),old.complete?'Completo':'Parcial'],['Nuevo · Empresa Andina Demo',`${num(fresh?.pairs_eligible||0)} / 15`,freshValue('TRTO_percent',' %'),freshValue('IDE_percent',' %'),freshValue('ETV_ratio'),fresh?.complete?'Completo':study.status==='awaiting_recharge'?'Sin iniciar':fresh?'Parcial':$('study-title').textContent]]) {
    const row=el('tr');for(const value of cells)row.append(el('td',value));$('study-results').append(row);
  }
  renderKPICards(study,fresh);renderReferenceChoices();if(typeof renderWorkspace==='function'){workspaceSignature='';renderWorkspace();}renderManualPlan();
  for(const [id,architecture] of [['compare-single','single'],['compare-multi','multiagent']]){
    const select=$(id),selected=select.value,candidates=state.runs.filter(r=>r.architecture===architecture);
    const signature=JSON.stringify(candidates.map(r=>[r.key,r.status,r.llm?.status,r.llm?.fallbacks]));
    if(select.dataset.signature!==signature){select.dataset.signature=signature;select.replaceChildren();for(const run of candidates){const option=el('option',`${run.name} · ${run.started_display} · ${run.status_name}${run.llm?.fallbacks?' · IA con '+run.llm.fallbacks+' incidencias':''}`);option.value=run.key;select.append(option);}if(candidates.some(r=>r.key===selected))select.value=selected;}
  }
  $('operational-runs').replaceChildren();for(const run of state.runs.slice(0,10)){const row=el('tr');for(const value of [run.name,run.architecture==='single'?'Único':'Multiagente',`${run.finished} / ${run.total}`,time(run.seconds),(run.llm.usage_complete?'':'≥ ')+num(run.llm.known_tokens),run.status_name])row.append(el('td',value));$('operational-runs').append(row);}

}
const referenceConditions={object_authorization:'Documento ajeno',file_boundary:'Límite de descarga',ipv6_authorization_gap:'Permisos distintos IPv4/IPv6',ssh_default_credential:'Credencial SSH por defecto',ftp_default_credential:'Credencial FTP por defecto',postgres_default_credential:'Credencial PostgreSQL por defecto',http_get_default_credential:'Credencial HTTP Basic por defecto'};
let referenceSequence=0;
function addReferenceCase(){
  if($('reference-cases').children.length>=128){showError('Máximo 128 condiciones por referencia.');return;}
  const row=el('div',undefined,'reference-case'),id=++referenceSequence;
  for(const [key,label] of [['address','IP del equipo'],['port','Puerto TCP'],['condition','Prueba'],['expected','Estado preparado']]){
    const box=el('div'),caption=el('label',label),input=el(['condition','expected'].includes(key)?'select':'input');input.dataset.referenceField=key;input.id='reference-'+id+'-'+key;caption.htmlFor=input.id;
    if(key==='address'){input.placeholder='192.168.56.20';input.maxLength=45;}
    if(key==='port'){input.type='number';input.min='1';input.max='65535';input.placeholder='8080';}
    if(input.tagName==='SELECT'){const empty=el('option','Selecciona…');empty.value='';input.append(empty);for(const [value,text] of Object.entries(key==='condition'?referenceConditions:{present:'Vulnerable · presente',absent:'Protegido · ausente'})){const option=el('option',text);option.value=value;input.append(option);}}
    box.append(caption,input);row.append(box);
  }
  const remove=el('button','Quitar','button ghost');remove.type='button';remove.addEventListener('click',()=>row.remove());row.append(remove);$('reference-cases').append(row);
}
function renderReferenceChoices(){
  const select=$('compare-reference'),selected=select.value;select.replaceChildren();const empty=el('option','Sin referencia: solo métricas operativas');empty.value='';select.append(empty);
  for(const item of state.evaluation_references||[]){const option=el('option',`${item.name} · ${item.cases} condiciones`);option.value=item.id;select.append(option);}select.value=[...select.options].some(o=>o.value===selected)?selected:'';
}
$('add-reference-case').addEventListener('click',addReferenceCase);
document.querySelector('.reference-settings').addEventListener('toggle',()=>{if(document.querySelector('.reference-settings').open&&!$('reference-cases').children.length)addReferenceCase();});
$('save-reference').addEventListener('click',async()=>{
  const cases=[...$('reference-cases').children].map(row=>{const value={};for(const input of row.querySelectorAll('[data-reference-field]'))value[input.dataset.referenceField]=input.dataset.referenceField==='port'?Number(input.value):input.value.trim();return value;});
  const response=await post('/api/evaluation-reference',{name:$('reference-name').value.trim(),cases});
  if(response){state.evaluation_references=[response.reference,...state.evaluation_references||[]];renderReferenceChoices();$('compare-reference').value=response.reference.id;$('reference-note').textContent=`Referencia guardada: ${response.reference.cases} condiciones. SHA-256: ${response.reference.sha256}. No se ha enviado a los agentes.`;}
});
function renderKPICards(study,fresh){
  const previous=$('kpi-study-select').value==='previous',source=previous?study.previous||{}:fresh||{},analysis=source.analysis||{},pairs=source.pairs_eligible||0;
  $('kpi-sample-note').textContent=previous?`${num(pairs)} parejas aptas del estudio anterior. Resultados exploratorios; no se mezclan con tus laboratorios nuevos.`:fresh?`${num(pairs)} parejas aptas de la cohorte nueva. Los fallos se conservan.`:'El estudio nuevo todavía no tiene resultados. Preparar una cohorte no acredita sus KPI.';
  $('kpi-scorecards').replaceChildren();
  for(const [key,title,target,suffix,formula] of [['TRTO_percent','TRTO · Reducción de tiempo',30,' %','(tiempo único − tiempo multi) / tiempo único'],['IDE_percent','IDE · Incremento de detección',20,' %','(TP multi − TP único) / TP único'],['ETV_ratio','ETV · Eficiencia por token',1.1,' ×','(tokens / TP) único ÷ (tokens / TP) multi']]){
    const value=analysis[key]?.mean,valid=Number.isFinite(value),card=el('article',undefined,'kpi-score'),head=el('div',undefined,'score-name');head.append(el('span',title),badge(valid?(value>=target?'complete':'partial'):'pending',valid?(value>=target?'Meta observada':'No alcanzada'):'Pendiente'));card.append(head,el('strong',valid?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(value)+suffix:'—'),el('p',`Meta ≥ ${target}${suffix} · ${num(analysis[key]?.n||pairs)} parejas`),el('code',formula));$('kpi-scorecards').append(card);
  }
}
$('kpi-study-select').addEventListener('change',renderStudy);
$('compare-runs').addEventListener('click',async()=>{
  const single=$('compare-single').value,multi=$('compare-multi').value;if(!single||!multi){showError('Necesitas una ejecución de agente único y otra multiagente para comparar.');return;}
  $('compare-runs').disabled=true;
  try{const response=await fetch('/api/compare?'+new URLSearchParams({single,multi,reference:$('compare-reference').value}),{signal:AbortSignal.timeout(10000)}),value=await response.json();if(!response.ok)throw new Error(value.error||'No se pudo leer la comparación.');const box=$('comparison-result');box.replaceChildren();
    if(!value.eligible){
      for(const item of value.assistance||[]){
        if(Number.isInteger(item.api_generations)&&item.api_generations>0)box.append(el('p',`${item.label}: sí utilizó la API (${item.api_generations} llamadas con generación). Decisiones de planificación aceptadas: ${item.planning_accepted}; revisiones aceptadas: ${item.reviews_accepted}.`,'field-note'));
      }
      const list=el('ul',undefined,'comparison-reasons');for(const reason of value.reasons)list.append(el('li',reason));box.append(list);return;
    }
    const metrics=el('div',undefined,'comparison-values');for(const [label,key,suffix] of [['Tiempo · TRTO','TRTO_percent',' %'],['Detección · IDE','IDE_percent',' %'],['Tokens / detección · ETV','ETV_ratio',' ×']]){const item=el('div',label);item.append(el('strong',Number.isFinite(value[key])?new Intl.NumberFormat('es',{maximumFractionDigits:2}).format(value[key])+suffix:value.truth_available?'No calculable':'Sin referencia'));metrics.append(item);}box.append(metrics,el('p',value.detection_note||'Verdaderos positivos contrastados con la misma referencia.','field-note'),el('p',value.note,'field-note'));
    if(value.evaluations){box.append(el('h3','Contraste con '+value.reference.name));const table=el('table'),head=el('tr');for(const label of ['Modo','Aciertos (TP)','Falsas alarmas (FP)','No detectadas (FN)','Protegidos (TN)'])head.append(el('th',label));table.append(head);value.evaluations.forEach((row,index)=>{const line=el('tr');for(const cell of [index===0?'Único':'Multiagente',row.TP,row.FP,row.FN,row.TN])line.append(el('td',cell));table.append(line);});const scroll=el('div',undefined,'table-scroll');scroll.append(table);box.append(scroll);for(const [i,row] of value.evaluations.entries())box.append(el('p',`${i===0?'Único':'Multiagente'}: ${row.unknown_negative_controls} controles negativos sin evaluar; ${row.unscored_findings} hallazgos sin etiqueta de referencia.`,'field-note'));}

  }catch(error){showError(error.message);}finally{$('compare-runs').disabled=false;}
});
form.addEventListener('submit',event=>{event.preventDefault();start('live');});
$('start-audit').addEventListener('click',()=>start('live'));
form.addEventListener('input',event=>{if(['ipv4','ipv6','interface','scope'].includes(event.target.name))personalCheckKey=null;updateOptions();});
form.addEventListener('change',event=>{updateOptions();if(event.target.name==='scope'){renderState();if(page==='new')showPage('new','replace');}});
$('simulate').addEventListener('click',()=>start('dry_run'));
$('acceptance-five-start').addEventListener('click',async()=>{const result=await post('/api/lab/acceptance-all',{});if(result)$('acceptance-five-note').textContent='Aceptación solicitada. Espera la actualización del recibo; las cinco comprobaciones se ejecutan sin IA y con cero tokens.';});
$('prepare-manual-next').addEventListener('click',prepareNextManualPosition);
$('use-manual-next').addEventListener('click',prepareNextManualPosition);
$('prepare-manual-run').addEventListener('click',()=>{form.querySelector('input[name=scope][value=empresa]').checked=true;$('manual-evaluation').checked=true;updateOptions();showSetupStep(1);renderState();showPage('new');});
$('check-lab').addEventListener('click',async()=>{if(options().scope==='personal'){if(!validateApplicationSelection()||!form.reportValidity())return;const value=options();const result=await post('/api/lab/personal/check',value);if(result)personalChecking={id:result.job.id,key:JSON.stringify({personal:value.personal,applications:value.applications||[]})};}else post(options().scenario?'/api/lab/suite/check':options().scope==='empresa'?'/api/lab/empresa/check':'/api/lab/check',options().scenario?{scenario:options().scenario}:{});});
let restoreScope='v2',restoreScenario='';
$('close-scenario').addEventListener('click',()=>{const value=options();if(value.scope==='empresa')post(value.scenario?'/api/lab/suite/down':'/api/lab/empresa/down',value.scenario?{scenario:value.scenario}:{});});
$('restore-lab').addEventListener('click',()=>{restoreScope=options().scope;restoreScenario=options().scenario||'';$('restore-copy').textContent=restoreScope==='empresa'?'Recrea los contenedores NovaFlow y conserva sus informes. Después pulsa Comprobar.':'Recrea los contenedores v2 y conserva sus informes anteriores.';$('restore-dialog').showModal();});
$('restore-dialog').addEventListener('close',()=>{if($('restore-dialog').returnValue==='restore')post(restoreScenario?'/api/lab/suite/restore':restoreScope==='empresa'?'/api/lab/empresa/restore':'/api/lab/restore',restoreScenario?{scenario:restoreScenario}:{});});
$('stop-audit').addEventListener('click',()=>$('stop-dialog').showModal());
$('stop-dialog').addEventListener('close',()=>{if($('stop-dialog').returnValue==='stop')post('/api/stop',{});});
for(const node of document.querySelectorAll('[data-page]'))node.addEventListener('click',()=>showPage(node.dataset.page));
document.querySelector('.nova-brand').addEventListener('click',event=>{event.preventDefault();showPage('thesis');});
for(const node of document.querySelectorAll('[data-tab]'))node.addEventListener('click',()=>selectTab(node.dataset.tab));
$('console-search').addEventListener('input',renderConsole);
$('console-category').addEventListener('change',renderConsole);
$('inventory-all').addEventListener('change',renderFindings);
$('console-pause').addEventListener('click',()=>{consolePaused=!consolePaused;$('console-pause').textContent=consolePaused?'Reanudar vista':'Pausar vista';$('console-pause').setAttribute('aria-pressed',String(consolePaused));if(consolePaused)$('console-note').textContent='Vista pausada. La auditoría continúa y sus registros se conservan.';else renderConsole();});
$('console-download').addEventListener('click',()=>{if(!detail)return;const text=`${detail.run.name}\n${detail.run.id}\n${detail.console?.note||''}\n\n${consoleText()}`;const url=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'}));const a=el('a');a.href=url;a.download='bitacora-auditoria.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('finding-search').addEventListener('input',renderFindings);$('history-search').addEventListener('input',renderHistory);
$('run-select').addEventListener('change',()=>{selectedKey=$('run-select').value;detail=null;followJob=null;pendingAudit=false;eventBaseline=null;recordedUntil=0;renderRunProvenance();loadDetail(selectedKey);});
$('architecture-details').addEventListener('toggle',()=>{if($('architecture-details').open&&!$('diagram').getAttribute('src'))$('diagram').src='/diagram';drawHalos();});
$('diagram').addEventListener('load',drawHalos);
setInterval(()=>{if(page==='live'&&tab==='architecture'){renderMap();drawHalos();}},250);
window.addEventListener('popstate',()=>showPage(location.hash.slice(1)||'thesis','none'));
window.addEventListener('hashchange',()=>showPage(location.hash.slice(1)||'thesis','none'));
updateOptions();showSetupStep(1);showPage(location.hash.slice(1)||'thesis','replace');poll();
