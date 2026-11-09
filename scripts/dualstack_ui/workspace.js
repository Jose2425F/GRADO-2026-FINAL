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
 $('overview-labs').textContent=`${acceptance?.completed_labs||0} / 5`;
 $('overview-runs').textContent=String((state.runs||[]).length);
 $('overview-pairs').textContent=`${manual?.completed_pairs||0} / ${manual?.planned_pairs||25}`;
 $('overview-api').textContent=value.api_configured?'Configurado':'Pendiente';
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
$('launch-personal')?.addEventListener('click',()=>chooseBench('personal'));
$('launch-v2')?.addEventListener('click',()=>chooseBench('v2'));
$('launch-applications')?.addEventListener('click',()=>{chooseBench('personal');showSetupStep(2);$('web-settings').open=true;});
for(const button of document.querySelectorAll('[data-own-lab]'))button.addEventListener('click',()=>chooseBench('personal'));
renderWorkspace();

function renderScenarioCards(){
 if(!$('suite-labs')){const section=el('section',undefined,'card');section.id='suite-labs';section.style.marginTop='24px';section.append(el('h2','Cuatro escenarios adicionales'),el('p','Casos y referencias separados. La dificultad describe carga y mezcla de controles; no añade tipos de explotación. Activa uno por vez.','field-note'));const progress=el('p',undefined,'notice');progress.id='suite-live-note';const grid=el('div',undefined,'role-grid');grid.id='suite-lab-grid';section.append(progress,grid);$('page-lab').append(section);}
 const accepted=state.acceptance_five||state.suite_acceptance||{},active=state.suite_progress?.active||state.acceptance_five?.active;
 $('suite-live-note').textContent=active?'Aceptación u operación de escenarios en curso. Cero API durante la aceptación.':accepted.status==='accepted'?'Los cuatro escenarios aprobaron su aceptación funcional sin IA. Falta preparar y congelar la evaluación con API.':accepted.status==='running'?'La aceptación aún no tiene cierre confirmado; consulta el estado antes de auditar.':accepted.status==='stopped'?'Aceptación detenida con incidencias: revisar antes de medir KPI.':'Escenarios preparados; la aceptación funcional se registra por separado.';
 $('suite-lab-grid').replaceChildren();
 for(const item of state.scenario_catalog||[]){const card=el('article',undefined,'suite-card card'),check=(accepted.scenarios||[]).find(x=>x.id===item.id);card.append(el('small',item.difficulty),el('h3',item.name),el('p',`${item.targets} objetivos · ${item.tasks} tareas · ${item.containers} contenedores`),el('p',item.detail));if(check)card.append(el('p',check.status==='accepted'?`Aceptación: ${check.evaluation.tasks_valid}/${check.expected_tasks} válidas; TP ${check.evaluation.TP}, FP ${check.evaluation.FP}, FN ${check.evaluation.FN}, TN ${check.evaluation.TN}.`:check.status==='running'?'Aceptación en curso, sin IA.':'Estado de aceptación: '+check.status,'field-note'));const button=el('button','Configurar este escenario','button');button.type='button';button.addEventListener('click',()=>{chooseBench('empresa');$('scenario').value=item.id;updateOptions();});card.append(button);$('suite-lab-grid').append(card);}
}

// ---- Tipo de auditoría: red de una empresa (IPv4 + IPv6) o laboratorio del estudio ----
function syncScopeSwitch(){const current=options().scope;for(const b of document.querySelectorAll('[data-scope-pick]'))b.setAttribute('aria-pressed',String(b.dataset.scopePick===current));}
for(const b of document.querySelectorAll('[data-scope-pick]'))b.addEventListener('click',()=>{const input=form.querySelector(`input[name=scope][value="${b.dataset.scopePick}"]`);if(!input||input.checked)return;input.checked=true;input.dispatchEvent(new Event('change',{bubbles:true}));syncScopeSwitch();});
syncScopeSwitch();setInterval(syncScopeSwitch,700);

// ---- Publicación: el administrador entrega los resultados a la cuenta de una empresa ----
let publishUsers=null,publishMap={};
async function loadPublishing(){
 if(document.body.dataset.role!=='admin')return;
 const [users,pubs]=await Promise.all([fetch('/api/admin/users',{cache:'no-store'}).then(r=>r.json()),fetch('/api/admin/publications',{cache:'no-store'}).then(r=>r.json())]);
 publishUsers=(users.users||[]).filter(u=>u.role!=='admin');publishMap=pubs.publications||{};
}
function renderPublish(){
 const card=$('publish-card');if(!card)return;
 const run=detail?.run,ready=Boolean(run&&detail.brief?.final&&run.status!=='running');
 card.hidden=!ready||document.body.dataset.role!=='admin'||document.body.dataset.supervising==='true';if(card.hidden)return;
 const published=publishMap[run.key]||[],signature=run.key+JSON.stringify(published)+JSON.stringify((publishUsers||[]).map(u=>[u.id,u.active]));
 if(card.dataset.signature===signature)return;card.dataset.signature=signature;
 const list=$('publish-targets');list.replaceChildren();
 if(!publishUsers){list.append(el('p','Cargando cuentas de empresa…','field-note'));return;}
 if(!publishUsers.length){const box=el('div',undefined,'publish-empty');box.append(el('strong','Todavía no hay cuentas de empresa'),el('p','Crea una en Empresas y accesos para entregarle resultados.'));const link=document.createElement('a');link.href='/admin';link.className='button';link.textContent='Crear cuenta de empresa';box.append(link);list.append(box);return;}
 for(const user of publishUsers){
  const entry=published.find(p=>p.user===user.id),row=el('div',undefined,'publish-row'+(entry?' is-published':'')),copy=el('div');
  const when=entry?.published_at?new Date(entry.published_at).toLocaleString('es-CO',{dateStyle:'medium',timeStyle:'short'}):'';
  copy.append(el('strong',user.name),el('small',entry?`Publicada · ${when}`:user.active?'Aún no la ve':'Cuenta suspendida'));
  const button=el('button',entry?'Retirar':'Publicar','button '+(entry?'ghost':'primary'));button.type='button';button.disabled=!entry&&!user.active;
  button.addEventListener('click',()=>togglePublish(run.key,user,!entry,button));
  row.append(el('span',user.name.slice(0,1).toUpperCase(),'publish-avatar'),copy,button);list.append(row);
 }
}
async function togglePublish(key,user,publish,button){
 button.disabled=true;$('publish-note').textContent='';
 try{
  const response=await fetch(publish?'/api/admin/publish':'/api/admin/unpublish',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({key,user:user.id})}),data=await response.json();
  if(!response.ok)throw new Error(data.error||'No se pudo completar la operación.');
  $('publish-note').textContent=publish?`Listo: ${user.name} ya ve esta auditoría en su portal.`:`Se retiró la auditoría del portal de ${user.name}.`;
  await loadPublishing();
 }catch(error){$('publish-note').textContent=error.message;}
 finally{button.disabled=false;$('publish-card').dataset.signature='';renderPublish();}
}
loadPublishing().catch(()=>{});setInterval(renderPublish,800);

// ---- Descubrimiento: encontrar los equipos de la red de la empresa y elegir cuáles auditar ----
let discovered=[];
async function loadInterfaces(){
 if(document.body.dataset.role!=='admin'||!$('discover-interface'))return;
 try{
  const data=await fetch('/api/lab/personal/interfaces',{cache:'no-store'}).then(r=>r.json()),select=$('discover-interface'),previous=select.value;
  select.replaceChildren();
  if(!data.interfaces?.length){select.append(new Option('No hay redes encendidas: enciende un laboratorio en Laboratorios',''));$('discover-run').disabled=true;return;}
  $('discover-run').disabled=false;
  // Agrupa las interfaces por laboratorio para saber qué red simulada se está auditando.
  const groups=new Map();
  for(const item of data.interfaces){const key=item.lab||'Otras redes del servidor';if(!groups.has(key))groups.set(key,[]);groups.get(key).push(item);}
  for(const [label,items] of groups){
   const group=document.createElement('optgroup');group.label=label;
   for(const item of items){const ranges=[...item.ipv4,...item.ipv6].join(' · ');group.append(new Option(`${item.zone?item.zone+' · ':''}${ranges} (${item.name})`,item.name));}
   select.append(group);
  }
  if([...select.options].some(option=>option.value===previous))select.value=previous;
 }catch{$('discover-interface').replaceChildren(new Option('No se pudieron cargar las interfaces',''));}
}
// Al encender o apagar un laboratorio cambian las redes disponibles: se recarga la lista.
let interfacesRuntime='';
setInterval(()=>{const now=JSON.stringify(state.lab_runtime||{});if(now!==interfacesRuntime){const first=!interfacesRuntime;interfacesRuntime=now;if(!first)loadInterfaces();}},2000);
function selectedHosts(){return [...document.querySelectorAll('#discover-hosts input:checked')].map(input=>discovered[Number(input.value)]);}
function updateDiscoverCount(){const chosen=selectedHosts(),v4=chosen.reduce((n,h)=>n+h.ipv4.length,0),v6=chosen.reduce((n,h)=>n+h.ipv6.length,0);$('discover-count').textContent=`${chosen.length} de ${discovered.length} equipos · ${v4} IPv4 · ${v6} IPv6`;$('discover-use').disabled=!chosen.length;for(const row of document.querySelectorAll('#discover-hosts tr'))row.classList.toggle('is-selected',row.querySelector('input').checked);$('discover-all').checked=chosen.length===discovered.length&&discovered.length>0;}
async function runDiscovery(){
 const name=$('discover-interface').value;if(!name)return;
 const button=$('discover-run');button.disabled=true;$('discover-results').hidden=true;
 $('discover-note').replaceChildren(el('span',undefined,'discover-busy'),document.createTextNode(`Buscando equipos en ${name}… el barrido IPv4 puede tardar hasta un minuto.`));
 try{
  const response=await fetch('/api/lab/personal/discover',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({interface:name})}),data=await response.json();
  if(!response.ok)throw new Error(data.error||'No se pudo descubrir la red.');
  discovered=data.hosts||[];const body=$('discover-hosts');body.replaceChildren();
  discovered.forEach((host,index)=>{const box=el('input');box.type='checkbox';box.value=String(index);box.checked=true;box.setAttribute('aria-label','Auditar '+(host.ipv4[0]||host.ipv6[0]));box.addEventListener('change',updateDiscoverCount);const row=el('tr');const c=el('td');c.append(box);row.append(c,el('td',host.ipv4.join(', ')||'—'),el('td',host.ipv6.join(', ')||'—'),el('td',host.mac||'—','mac'));body.append(row);});
  const v4=discovered.reduce((n,h)=>n+h.ipv4.length,0),v6=discovered.reduce((n,h)=>n+h.ipv6.length,0);
  $('discover-note').textContent=discovered.length?`${discovered.length} equipos encontrados en ${data.seconds} s: ${v4} con IPv4 y ${v6} con IPv6. Desmarca los que no quieras auditar.`:`No respondió ningún equipo en ${name}.`;
  $('discover-results').hidden=!discovered.length;$('discover-results').dataset.interface=name;updateDiscoverCount();
 }catch(error){$('discover-note').textContent=error.message;}
 finally{button.disabled=false;}
}
function useDiscovered(){
 const chosen=selectedHosts();if(!chosen.length)return;
 const set=(id,value)=>{const input=$(id);input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));};
 set('personal-ipv4',chosen.flatMap(h=>h.ipv4).join(','));set('personal-ipv6',chosen.flatMap(h=>h.ipv6).join(','));
 const iface=$('personal-interface'),name=$('discover-results').dataset.interface;
 if(name){if(![...iface.options].some(o=>o.value===name))iface.append(new Option(name,name));iface.value=name;iface.dispatchEvent(new Event('change',{bubbles:true}));}
 $('discover-note').textContent=`Listo: ${chosen.length} equipos cargados en el alcance. Revísalos abajo y continúa.`;
 $('personal-ipv4').scrollIntoView({behavior:'smooth',block:'center'});
}
if($('discover-run')){
 $('discover-run').addEventListener('click',runDiscovery);$('discover-use').addEventListener('click',useDiscovered);
 $('discover-all').addEventListener('change',event=>{for(const box of document.querySelectorAll('#discover-hosts input'))box.checked=event.target.checked;updateDiscoverCount();});
 loadInterfaces();
}

// ---- Presupuesto de tokens: campo libre con atajos ----
function syncTokenPresets(){const value=Number($('tokens').value);for(const b of document.querySelectorAll('[data-tokens]'))b.setAttribute('aria-pressed',String(Number(b.dataset.tokens)===value));}
for(const b of document.querySelectorAll('[data-tokens]'))b.addEventListener('click',()=>{const input=$('tokens');if(Number(b.dataset.tokens)>Number(input.max||80000))return;input.value=b.dataset.tokens;input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));syncTokenPresets();});
$('tokens').addEventListener('input',syncTokenPresets);
$('tokens').addEventListener('change',()=>{const input=$('tokens'),max=Number(input.max||80000),n=Math.round(Number(input.value));if(!Number.isFinite(n)||n<256)input.value='256';else if(n>max)input.value=String(max);else input.value=String(n);syncTokenPresets();});
syncTokenPresets();setInterval(syncTokenPresets,1000);
// ---- Redes simuladas: encender, comprobar y apagar los laboratorios Docker desde Laboratorios ----
let labSwitchSignature='',labAutoCheck=null,labNoteAt=0;
const LAB_ACTIONS={integrado:{restore:'/api/lab/empresa/restore',check:'/api/lab/empresa/check',down:'/api/lab/empresa/down'},
  suite:{restore:'/api/lab/suite/restore',check:'/api/lab/suite/check',down:'/api/lab/suite/down'}};
function labRows(){
  const base={id:'integrado',name:'NovaFlow · banco integrado',targets:10,containers:12,tasks:32,difficulty:'Banco principal',kind:'integrado',lab:state.empresa_lab||{status:'unknown'}};
  return [base,...(state.scenario_catalog||[]).map(item=>({...item,kind:'suite',lab:state.scenario_labs?.[item.id]||{status:'unknown'}}))];
}
function labJob(row){
  const actions=row.kind==='integrado'?['empresa_check','empresa_restore','empresa_down']:['suite_check','suite_restore','suite_down'];
  return [...(state.jobs||[])].reverse().find(job=>actions.includes(job.action)&&(row.kind==='integrado'||job.options?.scenario===row.id))||null;
}
function labStatus(row){
  const job=labJob(row),status=row.lab.status;
  if(job&&['queued','running'].includes(job.status))return {kind:'busy',label:job.action.endsWith('_down')?'Apagando…':job.action.endsWith('_check')?'Comprobando…':'Encendiendo…',note:job.message};
  if(status==='restoring')return {kind:'busy',label:'Encendiendo…',note:row.lab.message};
  if(status==='checking')return {kind:'busy',label:'Comprobando…',note:row.lab.message};
  // Docker dice qué está encendido de verdad; lo que el panel recuerda puede quedar viejo
  // si el laboratorio se encendió o apagó desde otra sesión, por consola o tras reiniciar.
  const runtime=state.lab_runtime||{};
  if(runtime.available===true){
    const running=runtime[row.id]||0,expected=row.containers||0;
    if(running===0)return {kind:'off',label:'Apagado',note:status==='error'||job?.status==='failed'?'La comprobación no encontró la red encendida. Pulsa Encender.':'Enciéndelo para auditarlo.'};
    if(expected&&running<expected)return {kind:'partial',label:`Encendido a medias · ${running} de ${expected}`,note:'Faltan contenedores. Vuelve a encenderlo para recrearlos.'};
    if(status==='ready')return {kind:'on',label:'Encendido',note:'Listo para auditar.'};
    if(status==='error')return {kind:'error',label:'Necesita atención',note:job?.message||row.lab.message};
    return {kind:'warm',label:'Encendido · falta comprobar',note:'Pulsa Comprobar para dejarlo listo para auditar.'};
  }
  if(status==='ready')return {kind:'on',label:'Encendido',note:'Listo para auditar.'};
  if(status==='error')return {kind:'error',label:'Necesita atención',note:job?.message||row.lab.message};
  if(job?.status==='complete'&&job.action.endsWith('_restore'))return {kind:'warm',label:'Encendido · falta comprobar',note:'Pulsa Comprobar para dejarlo listo para auditar.'};
  if(job?.status==='complete'&&job.action.endsWith('_down'))return {kind:'off',label:'Apagado',note:'Contenedores detenidos.'};
  return {kind:'off',label:'Apagado o sin comprobar',note:'Enciéndelo para auditarlo, o compruébalo si ya estaba encendido.'};
}
async function labAction(row,action,button){
  button.disabled=true;
  const path=LAB_ACTIONS[row.kind][action],body=row.kind==='integrado'?{}:{scenario:row.id};
  const result=await post(path,body);
  if(result&&row.kind==='integrado'&&action==='restore')labAutoCheck=result.job?.id||null;
  labNoteAt=Date.now();
  $('lab-switch-note').textContent=result?`${row.name}: ${action==='restore'?'encendiendo la red simulada. Tarda entre 1 y 3 minutos.':action==='down'?'apagando los contenedores.':'comprobando que la red responde.'}`:'';
  labSwitchSignature='';renderLabSwitch();
}
function renderLabSwitch(){
  const list=$('lab-switch-list');if(!list||document.body.dataset.role!=='admin')return;
  // Tras encender el banco integrado se comprueba solo, para dejarlo listo para auditar.
  if(labAutoCheck){const job=(state.jobs||[]).find(item=>item.id===labAutoCheck);
    if(job&&job.status==='complete'&&!state.busy){labAutoCheck=null;post(LAB_ACTIONS.integrado.check,{});}
    else if(job&&['failed','interrupted','cancelled'].includes(job.status))labAutoCheck=null;}
  const rows=labRows(),statuses=rows.map(labStatus),busy=Boolean(state.busy)||posting;
  // El aviso de la última acción se retira cuando la operación termina.
  if(labNoteAt&&Date.now()-labNoteAt>4000&&!busy&&!statuses.some(x=>x.kind==='busy')){$('lab-switch-note').textContent='';labNoteAt=0;}
  const activeSuite=rows.find((row,index)=>row.kind==='suite'&&['on','warm','partial'].includes(statuses[index].kind));
  const signature=JSON.stringify([busy,rows.map(r=>[r.id,r.name]),statuses,activeSuite?.id]);
  if(signature===labSwitchSignature)return;labSwitchSignature=signature;
  const fragment=document.createDocumentFragment();
  rows.forEach((row,index)=>{
    const status=statuses[index],item=el('article',undefined,'lab-switch-row is-'+status.kind),copy=el('div',undefined,'lab-switch-copy');
    const title=el('div',undefined,'lab-switch-title');title.append(el('strong',row.name),el('span',status.label,'lab-switch-state'));
    copy.append(title,el('small',`${row.difficulty?row.difficulty+' · ':''}${row.targets} objetivos · ${row.containers} contenedores`),el('p',status.note||'','lab-switch-note'));
    const actions=el('div',undefined,'lab-switch-actions'),blocked=row.kind==='suite'&&activeSuite&&activeSuite.id!==row.id;
    const add=(label,action,kind)=>{const b=el('button',label,'button '+kind);b.type='button';b.disabled=busy||status.kind==='busy'||(action==='restore'&&blocked);b.addEventListener('click',()=>labAction(row,action,b));actions.append(b);return b;};
    const docker=state.lab_runtime?.available===true;
    if(status.kind==='on'||status.kind==='warm'){add('Comprobar','check',status.kind==='warm'?'primary':'ghost');add('Apagar','down','ghost');}
    else if(status.kind==='partial'){add('Encender','restore','primary');add('Apagar','down','ghost');}
    else{const on=add('Encender','restore','primary');if(blocked)on.title=`Apaga primero ${activeSuite.name}: solo puede haber un escenario adicional encendido.`;if(!docker||status.kind!=='off')add('Comprobar','check','ghost');}
    if(blocked&&!['on','warm','partial'].includes(status.kind))copy.append(el('p',`Apaga primero ${activeSuite.name} para encender este.`,'lab-switch-hint'));
    item.append(el('span',undefined,'lab-switch-dot'),copy,actions);fragment.append(item);
  });
  list.replaceChildren(fragment);
}
renderLabSwitch();setInterval(renderLabSwitch,1000);

// ---- Trazabilidad corta: qué eligió la IA, qué encontró y cómo se comprobó ----
let traceSignature='';
const TRACE_FAMILIES=[
  {id:'discovery',name:'Descubrimiento',agents:['ipv4_services','ipv6_services'],conditions:[]},
  {id:'credentials',name:'Credenciales por defecto',agents:['ipv4_credentials'],conditions:['ssh_default_credential','ftp_default_credential','postgres_default_credential','http_get_default_credential']},
  {id:'applications',name:'Aplicaciones web',agents:['application_access'],conditions:['object_authorization','file_boundary','ipv6_authorization_gap']},
  {id:'ndp',name:'IPv6 · routers y vecinos',agents:['ipv6_ndp'],conditions:['untrusted_router_advertisement','neighbor_override','dad_interference']},
  {id:'fragmentation',name:'IPv6 · fragmentación',agents:['ipv6_fragmentation'],conditions:[]},
];
function traceFamily(agent){return TRACE_FAMILIES.find(f=>f.agents.includes(agent))||{id:'other',name:'Otras pruebas',agents:[],conditions:[]};}
function renderTrace(){
  const card=$('trace-card');if(!card)return;
  const current=typeof detail!=='undefined'&&detail&&detail.run.key===selectedKey?detail:null;
  const tasks=current?.run?.tasks||[];
  if(!current||!tasks.length){card.hidden=true;traceSignature='';return;}
  const run=current.run,cards=current.brief?.cards||[],evaluation=run.evaluation||{},decisions=current.assistance?.decisions||[];
  const signature=JSON.stringify([run.key,run.status,tasks.map(t=>[t.id,t.status,t.reason]),cards.map(c=>c.id),evaluation,decisions.length]);
  if(signature===traceSignature)return;traceSignature=signature;
  const groups=new Map();
  for(const task of tasks){
    const family=traceFamily(task.agent),row=groups.get(family.id)||{family,total:0,chosen:0,pending:0,found:0};
    row.total++;
    if(task.status==='skipped'&&task.reason==='task_budget_not_selected'){}else if(['pending','running','queued'].includes(task.status))row.pending++;else row.chosen++;
    groups.set(family.id,row);
  }
  for(const item of cards){const condition=String(item.id||'').split(':')[1],family=TRACE_FAMILIES.find(f=>f.conditions.includes(condition));const row=family&&groups.get(family.id);if(row)row.found++;}
  const budget=current.detection_budget||run.detection_budget||{},executed=tasks.filter(t=>!(t.status==='skipped'&&t.reason==='task_budget_not_selected')).length;
  const withAI=run.llm?.status!=='disabled'&&Boolean(run.llm?.model);
  card.hidden=false;
  $('trace-summary').textContent=budget.applied?`La IA eligió ${executed} de ${tasks.length} pruebas; el límite del protocolo era ${budget.task_limit}.`:`Se ejecutaron ${executed} de ${tasks.length} pruebas del catálogo.`;
  const steps=$('trace-steps');steps.replaceChildren();
  const step=(n,title,text)=>{const li=el('li');li.append(el('span',n,'trace-n'),el('div'));li.lastChild.append(el('strong',title),el('small',text));steps.append(li);};
  step('1','Exploró la red','Descubrió equipos, puertos y servicios por IPv4 e IPv6.');
  step('2',withAI?'La IA decidió qué probar':'Plan fijo, sin IA',withAI?`${decisions.length} ${decisions.length===1?'decisión registrada':'decisiones registradas'} del modelo, sin ver la referencia del evaluador.`:'Se siguió el orden del catálogo.');
  step('3','Ejecutó las pruebas elegidas',`${executed} pruebas con herramientas reales; ${tasks.length-executed} quedaron sin elegir.`);
  step('4','Validó cada hallazgo',`${cards.length} ${cards.length===1?'hallazgo confirmado':'hallazgos confirmados'} con evidencia independiente.`);
  const table=$('trace-table');table.replaceChildren();
  for(const row of [...groups.values()].sort((a,b)=>TRACE_FAMILIES.indexOf(a.family)-TRACE_FAMILIES.indexOf(b.family))){
    const tr=el('tr'),bar=el('span',undefined,'trace-bar');bar.style.setProperty('--p',row.total?row.chosen/row.total:0);
    const chosen=el('td');chosen.append(bar,el('span',`${row.chosen} de ${row.total}`));
    tr.append(el('th',row.family.name),chosen,el('td',row.family.conditions.length?String(row.found):'—'));
    if(row.chosen===0)tr.className='is-skipped';table.append(tr);
  }
  const verdict=$('trace-verdict');verdict.replaceChildren();
  if(Number.isInteger(evaluation.TP)){
    const positives=(evaluation.TP||0)+(evaluation.FN||0);
    verdict.append(el('strong',`Contra la referencia del laboratorio: encontró ${evaluation.TP} de ${positives} vulnerabilidades.`));
    const parts=[];if(evaluation.FN)parts.push(`${evaluation.FN} sin encontrar`);parts.push(`${evaluation.FP||0} falsas alarmas`);if(Number.isInteger(evaluation.TN))parts.push(`${evaluation.TN} controles seguros confirmados`);
    verdict.append(el('small',parts.join(' · ')+'. La referencia solo se usa al final para calificar; la IA nunca la ve.'));
    verdict.hidden=false;
  }else verdict.hidden=true;
}
setInterval(renderTrace,1000);
