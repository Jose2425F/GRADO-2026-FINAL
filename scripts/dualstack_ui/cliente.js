'use strict';
// Portal de la empresa: solo lectura de las auditorías que Novaflow publica en esta cuenta.
(()=>{
const root=document.getElementById('portal');
const SEV={critical:['Crítica','critical','var(--sev-critical)'],high:['Alta','high','var(--sev-high)'],medium:['Media','medium','var(--sev-medium)'],low:['Baja','low','var(--sev-low)']};
const ORDER=['critical','high','medium','low'];
let runs=[],current=null,selectionVersion=0;

function h(tag,attrs,...children){
  const node=document.createElement(tag);
  for(const [key,value] of Object.entries(attrs||{})){
    if(value===undefined||value===null||value===false)continue;
    if(key==='class')node.className=value;else if(key==='style')node.style.cssText=value;else if(key.startsWith('on'))node.addEventListener(key.slice(2),value);else node.setAttribute(key,value===true?'':value);
  }
  for(const child of children.flat()){if(child===null||child===undefined||child===false)continue;node.append(child instanceof Node?child:document.createTextNode(String(child)));}
  return node;
}
function svg(path){const wrap=document.createElement('span');wrap.innerHTML=`<svg viewBox="0 0 20 20" fill="none" aria-hidden="true">${path}</svg>`;return wrap.firstChild;}
const ST='stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"';
const ICON={doc:`<path d="M5.5 2.8h6l3 3v11.4h-9Z" ${ST}/><path d="M8 10h4.5M8 13h4.5" ${ST}/>`,chart:`<path d="M4 15.5V8.5M8.5 15.5V4.5M13 15.5v-5M17 15.5H3" ${ST}/>`,shield:`<path d="M10 2.8 16 5.2v4.6c0 3.6-2.5 6.2-6 7.4-3.5-1.2-6-3.8-6-7.4V5.2Z" ${ST}/><path d="m7.3 10 1.9 1.9 3.6-3.8" ${ST}/>`};
const fmtDate=run=>run.started_display||(run.started_at?new Date(run.started_at).toLocaleString('es-CO',{dateStyle:'long',timeStyle:'short'}):'');
async function getJSON(url){const response=await fetch(url,{cache:'no-store'});if(!response.ok)throw new Error('No se pudo cargar la información.');return response.json();}
function reportURL(key,audience){return `/report?key=${encodeURIComponent(key)}&audience=${audience}`;}

function empty(){
  root.replaceChildren(h('div',{class:'portal-empty'},
    h('span',{class:'icon'},svg(ICON.shield)),
    h('h2',null,'Todavía no hay resultados publicados'),
    h('p',null,'Cuando Novaflow termine la auditoría de tu red, aquí verás el resumen, el plan de corrección y los informes para descargar.')));
}

function posture(detail){
  const rv=detail.report_view||{},counts=rv.severity_counts||{},total=ORDER.reduce((n,k)=>n+(counts[k]||0),0);
  const hosts=rv.hosts||[],clean=hosts.filter(x=>!x.findings&&!x.issues).length,pending=hosts.filter(x=>!x.findings&&x.issues).length,pct=hosts.length?Math.round(clean/hosts.length*100):null;
  const worst=ORDER.find(k=>counts[k]);
  const ring=h('div',{class:'posture-ring',style:`--p:${pct??0};--ring:${pct===null?'var(--line-2)':pct>=80?'#12b76a':pct>=50?'var(--sev-medium)':'var(--sev-high)'}`},h('div',null,h('strong',null,pct===null?'—':pct+'%'),h('small',null,pct===null?'Sin datos de equipos':'de equipos sin hallazgos')));
  const bar=h('div',{class:'severity-bar',role:'img','aria-label':`${total} hallazgos por severidad`});
  for(const key of ORDER)if(counts[key])bar.append(h('i',{class:'sev-'+key,style:`width:${counts[key]/total*100}%`}));
  const legend=h('div',{class:'severity-legend'},ORDER.map(key=>h('span',null,h('i',{class:'dot sev-'+key}),SEV[key][0],' ',h('b',null,counts[key]||0))));
  return h('section',{class:'posture'},ring,h('div',null,
    h('h2',null,total?`${total} ${total===1?'hallazgo confirmado':'hallazgos confirmados'}`:'Sin hallazgos confirmados'),
    h('p',null,total?`La prioridad más alta es ${SEV[worst][0].toLowerCase()}. Empieza por el plan de corrección de abajo.`:hosts.length?'Las pruebas realizadas no confirmaron problemas en los equipos revisados.':'No hay evidencia suficiente para evaluar los equipos de esta auditoría.'),
    pending?h('p',{class:'pending-note'},`${pending} ${pending===1?'equipo quedó':'equipos quedaron'} con una comprobación incompleta: la prueba no dio un resultado concluyente y Novaflow la revisará.`):null,
    total?bar:null,total?legend:null));
}

function facts(detail){
  const rv=detail.report_view||{},b=detail.brief||{};
  const items=[['Equipos revisados',rv.scope_count??b.assets??'—'],['Equipos con hallazgos',b.affected??0],['Acciones de corrección',(rv.priorities||[]).length]];
  return h('div',{class:'portal-facts'},items.map(([label,value])=>h('div',null,h('span',null,label),h('strong',null,String(value)))));
}

function side(detail){
  const key=detail.run.key;
  const reports=h('section',{class:'report-card'},h('h2',null,'Informes'),h('p',null,'Ábrelos y guárdalos en PDF desde el botón de imprimir.'),
    h('div',{class:'report-links'},
      h('a',{class:'report-link',href:reportURL(key,'executive'),target:'_blank',rel:'noopener'},svg(ICON.chart),h('span',null,h('strong',null,'Informe ejecutivo'),h('small',null,'Para gerencia: riesgos y decisiones'))),
      h('a',{class:'report-link',href:reportURL(key,'technical'),target:'_blank',rel:'noopener'},svg(ICON.doc),h('span',null,h('strong',null,'Informe técnico'),h('small',null,'Para TI: evidencia y corrección')))));
  const list=h('div',{class:'audit-list'},runs.map(run=>h('button',{type:'button',class:'audit-item','aria-current':run.key===key?'true':'false',onclick:()=>select(run.key)},
    h('span',null,h('strong',null,run.name||'Auditoría'),h('small',null,fmtDate(run))),
    h('span',{class:'pill '+((run.findings||0)?'amber':'green')},(run.findings||0)?`${run.findings} hallazgos`:'Sin hallazgos'))));
  const history=h('section',{class:'report-card'},h('h2',null,'Auditorías publicadas'),h('p',null,runs.length===1?'1 auditoría disponible.':`${runs.length} auditorías disponibles.`),list);
  return h('aside',{class:'portal-side'},reports,history);
}

function plan(detail){
  const items=(detail.report_view?.priorities||[]).slice().sort((a,b)=>ORDER.indexOf(a.severity)-ORDER.indexOf(b.severity));
  if(!items.length)return null;
  return h('section',{class:'portal-section'},h('h2',null,'Plan de corrección'),h('p',null,'Ordenado por prioridad. Cada acción indica qué hacer, quién debería encargarse y cómo comprobar que quedó resuelta.'),
    h('div',{class:'plan'},items.map((item,i)=>{
      const sev=SEV[item.severity]||['Por clasificar','unknown','var(--line-2)'];
      const targets=(item.endpoints||[]).map(e=>e.address+(e.ports?.length?':'+e.ports.join(','):''));
      return h('article',{class:'plan-item',style:`--sev:${sev[2]}`},
        h('span',{class:'num'},String(i+1).padStart(2,'0')),
        h('div',null,h('h3',null,item.title),h('p',null,item.impact),h('p',null,h('b',null,'Qué hacer: '),item.fix),
          targets.length?h('div',{class:'targets'},targets.map(t=>h('span',null,t))):null,
          h('p',{class:'owner'},h('b',null,'Responsable sugerido: '),item.owner||'Sistemas',' · ',h('b',null,'Cómo verificar: '),item.verification||'Repetir la prueba y conservar la evidencia.')),
        h('span',{class:'sev-tag '+sev[1]},sev[0]));
    })));
}

function hostsTable(detail){
  const hosts=detail.report_view?.hosts||[];if(!hosts.length)return null;
  const rows=hosts.map(host=>h('tr',null,
    h('td',null,host.address),
    h('td',null,host.services?.length?host.services.map(s=>`${s.port}/${s.name}`).join(' · '):h('span',{class:'muted'},host.activity||'Sin servicios abiertos')),
    h('td',null,String(host.findings||0)),
    h('td',null,h('span',{class:'host-state '+(host.findings?'alert':host.issues?'review':'ok')},host.conclusion||''))));
  return h('section',{class:'portal-section'},h('h2',null,'Resultado por equipo'),h('p',null,'Servicios encontrados y conclusión para cada dirección IPv4 o IPv6 revisada.'),
    h('div',{class:'table-scroll'},h('table',{class:'host-table'},h('thead',null,h('tr',null,h('th',null,'Equipo'),h('th',null,'Servicios abiertos'),h('th',null,'Hallazgos'),h('th',null,'Conclusión'))),h('tbody',null,rows))));
}

function coverage(detail){
  const stages=detail.report_view?.progress?.stages||[];if(!stages.length)return null;
  return h('section',{class:'portal-section'},h('h2',null,'Qué se revisó'),h('p',null,detail.brief?.summary||''),
    h('div',{class:'portal-facts'},stages.map(stage=>h('div',null,h('span',null,stage.label),h('strong',null,String(stage.total)),h('span',null,`${stage.successful} completadas`)))));
}

function render(detail){
  const run=detail.run;
  root.replaceChildren(
    h('div',{class:'portal-head'},h('div',null,h('p',{class:'eyebrow'},'Resultados de seguridad'),h('h1',null,run.name||'Auditoría de seguridad'),h('p',null,`Realizada el ${fmtDate(run)}. ${detail.report_view?.headline||''}`))),
    h('div',{class:'portal-grid'},h('div',null,posture(detail),facts(detail)),side(detail)),
    ...[plan(detail),hostsTable(detail),coverage(detail)].filter(Boolean));
  window.scrollTo({top:0});
}

async function select(key){
  current=key;const version=++selectionVersion;
  try{const detail=await getJSON('/api/run?key='+encodeURIComponent(key));if(version===selectionVersion)render(detail);}
  catch(error){if(version!==selectionVersion)return;root.replaceChildren(h('div',{class:'portal-empty'},h('h2',null,'No se pudo abrir la auditoría'),h('p',null,error.message)));}
}

async function boot(){
  try{
    const state=await getJSON('/api/state');
    runs=(state.runs||[]).filter(run=>run.status!=='running').sort((a,b)=>String(b.started_at||'').localeCompare(String(a.started_at||'')));
    if(!runs.length){empty();return;}
    await select(runs[0].key);
  }catch(error){root.replaceChildren(h('div',{class:'portal-empty'},h('h2',null,'No pudimos cargar tus resultados'),h('p',null,'Revisa tu conexión y recarga la página.')));}
}
boot();
})();
