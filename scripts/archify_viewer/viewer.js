/* Observación de snapshots reales. Los halos están fuera del SVG exportable. */
'use strict';
const runSelect = document.querySelector('#run');
const frame = document.querySelector('#diagram');
const connection = document.querySelector('#connection');
const summary = document.querySelector('#summary');
const agents = document.querySelector('#agents');
const events = document.querySelector('#events');
const halos = document.querySelector('#halos');
let state = {runs: []}, connected = false, selected = null, recordingUntil = 0;
let previousEvents = null, previousKey = null;
const names = {ipv4_services:'IPv4 · Servicios', ipv4_credentials:'IPv4 · Credenciales', ipv6_ndp:'IPv6 · NDP/SLAAC', ipv6_fragmentation:'IPv6 · Fragmentación', application_access:'Acceso de aplicación dual-stack'};
const eventKey = event => JSON.stringify([event.time, event.kind, event.component, event.task, event.status]);

function render() {
  selected = state.runs.find(run => run.key === runSelect.value) || null;
  agents.replaceChildren(); events.replaceChildren();
  if (!connected || !selected) {
    summary.textContent = connected ? 'No hay una corrida disponible. Ejecuta el auditor desde su terminal habitual.' : 'Sin conexión. Los indicadores se apagaron; el último estado ya no se considera actual.';
    previousEvents = null; previousKey = null; recordingUntil = 0;
    drawHalos(); return;
  }
  const tasks = selected.tasks || [];
  const active = selected.status === 'running' ? tasks.filter(task => task.status === 'running') : [];
  summary.textContent = `${selected.id} · ${selected.status} · ${selected.mode === 'live' ? 'ejecución de laboratorio' : 'simulación / dry run'} · ${active.length} tareas activas · ${selected.finished}/${selected.total} terminadas.`;
  const groups = new Map();
  for (const task of tasks) {
    const group = groups.get(task.agent) || {total:0, active:0, finished:0};
    group.total++; group.active += active.includes(task) ? 1 : 0;
    group.finished += !['pending','running'].includes(task.status) ? 1 : 0;
    groups.set(task.agent, group);
  }
  for (const [role, group] of groups) {
    const item = document.createElement('div'); item.className = `agent${group.active ? ' active' : ''}`;
    item.textContent = names[role] || role || 'Agente sin identificar';
    const detail = document.createElement('small');
    detail.textContent = `${group.active} activas · ${group.finished}/${group.total} terminadas`;
    item.append(detail); agents.append(item);
  }
  const recent = selected.events || [];
  const keys = new Set(recent.map(eventKey));
  // La primera muestra y los cambios de corrida establecen una línea base.
  if (previousKey === selected.key && previousEvents && recent.some(event => !previousEvents.has(eventKey(event)))) recordingUntil = performance.now() + 900;
  previousKey = selected.key; previousEvents = keys;
  for (const event of recent.slice(0, 12)) {
    const item = document.createElement('li');
    const time = new Date(event.time);
    item.textContent = `${Number.isNaN(time.getTime()) ? '' : time.toLocaleTimeString('es')} · ${event.kind}${event.task ? ' · ' + event.task : ''}${event.status ? ' · ' + event.status : ''}`;
    events.append(item);
  }
  drawHalos();
}

function drawHalos() {
  halos.replaceChildren();
  if (!connected || !selected || !frame.contentDocument) return;
  const activity = [];
  const active = selected.status === 'running' ? (selected.tasks || []).filter(task => task.status === 'running').length : 0;
  if (selected.status === 'running') activity.push(['controlador', 'Supervisión de corrida', false]);
  if (active) activity.push(['perfiles', `${active} tareas activas`, false]);
  if (performance.now() < recordingUntil) activity.push(['registro', 'Evento registrado', true]);
  for (const [id, label, amber] of activity) {
    const node = frame.contentDocument.getElementById('node-' + id);
    if (!node) continue;
    const rect = node.getBoundingClientRect();
    if (!rect.width || !rect.height) continue;
    const halo = document.createElement('div'); halo.className = 'halo' + (amber ? ' amber' : ''); halo.dataset.node = id;
    Object.assign(halo.style, {left:`${rect.left - 5}px`,top:`${rect.top - 5}px`,width:`${rect.width + 10}px`,height:`${rect.height + 10}px`});
    const caption = document.createElement('span'); caption.textContent = label; halo.append(caption); halos.append(halo);
  }
}

async function poll() {
  try {
    const response = await fetch('/api/state', {cache:'no-store', signal:AbortSignal.timeout(4500)});
    if (!response.ok) throw new Error('panel unavailable');
    const next = await response.json();
    if (!Array.isArray(next.runs)) throw new Error('invalid state');
    state = next; connected = true;
    const old = runSelect.value;
    runSelect.replaceChildren();
    for (const run of state.runs) {
      const option = document.createElement('option'); option.value = run.key;
      option.textContent = `${run.id} · ${run.status}`; runSelect.append(option);
    }
    if (state.runs.some(run => run.key === old)) runSelect.value = old;
    else if (!old) runSelect.value = (state.runs.find(run => run.status === 'running') || state.runs.find(run => run.tasks?.length) || state.runs[0])?.key || '';
    else {const missing = document.createElement('option'); missing.value = old; missing.textContent = 'Corrida fuera de la ventana del panel'; runSelect.prepend(missing); runSelect.value = old;}
    connection.textContent = 'Conectado · ' + new Date().toLocaleTimeString('es'); connection.dataset.ok = 'true';
  } catch (_) {
    connected = false; connection.textContent = 'Panel desconectado'; connection.dataset.ok = 'false';
  }
  render();
  setTimeout(poll, 1000); // Evita consultas solapadas y carreras entre respuestas.
}
runSelect.addEventListener('change', render);
frame.addEventListener('load', drawHalos);
setInterval(drawHalos, 250); // Sigue el zoom y desplazamiento del diagrama.
poll();
