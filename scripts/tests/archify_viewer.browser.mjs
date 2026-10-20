// UI contract: synthetic snapshots; no tools, model calls, or audit execution.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch({executablePath:process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless:true, args:['--no-sandbox']});
try {
  const page = await browser.newPage({viewport:{width:1500,height:1000}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let disconnected = false;
  const run = {key:'fixture', id:'PRUEBA CONTROLADA — SIN AUDITORÍA',status:'running',mode:'dry_run',finished:0,total:2,tasks:[{id:'first',agent:'ipv4_services',status:'running'},{id:'second',agent:'ipv4_services',status:'running'}],events:[]};
  await page.route('**/api/state', route => route.fulfill({status:disconnected ? 503 : 200,contentType:'application/json',body:JSON.stringify(disconnected ? {error:'offline'} : {runs:[run]})}));
  await page.goto(process.argv[2] || 'http://127.0.0.1:8766/');
  await page.waitForSelector('.halo[data-node="perfiles"]');
  assert.match(await page.locator('#summary').textContent(), /simulación.*2 tareas activas/);
  assert.equal(await page.locator('.agent.active').count(), 1);
  assert.equal(await page.locator('.halo[data-node="registro"]').count(), 0, 'history must not pulse on baseline');
  assert.equal(await page.frameLocator('#diagram').locator('g[id^="node-"]').count(), 10);
  assert.equal(await page.frameLocator('#diagram').locator('.halo').count(), 0, 'runtime overlay must stay outside canonical SVG');
  await page.waitForFunction(() => {
    const frame = document.querySelector('#diagram');
    const node = frame.contentDocument.getElementById('node-perfiles').getBoundingClientRect();
    const halo = document.querySelector('.halo[data-node="perfiles"]').getBoundingClientRect();
    return Math.abs(halo.top - (frame.getBoundingClientRect().top + node.top - 5)) < 2;
  });
  if (process.env.ARCHIFY_SCREENSHOT) await page.screenshot({path:process.env.ARCHIFY_SCREENSHOT,fullPage:true});
  run.tasks[0].status = 'completed'; run.finished = 1;
  run.events.unshift({time:new Date().toISOString(),kind:'task_terminal',component:'orchestration',task:'first',status:'completed'});
  await page.waitForFunction(() => document.querySelector('#summary').textContent.includes('1 tareas activas'));
  await page.waitForSelector('.halo[data-node="registro"]');
  assert.equal(await page.locator('.halo[data-node="perfiles"]').count(), 1, 'parallel task must keep node active');
  run.tasks[1].status = 'failed'; run.finished = 2; run.status = 'partial';
  await page.waitForFunction(() => document.querySelector('#summary').textContent.includes('0 tareas activas'));
  assert.equal(await page.locator('.halo[data-node="perfiles"]').count(), 0);
  assert.equal(await page.locator('.halo[data-node="controlador"]').count(), 0);
  run.status = 'running'; run.tasks[0].status = 'running';
  await page.waitForSelector('.halo[data-node="perfiles"]');
  disconnected = true;
  await page.waitForFunction(() => document.querySelector('#connection').textContent === 'Panel desconectado');
  assert.equal(await page.locator('.halo').count(), 0, 'connection loss must clear stale activity');
  disconnected = false; run.status = 'interrupted';
  await page.waitForFunction(() => document.querySelector('#summary').textContent.includes('interrupted'));
  assert.equal(await page.locator('.halo').count(), 0, 'interrupted run must not light unfinished tasks');
  assert.deepEqual(errors, []);
  console.log('PASS: parallel activity, task end, stored event, dry run, disconnect, interrupted run, export isolation; zero browser errors.');
} finally { await browser.close(); }
