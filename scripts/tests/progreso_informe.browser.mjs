import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],requestedKey=process.argv[3],output=process.argv[4];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1100}});page.setDefaultTimeout(15000);
 let mutations=0;const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/**',route=>{if(route.request().method()!=='GET'){mutations++;return route.abort();}return route.fallback();});
 const state=await (await page.request.get(url+'api/state')).json();
 const run=state.runs.find(r=>requestedKey?r.key===requestedKey:r.bank==='personal'&&r.mode==='live'&&r.status==='partial');assert(run);
 const detail=await (await page.request.get(url+'api/run?key='+encodeURIComponent(run.key))).json(),progress=detail.report_view.progress;
 assert(progress);assert.equal(progress.closed,progress.successful+progress.issues+progress.skipped);
 assert.equal(progress.stages.reduce((n,s)=>n+s.total,0),progress.total);
 await page.goto(url+'#live');await page.locator('#run-select').selectOption(run.key);await page.waitForFunction(key=>detail?.run.key===key,run.key);
 assert.equal(await page.locator('#stat-progress').innerText(),`${progress.closed} / ${progress.total}`);
 assert.match(await page.locator('#stat-progress-note').innerText(),new RegExp(`${progress.successful} correctas.*${progress.issues} con incidencias`));
 assert.equal(await page.locator('.progress-stage').count(),progress.stages.length);
 assert.equal(await page.locator('.panel-incident').count(),detail.report_view.incident_groups.length);
 assert.match(await page.locator('#progress-explanation-text').innerText(),/no es una vulnerabilidad distinta/);
 assert.equal(await page.locator('#progress-fill').evaluate(e=>e.style.width),`${progress.percent}%`);
 if(output){await mkdir(output,{recursive:true});await page.locator('#progress-explanation').screenshot({path:output+'/progreso.png'});await page.screenshot({path:output+'/panel.png',animations:'disabled'});}
 // Simular solamente la respuesta HTTP permite comprobar un plan que crece sin iniciar una auditoría.
 const fixture=structuredClone(detail);fixture.run.status='running';fixture.brief.final=false;
 const nextPercent=Math.round(1000*progress.closed/(progress.total+1))/10;
 fixture.report_view.progress={...progress,total:progress.total+1,remaining:1,percent:nextPercent,
  stages:progress.stages.map((s,i)=>i===progress.stages.length-1?{...s,total:s.total+1}:s)};
 await page.route('**/api/run?*',route=>route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 await page.waitForFunction(total=>document.getElementById('stat-progress').textContent.endsWith('/ '+total),progress.total+1);
 assert.equal(await page.locator('#progress-outcome').innerText(),'Plan en construcción');
 assert.equal(await page.locator('#progress-fill').evaluate(e=>e.style.width),`${nextPercent}%`);
 for(const width of [390,768]){await page.setViewportSize({width,height:950});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'Progress must fit mobile');}
 const report=await browser.newPage({viewport:{width:1200,height:1050}});report.on('pageerror',e=>errors.push(e.message));
 await report.route('**/api/**',route=>{if(route.request().method()!=='GET'){mutations++;return route.abort();}return route.fallback();});
 for(const audience of ['executive','technical']){
  await report.goto(url+'report?key='+encodeURIComponent(run.key)+'&audience='+audience);
  assert.equal(await report.locator('.stage-box').count(),progress.stages.length);
  assert.equal(await report.locator('.host-matrix tbody tr').count(),detail.report_view.hosts.length);
  assert.equal(await report.locator('.incident-card').count(),detail.report_view.incident_groups.length);
  if(detail.report_view.findings.length)assert.match(await report.locator('body').innerText(),/rechazada|control protegido/);
  if(audience==='technical'){
   assert.equal(await report.locator('.finding').count(),detail.brief.cards.length);
   assert.equal(await report.locator('.finding .proof[open]').count(),detail.brief.cards.length);
   await report.emulateMedia({media:'print'});assert(!await report.locator('#technical-appendix').isVisible());
   if(detail.brief.cards.length)assert(await report.locator('.finding .proof').first().isVisible());
   await report.emulateMedia({media:'screen'});await report.getByLabel('Incluir anexo técnico').check();
   await report.emulateMedia({media:'print'});assert(await report.locator('#technical-appendix').isVisible());
   await report.emulateMedia({media:'screen'});
  }else assert.equal(await report.locator('#technical-appendix').count(),0);
  if(output){await report.locator('#ejecucion').screenshot({path:output+'/'+audience+'-ejecucion.png'});await report.locator('.host-matrix').screenshot({path:output+'/'+audience+'-equipos.png'});}
  for(const width of [390,768]){await report.setViewportSize({width,height:950});assert(await report.evaluate(()=>document.body.scrollWidth<=innerWidth),'Report must fit mobile');}
  await report.setViewportSize({width:1200,height:1050});
 }
 assert.equal(mutations,0);assert.deepEqual(errors,[]);
 console.log(`PASS: ${progress.closed}/${progress.total} closed, ${progress.successful} valid, ${progress.issues} incidents; dynamic growth, phases, per-host results, remediation verification, evidence in print, mobile; GET only.`);
}finally{await browser.close();}
