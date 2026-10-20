import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1460,height:1040}});page.setDefaultTimeout(12000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const actual=await (await page.request.get(url+'api/state')).json(),run=actual.runs.find(r=>r.bank==='v2'&&r.status==='complete'&&r.mode==='live');assert(run);
 const fixture=await (await page.request.get(url+'api/run?key='+encodeURIComponent(run.key))).json();
 fixture.run.name='PRUEBA DE INTERFAZ · DATOS CONTROLADOS';fixture.run.key='redesign-fixture';fixture.run.bank='personal';fixture.run.llm={...fixture.run.llm,status:'accepted',model:'gpt-6.1-sol',known_tokens:420,budget:6000};
 fixture.assistance={expert_mode:true,reviews:[{role:'applications',status:'accepted',interpretation:'PRUEBA: observaciones de aplicación registradas.',limitation:'PRUEBA: faltan controles del laboratorio.',next_step:'PRUEBA: repetir el control después de corregir.',evidence_tasks:['t001']}],decisions:[{role:'application_access',status:'accepted',tokens:120}]};
 const other={...fixture.run,key:'single-fixture',architecture:'single'};
 const state={...actual,busy:false,jobs:[],runs:[fixture.run,other],personal_lab:{status:'unknown',message:'Por comprobar'},openai_available:true,
   kpi_study:{...actual.kpi_study,status:'awaiting_recharge',source_compatible:false,readiness_note:'PRUEBA: revisar versión del protocolo.',previous:{runs_started:6,pairs_eligible:2,complete:false,analysis:{TRTO_percent:{mean:2.9,n:2},IDE_percent:{mean:0,n:2},ETV_ratio:{mean:1.84,n:2}}}}};
 let submitted=null,posts=0,compares=0;
 await page.route('**/api/state',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(state)}));
 await page.route('**/api/run?*',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 await page.route('**/api/compare?*',r=>{compares++;return r.fulfill({contentType:'application/json',body:JSON.stringify(compares===1?{eligible:false,reasons:['PRUEBA: los alcances no coinciden.']}:{eligible:true,TRTO_percent:30,IDE_percent:null,ETV_ratio:null,detection_note:'PRUEBA: falta referencia de detección.',note:'Comparación exploratoria.'})});});
 await page.route('**/api/**',r=>{
  if(r.request().method()!=='POST')return r.fallback();posts++;
  if(r.request().url().endsWith('/api/evaluation-reference')){
   const payload=r.request().postDataJSON();assert.equal(payload.cases.length,1);assert.equal(payload.cases[0].condition,'object_authorization');
   const reference={id:'a'.repeat(32),name:payload.name,cases:1,sha256:'b'.repeat(64),created_at:new Date().toISOString()};state.evaluation_references=[reference];
   return r.fulfill({status:201,contentType:'application/json',body:JSON.stringify({reference})});
  }
  if(r.request().url().endsWith('/api/lab/personal/check')){
   const job={id:'wizard-check',action:'personal_check',status:'complete'};state.jobs.push(job);state.personal_lab={status:'ready',message:'Comprobación controlada'};
   return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
  }
  assert(r.request().url().endsWith('/api/audit'));submitted=r.request().postDataJSON();const job={id:'wizard-audit',action:'audit',status:'complete',run_key:fixture.run.key};state.jobs.push(job);
  return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
 });
 await page.goto(url);assert(await page.locator('#setup-step-1').isVisible());assert(!await page.locator('#setup-step-2').isVisible());assert(!await page.locator('#start-audit').isVisible());
 await page.locator('[data-step-next="2"]').click();assert.match(await page.locator('#error-banner').textContent(),/Indica una IPv4/);assert(await page.locator('#setup-step-1').isVisible());
 await page.locator('#personal-ipv4').fill('192.168.56.0/24');await page.locator('[data-step-next="2"]').click();assert(await page.locator('#setup-step-2').isVisible());
 await page.locator('[data-step-next="3"]').click();assert(await page.locator('#setup-step-3').isVisible());
 await page.locator('input[name="ia"][value="openai"]').check();assert(await page.locator('#expert-mode').isChecked());assert(await page.locator('#expert-mode-note').isVisible());
 await page.locator('#check-lab').click();await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled,null,{timeout:12000});await page.locator('#start-audit').click();
 await page.waitForFunction(()=>detail?.run.key==='redesign-fixture',null,{timeout:12000});assert.equal(submitted.expert_mode,true);assert.equal(submitted.tokens,6000);
 await page.getByRole('tab',{name:'Agentes LLM',exact:true}).click();assert.match(await page.locator('#agent-roster').textContent(),/PRUEBA: observaciones/);
 const before=posts;await page.getByRole('button',{name:'Qué falta',exact:true}).click();assert.match(await page.locator('#agent-roster').textContent(),/PRUEBA: faltan controles/);assert.equal(posts,before,'Reading recorded reviews must not generate a paid request');
 await page.getByRole('button',{name:'KPI del proyecto'}).click();assert.match(await page.locator('#study-title').textContent(),/Revisar protocolo/);
 assert.match(await page.locator('#kpi-scorecards').textContent(),/0 %/);assert.equal(await page.locator('#kpi-scorecards .pill.amber').count(),2);
 await page.locator('#kpi-study-select').selectOption('new');assert.equal(await page.locator('#kpi-scorecards .pill').filter({hasText:'Pendiente'}).count(),3);
 await page.locator('.reference-settings > summary').click();await page.locator('#reference-name').fill('PRUEBA · Referencia del evaluador');
 const ref=page.locator('#reference-cases .reference-case').first();await ref.locator('[data-reference-field="address"]').fill('192.168.56.20');await ref.locator('[data-reference-field="port"]').fill('8080');await ref.locator('[data-reference-field="condition"]').selectOption('object_authorization');await ref.locator('[data-reference-field="expected"]').selectOption('present');
 await page.locator('#save-reference').click();await page.waitForFunction(()=>document.querySelector('#reference-note').textContent.includes('Referencia guardada'),null,{timeout:12000});assert.equal(await page.locator('#compare-reference').inputValue(),'a'.repeat(32));assert(!JSON.stringify(submitted).includes('cases'));
 await page.locator('#compare-runs').click();await page.waitForFunction(()=>document.querySelector('#comparison-result').textContent.includes('alcances no coinciden'),null,{timeout:12000});assert.match(await page.locator('#comparison-result').textContent(),/alcances no coinciden/);
 await page.locator('#compare-runs').click();await page.waitForFunction(()=>document.querySelector('#comparison-result').textContent.includes('30 %'),null,{timeout:12000});assert.match(await page.locator('#comparison-result').textContent(),/30 %/);assert.equal(await page.locator('#comparison-result strong').filter({hasText:'Sin referencia'}).count(),2);
 for(const width of [390,768]){await page.setViewportSize({width,height:940});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'KPI page must fit viewport');}
 await page.getByRole('button',{name:'Nueva auditoría',exact:false}).first().click();await page.locator('[data-setup-step="1"]').click();assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));
 assert.deepEqual(errors,[]);console.log('PASS: three-step wizard, bounded expert mode, recorded role answers without extra calls, truthful KPI cards and guarded comparison; all control requests intercepted.');
}finally{await browser.close();}
