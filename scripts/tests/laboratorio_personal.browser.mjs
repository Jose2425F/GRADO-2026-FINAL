import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const fixture=JSON.parse(await readFile(process.argv[3],'utf8'));
const url=process.argv[2]||'http://127.0.0.1:8765/';
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try {
 const page=await browser.newPage({viewport:{width:1450,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const base=await (await page.request.get(url+'api/state')).json();
 fixture.run.key='personal-ui-fixture';fixture.run.name='PRUEBA DE INTERFAZ · INVENTARIO CONTROLADO';
 const snapshot={...base,runs:[fixture.run],jobs:[],busy:false,openai_available:true,personal_lab:{status:'unknown',message:'Comprobar objetivos de prueba'}};
 let checks=0,started=null;
 await page.route('**/api/state',route=>route.fulfill({contentType:'application/json',body:JSON.stringify(snapshot)}));
 await page.route('**/api/run?*',route=>route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 // Intercept every POST: this test cannot dispatch a scan, restoration, or model call.
 await page.route('**/api/**',route=>{
  if(route.request().method()!=='POST')return route.fallback();
  const payload=route.request().postDataJSON();
  if(route.request().url().endsWith('/api/lab/personal/check')) {
   checks++;assert.equal(payload.scope,'personal');
   snapshot.personal_lab={status:'ready',message:'Ruta de prueba disponible'};
   const job={id:'check-'+checks,action:'personal_check',status:'complete'};snapshot.jobs.push(job);
   return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
  }
  assert(route.request().url().endsWith('/api/audit'),'Unexpected control request');
  started=payload;
  const job={id:'personal-start',action:'audit',status:'complete',run_key:fixture.run.key,message:'Inventario de interfaz publicado'};
  snapshot.jobs.push(job);
  return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
 });
 await page.goto(url);
 await page.locator('input[name="scope"][value="personal"]').check();
 assert(await page.locator('#personal-fields').isVisible());
 assert(!(await page.locator('#v2-targets').isVisible()));
 assert(await page.locator('#restore-lab').isDisabled());
 assert(await page.locator('#start-audit').isDisabled());
 await page.locator('#personal-ipv4').fill('127.0.0.1');
 await page.locator('#personal-ipv6').fill('::1');
 await page.locator('#personal-fields .network-settings > summary').click();assert.equal(await page.locator('#personal-ports').count(),0);
 await page.locator('[data-setup-step="3"]').click();
 await page.locator('#check-lab').click();
 await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled);
 await page.locator('[data-setup-step="1"]').click();await page.locator('#personal-interface').selectOption('lo');
 await page.locator('[data-setup-step="3"]').click();
 assert(await page.locator('#start-audit').isDisabled(),'Changing interface must invalidate the route check');
 await page.locator('#check-lab').click();
 await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled,null,{timeout:5000}).catch(async error=>{console.log({errors,checks,debug:await page.evaluate(()=>({personalCheckKey,personalChecking,posting,selected:options().personal,lab:state.personal_lab,jobs:state.jobs,note:document.querySelector('#lab-message').textContent,invalid:[...form.elements].filter(n=>n.validity&&!n.validity.valid).map(n=>({id:n.id,message:n.validationMessage})),error:document.querySelector('#error-banner').textContent,checkDisabled:document.querySelector('#check-lab').disabled}))});throw error;});
 await page.locator('input[name="ia"][value="openai"]').check();
 await page.locator('#tokens').selectOption('20000');
 assert(await page.locator('#start-audit').isEnabled(),'Changing AI budget must not invalidate target check');
 await page.locator('#start-audit').click();
 await page.waitForFunction(()=>document.querySelector('#stat-findings-label').textContent==='Servicios TCP abiertos');
 assert.equal(started.mode,'live');assert.equal(started.scope,'personal');assert.equal(started.ia,'openai');
 assert.deepEqual(started.personal,{ipv4:'127.0.0.1',ipv6:'::1',port_mode:'auto',interface:'lo'});
 assert.equal(started.tokens,20000);assert.equal(checks,2);
 assert.match(await page.locator('#stat-findings-note').textContent(),/no evaluadas/);
 assert.match(await page.locator('#findings').textContent(),/HTTP|http/);
 await page.getByRole('tab',{name:'Consola técnica'}).click();
 assert.match(await page.locator('#console-output').textContent(),/nmap -6/);
 assert(await page.locator('#executive-report-link').isVisible());
 await page.getByRole('button',{name:'Nueva auditoría',exact:false}).first().click();
 await page.setViewportSize({width:390,height:844});
 assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'IP form must fit mobile viewport');
 assert.deepEqual(errors,[]);
 console.log('PASS: own IPv4/IPv6 inputs, route check invalidation, explicit scope/budget, service inventory and console; all starts intercepted, zero scans or API calls.');
} finally {await browser.close();}
