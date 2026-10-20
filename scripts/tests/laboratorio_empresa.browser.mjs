import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2]||'http://127.0.0.1:8765/';
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try {
 const page=await browser.newPage({viewport:{width:1450,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const base=await (await page.request.get(url+'api/state')).json();
 const state={...base,busy:false,jobs:[],openai_available:true,empresa_lab:{status:'unknown',message:'Banco de interfaz por comprobar'}};
 let submitted=null;let checked=0;
 await page.route('**/api/state',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(state)}));
 // Ninguna operación de control sale de este navegador de prueba.
 await page.route('**/api/**',r=>{
  if(r.request().method()!=='POST')return r.fallback();
  if(r.request().url().endsWith('/api/lab/empresa/check')){
   checked++;state.empresa_lab={status:'ready',message:'Banco de interfaz listo'};
   const job={id:'company-check',status:'complete',action:'empresa_check'};state.jobs.push(job);
   return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
  }
  assert(r.request().url().endsWith('/api/audit'));
  submitted=r.request().postDataJSON();
  return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job:{id:'intercepted-company-audit'}})});
 });
 await page.goto(url);
 await page.locator('input[name="scope"][value="empresa"]').check();
 assert(await page.locator('#empresa-fields').isVisible());
 assert(await page.locator('#start-audit').isDisabled());
 assert(await page.locator('#check-lab').isEnabled());
 assert.match(await page.locator('#review-objectives').textContent(),/10 objetivos/);
 assert.match(await page.locator('#review-tasks').textContent(),/32 tareas/);
 await page.locator('[data-setup-step="3"]').click();await page.locator('#check-lab').click();
 await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled);
 await page.locator('input[name="ia"][value="openai"]').check();
 assert(await page.locator('#budget-settings').isVisible());
 await page.locator('#tokens').selectOption('6000');
 assert.match(await page.locator('#start-audit').textContent(),/con IA/);
 await page.locator('input[name="architecture"][value="multiagent"]').check();
 await page.locator('#start-audit').click();
 await page.waitForFunction(()=>location.hash==='#live');
 assert.equal(checked,1);assert.equal(submitted.scope,'empresa');assert.equal(submitted.ia,'openai');
 assert.equal(submitted.tokens,6000);assert.equal(submitted.architecture,'multiagent');assert.equal(submitted.mode,'live');
 assert.deepEqual(errors,[]);
 console.log('PASS: NovaFlow exige comprobación, muestra 32 tareas y transmite IA, presupuesto y arquitectura; todas las operaciones interceptadas, cero API.');
}finally{await browser.close();}
