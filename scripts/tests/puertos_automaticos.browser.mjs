import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],fixture=JSON.parse(await readFile(process.argv[3],'utf8'));
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(12000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const actual=await (await page.request.get(url+'api/state')).json();fixture.run.key='automatic-control-fixture';fixture.run.name='PRUEBA CONTROLADA · PUERTOS AUTOMÁTICOS';
 const state={...actual,runs:[fixture.run],busy:false,jobs:[],openai_available:false,personal_lab:{status:'unknown',message:'Por comprobar'}};
 let started=null,checked=0;
 await page.route('**/api/state',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(state)}));
 await page.route('**/api/run?*',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 await page.route('**/api/**',r=>{
  if(r.request().method()!=='POST')return r.fallback();
  const value=r.request().postDataJSON();assert.equal(value.personal.port_mode,'auto');assert(!Object.hasOwn(value.personal,'ports'));
  if(r.request().url().endsWith('/api/lab/personal/check')){
   checked++;state.personal_lab={status:'ready',message:'Rutas comprobadas · fixture'};const job={id:'auto-check',status:'complete',action:'personal_check'};state.jobs.push(job);
   return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
  }
  assert(r.request().url().endsWith('/api/audit'));started=value;const job={id:'auto-audit',status:'complete',action:'audit',run_key:fixture.run.key};state.jobs.push(job);
  return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
 });
 await page.goto(url);assert.equal(await page.locator('#personal-ports').count(),0);assert.match(await page.locator('.auto-ports').textContent(),/1–65535/);
 await page.locator('#personal-ipv4').fill('192.0.2.10,192.0.2.11');await page.locator('[data-setup-step="3"]').click();
 assert.match(await page.locator('#review-tasks').textContent(),/administrador/);await page.locator('#check-lab').click();
 await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled);await page.locator('#start-audit').click();
 await page.waitForFunction(()=>detail?.run.key==='automatic-control-fixture');assert.equal(checked,1);assert.equal(started.ia,'none');assert(!Object.hasOwn(started,'expert_mode'));
 await page.getByRole('tab',{name:'Consola técnica',exact:true}).click();await page.locator('#console-category').selectOption('administrator');
 assert.match(await page.locator('#console-output').textContent(),/Puertos TCP abiertos verificados: 2222, 15432, 31337/);
 assert.match(await page.locator('#console-output').textContent(),/lotes de reconocimiento/);
 await page.locator('#console-category').selectOption('commands');assert.match(await page.locator('#console-output').textContent(),/-p 1-65535/);
 assert.match(await page.locator('#console-output').textContent(),/-p 2222,15432,31337/);
 for(const width of [390,768]){await page.setViewportSize({width,height:900});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));}
 await page.getByRole('button',{name:'Nueva auditoría',exact:false}).first().click();await page.locator('[data-setup-step="1"]').click();assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));
 assert.deepEqual(errors,[]);console.log('PASS: no manual port input, automatic TCP scope, explicit route check, administrator handoff, open-only recognition and responsive UI; all starts intercepted, zero scans or paid calls.');
}finally{await browser.close();}
