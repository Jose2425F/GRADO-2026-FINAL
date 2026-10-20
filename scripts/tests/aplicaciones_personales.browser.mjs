import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2];
const fixture=JSON.parse(await readFile(process.argv[3],'utf8'));
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try {
 const page=await browser.newPage({viewport:{width:1450,height:1000}});
 page.setDefaultTimeout(12000);page.setDefaultNavigationTimeout(15000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const base=await (await page.request.get(url+'api/state')).json();
 const state={...base,runs:[fixture.run],busy:false,jobs:[],personal_lab:{status:'unknown',message:'Rutas por comprobar'},openai_available:true};
 let started=null,session=null,checks=0;
 await page.route('**/api/state',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(state)}));
 await page.route('**/api/run?*',r=>r.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 // Interceptar todos los POST: no guardar sesiones ni lanzar auditorías reales.
 await page.route('**/api/**',r=>{
  if(r.request().method()!=='POST')return r.fallback();
  const payload=r.request().postDataJSON();
  if(r.request().url().endsWith('/api/web-session')){
   session=payload;return r.fulfill({contentType:'application/json',body:JSON.stringify({name:payload.name,message:'Sesión privada de prueba guardada.'})});
  }
  if(r.request().url().endsWith('/api/lab/personal/check')){
   checks++;state.personal_lab={status:'ready',message:'Configuración de interfaz comprobada'};
   const job={id:'web-check-'+checks,action:'personal_check',status:'complete'};state.jobs.push(job);
   return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
  }
  assert(r.request().url().endsWith('/api/audit'));started=payload;
  const job={id:'web-start',action:'audit',status:'complete',run_key:fixture.run.key};state.jobs.push(job);
  return r.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job})});
 });
 await page.goto(url);console.log('Loaded form');
 assert(await page.locator('input[name="scope"][value="personal"]').isChecked());
 await page.locator('#personal-ipv4').fill('127.0.0.1');await page.locator('#personal-ipv6').fill('::1');assert.equal(await page.locator('#personal-ports').count(),0);await page.locator('[data-setup-step="2"]').click();
 await page.locator('#web-settings > summary').click();await page.locator('#personal-web').check();
 assert.equal(await page.locator('#web-applications > section').count(),1);
 await page.getByText('Guardar la sesión de la cuenta de prueba',{exact:true}).click();
 await page.locator('#web-session-header').selectOption('Authorization');
 await page.locator('#web-session-value').fill('Bearer SYNTHETIC_BROWSER_SESSION');await page.locator('#save-web-session').click();
 await page.waitForFunction(()=>document.querySelector('#web-session-note').textContent.includes('guardada'),null,{timeout:12000});
 assert.equal(await page.locator('#web-session-value').inputValue(),'');assert.equal(session.name,'cuenta-prueba');console.log('Saved private session');
 const card=page.locator('#web-applications > section');
 for(const [key,value] of Object.entries({ipv4:'127.0.0.1',ipv6:'::1',own_path:'/own',own_marker:'OWN_CANARY_2026'}))await card.locator(`[data-field="${key}"]`).fill(value);
 await card.getByText('Acceso a un documento ajeno · opcional',{exact:true}).click();
 await card.locator('[data-field="foreign_path"]').fill('/foreign');await card.locator('[data-field="foreign_marker"]').fill('FOREIGN_CANARY_2026');
 await card.locator('[data-field="scope_confirmed"]').check();
 await page.locator('[data-setup-step="3"]').click();await page.locator('#check-lab').click();await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled,null,{timeout:12000});
 await page.locator('[data-setup-step="2"]').click();await card.locator('[data-field="foreign_path"]').fill('/foreign-2');await page.locator('[data-setup-step="3"]').click();assert(await page.locator('#start-audit').isDisabled(),'Changing a web target must invalidate its precheck');
 await page.locator('#check-lab').click();await page.waitForFunction(()=>!document.querySelector('#start-audit').disabled,null,{timeout:12000});
 console.log('Checked configuration');await page.locator('#start-audit').click();await page.waitForFunction(key=>detail?.run.key===key&&detail.brief.final&&detail.brief.cards.length===5,fixture.run.key,{timeout:12000});
 assert.equal(started.applications.length,1);assert.equal(started.applications[0].foreign_path,'/foreign-2');assert.equal(started.applications[0].session,'cuenta-prueba');
 assert(!JSON.stringify(started).includes('SYNTHETIC_BROWSER_SESSION'));
 await page.getByRole('tab',{name:/^Hallazgos/}).click();
 assert.match(await page.locator('#findings').textContent(),/Documento ajeno|documentos de otro/);
 assert.match(await page.locator('#findings').textContent(),/Pruebas aplicadas a este equipo/);
 console.log('Verified findings');for(const audience of ['technical','executive']){
  const report=await browser.newPage();await report.goto(url+'report?key='+encodeURIComponent(fixture.run.key)+'&audience='+audience);
  assert.match(await report.locator('body').innerText(),/Hallazgos confirmados/);assert.match(await report.locator('body').innerText(),/documentos de otro usuario/);
  assert(!await report.locator('body').innerText().then(t=>t.includes('SYNTHETIC_TEST_SESSION')));await report.close();
 }
 await page.getByRole('button',{name:'Nueva auditoría',exact:false}).first().click();
 await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'Web form must fit mobile');
 assert.deepEqual(errors,[]);console.log('PASS: guided web configuration, private session save, precheck invalidation, detection cards and both reports; all POSTs intercepted.');
} finally {await browser.close();}
