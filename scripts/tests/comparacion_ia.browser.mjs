import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2]||'http://127.0.0.1:8765/',output=process.argv[3];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/**',route=>{assert.equal(route.request().method(),'GET','No se permiten operaciones de control');return route.continue();});
 const actual=await(await page.request.get(url+'api/state')).json();
 const single=actual.runs.find(r=>r.architecture==='single'&&r.key.includes('estudio_novaflow_20261017T175031/pilot/'));
 const multi=actual.runs.find(r=>r.architecture==='multiagent'&&r.key.includes('estudio_novaflow_20261017T175031/pilot/'));
 assert(single&&multi);assert.equal(single.llm.fallbacks,10);assert.equal(multi.llm.fallbacks,0);
 await page.goto(url+'#kpi');await page.locator('#compare-single option').first().waitFor({state:'attached'});
 await page.locator('#compare-single').selectOption(single.key);await page.locator('#compare-multi').selectOption(multi.key);
 assert.match(await page.locator('#compare-single option:checked').textContent(),/IA con 10 incidencias/);
 await page.locator('#compare-runs').click();await page.waitForFunction(()=>document.querySelector('#comparison-result').textContent.includes('validador de respuestas'));
 const text=await page.locator('#comparison-result').innerText();
 assert.match(text,/sí utilizó la API \(15 llamadas con generación\)/);assert.match(text,/presupuesto de planificación: 9/);assert.match(text,/validador de respuestas: 1/);
 assert.match(text,/intento se conserva/);assert.equal(await page.locator('#comparison-result .comparison-values').count(),0);
 const card=page.getByRole('heading',{name:'Comparación exploratoria de dos prácticas',exact:true}).locator('..').locator('..');
 if(output)await card.screenshot({path:output+'/comparacion-real.png',animations:'disabled'});
 await page.setViewportSize({width:390,height:1000});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));
 assert.deepEqual(errors,[]);
 console.log('PASS: comparación real distingue uso de API, 9 respaldos por presupuesto y 1 revisión rechazada; mantiene la exclusión, conserva la selección y funciona en móvil. Solo GET; ninguna auditoría ni generación.');
}finally{await browser.close();}
