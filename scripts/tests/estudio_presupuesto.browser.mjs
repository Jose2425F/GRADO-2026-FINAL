import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2]||'http://127.0.0.1:8765/';
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1050}});const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 const actual=await(await page.request.get(url+'api/state')).json();
 const study={...actual.thesis.study,id:'estudio_novaflow_20261017T190000',status:'pilot',active:true,
   pilot_runs:1,formal_runs:0,pairs:30,runs:60,budget_usd:20,known_cost_usd:0,held_usd:.2,
   predecessor_id:'estudio_novaflow_20261017T171746',known_cost_total_usd:.08369,budget_committed_usd:.45913,
   message:'Piloto de nueva versión; reserva anterior conservada.'};
 const fixture={...actual,thesis:{...actual.thesis,study}};
 await page.route('**/api/**',async route=>{
  assert.equal(route.request().method(),'GET','Esta verificación no permite operaciones de control');
  if(new URL(route.request().url()).pathname==='/api/state')return route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)});
  return route.fallback();
 });
 await page.goto(url+'#kpi');await page.locator('#page-kpi').waitFor();
 await page.waitForFunction(()=>document.querySelector('#study-title').textContent.includes('Piloto con API'));
 const text=await page.locator('#thesis-next-step').textContent();
 assert.match(text,/0\.0837/);assert.match(text,/0\.4591/);assert.match(text,/20\.00/);assert.match(text,/cohorte anterior/);
 assert.equal(await page.locator('#planned-runs').textContent(),'60');
 assert.equal(await page.locator('#thesis-kpi-scores .kpi-score').count(),3);
 for(const width of [390,768]){
  await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));
 }
 assert.deepEqual(errors,[]);
 console.log('PASS: presupuesto acumulado, reserva heredada, KPI sin resultados inventados y móvil. Datos simulados; ningún POST ni API del proveedor.');
}finally{await browser.close();}
