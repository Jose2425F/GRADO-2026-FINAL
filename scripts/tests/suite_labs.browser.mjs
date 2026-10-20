import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],output=process.argv[3];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[],starts=[];
 page.on('pageerror',e=>errors.push(e.message));
 const actual=await(await page.request.get(url+'api/state')).json();
 assert.equal(actual.scenario_catalog.length,4);
 const fixture={...actual,runs:[],jobs:[],busy:false,execution_guard:{blocked:false,message:''},
  scenario_labs:Object.fromEntries(actual.scenario_catalog.map(s=>[s.id,{status:'ready',message:'Disponibilidad simulada para probar el formulario.'}])),
  suite_progress:{active:false},study_progress:{active:false},thesis:{...actual.thesis,study:{...actual.thesis.study,active:false}}};
 await page.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  if(req.method()==='GET'&&path==='/api/state')return route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)});
  if(req.method()==='POST'&&path==='/api/audit'){
   const value=req.postDataJSON();assert.equal(value.scope,'empresa');assert.equal(value.tokens,60000);assert.equal(value.ia,'openai');assert(actual.scenario_catalog.some(s=>s.id===value.scenario));starts.push(value);
   return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job:{id:'fixture',status:'complete'}})});
  }
  assert.equal(req.method(),'GET','Operación de control inesperada');return route.fallback();
 });
 await page.goto(url+'#lab');await page.locator('.suite-card').first().waitFor();
 assert.equal(await page.locator('.suite-card').count(),4);
 if(output)await page.locator('#suite-labs').screenshot({path:output+'/laboratorios.png',animations:'disabled'});
 for(const scenario of actual.scenario_catalog){
  for(const architecture of ['single','multiagent']){
   await page.evaluate(id=>{chooseBench('empresa');document.getElementById('scenario').value=id;updateOptions();},scenario.id);
   assert.match(await page.locator('#scope-description').textContent(),new RegExp(`${scenario.targets} objetivos en ${scenario.containers} contenedores`));
   await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
   await page.locator(`input[name=architecture][value=${architecture}]`).check();
   assert.match(await page.locator('#review-tasks').textContent(),new RegExp(String(scenario.tasks)));
   assert.equal(await page.locator('#tokens').inputValue(),'60000');
   await page.locator('#start-audit').click();await page.waitForURL('**/#live');
  }
 }
 assert.equal(starts.length,8);
 await page.setViewportSize({width:390,height:1000});await page.goto(url+'#lab');
 assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));assert.deepEqual(errors,[]);
 console.log('PASS: cuatro tarjetas, selección de escenarios, conteos propios, ocho inicios interceptados (ambas arquitecturas), tokens60000, móvil y cero API real.');
}finally{await browser.close();}
