import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],output=process.argv[3];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1050}});page.setDefaultTimeout(15000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const actual=await (await page.request.get(url+'api/state')).json();
 // Esta prueba representa un espacio nuevo; no heredar un estudio real detenido o activo.
 const fixture={...actual,execution_guard:{blocked:false,message:''},runs:[],experiments:[],jobs:[],busy:false,
  study_progress:{active:false},suite_progress:{active:false},
  thesis:{...actual.thesis,active_runs:0,study:{...actual.thesis.study,id:null,active:false}},
  empresa_lab:{status:'unknown',message:'Comprobar el banco de prueba.'}};
 const starts=[];let checks=0;
 await page.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  if(req.method()==='GET'&&path==='/api/state')return route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)});
  if(req.method()==='POST'){
   if(path==='/api/lab/empresa/check'){checks++;fixture.empresa_lab={status:'ready',message:'Disponibilidad simulada para comprobar el formulario.'};return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job:{id:'check-fixture',status:'complete'}})});}
   if(path==='/api/audit'){const value=req.postDataJSON();starts.push(value);assert.equal(value.scope,'empresa');assert.equal(value.tokens,60000);assert.equal(value.ia,'openai');assert(value.expert_mode);return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job:{id:'audit-fixture',status:'complete'}})});}
   throw new Error('Unexpected control request '+path);
  }
  return route.fallback();
 });
 await page.goto(url+'#thesis');await page.locator('.capability').first().waitFor();
 assert.equal(await page.locator('.sidebar').count(),0);assert.equal(await page.locator('.capability').count(),4);assert.equal(await page.locator('.gate-card').count(),6);
 assert.match(await page.locator('.masthead').innerText(),/Desarrollo futuro/);assert.equal(await page.locator('.nova-brand img').getAttribute('src'),'/brand/wordmark.webp');
 if(output){await mkdir(output,{recursive:true});await page.screenshot({path:output+'/tesis.png',animations:'disabled'});}
 await page.getByRole('button',{name:'Arquitectura e IA',exact:true}).click();assert.equal(await page.locator('.role-card').count(),6);assert.match(await page.locator('#page-models').innerText(),/monolito/i);
 await page.getByRole('button',{name:'Evaluación y KPI',exact:true}).click();assert.equal(await page.locator('#thesis-kpi-scores .kpi-score').count(),3);assert.match(await page.locator('#study-title').innerText(),/Nueva etapa/);assert.equal(await page.locator('#study-cert').innerText(),actual.thesis.readiness?.acceptance?.acceptance_passed===true?'Funcional comprobada':'Pendiente');assert(!await page.locator('#kpi-scorecards').isVisible(),'Historical values must stay in future section');
 await page.getByRole('button',{name:'Desarrollo futuro 02',exact:true}).click();assert.equal(await page.locator('.future-grid .card').count(),4);assert(await page.locator('#architecture-details').isVisible());
 if(output)await page.screenshot({path:output+'/desarrollo-futuro.png',animations:'disabled'});
 await page.locator('#launch-personal').click();assert(await page.locator('#personal-fields').isVisible());assert.match(await page.locator('#audit-track-note').innerText(),/exploratoria/);assert(await page.locator('#scope-options').isVisible());
 await page.getByRole('button',{name:'Preparar auditoría',exact:true}).click();assert(await page.locator('#personal-fields').isVisible(),'Navigation must preserve the chosen lab');
 await page.getByRole('button',{name:'Laboratorio',exact:true}).click();await page.locator('#launch-thesis').click();assert(await page.locator('#empresa-fields').isVisible());assert(!await page.locator('#scope-options').isVisible());
 for(const architecture of ['multiagent','single']){
  if(architecture==='single'){await page.reload();await page.getByRole('button',{name:'Preparar auditoría',exact:true}).click();}
  await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
  await page.locator(`input[name=architecture][value=${architecture}]`).check();
  await page.locator('#check-lab').click();await page.waitForFunction(()=>state.empresa_lab?.status==='ready');
  assert(await page.locator('#start-audit').isEnabled());await page.locator('#start-audit').click();
  await page.waitForURL('**/#live');
 }
 assert.equal(starts.length,2);assert.deepEqual(starts.map(v=>v.architecture),['multiagent','single']);assert.equal(checks,2);
 for(const width of [390,768]){
  await page.setViewportSize({width,height:900});
  for(const route of ['thesis','lab','models','future','new','history','kpi','live']){await page.goto(url+'#'+route);await page.locator('#page-'+route).waitFor();assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),`${route} must fit ${width}px`);}
 }
 assert.deepEqual(errors,[]);
 console.log('PASS: NovaFlow identity, no sidebar, thesis/future separation, honest gates/KPI, modular roles, exploration controls, default OpenAI budget, both architectures, mobile navigation. All audit controls intercepted; no paid calls.');
}finally{await browser.close();}
