import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2]||'http://127.0.0.1:8765/',output=process.argv[3];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1100}}),errors=[],starts=[];
 page.on('pageerror',e=>errors.push(e.message));
 const actual=await(await page.request.get(url+'api/state')).json();
 const fixture={...actual,busy:false,jobs:[],runs:[],execution_guard:{blocked:false,message:''},empresa_lab:{status:'ready',message:'Estado simulado para verificar el formulario.'},
   study_progress:{},thesis:{...actual.thesis,study:{...actual.thesis.study,active:false}}};
 await page.route('**/api/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname;
  if(req.method()==='GET'&&path==='/api/state')return route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)});
  if(req.method()==='POST'&&path==='/api/audit'){
   const value=req.postDataJSON();assert.equal(value.scope,'empresa');assert.equal(value.tokens,60000);assert.equal(value.ia,'openai');assert.equal(value.expert_mode,true);starts.push(value);
   return route.fulfill({status:202,contentType:'application/json',body:JSON.stringify({job:{id:'fixture',status:'complete'}})});
  }
  assert.equal(req.method(),'GET','No se permite otra operación de control');return route.fallback();
 });
 await page.goto(url+'#new');await page.waitForFunction(()=>document.querySelector('#tokens').value==='60000');
 assert.equal(await page.locator('input[name=scope]:checked').inputValue(),'empresa');
 await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
 assert(await page.locator('#tokens option[value="80000"]').isEnabled());
 for(const architecture of ['single','multiagent']){
  if(architecture==='multiagent'){await page.getByRole('button',{name:'Preparar auditoría',exact:true}).click();}
  await page.locator(`input[name=architecture][value=${architecture}]`).check();
  assert.equal(await page.locator('#tokens').inputValue(),'60000');
  assert.match(await page.locator('#review-tokens').textContent(),/60[.,]000/);
  if(output&&architecture==='single')await page.locator('#page-new').screenshot({path:output+'/limite-60000.png',animations:'disabled'});
  await page.locator('#start-audit').click();await page.waitForURL('**/#live');
 }
 await page.evaluate(()=>chooseBench('v2'));
 assert.equal(await page.locator('#tokens').inputValue(),'20000');
 assert(await page.locator('#tokens option[value="60000"]').isDisabled());
 await page.evaluate(()=>chooseBench('empresa'));
 assert.equal(await page.locator('#tokens').inputValue(),'60000');
 assert(await page.locator('#tokens option[value="80000"]').isEnabled());
 assert.equal(starts.length,2);assert.deepEqual(errors,[]);
 await page.setViewportSize({width:390,height:1000});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth));
 console.log('PASS: límite predeterminado 60000, opción 80000 solo NovaFlow, 20000 en v2, recuperación al cambiar banco y ambas arquitecturas envían 60000. Inicios interceptados: cero auditorías y cero llamadas al proveedor.');
}finally{await browser.close();}
