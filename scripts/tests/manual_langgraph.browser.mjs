import assert from 'node:assert/strict';
import http from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const ui=fileURLToPath(new URL('../dualstack_ui/',import.meta.url));
const scenarios=[['sucursal','Sucursal Esencial',25],['comercial','Operación Comercial',28],['mixto','Empresa Mixta',32],['reforzado','Entorno Reforzado',37]].map(([id,name,tasks])=>({id,name,tasks,targets:10,containers:12,difficulty:'Laboratorio',detail:'Fixture sin red.'}));
const studyId='langgraph_manual_20261018';
const combinations=[...scenarios.map(x=>x.id),'integrado'].flatMap(scenario=>Array.from({length:5},(_,i)=>({scenario,pair:i+1})));combinations.unshift(combinations.splice(combinations.findIndex(x=>x.scenario==='sucursal'&&x.pair===2),1)[0]);
const schedule=combinations.flatMap((entry,index)=>(index%3===0?['multiagent','single']:['single','multiagent']).map(architecture=>({...entry,architecture}))).map((entry,index)=>({...entry,sequence:index+1,slot:index+1,restore_required:true}));
const protocol={status:'pending_confirmation',task_limit_status:'pending_confirmation',task_limit:null,proposed_task_limits:{sucursal:15,comercial:16,integrado:19,mixto:19,reforzado:22},model:'gpt-6.1-sol',tokens:60000,max_cost_usd:2,seed:20261018,sha256:'f'.repeat(64),schedule};
const manual={study_id:studyId,ready:false,message:'Protocolo pendiente de confirmación: el límite propuesto no está aplicado.',protocol,next_slot:schedule[0],planned_runs:50,planned_pairs:25,completed_runs:0,completed_pairs:0,failed_runs:0,scenarios:[{id:'integrado',label:'Banco integrado'},...scenarios.map(item=>({id:item.id,label:item.name}))].map(item=>({...item,completed_runs:0,completed_pairs:0,pairs:Array.from({length:5},(_,i)=>({pair:i+1,single:null,multiagent:null,complete:false}))}))};
const acceptanceFive={status:'pending',active:false,accepted:false,completed_labs:0,total_labs:5,known_tokens:0,new_api_generations:0,scenarios:[]};
const fixture={acceptance_five:acceptanceFive,runs:[],jobs:[],busy:false,lab:{status:'ready',message:'Fixture'},empresa_lab:{status:'ready',message:'Fixture',restoration_required:true,restored:false},scenario_catalog:scenarios,scenario_labs:Object.fromEntries(scenarios.map(s=>[s.id,{status:'ready',message:'Fixture',restoration_required:true,restored:false}])),interfaces:[],catalog:[],openai_available:true,execution_guard:{blocked:false},manual_evaluation:manual,kpi_study:{},experiments:[],references:[]};
const requests=[],errors=[],output=process.argv[2];if(output)await mkdir(output,{recursive:true});
const server=http.createServer(async(req,res)=>{
 const path=new URL(req.url,'http://localhost').pathname;
 if(path==='/api/state'){res.writeHead(200,{'Content-Type':'application/json'});return res.end(JSON.stringify(fixture));}
 if(path.startsWith('/api/')&&req.method==='POST'){
  let raw='';for await(const part of req)raw+=part;const body=JSON.parse(raw);requests.push({path,body});
  if(path==='/api/lab/acceptance-all'){acceptanceFive.status='running';acceptanceFive.active=true;}
  if(path==='/api/lab/suite/restore'){fixture.scenario_labs[body.scenario].restored=true;fixture.scenario_labs[body.scenario].restoration={id:'fixture-only'};fixture.scenario_labs[body.scenario].status='unknown';}
  if(path==='/api/lab/suite/check')fixture.scenario_labs[body.scenario].status='ready';
  res.writeHead(202,{'Content-Type':'application/json'});return res.end(JSON.stringify({job:{id:'fixture-only',status:'complete'}}));
 }
 if(path==='/brand/wordmark.webp'){res.writeHead(200,{'Content-Type':'image/webp'});return res.end(await readFile(ui+'brand/wordmark.webp'));}
 const assets={'/':'index.html','/app.js':'app.js','/workspace.js':'workspace.js','/styles.css':'styles.css','/novaflow.css':'novaflow.css'};
 const file=assets[path];if(!file){res.writeHead(404);return res.end();}
 const text=(await readFile(ui+file,'utf8')).replace('{{ csrf }}','fixture-csrf');
 res.writeHead(200,{'Content-Type':file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});res.end(text);
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base='http://127.0.0.1:'+server.address().port+'/';
const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BINARY||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(12000);page.on('pageerror',error=>errors.push(error.message));
 await page.goto(base+'#kpi');await page.waitForFunction(()=>document.getElementById('connection').textContent.startsWith('Conectado'));
 assert.equal(await page.locator('#planned-runs').textContent(),'50');
 assert.equal(await page.locator('#manual-run-matrix tr').count(),5);
 assert.equal(await page.locator('#manual-run-matrix .manual-slot').count(),25);
 assert.match(await page.locator('#manual-plan-count').textContent(),/0 \/ 25 parejas aptas/);
 assert.match(await page.locator('#manual-kpi-results').textContent(),/Pendiente/);
 if(output){await page.screenshot({path:output+'/manual-guide-desktop.png',fullPage:true});await page.locator('#manual-protocol-title').scrollIntoViewIfNeeded();await page.locator('.manual-protocol').screenshot({path:output+'/protocol-pending-desktop.png'});}
 assert.equal(requests.length,0,'Abrir la guía no debe iniciar auditorías ni controles');
 assert.equal(await page.locator('#manual-protocol-order tr').count(),25);
 assert.equal(await page.locator('#manual-protocol-status').textContent(),'Pendiente de confirmación');
 assert.match(await page.locator('#manual-protocol-values').textContent(),/60 % propuesto · sin aplicar/);assert.match(await page.locator('#manual-protocol-limits').textContent(),/60 % no impide cubrir todos los positivos/);assert.match(await page.locator('#manual-protocol-limits').textContent(),/15 de 25/);
 assert(await page.locator('#prepare-manual-next').isDisabled());
 assert.equal(await page.locator('#manual-export-zip').getAttribute('href'),'/api/manual/export?format=zip');
 assert.equal(await page.locator('#manual-export-csv').getAttribute('href'),'/api/manual/export?format=csv');
 await page.locator('#prepare-manual-run').click();assert(await page.locator('#close-scenario').isVisible());await page.locator('#close-scenario').click();await page.waitForFunction(()=>!posting);assert.deepEqual(requests.at(-1),{path:'/api/lab/empresa/down',body:{}});await page.locator('#manual-evaluation').uncheck();assert(await page.locator('#manual-practice-budget-note').isVisible());assert.match(await page.locator('#manual-practice-budget-note').textContent(),/prácticas con API también usan el límite del 60 %/);assert.equal(await page.evaluate(()=>options().manual_context),undefined);await page.locator('#manual-evaluation').check();await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
 assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/pendiente de confirmación/);assert.doesNotMatch(await page.locator('#review-tasks').textContent(),/tope (?:15|19)/);
 manual.protocol.status='frozen';manual.protocol.task_limit_status='confirmed';manual.protocol.task_limit=null;manual.protocol.task_limits={...manual.protocol.proposed_task_limits};manual.protocol.structural_validation={satisfied:false};manual.ready=true;manual.message='Protocolo congelado para la prueba de interfaz, sin llamadas reales.';
 await page.evaluate(async()=>{await poll();showPage('kpi');});await page.locator('#prepare-manual-next').click();
 assert.equal(await page.locator('#scenario').inputValue(),'sucursal');assert.equal(await page.locator('#manual-pair').inputValue(),'2');assert(await page.locator('input[name=architecture][value=multiagent]').isChecked());
 await page.locator('#scenario').selectOption('');assert.equal(await page.locator('#scenario').inputValue(),'');
 await page.locator('#use-manual-next').click();assert.equal(await page.locator('#scenario').inputValue(),'sucursal');
 assert.match(await page.locator('#manual-order-note').textContent(),/Multiagente.*Agente único/);
 await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
 if(output){const observed=await page.evaluate(()=>({buttons:Object.fromEntries(['manual-protocol-title','prepare-manual-next','use-manual-next','manual-export-zip','manual-export-csv','check-lab','restore-lab','start-audit','manual-context-title','manual-restoration-note','acceptance-five-start','acceptance-five-status'].map(id=>[id,document.getElementById(id).textContent.trim()])),wizard_steps:[...document.querySelectorAll('.wizard-nav button')].map(node=>node.textContent.trim()),wizard_next:[...document.querySelectorAll('[data-step-next]')].map(node=>node.textContent.trim()),navigation:[...document.querySelectorAll('.section-nav button')].map(node=>node.textContent.trim()),restore_confirmation:document.querySelector('#restore-dialog button[value=restore]').textContent.trim(),live_tabs:[...document.querySelectorAll('.view-tabs button')].map(node=>node.textContent.trim()),reports:[document.getElementById('report-link').textContent.trim(),document.getElementById('executive-report-link').textContent.trim()]}));await writeFile(output+'/observed-ui-texts.json',JSON.stringify(observed,null,2));}
 assert.equal(await page.locator('#tokens').inputValue(),'60000');assert(await page.locator('#expert-mode').isChecked());assert.match(await page.locator('#review-tasks').textContent(),/tope 15/);
 assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/Completa la aceptación sin IA de los cinco laboratorios/);
 await page.evaluate(()=>showPage('lab'));assert.equal(await page.locator('#acceptance-five-start').textContent(),'Aceptar los cinco laboratorios sin IA');await page.locator('#acceptance-five-start').click();await page.waitForFunction(()=>!posting);await page.evaluate(()=>poll());
 assert.deepEqual(requests.at(-1),{path:'/api/lab/acceptance-all',body:{}});assert.match(await page.locator('#acceptance-five-status').textContent(),/En curso/);assert(await page.locator('#acceptance-five-start').isDisabled());
 acceptanceFive.scenarios=[{id:'integrado',name:'Banco integrado',expected_tasks:32},...scenarios.map(item=>({id:item.id,name:item.name,expected_tasks:item.tasks}))].map((item,i)=>({...item,status:i<4?'accepted':'pending',phase:i<4?'finished':'pending',evaluation:{tasks_valid:i<4?item.expected_tasks:0}}));acceptanceFive.completed_labs=4;await page.evaluate(()=>poll());assert.doesNotMatch(await page.locator('#acceptance-five-status').textContent(),/5\/5/);
 acceptanceFive.scenarios.forEach(row=>{row.status='accepted';row.phase='finished';row.evaluation.tasks_valid=row.expected_tasks;});acceptanceFive.accepted=true;acceptanceFive.active=false;acceptanceFive.status='accepted';acceptanceFive.completed_labs=5;await page.evaluate(()=>poll());assert.equal(await page.locator('#acceptance-five-status').textContent(),'Aceptación completa · 5/5 laboratorios');assert.equal(await page.locator('#acceptance-five-labs .pill').filter({hasText:/^Aceptado$/}).count(),5);
 await page.evaluate(()=>{showPage('new');showSetupStep(3);});assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/Pulsa Restaurar/);

 await page.locator('input[name=ia][value=none]').check();assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/requiere OpenAI/);
 await page.locator('input[name=ia][value=openai]').check();await page.locator('#expert-mode').uncheck();assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/Activa la revisión LLM/);await page.locator('#expert-mode').check();
 await page.locator('#restore-lab').click();await page.locator('#restore-dialog button[value=restore]').click();await page.waitForFunction(()=>!posting);await page.evaluate(()=>poll());
 assert.deepEqual(requests.at(-1),{path:'/api/lab/suite/restore',body:{scenario:'sucursal'}});
 assert(await page.locator('#start-audit').isDisabled());
 await page.locator('#check-lab').click();await page.waitForFunction(()=>!posting);await page.evaluate(()=>poll());assert.deepEqual(requests.at(-1),{path:'/api/lab/suite/check',body:{scenario:'sucursal'}});
 await page.locator('#start-audit').click();await page.waitForURL('**/#live');
 const audit=requests.find(req=>req.path==='/api/audit');assert(audit);assert.deepEqual(audit.body.manual_context,{study_id:studyId,pair:2});assert.equal(audit.body.scope,'empresa');assert.equal(audit.body.scenario,'sucursal');assert.equal(audit.body.architecture,'multiagent');assert.equal(audit.body.ia,'openai');assert.equal(audit.body.expert_mode,true);assert.equal(audit.body.tokens,60000);
 await page.evaluate(()=>{showPage('new');detail={run:{architecture:'single',manual_context:{pair:2}},detection_budget:{applied:true,executed_tasks:19,catalogue_size:32,task_limit:19,not_selected_tasks:13}};renderDetectionBudget();});assert.match(await page.locator('#detection-budget-note').textContent(),/19 ejecutadas de 32.*13 no seleccionadas/);
 await page.evaluate(()=>{detail.detection_budget.not_selected_tasks=0;renderDetectionBudget();});assert.doesNotMatch(await page.locator('#detection-budget-note').textContent(),/no seleccionadas por el límite/);
 await page.evaluate(()=>{showPage('new');detail={run:{architecture:'single',manual_context:{pair:2}}};renderRunProvenance();});assert(await page.locator('#run-orchestration').isHidden(),'No se debe inventar LangGraph sin evidencia de motor');
 await page.evaluate(()=>{detail.run.orchestration={engine:'python'};renderRunProvenance();});assert.match(await page.locator('#run-orchestration').textContent(),/Motor registrado: python/);assert.doesNotMatch(await page.locator('#run-orchestration').textContent(),/LangGraph confirmado/);
 await page.evaluate(()=>{detail.run.orchestration={engine:'langgraph',version:'fixture'};renderRunProvenance();});assert.match(await page.locator('#run-orchestration').textContent(),/LangGraph confirmado/);
 await page.evaluate(()=>{detail=null;connected=true;showPage('new');showSetupStep(3);state.execution_guard={blocked:true,message:'Kernel requiere reinicio.'};updateButtons();});assert(await page.locator('#start-audit').isDisabled());assert.match(await page.locator('#start-note').textContent(),/Kernel requiere reinicio/);assert(await page.locator('#acceptance-five-start').isDisabled());
 manual.scenarios[0].pairs[0]={pair:1,single:{run_id:'a',status:'complete'},multiagent:{run_id:'b',status:'complete'},complete:true};manual.completed_pairs=1;manual.scenarios[1].pairs[0].single={run_id:'fallida',status:'failed'};await page.evaluate(async()=>{await poll();showPage('kpi');});assert.match(await page.locator('#manual-plan-count').textContent(),/1 \/ 25 parejas aptas/);assert.equal(await page.locator('#manual-run-matrix strong').count(),1);assert.match(await page.locator('#manual-run-matrix').textContent(),/revisar intento/);
 await page.setViewportSize({width:390,height:1000});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'El documento no debe desbordar en móvil');
 if(output)await page.screenshot({path:output+'/manual-guide-mobile.png',fullPage:true});
 assert.deepEqual(errors,[]);assert.equal(requests.filter(req=>req.path==='/api/audit').length,1);
 console.log('PASS: propuesta 60 % por laboratorio pendiente sin aplicar topes, congelación sintética, 25 parejas/50 posiciones desde el protocolo, export ZIP/CSV, selección explícita, aceptación sin IA 5/5, gate de muestra, presupuesto parcial explícito, restauración fresca/comprobación, bloqueo kernel, IA/revisión homogéneas, insignia solo con metadatos, móvil y cero API real.');
}finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
