import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(12000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const state=await (await page.request.get(url+'api/state')).json(),run=state.runs.find(r=>r.bank==='personal'&&r.status==='complete');assert(run);
 const actual=await (await page.request.get(url+'api/run?key='+encodeURIComponent(run.key))).json(),fixture=structuredClone(actual);
 fixture.run.key='focused-fixture';fixture.run.name='PRUEBA DE INTERFAZ · INVENTARIO CONTROLADO';
 fixture.brief.is_inventory=true;fixture.brief.has_credentials=false;fixture.brief.has_web=false;fixture.brief.cards=[];fixture.brief.issues=[];
 fixture.brief.inventory=[{asset:'PRUEBA A',address:'192.0.2.1',host_state:'up',ports:[{port:22,state:'open'},{port:80,state:'closed'}],services:[{port:22,name:'ssh'}]},
 {asset:'PRUEBA B',address:'192.0.2.2',host_state:'down',ports:[],services:[]},
 {asset:'PRUEBA C',address:'192.0.2.3',host_state:'up',ports:[{port:80,state:'closed'}],services:[]}];
 fixture.report_view={headline:'PRUEBA: un servicio abierto, sin afirmar vulnerabilidad.'};
 fixture.assistance={reviews:[]};
 fixture.console={note:'PRUEBA: eventos controlados.',lines:[
 {id:'1',time:run.started_at,kind:'COMANDO',tool:'Nmap',address:'192.0.2.1',text:'nmap --unprivileged -n -Pn -sT -sV -p 22 192.0.2.1',source:'PRUEBA tool_started',level:'info'},
 {id:'2',time:run.started_at,kind:'IA',tool:'Revisor LLM',text:'PRUEBA revisión registrada',source:'PRUEBA decision',level:'info'},
 {id:'3',time:run.started_at,kind:'CIERRE',tool:'Nmap',text:'PRUEBA tarea incompleta',source:'PRUEBA task_terminal',level:'error'}]};
 let mutations=0;
 await page.route('**/api/**',route=>{if(route.request().method()!=='GET'){mutations++;return route.abort();}return route.fallback();});
 await page.route('**/api/state',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({...state,runs:[fixture.run],jobs:[],busy:false})}));
 await page.route('**/api/run?*',route=>route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)}));
 await page.goto(url+'#live');await page.waitForFunction(()=>detail?.run.key==='focused-fixture');
 const content=()=>page.locator('#findings').innerText();assert.match(await content(),/192.0.2.1/);assert(!await content().then(s=>s.includes('192.0.2.2')));assert(!await content().then(s=>s.includes('Cerrado')));
 await page.locator('#inventory-all').check();assert.match(await content(),/192.0.2.2/);assert.match(await content(),/Cerrado/);
 await page.locator('#inventory-all').uncheck();assert(!await content().then(s=>s.includes('192.0.2.2')));
 await page.getByRole('tab',{name:'Consola técnica',exact:true}).click();assert.equal(await page.locator('.console-line').count(),3);
 await page.locator('#console-category').selectOption('commands');assert.equal(await page.locator('.console-line').count(),1);assert.match(await page.locator('#console-output').textContent(),/nmap --unprivileged/);
 await page.locator('#console-category').selectOption('issues');assert.match(await page.locator('#console-output').textContent(),/tarea incompleta/);assert(!await page.locator('#console-output').textContent().then(s=>s.includes('revisión registrada')));
 await page.locator('#console-category').selectOption('all');await page.locator('#console-pause').click();const paused=await page.locator('#console-output').textContent();
 fixture.console.lines.push({id:'4',time:run.started_at,kind:'SERVICIO',tool:'Nmap',text:'PRUEBA nuevo servicio',source:'PRUEBA resultado',level:'info'});
 await page.waitForResponse(r=>r.url().includes('/api/run?'));assert.equal(await page.locator('#console-output').textContent(),paused);
 await page.locator('#console-pause').click();assert.match(await page.locator('#console-output').textContent(),/nuevo servicio/);
 for(const width of [390,768]){await page.setViewportSize({width,height:900});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'Console must fit mobile');}
 // Informes reales conservados: GET solamente, sin modificar evidencia ni consultar modelos.
 const report=await browser.newPage({viewport:{width:1200,height:1000}});await report.goto(url+'report?key='+encodeURIComponent(run.key)+'&audience=technical');
 assert(await report.locator('#technical-appendix').count());assert.equal(await report.locator('#technical-appendix').getAttribute('open'),null);
 await report.emulateMedia({media:'print'});assert(!await report.locator('#technical-appendix').isVisible());
 await report.emulateMedia({media:'screen'});await report.getByLabel('Incluir anexo técnico').check();await report.emulateMedia({media:'print'});assert(await report.locator('#technical-appendix').isVisible());
 await report.emulateMedia({media:'screen'});await report.goto(url+'report?key='+encodeURIComponent(run.key)+'&audience=executive');
 assert.equal(await report.locator('#technical-appendix').count(),0);assert(!await report.locator('body').innerText().then(t=>t.includes('Revisión no realizada')||t.includes('Sin IA registrada')||t.includes('Pendientes de configuración')));
 await report.setViewportSize({width:390,height:900});assert(await report.evaluate(()=>document.body.scrollWidth<=innerWidth),'Report must fit mobile');
 assert.equal(mutations,0);assert.deepEqual(errors,[]);
 console.log('PASS: exposure focus, explicit diagnostic toggle, typed console filters, paused view, technical print appendix, concise executive report and mobile containment; zero control mutations or paid calls.');
}finally{await browser.close();}
