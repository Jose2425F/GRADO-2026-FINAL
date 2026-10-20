import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir} from 'node:fs/promises';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2];
const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1365,height:960}}),errors=[],posts=[];
 page.on('pageerror',error=>errors.push(error.message));
 const actual=await (await page.request.get(url+'api/state')).json();
 const fixture={...actual,runs:[],jobs:[],busy:false,execution_guard:{blocked:true,reason:'kernel_fault',message:'Kali registró un fallo del kernel. Reinicia Kali.'},empresa_lab:{status:'error',message:'Kali registró un fallo del kernel. Reinicia Kali.'}};
 await page.route('**/api/**',route=>{
  if(route.request().method()!=='GET'){posts.push(route.request().url());return route.abort();}
  if(new URL(route.request().url()).pathname==='/api/state')return route.fulfill({contentType:'application/json',body:JSON.stringify(fixture)});
  return route.fallback();
 });
 await page.goto(url+'#lab');await page.locator('#lab-current-message').getByText(/Reinicia Kali/).waitFor();
 assert(await page.locator('#runtime-blocker').isVisible());assert.match(await page.locator('.own-lab-guide').innerText(),/no demuestra una vulnerabilidad/);
 await page.locator('#launch-thesis').click();assert.match(await page.locator('#setup-guide-text').innerText(),/no debes introducir IP/);
 await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
 assert(!await page.locator('#start-audit').isEnabled());assert(!await page.locator('#check-lab').isEnabled());assert(!await page.locator('#restore-lab').isEnabled());assert.match(await page.locator('#start-note').innerText(),/Reinicia Kali/);
 await page.getByRole('button',{name:'Laboratorio',exact:true}).click();await page.locator('[data-own-lab]').click();
 assert.equal(new URL(page.url()).hash,'#new?scope=personal');assert(await page.locator('#personal-fields').isVisible());assert.match(await page.locator('#setup-description').innerText(),/tus equipos/);
 await page.locator('#personal-ipv4').fill('192.168.56.20');
 await page.getByRole('button',{name:'Resultados',exact:true}).click();await page.goBack();
 await page.locator('#personal-fields').waitFor();assert.equal(await page.locator('#personal-ipv4').inputValue(),'192.168.56.20');
 await page.reload();await page.locator('#personal-fields').waitFor();assert(await page.locator('input[name=scope][value=personal]').isChecked());assert.match(await page.locator('#setup-guide-text').innerText(),/IPv6 requiere una lista/);
 await page.getByRole('button',{name:'Preparar auditoría',exact:true}).click();assert(await page.locator('#personal-fields').isVisible());
 await page.locator('input[name=scope][value=empresa]').check();assert.match(await page.locator('#setup-guide-text').innerText(),/no debes introducir IP/);assert.match(await page.locator('#audit-track-note').innerText(),/banco integrado/);assert(!await page.locator('#scope-options').isVisible());
 await page.getByRole('button',{name:'Desarrollo futuro 02',exact:true}).click();await page.locator('.historical-kpi summary').click();assert.equal(await page.locator('#kpi-scorecards .kpi-score').count(),3,'Historical results must load on first visit to Future');
 fixture.execution_guard={blocked:false,message:'',reason:null};fixture.empresa_lab={status:'ready',message:'Banco de prueba disponible.'};
 await page.goto(url+'#new');await page.reload();await page.locator('[data-step-next="2"]').click();await page.locator('[data-step-next="3"]').click();
 await page.waitForFunction(()=>document.querySelector('#start-audit').disabled===false);
 assert(!await page.locator('#runtime-blocker').isVisible());assert(await page.locator('#restore-lab').isEnabled());
 assert.deepEqual(posts,[]);assert.deepEqual(errors,[]);
 if(process.argv[3]){
  await mkdir(process.argv[3],{recursive:true});
  const live=await browser.newPage({viewport:{width:1440,height:1050}});
  await live.goto(url+'#lab');await live.locator('#lab-current-message').filter({hasNotText:'Cargando'}).waitFor();
  await live.screenshot({path:process.argv[3]+'/estado-real.png',animations:'disabled'});
  await live.locator('.own-lab-guide').scrollIntoViewIfNeeded();await live.screenshot({path:process.argv[3]+'/guia-real.png',animations:'disabled'});
 }

 console.log('PASS: runtime blocker, independent availability, lab guide, scope-aware help, browser back/reload, no silent bank change, first-open historical KPI, recovery. Zero control requests or API calls.');
}finally{await browser.close();}
