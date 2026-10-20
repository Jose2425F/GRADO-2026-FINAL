import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const url=process.argv[2],output=process.argv[3],browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1050}});page.setDefaultTimeout(15000);const errors=[];page.on('pageerror',e=>errors.push(e.message));let mutations=0;
 await page.route('**/*',r=>{if(r.request().method()!=='GET'){mutations++;return r.abort();}return r.fallback();});
 const state=await (await page.request.get(url+'api/state')).json();assert.equal(state.runs.length,0);const archive=state.thesis.archives[0];assert(archive);
 await page.goto(url+'#thesis');await page.locator('.capability').first().waitFor();assert.equal(await page.locator('.sidebar').count(),0);
 if(output){await mkdir(output,{recursive:true});await page.screenshot({path:output+'/portada-real.png',animations:'disabled'});}
 await page.getByRole('button',{name:'Resultados',exact:true}).click();assert.match(await page.locator('#history').innerText(),/No hay auditorías|Todavía|No hay resultados|No hay ejecuciones|Aún/);
 await page.getByRole('button',{name:'Desarrollo futuro 02',exact:true}).click();assert.match(await page.locator('#archive-count').innerText(),new RegExp(String(archive.runs_count)));
 await page.goto(url+'archive?id='+encodeURIComponent(archive.id));assert.equal(await page.locator('tbody tr').count(),archive.runs_count);
 const links=await page.locator('a[href*="/report?archive="]').evaluateAll(a=>a.map(v=>({href:v.getAttribute('href'),text:v.textContent})));
 assert(links.length);const latest=links.find(l=>l.href.includes('7432c1c7e859')&&l.href.includes('technical'));assert(latest);
 await page.goto(url+latest.href.replace(/^\//,''));assert.equal(await page.locator('.finding').count(),13);assert.equal(await page.locator('.host-matrix tbody tr').count(),10);
 assert.equal(await page.locator('.finding .proof[open]').count(),13);
 const text=await page.locator('body').innerText();assert.match(text,/Candidatos CVE pendientes/);assert.match(text,/32 \/ 32/);assert.match(text,/13 hallazgos/);
 assert(await page.locator('a[href*="audience=executive"]').getAttribute('href').then(h=>h.includes('archive=')));
 await page.emulateMedia({media:'print'});assert(!await page.locator('#technical-appendix').isVisible());assert(await page.locator('.finding .proof').first().isVisible());
 await page.emulateMedia({media:'screen'});await page.getByLabel('Incluir anexo técnico').check();await page.emulateMedia({media:'print'});assert(await page.locator('#technical-appendix').isVisible());await page.emulateMedia({media:'screen'});
 if(output)await page.locator('.host-matrix').screenshot({path:output+'/banco-resultados.png'});
 await page.locator('a[href*="audience=executive"]').click();assert.equal(await page.locator('#technical-appendix').count(),0);assert.equal(await page.locator('.host-matrix tbody tr').count(),10);
 for(const width of [390,768]){await page.setViewportSize({width,height:950});assert(await page.evaluate(()=>document.body.scrollWidth<=innerWidth),'Executive report must fit mobile');}
 const bad=await page.request.get(url+'report?archive=../&key=x');assert.equal(bad.status(),404);
 assert.equal(mutations,0);assert.deepEqual(errors,[]);
 console.log(`PASS: ${archive.runs_count} archived runs, empty active history, valid archived report navigation, 13 findings/10 hosts/32 valid tasks, candidates separate, evidence and appendix in print, mobile, GET only.`);
}finally{await browser.close();}
