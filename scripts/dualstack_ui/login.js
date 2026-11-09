'use strict';
const loginForm=document.getElementById('login-form'),loginError=document.getElementById('login-error'),submit=loginForm.querySelector('[type=submit]'),tokenMeta=document.querySelector('meta[name=csrf-token]');
document.getElementById('toggle-password').addEventListener('click',event=>{const input=document.getElementById('password'),show=input.type==='password';input.type=show?'text':'password';event.currentTarget.textContent=show?'Ocultar':'Mostrar';event.currentTarget.setAttribute('aria-pressed',String(show));});
// Si otra pestaña o el tiempo invalidaron el desafío de acceso, se pide uno nuevo sin recargar.
async function refreshChallenge(){const html=await (await fetch('/login',{cache:'no-store',signal:AbortSignal.timeout(10000)})).text(),match=html.match(/name="csrf-token" content="([^"]+)"/);if(!match)return false;tokenMeta.content=match[1];return true;}
function attempt(data){return fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tokenMeta.content},body:JSON.stringify({username:data.get('username'),password:data.get('password')}),signal:AbortSignal.timeout(15000)});}
loginForm.addEventListener('submit',async event=>{event.preventDefault();loginError.hidden=true;submit.disabled=true;submit.textContent='Verificando acceso…';try{const data=new FormData(loginForm);let response=await attempt(data),result=await response.json();if(response.status===403&&await refreshChallenge()){response=await attempt(data);result=await response.json();}if(!response.ok)throw new Error(result.error||'No se pudo iniciar sesión.');location.replace('/');}catch(error){loginError.textContent=error.name==='TimeoutError'?'El servidor tardó demasiado. Inténtalo de nuevo.':error.message;loginError.hidden=false;submit.disabled=false;submit.textContent='Entrar a mi espacio →';}});
// Carrera agente único vs multiagente: ilustra el protocolo que compara la tesis (no son resultados).
(()=>{
  const race=document.querySelector('[data-race]');if(!race)return;
  const multiEnd=Number(race.dataset.multiEnd),gap=race.querySelector('[data-gap]'),head=race.querySelector('[data-playhead]');
  const lanes=[...race.querySelectorAll('[data-lane]')].map(el=>({fill:el.querySelector('[data-fill]'),state:el.querySelector('[data-state]'),
    ends:el.dataset.ends.split(',').map(Number).sort((a,b)=>a-b),end:el.dataset.lane==='multi'?multiEnd:1}));
  const RUN=9000,HOLD=3400,FADE=500,CYCLE=RUN+HOLD;let box={left:0,width:0};
  function measure(){
    const card=race.getBoundingClientRect(),tracks=[...race.querySelectorAll('.track')].map(t=>t.getBoundingClientRect());if(!tracks.length)return;
    box={left:tracks[0].left-card.left,width:tracks[0].width};
    head.style.top=(tracks[0].top-card.top-6)+'px';head.style.bottom='auto';head.style.height=(tracks.at(-1).bottom-tracks[0].top+12)+'px';
  }
  function paint(p,alpha=1){
    head.style.left=(box.left+p*box.width)+'px';head.classList.toggle('on',p>0&&p<1);
    for(const lane of lanes){
      const q=Math.min(p,lane.end),total=lane.ends.length,done=lane.ends.filter(e=>e<=q+1e-6).length,finished=p>=lane.end-1e-6;
      lane.fill.style.setProperty('--p',q);lane.fill.style.opacity=alpha;
      const text=p<=0?'Preparando':finished?`Completada · ${total}/${total}`:done===total?'Validando evidencia':`Ejecutando · ${done}/${total}`;
      if(lane.state.textContent!==text)lane.state.textContent=text;
      lane.state.classList.toggle('running',p>0&&!finished);lane.state.classList.toggle('done',finished);
    }
    const width=Math.max(0,p-multiEnd)*box.width;
    gap.classList.toggle('on',width>0);gap.classList.toggle('wide',width>110);gap.style.setProperty('--gw',width+'px');gap.style.opacity=width>0?alpha:0;
  }
  measure();addEventListener('resize',measure);
  if(matchMedia('(prefers-reduced-motion: reduce)').matches){paint(1);return;}
  const start=performance.now()+700;
  requestAnimationFrame(function frame(now){
    if(race.offsetParent!==null){
      const t=now-start;
      if(t<0)paint(0);
      else{const c=t%CYCLE;paint(Math.min(1,c/RUN),c>CYCLE-FADE?(CYCLE-c)/FADE:1);}
    }
    requestAnimationFrame(frame);
  });
})();
