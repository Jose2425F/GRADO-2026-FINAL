from pathlib import Path
import os,sys,json,subprocess,datetime,hashlib
root=Path('/home/kali/Documents/Codex/2026-11-07/cone/work/publicacion-20261109')
repo=root/'repo';out=root/'pruebas-publicacion';guard=out/'guardas';guard.mkdir(exist_ok=True);binpath=guard/'bin';binpath.mkdir(exist_ok=True)
(guard/'sitecustomize.py').write_text('''import socket,ipaddress,os
from pathlib import Path
def allowed(host):
 if host is None or host in ("localhost", ""): return True
 try:return ipaddress.ip_address(str(host).split("%",1)[0]).is_loopback
 except ValueError:return False
def reject(host):
 log=os.environ.get("TEST_NETWORK_GUARD_LOG")
 if log:
  with open(log,"a") as f:f.write("blocked connection outside loopback: "+str(host)+"\\n")
 raise OSError("validation guard blocked a connection outside loopback")
_orig_connect=socket.socket.connect
_orig_connect_ex=socket.socket.connect_ex
_orig_getaddrinfo=socket.getaddrinfo
def connect(s,address):
 if s.family in (socket.AF_INET,socket.AF_INET6) and not allowed(address[0]):reject(address[0])
 return _orig_connect(s,address)
def connect_ex(s,address):
 if s.family in (socket.AF_INET,socket.AF_INET6) and not allowed(address[0]):reject(address[0])
 return _orig_connect_ex(s,address)
def getaddrinfo(host,*args,**kwargs):
 if not allowed(host):reject(host)
 return _orig_getaddrinfo(host,*args,**kwargs)
socket.socket.connect=connect
socket.socket.connect_ex=connect_ex
socket.getaddrinfo=getaddrinfo
''')
for tool in ['nmap','hydra','docker']:
 p=binpath/tool;p.write_text('#!/bin/sh\nprintf "%s\\n" "TEST_GUARD: real audit tool invocation blocked" >&2\nexit 126\n');p.chmod(0o755)
py='/home/kali/Documents/Codex/2026-11-07/cone/work/ajustes-profesor-20261109/entorno-reproducido/bin/python'
node='/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
env={k:v for k,v in os.environ.items() if not any(t in k.upper() for t in ['API_KEY','ACCESS_TOKEN','AUTH_TOKEN','SECRET'])}
env['PYTHONPATH']=os.pathsep.join(map(str,[guard,repo/'piloto_kali/prototipo/src',repo/'scripts']))
env['PATH']=str(binpath)+os.pathsep+env.get('PATH','')
env['TEST_NETWORK_GUARD_LOG']=str(out/'network-guard.log')
commands=[('python-regresion',[py,'-m','pytest','-q','scripts/tests','piloto_kali/prototipo/tests','-k','not test_whole_runner_real_nmap_and_web_without_api_in_both_architectures','--junitxml='+str(out/'python-regresion.xml')]),('javascript-ui',[node,'--test','scripts/tests/test_centinela_ui.cjs'])]
results=[]
for name,cmd in commands:
 start=datetime.datetime.now(datetime.timezone.utc)
 with (out/(name+'.log')).open('w') as log:
  process=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT)
 record={'name':name,'command':cmd,'cwd':str(repo),'started_at':start.isoformat(),'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':process.returncode,'log':name+'.log','sha256_log':hashlib.sha256((out/(name+'.log')).read_bytes()).hexdigest()}
 results.append(record);print(json.dumps(record),flush=True)
 (out/'resultados.json').write_text(json.dumps({'scope':'Regresión sin API ni herramientas de auditoría reales. HTTP local de pruebas permitido.','excluded_test':'test_whole_runner_real_nmap_and_web_without_api_in_both_architectures (requires real Nmap loopback execution)','network_guard':'Python sockets/getaddrinfo restricted to loopback; command wrappers reject nmap/hydra/docker','results':results},ensure_ascii=False,indent=2)+'\n')
