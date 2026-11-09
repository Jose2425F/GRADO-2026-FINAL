from pathlib import Path
import os,sys,json,subprocess,datetime,hashlib,shutil
root=Path('/home/kali/Documents/Codex/2026-11-07/cone/work/publicacion-20261109');repo=root/'repo';out=root/'pruebas-publicacion';guard=out/'guardas-loopback';guard.mkdir(exist_ok=True);binpath=guard/'bin';binpath.mkdir(exist_ok=True)
shutil.copy2(out/'guardas/sitecustomize.py',guard/'sitecustomize.py')
for tool in ['hydra','docker']:shutil.copy2(out/'guardas/bin'/tool,binpath/tool)
wrapper='''#!/home/kali/Documents/Codex/2026-11-07/cone/work/ajustes-profesor-20261109/entorno-reproducido/bin/python
import sys,os
from pathlib import Path
args=sys.argv[1:]
def blocked():
 print("TEST_GUARD: Nmap permitted only for the exact TCP loopback fixture profile",file=sys.stderr);sys.exit(126)
if not args or args[-1] not in ("127.0.0.1","::1"):blocked()
try:port=args[args.index("-p")+1];n=int(port)
except (ValueError,IndexError):blocked()
if not 1024<=n<=65535:blocked()
expected=(["-6"] if args[-1]=="::1" else [])+["--unprivileged","-n","-Pn","-sT","-sV","--version-light","--max-retries","1","--host-timeout","60s","-e","lo","-p",port,"-oX","-",args[-1]]
if args!=expected:blocked()
listening=[]
for name,addr in [("tcp","0100007F"),("tcp6","00000000000000000000000001000000")]:
 for line in (Path("/proc/net")/name).read_text().splitlines()[1:]:
  columns=line.split();host,p=columns[1].split(":")
  if host==addr and int(p,16)==n and columns[3]=="0A":listening.append(name)
if set(listening)!={"tcp","tcp6"}:blocked()
with open(os.environ["TEST_NMAP_GUARD_LOG"],"a") as log:log.write("authorized fixture TCP "+args[-1]+":"+port+"\\n")
os.execv("/usr/bin/nmap",["/usr/bin/nmap",*args])
'''
p=binpath/'nmap';p.write_text(wrapper);p.chmod(0o755)
py='/home/kali/Documents/Codex/2026-11-07/cone/work/ajustes-profesor-20261109/entorno-reproducido/bin/python'
env={k:v for k,v in os.environ.items() if not any(t in k.upper() for t in ['API_KEY','ACCESS_TOKEN','AUTH_TOKEN','SECRET'])}
env['PYTHONPATH']=os.pathsep.join(map(str,[guard,repo/'piloto_kali/prototipo/src',repo/'scripts']))
env['PATH']=str(binpath)+os.pathsep+env.get('PATH','');env['TEST_NETWORK_GUARD_LOG']=str(out/'network-guard-loopback.log');env['TEST_NMAP_GUARD_LOG']=str(out/'nmap-loopback.log')
cmd=[py,'-m','pytest','-q','scripts/tests/test_aplicaciones_personales.py::ApplicationTests::test_whole_runner_real_nmap_and_web_without_api_in_both_architectures','--junitxml='+str(out/'python-loopback.xml')]
start=datetime.datetime.now(datetime.timezone.utc)
with (out/'python-loopback.log').open('w') as log:process=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT)
result={'scope':'Integration with real Nmap constrained to exact TCP loopback fixture profile; only currently listening dual-stack fixture port, no API; external network, Hydra and Docker blocked','command':cmd,'cwd':str(repo),'started_at':start.isoformat(),'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':process.returncode,'log':'python-loopback.log','sha256_log':hashlib.sha256((out/'python-loopback.log').read_bytes()).hexdigest()}
(out/'resultado-loopback.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result),flush=True)
