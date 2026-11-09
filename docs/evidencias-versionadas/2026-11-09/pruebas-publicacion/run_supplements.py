from pathlib import Path
import os,json,subprocess,datetime,hashlib
root=Path('/home/kali/Documents/Codex/2026-11-07/cone/work/publicacion-20261109');repo=root/'repo';out=root/'pruebas-publicacion';guard=out/'guardas'
venv=repo/'piloto_kali/prototipo/.venv'
if not venv.exists() and not venv.is_symlink():venv.symlink_to('/home/kali/Documents/Codex/2026-11-07/cone/work/ajustes-profesor-20261109/entorno-reproducido',target_is_directory=True)
py='/home/kali/Documents/Codex/2026-11-07/cone/work/ajustes-profesor-20261109/entorno-reproducido/bin/python';node='/home/kali/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
env={k:v for k,v in os.environ.items() if not any(t in k.upper() for t in ['API_KEY','ACCESS_TOKEN','AUTH_TOKEN','SECRET'])}
env['PYTHONPATH']=os.pathsep.join(map(str,[guard,repo/'piloto_kali/prototipo/src',repo/'scripts',repo/'src']))
env['PATH']=str(guard/'bin')+os.pathsep+env.get('PATH','');env['TEST_NETWORK_GUARD_LOG']=str(out/'network-guard.log')
env['NODE_PATH']='/home/kali/Documents/Codex/2026-11-07/cone/work/GRADO-2026-FINAL/scripts/tests/node_modules'
commands=[('python-legacy',[py,'-m','pytest','-q','tests','--junitxml='+str(out/'python-legacy.xml')]),('javascript-ui-validated',[node,'--test','scripts/tests/test_centinela_ui.cjs'])]
results=[]
for name,cmd in commands:
 start=datetime.datetime.now(datetime.timezone.utc)
 with (out/(name+'.log')).open('w') as log:process=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT)
 record={'name':name,'command':cmd,'cwd':str(repo),'started_at':start.isoformat(),'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':process.returncode,'log':name+'.log','sha256_log':hashlib.sha256((out/(name+'.log')).read_bytes()).hexdigest()}
 results.append(record);print(json.dumps(record),flush=True)
 (out/'resultados-complementarios.json').write_text(json.dumps({'scope':'Legacy graph stubs and current JS DOM regression; no API/audit tools; dependencies reused from existing environment with source imports restricted to integrated checkout','environment_note':'First JS attempt failed because the clean checkout lacked jsdom and .venv. Preserved in javascript-ui.log. Final attempt reuses installed jsdom via NODE_PATH and the reproduced Python environment via an ignored .venv symlink.','NODE_PATH':env['NODE_PATH'],'PYTHONPATH':env['PYTHONPATH'],'results':results},ensure_ascii=False,indent=2)+'\n')
