"""Aceptación del filtro en namespaces nuevos; no modifica redes del aplicativo.

Esta prueba caracteriza el componente de red. La aceptación del aplicativo debe
ejecutarse además en la instalación protegida que utiliza la misma política.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from uuid import uuid4


MODULE=Path(__file__).with_name('filtrado_origen.py')
CLIENT=r'''
import json,os,socket,sys,time
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s=socket.socket(family,socket.SOCK_STREAM);s.settimeout(.6)
result={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),
        'address':sys.argv[1],'port':int(sys.argv[2]),'namespace':os.readlink('/proc/self/ns/net')}
result['privileges']={k:v.strip() for k,v in (line.split(':',1) for line in open('/proc/self/status'))
                      if k in {'Uid','Gid','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}}
try:
 s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(sys.argv[3].encode());result['received']=s.recv(4096).decode();result['connected']=True
except OSError as e:result.update(connected=False,error=type(e).__name__)
finally:
 result['source_address'],result['source_port']=s.getsockname()[:2]
 s.close()
print(json.dumps(result))
'''
SERVER=r'''
import json,socket,threading,time
def listen(family,port):
 s=socket.socket(family,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port));s.listen(32)
 print(json.dumps({'listening':True,'family':family,'port':port}),flush=True)
 while True:
  c,a=s.accept()
  try:
   c.settimeout(1);raw=c.recv(4096);print(json.dumps({'peer':a,'nonce':raw.decode()}),flush=True);c.sendall(raw)
  except OSError:pass
  finally:c.close()
for family in [socket.AF_INET,socket.AF_INET6]:
 for port in [18080,18081]:threading.Thread(target=listen,args=(family,port),daemon=True).start()
while True:time.sleep(1)
'''


def policy(name):
    return {'version':1,'name':name,'audit_uid':1000,'audit_uids':[1000,65532,65533],
      'nodes':[
        {'name':'controller','role':'controller','interface':'pctl0','audit_interface':'eth0','bridge':'br113',
         'mac':'02:ce:11:03:00:01','ipv4':['198.18.113.10'],
         'ipv6':['fd00:113::10','fe80::ce:11:3:1']},
        {'name':'target','interface':'ptgt0','bridge':'br113','mac':'02:ce:11:03:00:02',
         'ipv4':['198.18.113.20'],'ipv6':['fd00:113::20','fe80::ce:11:3:2']},
      ],'flows':[{'source':'controller','destination':'target','protocol':'tcp','ports':[18080],
                  'uids':[1000]}]}


def run(output):
    if os.geteuid()!=0:raise SystemExit('Esta prueba aislada requiere el operador con privilegios de namespace.')
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    suffix=uuid4().hex[:6];names={role:'c113f_'+suffix+'_'+role for role in ['br','ctl','tgt','bad']}
    processes=[];created=[];commands=[];results=[];artifacts={}
    report={'started_at':datetime.now(timezone.utc).isoformat(),'namespaces':names,
            'scope':'Componente nft en namespaces nuevos; no aceptación completa del aplicativo.',
            'existing_docker_modified':False,'api_calls':0,'results':results}
    def command(args,*,check=True,input=None,timeout=15):
        result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
        commands.append({'argv':args,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        if check and result.returncode:raise RuntimeError(f'Comando fallido: {args!r}: {result.stderr[:2000]}')
        return result.stdout
    def ip(role,*args):return command(['ip','-n',names[role],*args])
    def nft(role,script):
        return command(['ip','netns','exec',names[role],sys.executable,str(MODULE),'raw'],input=script)
    def apply(role,kind):
        return json.loads(command(['ip','netns','exec',names[role],sys.executable,str(MODULE),
                                  'apply','--policy',str(output/'policy.json'),'--kind',kind]))
    def remove(role,kind):
        return command(['ip','netns','exec',names[role],sys.executable,str(MODULE),
                        'remove','--policy',str(output/'policy.json'),'--kind',kind])
    def client(role,address,port,*,uid=1000,expected):
        nonce='c113-'+uuid4().hex
        start=time.monotonic()
        value=json.loads(command(['ip','netns','exec',names[role],'setpriv',
            '--reuid',str(uid),'--regid',str(uid),'--clear-groups','--inh-caps=-all',
            '--ambient-caps=-all','--bounding-set=-all','--no-new-privs',sys.executable,
            '-c',CLIENT,address,str(port),nonce],timeout=5))
        value.update(role=role,expected=expected,nonce=nonce,seconds=round(time.monotonic()-start,6))
        value['passed']=value['connected'] is expected and (not expected or value['received']==nonce)
        assert all(value['privileges'][k]=='0000000000000000' for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
        assert value['privileges']['NoNewPrivs']=='1' and value['uid']!=0 and not value['groups']
        results.append(value)
        if not value['passed']:raise AssertionError(json.dumps(value))
    def save(name,body):
        (output/name).write_text(body);artifacts[name]=hashlib.sha256(body.encode()).hexdigest()
    try:
        # Sólo consultas de lectura sobre el namespace inicial, para cotejar las tablas ajenas.
        host_before=command([sys.executable,str(MODULE),'raw'],input='list ruleset\n')
        save('host-rules-before.txt',host_before)
        for ns in names.values():command(['ip','netns','add',ns]);created.append(ns)
        ip('br','link','add','br113','type','bridge');ip('br','link','set','br113','up')
        for role,peer,mac,v4,v6,ll in [
            ('ctl','pctl0','02:ce:11:03:00:01','198.18.113.10','fd00:113::10','fe80::ce:11:3:1'),
            ('tgt','ptgt0','02:ce:11:03:00:02','198.18.113.20','fd00:113::20','fe80::ce:11:3:2'),
            ('bad','pbad0','02:ce:11:03:00:03','198.18.113.30','fd00:113::30','fe80::ce:11:3:3')]:
            ip('br','link','add',peer,'type','veth','peer','name',role+'end')
            ip('br','link','set',role+'end','netns',names[role])
            ip(role,'link','set',role+'end','name','eth0');ip(role,'link','set','eth0','address',mac)
            ip('br','link','set',peer,'master','br113');ip('br','link','set',peer,'up')
            ip(role,'link','set','lo','up');ip(role,'link','set','eth0','up')
            command(['ip','netns','exec',names[role],'sysctl','-qw','net.ipv6.conf.eth0.accept_ra=0'])
            command(['ip','netns','exec',names[role],'sysctl','-qw','net.ipv6.conf.eth0.autoconf=0'])
            ip(role,'addr','add',v4+'/24','dev','eth0')
            ip(role,'-6','addr','add',v6+'/64','dev','eth0','nodad')
            ip(role,'-6','addr','add',ll+'/64','dev','eth0','nodad')
        # Un destino no aprobado también tendrá servicio escuchando: evita un falso negativo.
        ip('tgt','addr','add','198.18.113.21/24','dev','eth0')
        ip('tgt','-6','addr','add','fd00:113::21/64','dev','eth0','nodad')
        server_log=(output/'server.log').open('w')
        process=subprocess.Popen(['ip','netns','exec',names['tgt'],'setpriv','--reuid','1000',
            '--regid','1000','--clear-groups','--inh-caps=-all','--ambient-caps=-all',
            '--bounding-set=-all','--no-new-privs',sys.executable,'-u','-c',SERVER],
            stdout=server_log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append((process,server_log))
        for _ in range(30):
            if (output/'server.log').read_text().count('"listening": true')==4:break
            if process.poll() is not None:raise RuntimeError((output/'server.log').read_text())
            time.sleep(.1)
        assert (output/'server.log').read_text().count('"listening": true')==4
        # Captura en puerto físico: ve intentos de ingreso incluso si nft los descarta.
        for role,iface,name in [('br','pbad0','hostile-ingress.pcap'),('br','ptgt0','target-port.pcap')]:
            log=(output/(name+'.log')).open('w')
            proc=subprocess.Popen(['ip','netns','exec',names[role],'tcpdump','-U','-n','-Z','root',
                '-i',iface,'-w',str(output/name)],stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
            processes.append((proc,log))
        time.sleep(.3)
        for address in ['198.18.113.20','fd00:113::20','198.18.113.21','fd00:113::21']:
            client('bad',address,18080,expected=True)
        for address in ['198.18.113.20','fd00:113::20']:
            client('bad',address,18081,expected=True)
        p=policy('proof_'+suffix);(output/'policy.json').write_text(json.dumps(p,indent=2)+'\n')
        nft('br','add table inet c113_sentinel\n')
        report['bridge_install']=apply('br','bridge');report['auditor_install']=apply('ctl','auditor')
        # Las entradas de vecino se fijan en el atacante: los rechazos prueban el
        # filtro de origen/IP, no ausencia accidental de ARP o resolución IPv6.
        for role in ['bad','ctl']:
            for address in ['198.18.113.20','198.18.113.21']:
                ip(role,'neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
            for address in ['fd00:113::20','fd00:113::21']:
                ip(role,'-6','neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
        for address in ['198.18.113.20','fd00:113::20']:
            client('ctl',address,18080,expected=True)
            client('ctl',address,18080,uid=1001,expected=False)
            client('ctl',address,18081,expected=False)
            client('bad',address,18080,expected=False)
        for address in ['198.18.113.21','fd00:113::21']:
            client('ctl',address,18080,expected=False)
        # Misma IP y misma MAC del controlador desde otro veth no autorizan el origen.
        ip('bad','addr','del','198.18.113.30/24','dev','eth0')
        ip('bad','-6','addr','del','fd00:113::30/64','dev','eth0')
        ip('bad','addr','add','198.18.113.10/24','dev','eth0')
        ip('bad','-6','addr','add','fd00:113::10/64','dev','eth0','nodad')
        for address in ['198.18.113.20','198.18.113.21']:
            ip('bad','neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
        for address in ['fd00:113::20','fd00:113::21']:
            ip('bad','-6','neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
        for address in ['198.18.113.20','fd00:113::20']:client('bad',address,18080,expected=False)
        ip('bad','link','set','eth0','address','02:ce:11:03:00:01')
        for address in ['198.18.113.20','198.18.113.21']:
            ip('bad','neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
        for address in ['fd00:113::20','fd00:113::21']:
            ip('bad','-6','neigh','replace',address,'lladdr','02:ce:11:03:00:02','nud','permanent','dev','eth0')
        for address in ['198.18.113.20','fd00:113::20']:client('bad',address,18080,expected=False)
        for address in ['198.18.113.20','fd00:113::20']:client('ctl',address,18080,expected=True)
        save('bridge-counters-before-reload.txt',nft('br',f'list table bridge centinela_proof_{suffix}\n'))
        save('auditor-counters-before-reload.txt',nft('ctl',f'list table inet centinela_proof_{suffix}\n'))
        assert re.search(r'counter packets [1-9]\d* bytes \d+ drop comment "unregistered_port_denied"',(output/'bridge-counters-before-reload.txt').read_text())
        assert re.search(r'counter packets [1-9]\d* bytes \d+ drop comment "auditor_output_denied"',(output/'auditor-counters-before-reload.txt').read_text())
        report['reload_bridge']=apply('br','bridge');report['reload_auditor']=apply('ctl','auditor')
        assert report['reload_bridge']['replaced'] and report['reload_auditor']['replaced']
        for address in ['198.18.113.20','fd00:113::20']:
            client('ctl',address,18080,expected=True);client('bad',address,18080,expected=False)
        assert 'table inet c113_sentinel' in nft('br','list tables\n')
        remove('br','bridge');remove('ctl','auditor')
        assert nft('br','list tables\n').strip()=='table inet c113_sentinel'
        assert not nft('ctl','list tables\n').strip()
        time.sleep(.1)
        decoder=json.JSONDecoder();buffer=(output/'server.log').read_text();server_rows=[]
        while buffer.strip():
            row,end=decoder.raw_decode(buffer.lstrip());server_rows.append(row);buffer=buffer.lstrip()[end:]
        accepted={row['nonce'] for row in server_rows if 'nonce' in row}
        report['negative_nonces_arriving_at_service']=[row['nonce'] for row in results if not row['expected'] and row['nonce'] in accepted]
        report['positive_nonces_missing_at_service']=[row['nonce'] for row in results if row['expected'] and row['nonce'] not in accepted]
        assert not report['negative_nonces_arriving_at_service']
        assert not report['positive_nonces_missing_at_service']
        host_after=command([sys.executable,str(MODULE),'raw'],input='list ruleset\n')
        save('host-rules-after.txt',host_after)
        normalize=lambda text:re.sub(r'counter packets \d+ bytes \d+','counter',text)
        report['initial_namespace_rules_unchanged']=normalize(host_before)==normalize(host_after)
        if not report['initial_namespace_rules_unchanged']:
            raise AssertionError('La política del namespace inicial cambió durante la prueba.')
        report['passed']=all(x['passed'] for x in results)
        return report
    finally:
        for process,stream in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
            stream.close()
        cleanup=[]
        for ns in reversed(created):
            result=subprocess.run(['ip','netns','del',ns],text=True,capture_output=True)
            cleanup.append({'namespace':ns,'returncode':result.returncode,'stderr':result.stderr})
        report['cleanup']=cleanup;report['finished_at']=datetime.now(timezone.utc).isoformat()
        report['cleanup_successful']=all(row['returncode']==0 for row in cleanup)
        report['passed']=report.get('passed',False) and report['cleanup_successful']
        # Un timeout sin SYN de ingreso no demuestra el filtro. Exigir la
        # captura evita confundir resolución ARP/NDP con una denegación real.
        for row in results:
            if row['role']=='bad' and not row['expected']:
                capture=subprocess.run(['tcpdump','-nn','-r',str(output/'hostile-ingress.pcap'),
                    'tcp','and','src','port',str(row['source_port'])],text=True,capture_output=True)
                row['syn_seen_at_hostile_ingress']=capture.returncode==0 and bool(capture.stdout)
                row['passed']=row['passed'] and row['syn_seen_at_hostile_ingress']
        report['passed']=report['passed'] and all(row['passed'] for row in results)
        report['python']=sys.version;report['interpreter']=sys.executable
        for path in sorted(output.glob('*.pcap')):
            artifacts[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        report['artifacts_sha256']=artifacts
        (output/'commands.json').write_text(json.dumps(commands,ensure_ascii=False,indent=2)+'\n')
        (output/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=run(args.output)
    print(json.dumps({'passed':result['passed'],'tests':len(result['results']),'output':str(args.output)},ensure_ascii=False))
    if not result['passed']:raise SystemExit(1)
