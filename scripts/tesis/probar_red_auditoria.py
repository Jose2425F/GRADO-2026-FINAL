"""Pruebas de red sobre el banco protegido real, sin autenticación ni auditorías.

El operador crea sólo un intruso temporal y dos listeners de control. Las
inyecciones Ethernet son del operador con NET_RAW; el controlador medido usa
UID no privilegiado, capacidades vacías y NoNewPrivs. No son la misma función.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from uuid import uuid4

from tesis.red_auditoria import _trusted, inspect_auditor


MODULE=Path(__file__).with_name('filtrado_origen.py')
CLIENT=r'''
import json,os,socket,sys
address,port,source,sport,nonce,mode=sys.argv[1:]
family=socket.AF_INET6 if ':' in address else socket.AF_INET
s=socket.socket(family);s.settimeout(.8)
r={'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'address':address,'port':int(port),'source':source,'source_port':int(sport),'namespace':os.readlink('/proc/self/ns/net')}
r['privileges']={k:v.strip() for k,v in (line.split(':',1) for line in open('/proc/self/status')) if k in {'Uid','Gid','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}}
try:
 s.bind((source if source!='-' else ('::' if family==socket.AF_INET6 else '0.0.0.0'),int(sport)))
 s.connect((address,int(port)));r['connected']=True
 if mode=='http':s.sendall(('GET /__c113_'+nonce+' HTTP/1.0\r\nHost: lab\r\n\r\n').encode())
 if mode=='echo':s.sendall(nonce.encode())
 r['received']=s.recv(4096).decode(errors='replace')[:200]
except OSError as e:r.update(connected=False,error=type(e).__name__,errno=e.errno)
finally:s.close()
print(json.dumps(r))
'''
SERVER=r'''
import json,socket,threading,time,sys
port=int(sys.argv[1])
def listen(family):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port));s.listen(8)
 print(json.dumps({'listening':True,'family':family,'port':port}),flush=True)
 while True:
  c,a=s.accept()
  try:c.settimeout(1);b=c.recv(4096);print(json.dumps({'peer':a,'nonce':b.decode(errors='replace')}),flush=True);c.sendall(b)
  except OSError:pass
  finally:c.close()
for f in [socket.AF_INET,socket.AF_INET6]:threading.Thread(target=listen,args=(f,),daemon=True).start()
while True:time.sleep(1)
'''
FORGE=r'''
from scapy.all import Ether,IP,IPv6,TCP,sendp
import sys,json,os
iface,smac,dmac,source,dest,sport=sys.argv[1:]
layer=IPv6(src=source,dst=dest) if ':' in dest else IP(src=source,dst=dest)
p=Ether(src=smac,dst=dmac)/layer/TCP(sport=int(sport),dport=8088,flags='S',seq=113113)
sendp(p,iface=iface,count=1,verbose=False)
print(json.dumps({'operator_uid':os.getuid(),'operator_injection':True,'source':source,'destination':dest,'source_port':int(sport),'interface':iface}))
'''


def run(receipt_path,output):
    if os.geteuid()!=0:raise SystemExit('Sólo el operador de infraestructura puede ejecutar esta prueba.')
    receipt=json.loads(_trusted(receipt_path).read_text());policy=receipt['policy']
    out=Path(output);out.mkdir(parents=True,exist_ok=False)
    tag=uuid4().hex[:6];badns='c113b_'+tag;peer='c3bad'+tag;temporary='c3end'+tag
    lab,audit=receipt['lab_namespace'],receipt['namespace']
    app=next(n for n in policy['nodes'] if n['name'].endswith('-app-crm'))
    ctl=next(n for n in policy['nodes'] if n['role']=='controller' and n['bridge']==app['bridge'])
    observer=next(n for n in policy['nodes'] if n['name'].endswith('-receiver-a'))
    observer_ctl=next(n for n in policy['nodes'] if n['role']=='controller' and n['bridge']==observer['bridge'])
    portal=next(n for n in policy['nodes'] if n['name'].endswith('-portal') and n['bridge'].endswith('dmz'))
    dmz_ctl=next(n for n in policy['nodes'] if n['role']=='controller' and n['bridge']==portal['bridge'])
    global6=lambda n:next(a for a in n['ipv6'] if not ip_address(a).is_link_local)
    a4=app['ipv4'][0];a6=global6(app);c4=ctl['ipv4'][0];c6=global6(ctl)
    net4=ip_network(a4+'/24',strict=False);net6=ip_network(a6+'/64',strict=False)
    bad4=str(net4.network_address+242);bad6=str(net6.network_address+0x242)
    badmac='02:c1:13:ff:fe:42';commands=[];results=[];processes=[];created=False
    source_port=20000+int(tag,16)%20000
    report={'scope':'Banco clonado integrado con firewall y namespace del auditor reales. No ejecuta catálogo de auditorías ni autenticaciones.',
        'started_at_utc':datetime.now(timezone.utc).isoformat(),'api_calls':0,'audit_namespace':audit,
        'lab_namespace':lab,'operator_injections_are_controller_actions':False,'results':results,
        'temporary_namespace':badns,'passed':False}
    def command(argv,*,input=None,check=True):
        r=subprocess.run([str(x) for x in argv],input=input,text=True,capture_output=True,timeout=30)
        commands.append({'argv':list(map(str,argv)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        if check and r.returncode:raise RuntimeError(str(argv)+': '+r.stderr[:2000])
        return r.stdout
    def nft(ns,family):
        return command(['ip','netns','exec',ns,sys.executable,MODULE,'raw'],input=f'list table {family} centinela_{policy["name"]}\n')
    def drop(uid):
        return ['setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups','--inh-caps=-all',
                '--ambient-caps=-all','--bounding-set=-all','--no-new-privs']
    def client(name,ns,address,port,source='-',*,uid=65531,expected,mode='http',prefix=None):
        nonlocal source_port
        source_port+=1;nonce=uuid4().hex
        argv=(prefix if prefix else ['ip','netns','exec',ns])+drop(uid)+[sys.executable,'-c',CLIENT,address,str(port),source,str(source_port),nonce,mode]
        r=json.loads(command(argv));r.update(name=name,nonce=nonce,expected=expected,method='unprivileged TCP')
        r['passed']=r['connected']==expected and (not expected or bool(r.get('received')))
        assert all(r['privileges'][k]=='0000000000000000' for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
        assert r['privileges']['NoNewPrivs']=='1' and not r['groups']
        results.append(r)
        if not r['passed']:raise AssertionError(json.dumps(r))
        return r
    def spawn(argv,name):
        stream=(out/name).open('w')
        proc=subprocess.Popen(list(map(str,argv)),stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append((proc,stream));return proc
    def forge(name,src,dst,mac):
        nonlocal source_port
        source_port+=1
        r=json.loads(command(['ip','netns','exec',audit,sys.executable,'-c',FORGE,
            ctl['audit_interface'],ctl['mac'],mac,src,dst,str(source_port)]))
        r.update(name=name,expected=False,method='operator Ethernet injection',target_capture_required=False)
        results.append(r)
    before_auditor=inspect_auditor(audit)
    before_bridge=nft(lab,'bridge');before_inet=nft(audit,'inet')
    (out/'bridge-before.nft').write_text(before_bridge);(out/'auditor-before.nft').write_text(before_inet)
    try:
        # Los dos listeners de control son procesos efímeros del operador.
        docker_host=receipt['docker_host'];container_id=receipt['expected_endpoints'][app['name']]['container_id']
        pid=int(command(['docker','--host',docker_host,'container','inspect','--format','{{.State.Pid}}',container_id]).strip())
        app_prefix=['nsenter','--target',str(pid),'--net']
        spawn(app_prefix+drop(65531)+[sys.executable,'-u','-c',SERVER,'18081'],'wrong-port-server.log')
        command(['ip','netns','add',badns]);created=True
        command(['ip','-n',lab,'link','add',temporary,'type','veth','peer','name',peer])
        command(['ip','-n',lab,'link','set',temporary,'netns',badns])
        command(['ip','-n',badns,'link','set',temporary,'name','eth0'])
        command(['ip','-n',badns,'link','set','eth0','address',badmac])
        command(['ip','-n',lab,'link','set',peer,'master',app['bridge']])
        command(['ip','-n',lab,'link','set',peer,'up'])
        command(['ip','netns','exec',badns,'sysctl','-qw','net.ipv6.conf.eth0.accept_ra=0','net.ipv6.conf.eth0.autoconf=0','net.ipv6.conf.eth0.addr_gen_mode=1'])
        command(['ip','-n',badns,'link','set','lo','up']);command(['ip','-n',badns,'link','set','eth0','up'])
        command(['ip','-n',badns,'addr','add',bad4+'/32','dev','eth0'])
        command(['ip','-n',badns,'-6','addr','add',bad6+'/128','dev','eth0','nodad'])
        for address,src in [(a4,bad4),(a6,bad6)]:
            version='-6' if ':' in address else '-4';bits='/128' if ':' in address else '/32'
            command(['ip','-n',badns,version,'route','add',address+bits,'dev','eth0','src',src])
            command(['ip','-n',badns,version,'neigh','replace',address,'lladdr',app['mac'],'nud','permanent','dev','eth0'])
        spawn(['ip','netns','exec',badns]+drop(65531)+[sys.executable,'-u','-c',SERVER,'8088'],'wrong-destination-server.log')
        for name,ns,interface in [('app-port.pcap',lab,app['interface']),('hostile-port.pcap',lab,peer),('audit-corp.pcap',audit,ctl['audit_interface'])]:
            spawn(['ip','netns','exec',ns,'tcpdump','-U','-s','0','-n','-Z','root','-i',interface,'-w',out/name],name+'.log')
        for _ in range(40):
            if all((out/name).read_text().count('"listening": true')==2 for name in ['wrong-port-server.log','wrong-destination-server.log']):break
            time.sleep(.1)
        assert all((out/name).read_text().count('"listening": true')==2 for name in ['wrong-port-server.log','wrong-destination-server.log'])
        time.sleep(.3)
        for address in [a4,a6]:
            client('listening-denied-port-control',None,address,18081,expected=True,mode='echo',prefix=app_prefix)
        for address in [bad4,bad6]:
            client('listening-denied-destination-control',badns,address,8088,expected=True,mode='echo')
        for address,src in [(a4,c4),(a6,c6)]:
            client('controller-app-http',audit,address,8088,src,expected=True)
            client('wrong-uid',audit,address,8088,src,uid=65530,expected=False)
            client('wrong-port-with-listener',audit,address,18081,src,expected=False,mode='echo')
        for address,src in [(observer['ipv4'][0],observer_ctl['ipv4'][0]),(global6(observer),global6(observer_ctl))]:
            client('controller-observer-http',audit,address,8000,src,expected=True)
        for uid in [65532,65533]:
            client('worker-service-role',audit,portal['ipv4'][0],21,dmz_ctl['ipv4'][0],uid=uid,expected=True,mode='banner')
        client('controller-cannot-use-worker-service',audit,portal['ipv4'][0],21,dmz_ctl['ipv4'][0],expected=False,mode='banner')
        for address,src in [(bad4,c4),(bad6,c6),('198.18.113.254',c4),('fd00:113::254',c6)]:
            client('outside-exact-routes',audit,address,8088,src,expected=False)
        for address,src in [(a4,bad4),(a6,bad6)]:
            client('unregistered-origin',badns,address,8088,src,expected=False)
        # Inyecciones atribuibles al operador, para medir source/destination pinning.
        forge('nonwhitelisted-source-on-approved-interface',str(net4.network_address+241),a4,app['mac'])
        forge('nonwhitelisted-source-on-approved-interface',str(net6.network_address+0x241),a6,app['mac'])
        forge('nonwhitelisted-destination-with-listener',c4,bad4,badmac)
        forge('nonwhitelisted-destination-with-listener',c6,bad6,badmac)
        command(['ip','-n',badns,'link','set','eth0','address',ctl['mac']])
        command(['ip','-n',badns,'addr','add',c4+'/32','dev','eth0'])
        command(['ip','-n',badns,'-6','addr','add',c6+'/128','dev','eth0','nodad'])
        for address,src in [(a4,c4),(a6,c6)]:
            family='-6' if ':' in address else '-4';bits='/128' if ':' in address else '/32'
            command(['ip','-n',badns,family,'route','replace',address+bits,'dev','eth0','src',src])
            # Cambiar la MAC puede invalidar la caché de vecinos. Se vuelve a
            # fijar para que la prueba llegue al filtro, sin depender de ARP/NS.
            command(['ip','-n',badns,family,'neigh','replace',address,'lladdr',app['mac'],'nud','permanent','dev','eth0'])
            client('spoofed-ip-and-mac-wrong-ingress',badns,address,8088,src,expected=False)
        for address,src in [(a4,c4),(a6,c6)]:
            client('controller-after-spoof',audit,address,8088,src,expected=True)
        time.sleep(.5)
        report['auditor_routes_and_addresses_unchanged']=before_auditor==inspect_auditor(audit)
        after_bridge=nft(lab,'bridge');after_inet=nft(audit,'inet')
        (out/'bridge-after.nft').write_text(after_bridge);(out/'auditor-after.nft').write_text(after_inet)
        normalize=lambda s:re.sub(r'counter packets \d+ bytes \d+','counter',s)
        report['rules_unchanged']=normalize(before_bridge)==normalize(after_bridge) and normalize(before_inet)==normalize(after_inet)
        def counters(text):
            result={}
            for line in text.splitlines():
                count=re.search(r'counter packets (\d+)',line);comment=re.search(r'comment "([^"]+)"',line)
                if count and comment:result[comment[1]]=result.get(comment[1],0)+int(count[1])
            return result
        report['counter_delta']={}
        for family,before,after in [('bridge',before_bridge,after_bridge),('inet',before_inet,after_inet)]:
            b,a=counters(before),counters(after)
            report['counter_delta'][family]={k:v-b.get(k,0) for k,v in a.items() if v-b.get(k,0)}
        assert report['counter_delta']['bridge'].get('source_ip_denied',0)>=2
        assert report['counter_delta']['bridge'].get('unregistered_port_denied',0)>=4
        assert report['counter_delta']['bridge'].get('origin_flow_denied',0)>=2
        assert report['counter_delta']['inet'].get('auditor_output_denied',0)>=5
    finally:
        for proc,stream in reversed(processes):
            if proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.wait(timeout=3)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
            stream.close()
        if created:command(['ip','netns','del',badns],check=False)
        report['temporary_namespace_removed']=not Path('/run/netns',badns).exists()
        report['original_auditor_retained']=Path('/run/netns',audit).exists()
        from scapy.all import PcapReader,IP,IPv6,TCP
        captures={}
        for name in ['app-port.pcap','hostile-port.pcap','audit-corp.pcap']:
            path=out/name
            if path.exists():
                packets=list(PcapReader(str(path)));captures[name]=packets
        for row in results:
            sport=row.get('source_port');at_target=[]
            for packet in captures.get('app-port.pcap',[]):
                if TCP in packet and packet[TCP].sport==sport:at_target.append(packet)
            row['packets_at_real_app_port']=len(at_target)
            if row.get('name') in {'controller-app-http','controller-after-spoof'}:
                row['positive_nonce_captured']=any(row['nonce'].encode() in bytes(p) for p in at_target)
                row['passed']=row['passed'] and row['positive_nonce_captured']
            if not row['expected']:
                row['absent_at_target']=not at_target
                if row['method']=='operator Ethernet injection':row['passed']=row['absent_at_target']
                else:row['passed']=row['passed'] and row['absent_at_target']
            if row.get('name') in {'unregistered-origin','spoofed-ip-and-mac-wrong-ingress'}:
                row['seen_at_hostile_ingress']=any(TCP in p and p[TCP].sport==sport for p in captures.get('hostile-port.pcap',[]))
                row['passed']=row['passed'] and row['seen_at_hostile_ingress']
        report['artifacts']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()}
        report['passed']=(all(r.get('passed') for r in results) and report.get('rules_unchanged',False)
            and report.get('auditor_routes_and_addresses_unchanged',False) and report['temporary_namespace_removed'])
        (out/'commands.json').write_text(json.dumps(commands,ensure_ascii=False,indent=2)+'\n')
        (out/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if not report['passed']:raise AssertionError('Falló la prueba del banco protegido: '+str(out/'summary.json'))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();r=run(args.receipt,args.output)
    print(json.dumps({'passed':r['passed'],'tests':len(r['results']),'output':str(args.output)}))


if __name__=='__main__':main()
