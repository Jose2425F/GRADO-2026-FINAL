"""Captura pasiva del operador para comparar fragmentos antes y después del bridge."""
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
import time


def collect(namespace,private,output,*,interval=.2,limit=64_000_000):
    if os.geteuid()!=0 or not re.fullmatch(r'c113-[0-9a-f]{12}',namespace):
        raise ValueError('La captura corresponde al operador del laboratorio aislado.')
    private=Path(private);out=Path(output);out.mkdir(mode=0o700,parents=True,exist_ok=False)
    if private.is_symlink() or private.stat().st_uid!=0 or private.stat().st_mode&0o077:
        raise ValueError('Estado privado del operador no válido.')
    started=time.time();pcap=out/'lab-ipv6-any.pcap';log=(out/'tcpdump.log').open('w')
    proc=subprocess.Popen(['ip','netns','exec',namespace,'tcpdump','-U','-s','0','-n','-Z','root',
                           '-i','any','-w',str(pcap),'ip6'],stdout=subprocess.DEVNULL,stderr=log)
    meta={'scope':'Captura pasiva de infraestructura; el emisor de los perfiles y el controlador son roles distintos.',
        'namespace':namespace,'namespace_inode':Path('/run/netns',namespace).stat().st_ino,
        'started_at':started,'started_at_utc':datetime.now(timezone.utc).isoformat(),
        'capture_filter':'ip6','capture_interface':'any','format':'Linux cooked v2 with interface index and packet type',
        'operator_pid':os.getpid(),'capture_pid':proc.pid,'ip_link_poll_seconds':interval,
        'max_pcap_bytes':limit,'stop_file':str(out/'stop'),'read_only':True,'api_calls':0}
    timeline=(out/'interface-timeline.jsonl').open('w',buffering=1);last=None;polls=0;snapshots=0;reason='requested'
    (out/'started.json').write_text(json.dumps(meta,indent=2)+'\n')
    print(json.dumps({'ready':True,'output':str(out),'capture_pid':proc.pid}),flush=True)
    try:
        while not (out/'stop').exists():
            if proc.poll() is not None:raise RuntimeError('tcpdump terminó antes de la solicitud de parada.')
            if pcap.exists() and pcap.stat().st_size>limit:reason='size_limit';break
            links=json.loads(subprocess.check_output(['ip','-n',namespace,'-j','link','show'],text=True,timeout=5))
            links=[{k:row.get(k) for k in ['ifindex','ifname','master','link_index','address']} for row in links]
            receipt_meta=[]
            for path in sorted(private.glob('audit-*/receipt.json')):
                info=path.stat();receipt_meta.append((str(path),info.st_mtime_ns,info.st_size))
            signature=json.dumps([links,receipt_meta],sort_keys=True)
            polls+=1
            if signature!=last:
                roles=[]
                for name,_,_ in receipt_meta:
                    path=Path(name)
                    if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o022:continue
                    receipt=json.loads(path.read_text())
                    if receipt.get('lab_namespace')!=namespace:continue
                    roles.extend({'bank':receipt['scenario'],**{k:n[k] for k in ['name','role','interface','bridge','ipv4','ipv6']}}
                                 for n in receipt['policy']['nodes'])
                timeline.write(json.dumps({'time':time.time(),'links':links,'roles':roles},sort_keys=True)+'\n')
                last=signature;snapshots+=1
            time.sleep(interval)
    except KeyboardInterrupt:reason='interrupted'
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        timeline.close();log.close()
        meta.update(ended_at=time.time(),reason=reason,polls=polls,snapshots=snapshots,tcpdump_exit=proc.returncode)
        meta['artifacts_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir()
                                  if p.is_file() and p.name!='summary.json'}
        (out/'summary.json').write_text(json.dumps(meta,indent=2)+'\n')
    return meta


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace',required=True);parser.add_argument('--private',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    collect(args.namespace,args.private,args.output)
