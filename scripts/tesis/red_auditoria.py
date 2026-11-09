"""Red del auditor: namespace propio, rutas exactas y filtrado por rol.

Lo ejecuta el operador de infraestructura, antes de iniciar al controlador.
El controlador no recibe esta API, capacidades de red ni acceso a Docker.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

from tesis.filtrado_origen import (
    FirewallError, endpoints_from_topology, policy_for_bank, validate_policy,
)


SCENARIOS=('integrado','sucursal','comercial','mixto','reforzado')
ROLE_UIDS={'controller':65531,'nmap':65532,'hydra':65533}
MODULE=Path(__file__).with_name('filtrado_origen.py').resolve()


def _run(argv, *, input=None):
    result=subprocess.run([str(x) for x in argv],input=input,text=True,
                          capture_output=True,timeout=40)
    if result.returncode:
        raise FirewallError('Falló operación de red '+repr(argv)+': '+result.stderr[:4000])
    return result.stdout


def _json(argv):
    return json.loads(_run(argv))


def _root():
    if os.geteuid()!=0:raise FirewallError('La preparación de red corresponde al operador root.')


def _trusted(path, *, directory=False):
    path=Path(path)
    info=path.lstat()
    if (path.is_symlink() or info.st_uid!=0 or info.st_mode&0o022
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))):
        raise FirewallError('El estado del operador debe ser propiedad de root y no modificable por terceros.')
    return path


def _write(path, value):
    path=Path(path);tmp=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    descriptor=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
        stream.flush();os.fsync(stream.fileno())
    os.replace(tmp,path)


def load_bank(scenario):
    if scenario not in SCENARIOS:raise FirewallError('Banco cerrado no reconocido.')
    if scenario=='integrado':
        from auditoria import lab_empresa
        return lab_empresa
    from tesis.laboratorios import Context
    return Context(scenario).lab


def _ns_inode(name):
    if not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,48}',name):
        raise FirewallError('Nombre de namespace no válido.')
    return Path('/run/netns',name).stat().st_ino


def _apply(policy,kind,namespace,private):
    path=private/'policy.json';_write(path,policy)
    return json.loads(_run(['ip','netns','exec',namespace,sys.executable,MODULE,
                           'apply','--policy',path,'--kind',kind]))


def plan_bank(bank,topology,*,tag,role_uids=None):
    """Plan puro; las IP autorizadas salen del catálogo, no de rutas amplias."""
    if not re.fullmatch(r'[0-9a-f]{8}',tag):raise FirewallError('Identificador de red no válido.')
    endpoints=endpoints_from_topology(topology)
    controllers={};routes=[]
    for index,(_, (bridge,subnets,members)) in enumerate(sorted(bank.NETWORKS.items())):
        selected=[ip_network(s) for s in subnets]
        v4=[str(n.network_address+240) for n in selected if n.version==4]
        v6=[str(n.network_address+240) for n in selected if n.version==6]
        if len(v4)!=1 or len(v6)>1:raise FirewallError('El segmento requiere una IPv4 y como máximo una IPv6.')
        source={'interface':f'c3p{tag}{index:02x}','audit_interface':bridge,
                'mac':f'02:c1:13:{tag[:2]}:{tag[2:4]}:{index:02x}',
                'ipv4':v4,'ipv6':v6+(['fe80::f0'] if v6 else [])}
        controllers[bridge]=source
    policy=policy_for_bank(bank,endpoints,controllers,name='audit113_'+tag,
                           role_uids=ROLE_UIDS if role_uids is None else role_uids)
    for node in policy['nodes']:
        if node['role']=='controller':continue
        controller=controllers[node['bridge']]
        for address in node['ipv4']+node['ipv6']:
            ip=ip_address(address)
            sources=controller['ipv4'] if ip.version==4 else controller['ipv6']
            if not sources:continue
            source=next((s for s in sources if ip_address(s).is_link_local==ip.is_link_local),None)
            if source is None:continue
            row={'address':address,'version':ip.version,'interface':controller['audit_interface'],'source':source}
            if row not in routes:routes.append(row)
    return {'policy':policy,'controllers':controllers,'routes':routes,'endpoints':endpoints}


def inspect_auditor(namespace):
    routes4=_json(['ip','-n',namespace,'-j','-4','route','show','table','main'])
    routes6=_json(['ip','-n',namespace,'-j','-6','route','show','table','main'])
    if any(r.get('dst')=='default' for r in routes4+routes6):
        raise FirewallError('El auditor no puede tener una ruta por defecto.')
    return {'links':_json(['ip','-n',namespace,'-j','link','show']),
            'addresses':_json(['ip','-n',namespace,'-j','addr','show']),
            'routes4':routes4,'routes6':routes6,
            'namespace_inode':_ns_inode(namespace),'default_routes':0}


def prepare_bank(scenario,topology_path,private_dir,*,tag=None):
    """Crea la red; devuelve receipt para arrancar procesos con ip netns exec."""
    _root();topology=json.loads(_trusted(topology_path).read_text())
    bank=load_bank(scenario);tag=tag or secrets.token_hex(4)
    plan=plan_bank(bank,topology,tag=tag)
    private=Path(private_dir)
    _trusted(private.parent,directory=True)
    private.mkdir(mode=0o700,exist_ok=False);_trusted(private,directory=True)
    namespace='c113a_'+tag;lab_namespace=topology['namespace']
    lab_inode=_ns_inode(lab_namespace)
    if Path('/run/netns',namespace).exists():raise FirewallError('El namespace de auditoría ya existe.')
    receipt={'schema':'centinela-audit-network/1','scenario':scenario,
             'created_at_utc':datetime.now(timezone.utc).isoformat(),
             'namespace':namespace,'lab_namespace':lab_namespace,'lab_namespace_inode':lab_inode,
             'docker_host':topology['docker_host'],'topology_path':str(topology_path),
             'topology_networks':topology['networks'],
             'private_dir':str(private),'role_uids':ROLE_UIDS,'controllers':plan['controllers'],
             'routes':plan['routes'],'expected_endpoints':plan['endpoints'],
             'policy':plan['policy'],'ready':False,'cleanup':False}
    made=False;created_peers=[]
    try:
        _run(['ip','netns','add',namespace]);made=True
        receipt['namespace_inode']=_ns_inode(namespace)
        _write(private/'receipt.json',receipt)
        _run(['ip','netns','exec',namespace,'sysctl','-qw',
              'net.ipv4.ip_forward=0','net.ipv6.conf.all.forwarding=0',
              'net.ipv6.conf.default.accept_ra=0','net.ipv6.conf.default.autoconf=0',
              'net.ipv6.conf.default.router_solicitations=0','net.ipv6.conf.default.addr_gen_mode=1'])
        _run(['ip','-n',namespace,'link','set','lo','up'])
        for index,(bridge,ctl) in enumerate(plan['controllers'].items()):
            temporary=f'c3a{tag}{index:02x}';peer=ctl['interface']
            _run(['ip','-n',lab_namespace,'link','add',temporary,'type','veth','peer','name',peer])
            created_peers.append(peer)
            _run(['ip','-n',lab_namespace,'link','set',temporary,'netns',namespace])
            _run(['ip','-n',namespace,'link','set',temporary,'name',bridge])
            _run(['ip','-n',namespace,'link','set',bridge,'address',ctl['mac']])
            _run(['ip','-n',lab_namespace,'link','set',peer,'master',bridge])
            _run(['ip','netns','exec',namespace,'sysctl','-qw',
                  f'net.ipv6.conf.{bridge}.accept_ra=0',f'net.ipv6.conf.{bridge}.autoconf=0',
                  f'net.ipv6.conf.{bridge}.router_solicitations=0',f'net.ipv6.conf.{bridge}.addr_gen_mode=1'])
            # El puerto del lab permanece DOWN hasta instalar ambos filtros.
            _run(['ip','-n',namespace,'link','set',bridge,'up'])
            for address in ctl['ipv4']:
                _run(['ip','-n',namespace,'addr','add',address+'/32','dev',bridge])
            for address in ctl['ipv6']:
                _run(['ip','-n',namespace,'-6','addr','add',address+'/128','dev',bridge,'nodad'])
        for route in plan['routes']:
            family='-4' if route['version']==4 else '-6'
            prefix='/32' if route['version']==4 else '/128'
            _run(['ip','-n',namespace,family,'route','add',route['address']+prefix,
                  'dev',route['interface'],'src',route['source']])
        receipt['bridge_apply']=_apply(plan['policy'],'bridge',lab_namespace,private)
        receipt['auditor_apply']=_apply(plan['policy'],'auditor',namespace,private)
        for ctl in plan['controllers'].values():
            _run(['ip','-n',lab_namespace,'link','set',ctl['interface'],'up'])
        receipt['inspection']=inspect_auditor(namespace);receipt['ready']=True
        _write(private/'receipt.json',receipt)
        return receipt
    except Exception:
        # No se deja una red parcialmente preparada accesible al auditor.
        for peer in created_peers:
            subprocess.run(['ip','-n',lab_namespace,'link','del',peer],capture_output=True)
        if made:subprocess.run(['ip','netns','del',namespace],capture_output=True)
        try:
            _run(['ip','netns','exec',lab_namespace,sys.executable,MODULE,'remove',
                  '--policy',private/'policy.json','--kind','bridge'])
        except Exception:pass
        receipt['cleanup']=True;_write(private/'receipt.json',receipt)
        raise


def _refresh_value(receipt_path,topology):
    _root();receipt_path=_trusted(receipt_path)
    receipt=json.loads(receipt_path.read_text());private=_trusted(receipt_path.parent,directory=True)
    if (_ns_inode(receipt['namespace'])!=receipt['namespace_inode'] or
            _ns_inode(receipt['lab_namespace'])!=receipt['lab_namespace_inode']):
        raise FirewallError('Cambió la identidad del namespace autorizado.')
    if topology['namespace']!=receipt['lab_namespace']:raise FirewallError('La topología pertenece a otro laboratorio.')
    current=endpoints_from_topology(topology)
    for name,expected in receipt['expected_endpoints'].items():
        if name not in current:raise FirewallError('Falta un activo fijado en el estado del operador.')
        for field in ['container_id','container_image','bridge','mac','configured_ipv4','configured_ipv6']:
            if current[name].get(field)!=expected.get(field):
                raise FirewallError('Cambió la identidad fijada del activo: '+name+'/'+field)
    policy=policy_for_bank(load_bank(receipt['scenario']),current,receipt['controllers'],
        name=receipt['policy']['name'],role_uids=receipt['role_uids'])
    result=_apply(policy,'bridge',receipt['lab_namespace'],private)
    receipt['policy']=policy;receipt['last_refresh']=result
    receipt['refreshed_at_utc']=datetime.now(timezone.utc).isoformat()
    _write(receipt_path,receipt)
    return result


def refresh_bank(receipt_path,topology_path):
    """Tras restart, cambia veth de forma atómica conservando ID/MAC/IP fijados."""
    return _refresh_value(receipt_path,json.loads(_trusted(topology_path).read_text()))


def refresh_bank_live(receipt_path, *, container=None):
    """Inspección cerrada del operador para confirmar un restart antes del ACK.

    No acepta comandos Docker, nombres ni sockets del auditor. container sólo
    comprueba que la notificación pertenece al catálogo ya fijado en el receipt.
    """
    _root();receipt_path=_trusted(receipt_path);receipt=json.loads(receipt_path.read_text())
    expected=receipt['expected_endpoints']
    if container is not None and container not in expected:
        raise FirewallError('La notificación de restart no pertenece al catálogo fijado.')
    if _ns_inode(receipt['lab_namespace'])!=receipt['lab_namespace_inode']:
        raise FirewallError('Cambió el namespace del laboratorio.')
    host=receipt['docker_host']
    private=_trusted(receipt_path.parent.parent,directory=True)
    if host!='unix://'+str(private/'docker.sock'):
        raise FirewallError('El daemon debe ser el socket privado fijado del laboratorio.')
    socket_path=private/'docker.sock';socket_info=socket_path.lstat()
    if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid!=0:
        raise FirewallError('No se encontró el socket de infraestructura fijado.')
    template='{"name":{{json .Name}},"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"networks":{{json .NetworkSettings.Networks}}}'
    ids=[row['container_id'] for row in expected.values()]
    rows=[json.loads(line) for line in _run(['docker','--host',host,'container','inspect',
                 '--format',template,*ids]).splitlines()]
    if len(rows)!=len(ids):raise FirewallError('La inspección cerrada no devolvió todos los activos.')
    for row in rows:
        name=row['name'].removeprefix('/')
        if name not in expected or row['id']!=expected[name]['container_id'] or not row['running']:
            raise FirewallError('Un activo fijado cambió de identidad o aún no está listo.')
        pid=row['pid']
        if type(pid) is not int or pid<=1:raise FirewallError('PID de activo no válido.')
        row['links']=_json(['nsenter','--target',str(pid),'--net','ip','-j','link','show'])
        row['addresses']=_json(['nsenter','--target',str(pid),'--net','ip','-j','addr','show'])
    topology={'schema':'centinela-isolated-topology/2','namespace':receipt['lab_namespace'],
              'containers':rows,'networks':receipt['topology_networks'],
              'namespace_links':_json(['ip','-n',receipt['lab_namespace'],'-j','link','show'])}
    result=_refresh_value(receipt_path,topology)
    result['inspected_fixed_containers']=len(rows)
    result['trigger_container']=container
    return result


def watch_bank(receipt_path, *, interval=0.2):
    """Supervisor opcional: sólo refresca si desaparece un veth fijado."""
    _root();receipt_path=_trusted(receipt_path)
    if not 0.1<=interval<=10:raise FirewallError('Intervalo del supervisor fuera de rango.')
    while True:
        receipt=json.loads(receipt_path.read_text())
        if receipt.get('cleanup'):return
        links={row['ifname']:row for row in _json(['ip','-n',receipt['lab_namespace'],'-j','link','show'])}
        vanished=[n['name'] for n in receipt['policy']['nodes']
                  if n['role']!='controller' and (n['interface'] not in links or
                      links[n['interface']].get('master')!=n['bridge'])]
        if vanished:
            try:
                result=refresh_bank_live(receipt_path)
                _write(receipt_path.parent/'watch-status.json',{'ok':True,'refreshed':vanished,
                    'policy_sha256':result['policy_sha256'],'time_utc':datetime.now(timezone.utc).isoformat()})
            except (FirewallError,OSError) as exc:
                _write(receipt_path.parent/'watch-status.json',{'ok':False,'fail_closed':True,
                    'error':str(exc)[:1000],'time_utc':datetime.now(timezone.utc).isoformat()})
        time.sleep(interval)


def cleanup_bank(receipt_path):
    """Sólo después de detener al auditor; nunca mata procesos de terceros."""
    _root();receipt_path=_trusted(receipt_path);receipt=json.loads(receipt_path.read_text())
    namespace=receipt['namespace'];lab=receipt['lab_namespace']
    if _ns_inode(namespace)!=receipt['namespace_inode'] or _ns_inode(lab)!=receipt['lab_namespace_inode']:
        raise FirewallError('Cambió la identidad del namespace; no se elimina.')
    pids=_run(['ip','netns','pids',namespace]).split()
    if pids:raise FirewallError('Debe detener los procesos del auditor antes de retirar su red.')
    # Primero cerrar enlaces; después retirar exclusivamente la tabla propia.
    for ctl in receipt['controllers'].values():
        _run(['ip','-n',lab,'link','set',ctl['interface'],'down'])
    _run(['ip','netns','exec',lab,sys.executable,MODULE,'remove',
          '--policy',receipt_path.parent/'policy.json','--kind','bridge'])
    _run(['ip','netns','del',namespace])
    receipt['cleanup']=True;receipt['ready']=False
    receipt['cleaned_at_utc']=datetime.now(timezone.utc).isoformat();_write(receipt_path,receipt)
    return {'namespace':namespace,'removed':True,'own_bridge_table_removed':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','refresh','refresh-live','watch','cleanup','inspect'])
    parser.add_argument('--scenario',choices=SCENARIOS)
    parser.add_argument('--topology',type=Path)
    parser.add_argument('--private-dir',type=Path)
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--container')
    args=parser.parse_args()
    if args.action=='prepare':
        if not args.scenario or not args.topology or not args.private_dir:
            parser.error('prepare requiere --scenario, --topology y --private-dir')
        result=prepare_bank(args.scenario,args.topology,args.private_dir)
    elif args.action=='refresh':
        if not args.receipt or not args.topology:parser.error('refresh requiere --receipt y --topology')
        result=refresh_bank(args.receipt,args.topology)
    elif args.action=='refresh-live':
        if not args.receipt:parser.error('refresh-live requiere --receipt')
        result=refresh_bank_live(args.receipt,container=args.container)
    elif args.action=='watch':
        if not args.receipt:parser.error('watch requiere --receipt')
        watch_bank(args.receipt);return
    elif args.action=='cleanup':
        if not args.receipt:parser.error('cleanup requiere --receipt')
        result=cleanup_bank(args.receipt)
    else:
        if not args.receipt:parser.error('inspect requiere --receipt')
        result=inspect_auditor(json.loads(_trusted(args.receipt).read_text())['namespace'])
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
