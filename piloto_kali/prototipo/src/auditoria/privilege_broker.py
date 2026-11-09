"""Frontera local entre el controlador sin privilegios y operaciones IPv6 cerradas.

El broker conserva autoridad sobre Docker. No entrega el socket del daemon al
controlador ni acepta una API Docker general. Sus permisos proceden de un
catálogo instalado por el operador y caducan con ese catálogo.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import threading
import time
import io


POLICY_VERSION = 1
MAX_REQUEST = 32768
MAX_OUTPUT = 8_000_000
MAX_SECONDS = 60
PROFILES = frozenset({'ra_route', 'ra_mtu', 'na_neighbor', 'dad_na', 'control',
    'control_middle', 'plain', 'overlap', 'overlap_middle', 'atomic', 'incomplete_chain'})
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}')
NONCE = re.compile(r'[a-f0-9]{16}')
ID = re.compile(r'[a-f0-9]{64}')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}')
IDENTITY_FORMAT = '{{json .Name}}\t{{json .Image}}\t{{json .Config.Labels}}'


class BrokerError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def process_identity():
    fields = {}
    for line in Path('/proc/self/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in {'Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs'}:
            fields[key] = value.strip()
    fields.update(pid=os.getpid(), uid=os.geteuid(), gid=os.getegid())
    return fields


def require_broker_identity():
    result = process_identity()
    if (result['uid'] != 0 or result.get('Uid','').split()!=['0']*4 or result.get('NoNewPrivs') != '1'
            or any(int(result.get(k, '1'), 16) != 0 for k in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'])):
        raise BrokerError('broker_requires_root_identity_with_empty_capabilities_and_no_new_privileges')
    return result


def require_controller_identity():
    result = process_identity()
    if (result['uid'] == 0 or result['gid'] == 0 or result.get('NoNewPrivs') != '1'
            or result.get('Uid','').split()!=[str(result['uid'])]*4
            or result.get('Gid','').split()!=[str(result['gid'])]*4
            or any(int(result.get(k, '1'), 16) != 0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
            or result.get('Groups', '').strip()):
        raise BrokerError('controller_requires_nonroot_empty_capabilities_no_groups_and_no_new_privileges')
    return result


def peer_identity(pid, expected_uid, expected_gid=None):
    fields={}
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            key,_,value=line.partition(':')
            if key in {'Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'}:
                fields[key]=value.strip()
        gid=int(fields['Gid'].split()[1]) if expected_gid is None else expected_gid
        if (fields['Uid'].split()!=[str(expected_uid)]*4 or expected_uid==0 or gid==0
                or fields['Gid'].split()!=[str(gid)]*4
                or fields.get('NoNewPrivs')!='1' or fields.get('Groups','').strip()
                or any(int(fields.get(k,'1'),16) for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])):
            raise BrokerError('broker_peer_privileges_denied')
    except (OSError,ValueError,KeyError):
        raise BrokerError('broker_peer_identity_unavailable') from None
    return {'pid':pid,**fields}


def process_start_time(pid):
    """El campo starttime no requiere leer enlaces de namespace por ptrace."""
    try:
        raw=Path(f'/proc/{int(pid)}/stat').read_text()
        value=raw[raw.rindex(')')+1:].split()[19]
        if not value.isdecimal() or int(value)<=0:raise ValueError
        return value
    except (OSError,ValueError,IndexError):
        raise BrokerError('broker_peer_start_time_unavailable') from None


def _secure_file(path, *, root=True):
    path = Path(path)
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_mode & 0o022 or (root and st.st_uid != 0):
        raise BrokerError('broker_file_not_trusted')
    _secure_directory(path.parent)
    return st


def _secure_directory(path):
    current = Path(path)
    while True:
        info = current.lstat()
        sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or (info.st_mode & 0o022 and not sticky)):
            raise BrokerError('broker_directory_not_trusted')
        if current == current.parent:
            break
        current = current.parent
    return current


def _clean_args(args):
    if (not isinstance(args, list) or not 1 <= len(args) <= 256
            or any(not isinstance(x, str) or not x or len(x) > 512
                   or (any(ord(c) < 32 for c in x) and x != IDENTITY_FORMAT) for x in args)):
        raise BrokerError('broker_arguments_invalid')
    return list(args)


def build_policy(allowed_uid, allowed_gid, banks, *, docker='/usr/bin/docker', docker_endpoint=None,
                 pinned_files=(), expires_at=None, inspect_runner=None, controller_pid=None):
    """Sólo operador: deriva permisos de módulos de banco de código confiable.

    ``banks`` contiene los módulos lab_empresa/lab_v2 o sus copias de suite ya
    preparadas. El operador debe restaurarlos antes de generar el catálogo.
    """
    if type(allowed_uid) is not int or allowed_uid <= 0 or type(allowed_gid) is not int or allowed_gid <= 0:
        raise BrokerError('broker_requires_nonroot_controller_identity')
    docker = str(Path(docker).resolve(strict=True))
    _secure_file(docker)
    if not isinstance(docker_endpoint,str) or not docker_endpoint.startswith('unix:///'):
        raise BrokerError('broker_requires_explicit_private_docker_endpoint')
    runner = inspect_runner or (lambda args: subprocess.run([docker,'--host',docker_endpoint,*args], check=True,
        capture_output=True, text=True, timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin',
            'LANG':'C.UTF-8','DOCKER_HOST':docker_endpoint}).stdout)
    names = set(); networks = set(); receiver_rules = []; sender_rules = []
    for bank in banks:
        for network, (_, _, members) in bank.NETWORKS.items():
            networks.add(network); names.update(members)
        for asset, receiver in bank.RECEIVERS.items():
            receiver_rules.append({'container': receiver['container'], 'address': receiver['address'],
                'dad': receiver['dad'], 'neighbor_address': bank.SENDER, 'neighbor_mac': bank.SENDER_MAC,
                'neighbor_state': 'permanent' if asset == 'receiver_b' else 'reachable'})
        sender_name = next(name for name in names if name.endswith('-sender')
                           and any(name in members for _, _, members in bank.NETWORKS.values()))
        script = '/app/v2/sender.py' if sender_name == 'v2-sender' else '/app/datacenter/sender.py'
        sender_rules.append({'container': sender_name, 'script': script,
            'targets': sorted(r['address'] for r in bank.RECEIVERS.values()), 'profiles': sorted(PROFILES)})
    containers = {};images={};projects={}
    for name in sorted(names):
        if not NAME.fullmatch(name):raise BrokerError('broker_container_name_invalid')
        record = json.loads(runner(['container', 'inspect', name]))[0]
        containers[name] = {'id': record['Id'], 'image': record['Image'],
            'networks':{n:v['NetworkID'] for n,v in record.get('NetworkSettings',{}).get('Networks',{}).items()}}
        images[record['Image']]=record['Image']
        reference=record.get('Config',{}).get('Image')
        if reference:images[reference]=record['Image']
        project=(record.get('Config',{}).get('Labels') or {}).get('com.docker.compose.project')
        if project:projects.setdefault(project,[]).append(name)
    net_records = {}
    for name in sorted(networks):
        record = json.loads(runner(['network', 'inspect', name]))[0]
        net_records[name] = {'id': record['Id']}
    files = {}
    for raw in pinned_files:
        p = Path(raw).resolve(strict=True);_secure_file(p)
        files[str(p)] = sha256(p.read_bytes())
    result = {'version': POLICY_VERSION, 'allowed_uid': allowed_uid, 'allowed_gid': allowed_gid,
        'principal':None if controller_pid is None else {'pid':controller_pid,
            'start_time':process_start_time(controller_pid),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()},
        'expires_at': time.time()+3600 if expires_at is None else expires_at,
        'docker': docker, 'docker_endpoint':docker_endpoint,'docker_sha256': sha256(Path(docker).read_bytes()),
        'containers': containers, 'networks': net_records,'images':images,'projects':projects,
        'receivers': receiver_rules, 'senders': sender_rules, 'pinned_files': files}
    validate_policy(result)
    return result


def validate_policy(p):
    expected = {'version','allowed_uid','allowed_gid','principal','expires_at','docker','docker_endpoint','docker_sha256',
                'containers','networks','images','projects','receivers','senders','pinned_files'}
    if not isinstance(p, dict) or set(p) != expected or type(p['version']) is not int or p['version'] != POLICY_VERSION:
        raise BrokerError('broker_policy_invalid')
    if (type(p['allowed_uid']) is not int or p['allowed_uid'] <= 0
            or type(p['allowed_gid']) is not int or p['allowed_gid'] <= 0
            or not isinstance(p['expires_at'], (int,float)) or isinstance(p['expires_at'],bool)
            or not 0 < p['expires_at'] < float('inf')):
        raise BrokerError('broker_policy_identity_invalid')
    principal=p['principal']
    if principal is not None and (not isinstance(principal,dict) or set(principal)!={'pid','start_time','boot_id'}
            or type(principal['pid']) is not int or principal['pid']<=0
            or not isinstance(principal['start_time'],str) or not principal['start_time'].isdecimal()
            or not isinstance(principal['boot_id'],str) or not re.fullmatch('[a-f0-9-]{36}',principal['boot_id'])):
        raise BrokerError('broker_policy_principal_invalid')
    if not isinstance(p['containers'],dict) or not p['containers'] or len(p['containers'])>128:
        raise BrokerError('broker_policy_containers_invalid')
    for name, row in p['containers'].items():
        if (not NAME.fullmatch(name) or set(row) != {'id','image','networks'}
                or not ID.fullmatch(row['id']) or not IMAGE.fullmatch(row['image'])
                or not isinstance(row['networks'],dict)
                or any(not NAME.fullmatch(n) or not ID.fullmatch(v) for n,v in row['networks'].items())):
            raise BrokerError('broker_policy_container_invalid')
    if not isinstance(p['networks'],dict) or len(p['networks'])>32:
        raise BrokerError('broker_policy_networks_invalid')
    for name,row in p['networks'].items():
        if not NAME.fullmatch(name) or set(row) != {'id'} or not ID.fullmatch(row['id']):
            raise BrokerError('broker_policy_network_invalid')
    if not isinstance(p['images'],dict) or not isinstance(p['projects'],dict):
        raise BrokerError('broker_policy_inventory_invalid')
    for name,identifier in p['images'].items():
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,240}',name) or not IMAGE.fullmatch(identifier):
            raise BrokerError('broker_policy_image_invalid')
    for name,members in p['projects'].items():
        if not NAME.fullmatch(name) or not isinstance(members,list) or not members or not set(members)<=set(p['containers']):
            raise BrokerError('broker_policy_project_invalid')
    if not isinstance(p['receivers'],list) or not isinstance(p['senders'],list):
        raise BrokerError('broker_policy_catalog_invalid')
    from ipaddress import IPv6Address
    for row in p['receivers']:
        if set(row)!={'container','address','dad','neighbor_address','neighbor_mac','neighbor_state'} or row['container'] not in p['containers']:
            raise BrokerError('broker_policy_receiver_invalid')
        for key in ['address','dad','neighbor_address']:IPv6Address(row[key])
        if not re.fullmatch(r'(?:[a-f0-9]{2}:){5}[a-f0-9]{2}',row['neighbor_mac']) or row['neighbor_state'] not in {'permanent','reachable'}:
            raise BrokerError('broker_policy_receiver_invalid')
    for row in p['senders']:
        if (set(row)!={'container','script','targets','profiles'} or row['container'] not in p['containers']
                or row['script'] not in {'/app/v2/sender.py','/app/datacenter/sender.py'}
                or not set(row['profiles']) <= PROFILES or not row['profiles']):
            raise BrokerError('broker_policy_sender_invalid')
        for address in row['targets']:IPv6Address(address)
        if not row['targets'] or not set(row['targets']) <= {r['address'] for r in p['receivers']}:
            raise BrokerError('broker_policy_sender_target_invalid')
        sender_networks=set(p['containers'][row['container']]['networks'].values())
        for address in row['targets']:
            receiver=next(r for r in p['receivers'] if r['address']==address)
            if not sender_networks & set(p['containers'][receiver['container']]['networks'].values()):
                raise BrokerError('broker_policy_sender_network_invalid')
    if not isinstance(p['docker'],str) or not Path(p['docker']).is_absolute() or not re.fullmatch('[a-f0-9]{64}',p['docker_sha256']):
        raise BrokerError('broker_policy_executable_invalid')
    if (not isinstance(p['docker_endpoint'],str) or not p['docker_endpoint'].startswith('unix:///')
            or '..' in Path(p['docker_endpoint'][7:]).parts or len(p['docker_endpoint'][7:])>100):
        raise BrokerError('broker_policy_endpoint_invalid')
    if not isinstance(p['pinned_files'],dict) or any(not Path(k).is_absolute() or not re.fullmatch('[a-f0-9]{64}',v) for k,v in p['pinned_files'].items()):
        raise BrokerError('broker_policy_files_invalid')
    return p


def permitted(policy, args, *, stream=False):
    """Reconoce formas cerradas, no expresiones de shell ni comandos arbitrarios."""
    args = _clean_args(args)
    if time.time() >= policy['expires_at']:raise BrokerError('broker_policy_expired')
    containers, networks = policy['containers'], policy['networks']
    images = set(policy['images'])
    names = set(containers)
    if args == ['version','--format','{{.Server.Version}}']:
        return {'kind':'read','containers':[]}
    if not stream:
        if (len(args)==6 and args[:3]==['ps','--all','--filter'] and args[-2:]==['--format','{{.Names}}']
                and args[3].startswith('label=com.docker.compose.project=')
                and args[3].partition('=')[2].partition('=')[2] in policy['projects']):
            return {'kind':'read','containers':[]}
        for kind, known in [('container',names),('network',set(networks)),('image',images)]:
            if len(args)>=3 and args[:2]==[kind,'inspect']:
                rest=args[2:]
                if rest[:2]==['--format','{{json .}}']:rest=rest[2:]
                elif kind=='image' and rest[:2]==['--format','{{.Id}}']:rest=rest[2:]
                if rest and len(rest)==len(set(rest)) and set(rest)<=known:
                    return {'kind':'read','containers':list(set(rest)&names)}
        if (args[:1]==['inspect'] and len(args)>=4 and args[1:3] in [
                ['--format','{{json .}}'],['--format','{{.Name}} {{.Image}}']]
                and len(args[3:])==len(set(args[3:])) and set(args[3:])<=names):
            return {'kind':'read','containers':args[3:]}
        if (args[:1]==['inspect'] and len(args)>=4
                and args[1:3]==['--format',IDENTITY_FORMAT]
                and len(args[3:])==len(set(args[3:])) and set(args[3:])<=names):
            return {'kind':'read','containers':args[3:]}
    for row in policy['receivers']:
        name=row['container']
        allowed = [
            ['exec',name,'ip','-j','-6','addr','show','dev','eth0'],
            ['exec',name,'ip','-j','-6','route','show'],
            ['exec',name,'ip','-j','-6','neigh','show'],
            ['exec',name,'cat','/proc/sys/net/ipv6/conf/eth0/mtu'],
            ['exec',name,'cat','/proc/net/route'],
            ['exec',name,'cat','/proc/net/ipv6_route'],
            ['restart','-t','1',name],
            ['exec',name,'ip','-6','addr','add',row['dad']+'/64','dev','eth0'],
            ['exec',name,'ip','-6','neigh','replace',row['neighbor_address'],'lladdr',row['neighbor_mac'],
             'nud',row['neighbor_state'],'dev','eth0'],
        ]
        if not stream and args in allowed:return {'kind':'receiver','containers':[name]}
    for row in policy['senders']:
        prefix=['exec',row['container'],'python',row['script']]
        if (len(args)==7 and args[:4]==prefix and args[4] in row['profiles']
                and args[5] in row['targets'] and NONCE.fullmatch(args[6])
                and (not stream or args[4]=='dad_na')):
            return {'kind':'sender','containers':[row['container']]}
    raise BrokerError('broker_operation_denied')


class PolicyRuntime:
    def __init__(self, path, *, strict=True, runner=None):
        self.path=Path(path);self.strict=strict
        if strict:
            _secure_file(self.path)
            if self.path.stat().st_mode & 0o077:raise BrokerError('broker_policy_not_private')
        raw=self.path.read_bytes()
        if len(raw)>1_000_000:raise BrokerError('broker_policy_too_large')
        self.policy=validate_policy(json.loads(raw));self.policy_sha256=sha256(canonical(self.policy))
        if strict and self.policy['principal'] is None:raise BrokerError('broker_requires_pinned_controller_process')
        self.runner=runner or subprocess.run
        self._file_cache={}
        self.verify_files()

    def verify_files(self):
        if self.strict:_secure_file(self.path)
        current=validate_policy(json.loads(self.path.read_text()))
        if sha256(canonical(current))!=self.policy_sha256:raise BrokerError('broker_policy_changed')
        if time.time()>=self.policy['expires_at']:raise BrokerError('broker_policy_expired')
        principal=self.policy['principal']
        if principal is not None:
            if principal['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():
                raise BrokerError('broker_principal_boot_changed')
        if self.strict:
            daemon=Path(self.policy['docker_endpoint'][7:]);info=daemon.lstat()
            _secure_directory(daemon.parent)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
                raise BrokerError('broker_daemon_endpoint_not_private')
        for path,digest in {self.policy['docker']:self.policy['docker_sha256'],**self.policy['pinned_files']}.items():
            p=Path(path)
            info=_secure_file(p) if self.strict else p.stat()
            key=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            if self._file_cache.get(path)!=key:
                if sha256(p.read_bytes())!=digest:raise BrokerError('broker_source_changed')
                self._file_cache[path]=key

    def authorize(self, args, peer_uid, *, stream=False, peer_pid=None):
        if peer_uid!=self.policy['allowed_uid']:raise BrokerError('broker_peer_denied')
        principal=self.policy['principal']
        if principal is not None and (peer_pid!=principal['pid'] or process_start_time(peer_pid)!=principal['start_time']):
            raise BrokerError('broker_peer_process_denied')
        self.verify_files();rule=permitted(self.policy,args,stream=stream)
        for name in rule['containers']:
            result=self.runner([self.policy['docker'],'--host',self.policy['docker_endpoint'],'container','inspect',name],capture_output=True,text=True,check=True,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','DOCKER_HOST':self.policy['docker_endpoint']})
            row=json.loads(result.stdout)[0];pin=self.policy['containers'][name]
            if row.get('Id')!=pin['id'] or row.get('Image')!=pin['image']:
                raise BrokerError('broker_container_changed')
            networks={n:v.get('NetworkID') for n,v in row.get('NetworkSettings',{}).get('Networks',{}).items()}
            if networks!=pin['networks']:raise BrokerError('broker_container_network_changed')
            host=row.get('HostConfig',{})
            if host.get('Privileged') or host.get('NetworkMode')=='host' or host.get('PidMode')=='host':
                raise BrokerError('broker_container_privilege_changed')
            if rule['kind'] in {'sender','receiver'}:
                caps={str(c).upper().removeprefix('CAP_') for c in host.get('CapAdd') or []}
                drop={str(c).upper().removeprefix('CAP_') for c in host.get('CapDrop') or []}
                expected={'NET_RAW'} if rule['kind']=='sender' else {'NET_ADMIN','NET_RAW'}
                if caps!=expected or drop!={'ALL'}:raise BrokerError('broker_container_capabilities_changed')
                if not host.get('ReadonlyRootfs') or 'no-new-privileges:true' not in (host.get('SecurityOpt') or []):
                    raise BrokerError('broker_container_sandbox_changed')
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','DOCKER_HOST':self.policy['docker_endpoint']}
        if len(args)>=3 and args[:2]==['network','inspect']:
            for name in args[2:]:
                if name=='--format' or name=='{{json .}}':continue
                result=self.runner([self.policy['docker'],'--host',self.policy['docker_endpoint'],'network','inspect',name],capture_output=True,text=True,check=True,timeout=10,env=env)
                if json.loads(result.stdout)[0].get('Id')!=self.policy['networks'][name]['id']:
                    raise BrokerError('broker_network_changed')
        if len(args)>=3 and args[:2]==['image','inspect']:
            refs=args[4:] if args[2:4] in [['--format','{{.Id}}'],['--format','{{json .}}']] else args[2:]
            for name in refs:
                result=self.runner([self.policy['docker'],'--host',self.policy['docker_endpoint'],'image','inspect','--format','{{.Id}}',name],capture_output=True,text=True,check=True,timeout=10,env=env)
                if result.stdout.strip()!=self.policy['images'][name]:raise BrokerError('broker_image_changed')
        return rule


_PUBLIC_LABELS={'com.docker.compose.project','com.docker.compose.service',
    'com.docker.compose.config-hash','com.docker.compose.container-number',
    'com.docker.compose.oneoff','com.docker.compose.version','com.docker.compose.image'}
_PUBLIC_FIXTURE_ENV={'LAB_FIXTURE_SEED','LAB_SCENARIO','LAB_GUARDED'}


def inspection_kind(args):
    if args[:2]==['inspect','--format'] and args[2] in {'{{json .}}',IDENTITY_FORMAT}:
        return 'identity' if args[2]==IDENTITY_FORMAT else 'container'
    if len(args)>=3 and args[0] in {'container','network','image'} and args[1]=='inspect':
        if '--format' not in args:return args[0]
        if args[2:4]==['--format','{{json .}}']:return args[0]
    return None


def _public_labels(value):
    return {k:v for k,v in (value or {}).items() if k in _PUBLIC_LABELS}


def _public_ports(value):
    return {port:None if rows is None else [{k:v for k,v in row.items() if k in {'HostIp','HostPort'}} for row in rows]
            for port,rows in (value or {}).items()}


def public_inspection(kind,value):
    if not isinstance(value,dict):raise BrokerError('broker_inspection_invalid')
    pick=lambda source,keys:{k:v for k,v in source.items() if k in keys}
    if kind=='container':
        out=pick(value,{'Id','Image','Name'})
        config=value.get('Config') or {}
        out['Config']=pick(config,{'Image'})
        out['Config']['Labels']=_public_labels(config.get('Labels'))
        out['Config']['Env']=[item for item in config.get('Env') or []
            if isinstance(item,str) and item.partition('=')[0] in _PUBLIC_FIXTURE_ENV]
        out['State']=pick(value.get('State') or {},{'Running','Pid'})
        out['HostConfig']=pick(value.get('HostConfig') or {},{'Privileged','CapAdd','CapDrop','NetworkMode',
            'PidMode','SecurityOpt','ReadonlyRootfs','NanoCpus','Memory','PidsLimit'})
        out['HostConfig']['PortBindings']=_public_ports((value.get('HostConfig') or {}).get('PortBindings'))
        settings=value.get('NetworkSettings') or {}
        out['NetworkSettings']={'Ports':_public_ports(settings.get('Ports')),'Networks':{}}
        for name,attachment in (settings.get('Networks') or {}).items():
            row=pick(attachment,{'NetworkID','EndpointID','Gateway','IPAddress','IPPrefixLen','IPv6Gateway',
                'GlobalIPv6Address','GlobalIPv6PrefixLen','MacAddress'})
            if attachment.get('IPAMConfig') is not None:
                row['IPAMConfig']=pick(attachment['IPAMConfig'],{'IPv4Address','IPv6Address'})
            out['NetworkSettings']['Networks'][name]=row
        # Keep only the mount type so preflight can reject bind/volume mounts.
        out['Mounts']=[pick(row,{'Type'}) for row in value.get('Mounts') or []]
        return out
    if kind=='image':
        out=pick(value,{'Id','RepoTags','RepoDigests','Architecture','Os'})
        config=value.get('Config') or {}
        out['Config']=pick(config,{'Image'});out['Config']['Labels']=_public_labels(config.get('Labels'))
        return out
    if kind=='network':
        out=pick(value,{'Id','Name','Driver','Internal','EnableIPv6'})
        ipam=value.get('IPAM') or {}
        out['IPAM']={'Driver':ipam.get('Driver'),'Config':[pick(row,{'Subnet','Gateway','IPRange'}) for row in ipam.get('Config') or []]}
        out['Options']=pick(value.get('Options') or {},{'com.docker.network.bridge.name'})
        out['Containers']={key:pick(row,{'Name','EndpointID','MacAddress','IPv4Address','IPv6Address'})
            for key,row in (value.get('Containers') or {}).items()}
        out['Labels']=_public_labels(value.get('Labels'))
        return out
    raise BrokerError('broker_inspection_invalid')


def redact_inspection(args,raw):
    kind=inspection_kind(args)
    try:
        text=raw.decode('utf-8')
        if kind=='identity':
            lines=[]
            for line in text.splitlines():
                name,image,labels=line.split('\t')
                lines.append('\t'.join([name,image,json.dumps(_public_labels(json.loads(labels)),separators=(',',':'))]))
            return ('\n'.join(lines)+'\n').encode()
        if '--format' in args:
            return b''.join(canonical(public_inspection(kind,json.loads(line)))+b'\n' for line in text.splitlines() if line.strip())
        values=json.loads(text)
        if not isinstance(values,list):raise BrokerError('broker_inspection_invalid')
        return canonical([public_inspection(kind,value) for value in values])+b'\n'
    except (ValueError,TypeError,KeyError,AttributeError):
        raise BrokerError('broker_inspection_invalid') from None


def _frame(connection, value):
    connection.sendall(canonical(value)+b'\n')


class BrokerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True
    allow_reuse_address=False

    def __init__(self, endpoint, runtime, *, audit_path=None, strict_identity=True):
        self.runtime=runtime;self.audit_path=Path(audit_path) if audit_path else None
        self.refresh_lock=threading.Lock();self.refresh_socket=None
        refresh_fd=os.environ.get('CENTINELA_REFRESH_FD')
        if refresh_fd is not None:
            try:
                self.refresh_socket=socket.socket(fileno=os.dup(int(refresh_fd)))
                if self.refresh_socket.family!=socket.AF_UNIX or self.refresh_socket.type!=socket.SOCK_STREAM:
                    raise ValueError('invalid socket type')
                self.refresh_socket.settimeout(15)
            except (ValueError,OSError):raise BrokerError('broker_refresh_channel_invalid') from None
        self.audit_lock=threading.Lock();self.identity=require_broker_identity() if strict_identity else process_identity()
        self.audit_fd=None
        if strict_identity:
            if self.identity.get('Groups','').strip() or self.identity.get('Gid','').split()!=[str(runtime.policy['allowed_gid'])]*4:
                raise BrokerError('broker_group_identity_denied')
            _secure_directory(Path(endpoint).parent)
            if self.audit_path:
                _secure_directory(self.audit_path.parent)
                if self.audit_path.exists() or self.audit_path.is_symlink():
                    _secure_file(self.audit_path)
                    if self.audit_path.stat().st_mode&0o077:raise BrokerError('broker_audit_log_not_private')
        if self.audit_path:
            self.audit_fd=os.open(self.audit_path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
        self.semaphore=threading.BoundedSemaphore(4)
        super().__init__(str(endpoint),BrokerHandler)
        os.chmod(endpoint,0o660)
        if strict_identity:os.chown(endpoint,0,runtime.policy['allowed_gid'])

    def event(self, value):
        if self.audit_fd is not None:
            with self.audit_lock:
                content=canonical({'time':time.time(),**value})+b'\n'
                while content:
                    written=os.write(self.audit_fd,content);content=content[written:]
                os.fsync(self.audit_fd)

    def refresh_after_restart(self, container):
        # The root operator owns the firewall. The Docker role cannot mutate it.
        if self.refresh_socket is None:raise BrokerError('broker_refresh_required')
        with self.refresh_lock:
            raw=canonical({'operation':'refresh','container':container})
            try:
                self.refresh_socket.sendall(struct.pack('!I',len(raw))+raw)
                def read_exact(size):
                    chunks=[]
                    while size:
                        chunk=self.refresh_socket.recv(size)
                        if not chunk:raise BrokerError('broker_refresh_disconnected')
                        chunks.append(chunk);size-=len(chunk)
                    return b''.join(chunks)
                size=struct.unpack('!I',read_exact(4))[0]
                if not 0<size<=4096:raise BrokerError('broker_refresh_invalid')
                if json.loads(read_exact(size))!={'ok':True}:raise BrokerError('broker_refresh_denied')
            except (OSError,ValueError):raise BrokerError('broker_refresh_failed') from None
        self.event({'event':'firewall_refreshed','container':container})

    def server_close(self):
        super().server_close()
        if self.refresh_socket is not None:
            self.refresh_socket.close();self.refresh_socket=None
        if self.audit_fd is not None:
            os.close(self.audit_fd);self.audit_fd=None


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        server=self.server
        pid,uid,gid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        process=None;args=None;acquired=False
        try:
            if uid!=server.runtime.policy['allowed_uid']:raise BrokerError('broker_peer_denied')
            identity=peer_identity(pid,uid,server.runtime.policy['allowed_gid']) if server.runtime.strict else {'pid':pid,'uid':uid,'test_mode':True}
            if not server.semaphore.acquire(blocking=False):raise BrokerError('broker_busy')
            acquired=True
            self.request.settimeout(3)
            data=self.rfile.readline(MAX_REQUEST+1)
            if len(data)>MAX_REQUEST or not data.endswith(b'\n'):raise BrokerError('broker_request_too_large')
            value=json.loads(data)
            if (not isinstance(value,dict) or set(value)!={'version','args','timeout','stream'}
                    or type(value['version']) is not int or value['version']!=1 or type(value['stream']) is not bool):
                raise BrokerError('broker_request_invalid')
            args=_clean_args(value['args']);seconds=value['timeout']
            if isinstance(seconds,bool) or not isinstance(seconds,(int,float)) or not 0<seconds<=MAX_SECONDS:
                raise BrokerError('broker_timeout_invalid')
            rule=server.runtime.authorize(args,uid,stream=value['stream'],peer_pid=pid)
            server.event({'event':'admitted','peer_uid':uid,'peer_pid':pid,'args':args,
                          'policy_sha256':server.runtime.policy_sha256,'broker':server.identity,'controller':identity})
            try:
                process=subprocess.Popen([server.runtime.policy['docker'],'--host',server.runtime.policy['docker_endpoint'],*args],stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8',
                        'DOCKER_HOST':server.runtime.policy['docker_endpoint']})
                for pipe in [process.stdout,process.stderr]:os.set_blocking(pipe.fileno(),False)
                active={process.stdout:'stdout',process.stderr:'stderr'};deadline=time.monotonic()+seconds;size=0
                inspect_output=inspection_kind(args) is not None
                buffered={'stdout':bytearray(),'stderr':bytearray()}
                while active:
                    if time.monotonic()>=deadline:raise BrokerError('broker_operation_timeout')
                    readable,_,_=select.select([*active,self.request],[],[],min(.1,max(0,deadline-time.monotonic())))
                    if self.request in readable:
                        # Sólo cancelación o cierre, nunca una segunda operación.
                        self.request.recv(256)
                        raise BrokerError('broker_client_cancelled')
                    for pipe in [p for p in readable if p in active]:
                        chunk=os.read(pipe.fileno(),65536)
                        if not chunk:active.pop(pipe);continue
                        size+=len(chunk)
                        if size>MAX_OUTPUT:raise BrokerError('broker_output_too_large')
                        if inspect_output:buffered[active[pipe]].extend(chunk)
                        else:_frame(self.request,{'channel':active[pipe],'data':base64.b64encode(chunk).decode()})
                code=process.wait(timeout=max(.01,deadline-time.monotonic()))
                if inspect_output:
                    if code==0:
                        clean=redact_inspection(args,bytes(buffered['stdout']))
                        _frame(self.request,{'channel':'stdout','data':base64.b64encode(clean).decode()})
                    else:_frame(self.request,{'channel':'stderr','data':base64.b64encode(b'approved_inspection_failed').decode()})
                if code==0 and args[:3]==['restart','-t','1']:
                    server.refresh_after_restart(args[3])
                _frame(self.request,{'exit_code':code,'policy_sha256':server.runtime.policy_sha256})
                server.event({'event':'finished','peer_uid':uid,'args':args,'exit_code':code})
            finally:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
        except Exception as exc:
            reason=str(exc) if isinstance(exc,BrokerError) else 'broker_operation_failed'
            server.event({'event':'rejected','peer_uid':uid,'args':args,'reason':reason})
            try:_frame(self.request,{'error':reason})
            except OSError:pass
        finally:
            if acquired:server.semaphore.release()


class _TextPipe:
    """Lectura de línea sin adelantar bytes que luego consume communicate."""
    def __init__(self, descriptor):self.descriptor=descriptor
    def fileno(self):return self.descriptor
    def readline(self):
        content=bytearray()
        while len(content)<=MAX_OUTPUT:
            char=os.read(self.descriptor,1)
            content.extend(char)
            if not char or char==b'\n':return content.decode()
        raise BrokerError('broker_response_too_large')
    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor);self.descriptor=None
    def __del__(self):
        try:self.close()
        except OSError:pass


class BrokerProcess:
    """Interfaz mínima compatible con la lectura READY del emisor DAD existente."""
    def __init__(self, args, *, timeout=15, endpoint=None, expected_server_uid=0):
        endpoint=Path(endpoint or os.environ.get('CENTINELA_BROKER_SOCKET',''))
        if not str(endpoint) or str(endpoint)=='.':raise BrokerError('broker_endpoint_missing')
        info=endpoint.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=expected_server_uid or info.st_mode&0o002:
            raise BrokerError('broker_endpoint_untrusted')
        if expected_server_uid==0:_secure_directory(endpoint.parent)
        self.connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.connection.settimeout(3)
        self.connection.connect(str(endpoint))
        _,uid,_=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=expected_server_uid:self.connection.close();raise BrokerError('broker_server_identity_denied')
        self.connection.settimeout(timeout+5)
        _frame(self.connection,{'version':1,'args':list(args),'timeout':timeout,'stream':True})
        read_fd,write_fd=os.pipe();self.stdout=_TextPipe(read_fd);self._write=write_fd
        self.returncode=None;self.error=None;self._stderr=bytearray();self._finished=threading.Event()
        self.thread=threading.Thread(target=self._receive,daemon=True);self.thread.start()

    def _receive(self):
        try:
            size=0
            with self.connection.makefile('rb') as stream:
                for line in stream:
                    if len(line)>MAX_OUTPUT*2:raise BrokerError('broker_response_too_large')
                    frame=json.loads(line)
                    if 'error' in frame:raise BrokerError(frame['error'])
                    if 'exit_code' in frame:self.returncode=frame['exit_code'];break
                    chunk=base64.b64decode(frame['data'],validate=True)
                    size+=len(chunk)
                    if size>MAX_OUTPUT:raise BrokerError('broker_response_too_large')
                    if frame['channel']=='stdout':
                        while chunk:
                            count=os.write(self._write,chunk);chunk=chunk[count:]
                    elif frame['channel']=='stderr':self._stderr.extend(chunk)
                    else:raise BrokerError('broker_response_invalid')
        except Exception as exc:
            self.error=exc;self.returncode=126
        finally:
            os.close(self._write);self._finished.set();self.connection.close()

    def poll(self):return self.returncode

    def communicate(self,timeout=None):
        chunks=[]
        # Consumir la tubería mientras se recibe evita bloquear por su capacidad.
        deadline=time.monotonic()+(timeout if timeout is not None else MAX_SECONDS+5)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise subprocess.TimeoutExpired('broker',timeout)
            ready,_,_=select.select([self.stdout],[],[],min(.1,remaining))
            if ready:
                chunk=os.read(self.stdout.fileno(),65536)
                if not chunk:break
                chunks.append(chunk)
        self._finished.wait(max(.01,deadline-time.monotonic()))
        if self.error:raise BrokerError(str(self.error))
        return b''.join(chunks).decode(),self._stderr.decode(errors='replace')

    def kill(self):
        try:self.connection.sendall(b'cancel\n')
        except OSError:pass


def broker_enabled():return bool(os.environ.get('CENTINELA_BROKER_SOCKET'))


def docker_command(args, *, timeout=15, endpoint=None):
    # El protocolo de respuesta es el mismo, pero sólo se admiten operaciones
    # síncronas en esta entrada. Un sender distinto de DAD no necesita READY.
    endpoint=Path(endpoint or os.environ.get('CENTINELA_BROKER_SOCKET',''))
    info=endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o002:raise BrokerError('broker_endpoint_untrusted')
    _secure_directory(endpoint.parent)
    output=bytearray();error=bytearray()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout+5);connection.connect(str(endpoint))
        _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise BrokerError('broker_server_identity_denied')
        _frame(connection,{'version':1,'args':list(args),'timeout':timeout,'stream':False})
        with connection.makefile('rb') as stream:
            for line in stream:
                if len(line)>MAX_OUTPUT*2:raise BrokerError('broker_response_too_large')
                frame=json.loads(line)
                if 'error' in frame:raise BrokerError(frame['error'])
                if 'exit_code' in frame:
                    if frame['exit_code']:raise BrokerError('broker_docker_failed')
                    return output.decode()
                chunk=base64.b64decode(frame['data'],validate=True)
                if frame['channel']=='stdout':output.extend(chunk)
                elif frame['channel']=='stderr':error.extend(chunk)
                else:raise BrokerError('broker_response_invalid')
                if len(output)+len(error)>MAX_OUTPUT:raise BrokerError('broker_response_too_large')
    raise BrokerError('broker_response_incomplete')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',type=Path,required=True);parser.add_argument('--socket',type=Path,required=True)
    parser.add_argument('--audit-log',type=Path,required=True)
    args=parser.parse_args()
    _secure_file(__file__)
    runtime=PolicyRuntime(args.policy)
    if args.socket.exists() or args.socket.is_symlink():raise BrokerError('broker_socket_already_exists')
    with BrokerServer(args.socket,runtime,audit_path=args.audit_log) as server:
        server.event({'event':'broker_started','identity':server.identity,'policy_sha256':runtime.policy_sha256})
        try:server.serve_forever(poll_interval=.2)
        finally:args.socket.unlink(missing_ok=True)


if __name__=='__main__':main()
