"""El canal privilegiado no acepta la API Docker ni comandos generales."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

import pytest

from auditoria.privilege_broker import (BrokerError,BrokerProcess,BrokerServer,
    PolicyRuntime,canonical,permitted,validate_policy,sha256,peer_identity,process_start_time)


def policy(docker='/usr/bin/true'):
    return {'version':1,'allowed_uid':os.geteuid() or 1000,'allowed_gid':os.getegid() or 1000,
        'principal':None,'expires_at':time.time()+3600,'docker':docker,'docker_endpoint':'unix:///tmp/private-docker.sock',
        'docker_sha256':sha256(Path(docker).read_bytes()),
        'containers':{'sender':{'id':'a'*64,'image':'sha256:'+'b'*64,'networks':{'lab':'c'*64}},
                      'receiver':{'id':'d'*64,'image':'sha256:'+'e'*64,'networks':{'lab':'c'*64}}},
        'networks':{'lab':{'id':'c'*64}},'pinned_files':{},
        'images':{'sha256:'+'b'*64:'sha256:'+'b'*64,'sha256:'+'e'*64:'sha256:'+'e'*64},
        'projects':{'fixture':['sender','receiver']},
        'receivers':[{'container':'receiver','address':'fd00::20','dad':'fd00::30',
            'neighbor_address':'fd00::10','neighbor_mac':'02:00:00:00:00:10','neighbor_state':'reachable'}],
        'senders':[{'container':'sender','script':'/app/datacenter/sender.py',
            'targets':['fd00::20'],'profiles':['dad_na','ra_route','plain']}]}


def sender(profile='ra_route',target='fd00::20',nonce='0123456789abcdef'):
    return ['exec','sender','python','/app/datacenter/sender.py',profile,target,nonce]


@pytest.mark.parametrize('args',[
    ['exec','receiver','ip','-j','-6','addr','show','dev','eth0'],
    ['exec','receiver','ip','-j','-6','route','show'],
    ['exec','receiver','ip','-j','-6','neigh','show'],
    ['exec','receiver','cat','/proc/sys/net/ipv6/conf/eth0/mtu'],
    ['restart','-t','1','receiver'],
    ['exec','receiver','ip','-6','addr','add','fd00::30/64','dev','eth0'],
    ['exec','receiver','ip','-6','neigh','replace','fd00::10','lladdr','02:00:00:00:00:10','nud','reachable','dev','eth0'],
    ['container','inspect','receiver'],['network','inspect','lab'],
    ['image','inspect','--format','{{.Id}}','sha256:'+'b'*64],sender(),
    ['ps','--all','--filter','label=com.docker.compose.project=fixture','--format','{{.Names}}'],
    ['inspect','--format','{{json .Name}}\t{{json .Image}}\t{{json .Config.Labels}}','receiver'],
    ['inspect','--format','{{.Name}} {{.Image}}','receiver'],
])
def test_only_expected_catalog_operations_are_admitted(args):
    assert permitted(policy(),args)['kind'] in {'read','receiver','sender'}


@pytest.mark.parametrize('args',[
    ['run','--privileged','-v','/:/host','alpine'],['compose','up','-d'],
    ['build','.'],['container','rm','receiver'],['network','rm','lab'],
    ['exec','receiver','sh','-c','id'],['exec','receiver','cat','/etc/shadow'],
    ['exec','receiver','ip','-6','addr','add','fd00::99/64','dev','eth0'],
    ['exec','receiver','ip','-6','neigh','replace','fd00::10','lladdr','02:00:00:00:00:99','nud','reachable','dev','eth0'],
    ['--host','unix:///var/run/docker.sock','container','inspect','receiver'],
    ['container','inspect','unknown'],['container','inspect','--format','{{.Config.Env}}','receiver'],
    ['restart','-t','1','sender'],sender(target='fd00::99'),sender(profile='arbitrary'),
    sender(nonce='0123456789abcde;'),sender()+['--privileged'],
    ['exec','-u','0','receiver','id'],
])
def test_general_docker_authority_and_scope_expansion_are_rejected(args):
    with pytest.raises(BrokerError,match='denied'):permitted(policy(),args)


def test_only_dad_profile_can_request_streaming():
    assert permitted(policy(),sender('dad_na'),stream=True)['kind']=='sender'
    with pytest.raises(BrokerError):permitted(policy(),sender(),stream=True)


def test_expired_policy_and_boolean_versions_are_rejected():
    p=policy();p['expires_at']=time.time()-1
    with pytest.raises(BrokerError,match='expired'):permitted(p,sender())
    p=policy();p['version']=True
    with pytest.raises(BrokerError):validate_policy(p)


def runtime(tmp_path, p=None):
    p=p or policy();path=tmp_path/'policy.json';path.write_bytes(canonical(p))
    def inspect(args,**kwargs):
        name=args[-1];row=p['containers'][name]
        return subprocess.CompletedProcess(args,0,json.dumps([{
            'Id':row['id'],'Image':row['image'],'HostConfig':{
                'CapAdd':['NET_RAW'] if name=='sender' else ['NET_ADMIN','NET_RAW'],'CapDrop':['ALL'],
                'Privileged':False,'NetworkMode':'lab','PidMode':'','ReadonlyRootfs':True,
                'SecurityOpt':['no-new-privileges:true']},
            'NetworkSettings':{'Networks':{n:{'NetworkID':v} for n,v in row['networks'].items()}}
        }]))
    return PolicyRuntime(path,strict=False,runner=inspect)


def test_peer_is_checked_before_any_daemon_request(tmp_path):
    r=runtime(tmp_path);r.runner=lambda *a,**k:pytest.fail('Docker must not be reached')
    with pytest.raises(BrokerError,match='peer_denied'):
        r.authorize(sender(),r.policy['allowed_uid']+1)


def test_changed_policy_requires_a_new_broker(tmp_path):
    r=runtime(tmp_path);p=deepcopy(r.policy);p['expires_at']+=1;r.path.write_bytes(canonical(p))
    with pytest.raises(BrokerError,match='policy_changed'):
        r.authorize(sender(),r.policy['allowed_uid'])


def test_a_different_process_with_same_uid_is_not_the_controller(tmp_path):
    p=policy();p['principal']={'pid':os.getpid(),'start_time':process_start_time(os.getpid()),
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    r=runtime(tmp_path,p);r.runner=lambda *a,**k:pytest.fail('Docker must not be reached')
    with pytest.raises(BrokerError,match='process_denied'):
        r.authorize(sender(),r.policy['allowed_uid'],peer_pid=os.getpid()+1)


def test_pid_reuse_with_a_different_start_time_is_rejected(tmp_path):
    p=policy();p['principal']={'pid':os.getpid(),'start_time':str(int(process_start_time(os.getpid()))+1),
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    r=runtime(tmp_path,p);r.runner=lambda *a,**k:pytest.fail('Docker must not be reached')
    with pytest.raises(BrokerError,match='process_denied'):
        r.authorize(sender(),r.policy['allowed_uid'],peer_pid=os.getpid())


@pytest.mark.parametrize('change', ['id','image','network','privileged','sender_caps'])
def test_container_identity_and_capabilities_are_rechecked(tmp_path,change):
    r=runtime(tmp_path);original=r.runner
    def changed(args,**kwargs):
        result=original(args,**kwargs);row=json.loads(result.stdout)[0]
        if change=='id':row['Id']='f'*64
        if change=='image':row['Image']='sha256:'+'f'*64
        if change=='network':row['NetworkSettings']['Networks']['lab']['NetworkID']='f'*64
        if change=='privileged':row['HostConfig']['Privileged']=True
        if change=='sender_caps':row['HostConfig']['CapAdd'].append('NET_ADMIN')
        result.stdout=json.dumps([row]);return result
    r.runner=changed
    with pytest.raises(BrokerError):r.authorize(sender(),r.policy['allowed_uid'])


def test_changed_pinned_source_blocks_dispatch(tmp_path):
    path=tmp_path/'sender.py';path.write_text('original')
    p=policy();p['pinned_files']={str(path):sha256(path.read_bytes())}
    r=runtime(tmp_path,p);path.write_text('changed')
    with pytest.raises(BrokerError,match='source_changed'):
        r.authorize(sender(),r.policy['allowed_uid'])


def test_docker_endpoint_is_fixed_by_operator_not_environment(tmp_path,monkeypatch):
    r=runtime(tmp_path);seen=[];original=r.runner
    def inspect(args,**kwargs):seen.append(kwargs['env']);return original(args,**kwargs)
    r.runner=inspect;monkeypatch.setenv('DOCKER_HOST','tcp://198.51.100.99:2375')
    r.authorize(sender(),r.policy['allowed_uid'])
    assert seen[0]['DOCKER_HOST']=='unix:///tmp/private-docker.sock'
    assert 'HOME' not in seen[0]


@pytest.mark.parametrize(('field','value'),[
    ('CapEff','0000000000002000'),('CapPrm','0000000000002000'),
    ('CapInh','0000000000002000'),('CapBnd','0000000000002000'),
    ('CapAmb','0000000000002000'),('NoNewPrivs','0'),('Groups','1000'),
    ('Uid','1000\t1000\t0\t1000'),('Gid','1000\t1000\t0\t1000'),
    ('Gid','0\t0\t0\t0')])
def test_socket_cannot_hide_privileged_or_group_membership_state(monkeypatch,field,value):
    # Las propiedades del proceso que ejecuta pytest no cambian el resultado.
    fields={'Uid':'1000\t1000\t1000\t1000','Gid':'1000\t1000\t1000\t1000',
        'Groups':'','CapInh':'0','CapPrm':'0','CapEff':'0','CapBnd':'0','CapAmb':'0','NoNewPrivs':'1'}
    fields[field]=value
    content='\n'.join(k+':\t'+v for k,v in fields.items())
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**k:content)
    with pytest.raises(BrokerError):peer_identity(12345,1000)


@pytest.mark.skipif(os.geteuid()==0,reason='Offline transport fixture models a non-root test broker')
def test_ready_stream_preserves_bytes_already_following_the_ready_line(tmp_path):
    fake=tmp_path/'docker-fixture'
    fake.write_text('#!/usr/bin/python3\nimport sys\nsys.stdout.write(\'READY\\n{"packet_count":1,"fixture":true}\\n\')\nsys.stdout.flush()\n')
    fake.chmod(0o700);p=policy(str(fake));r=runtime(tmp_path,p)
    endpoint=tmp_path/'broker.sock';server=BrokerServer(endpoint,r,strict_identity=False)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        process=BrokerProcess(sender('dad_na'),endpoint=endpoint,expected_server_uid=os.geteuid())
        assert process.stdout.readline()=='READY\n'
        stdout,stderr=process.communicate(timeout=3)
        assert json.loads(stdout)=={'packet_count':1,'fixture':True}
        assert stderr=='' and process.returncode==0
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


@pytest.mark.parametrize('args',[
    ['container','inspect','receiver'],['container','inspect','--format','{{json .}}','receiver'],
    ['inspect','--format','{{json .}}','receiver'],['image','inspect','sha256:'+'b'*64],
    ['image','inspect','--format','{{json .}}','sha256:'+'b'*64],
])
def test_inspect_never_transfers_environment_mount_paths_or_metadata_secrets(args):
    from auditoria.privilege_broker import redact_inspection
    raw={'Id':'a'*64,'Name':'/receiver','Image':'sha256:'+'b'*64,
         'Config':{'Image':'fixture:current','Env':['OPENAI_API_KEY=secret-token','POSTGRES_PASSWORD=secret-password',
             'LAB_FIXTURE_SEED=2026','LAB_SCENARIO=alpha','LAB_GUARDED=0'],
             'Labels':{'private-secret':'secret-label','com.docker.compose.project':'fixture'},
             'Cmd':['secret-command']},
         'HostConfig':{'Privileged':False,'CapAdd':['NET_RAW'],'CapDrop':['ALL'],'ReadonlyRootfs':True,
             'Binds':['/secret-path:/app'],'NanoCpus':250000000,'Memory':67108864,'PidsLimit':32},
         'State':{'Running':True,'Pid':123,'Error':'secret-error'},
         'Mounts':[{'Type':'bind','Source':'/secret-mount','Destination':'/secret-target'}],
         'NetworkSettings':{'Ports':{},'Networks':{'fixture':{'NetworkID':'c'*64,'IPAddress':'192.0.2.10',
             'MacAddress':'02:00:00:00:00:10','secret-option':'secret-network'}}},
         'History':[{'CreatedBy':'secret-history'}]}
    payload=json.dumps(raw if '--format' in args else [raw]).encode()
    clean=redact_inspection(args,payload)
    assert b'secret' not in clean
    row=json.loads(clean) if '--format' in args else json.loads(clean)[0]
    assert row['Id']=='a'*64
    if args[0]!='image':
        assert row['Config']['Env']==['LAB_FIXTURE_SEED=2026','LAB_SCENARIO=alpha','LAB_GUARDED=0']
        assert row['HostConfig']['Memory']==67108864
        assert row['NetworkSettings']['Networks']['fixture']['IPAddress']=='192.0.2.10'
        assert row['Mounts']==[{'Type':'bind'}]
    else:assert 'Env' not in row['Config']


def test_inspect_identity_labels_are_filtered_and_bad_json_fails_closed():
    from auditoria.privilege_broker import redact_inspection, IDENTITY_FORMAT
    args=['inspect','--format',IDENTITY_FORMAT,'receiver']
    raw=b'"/receiver"\t"sha256:abc"\t{"secret":"secret-token","com.docker.compose.project":"fixture"}\n'
    clean=redact_inspection(args,raw)
    assert b'secret' not in clean and b'fixture' in clean
    with pytest.raises(BrokerError):redact_inspection(['container','inspect','receiver'],b'{invalid secret-token')


def test_restart_requires_synchronous_root_firewall_ack():
    from auditoria.privilege_broker import BrokerServer
    server=object.__new__(BrokerServer);server.refresh_lock=threading.Lock();server.refresh_socket=None
    with pytest.raises(BrokerError,match='refresh_required'):server.refresh_after_restart('receiver')
    for response,accepted in [({'ok':True},True),({'ok':False},False)]:
        first,second=socket.socketpair();first.settimeout(1);server.refresh_socket=first;server.event=lambda value:None
        observed=[]
        def operator():
            size=int.from_bytes(second.recv(4),'big');observed.append(json.loads(second.recv(size)))
            data=json.dumps(response).encode();second.sendall(len(data).to_bytes(4,'big')+data)
        thread=threading.Thread(target=operator);thread.start()
        try:
            if accepted:server.refresh_after_restart('receiver')
            else:
                with pytest.raises(BrokerError,match='refresh_denied'):server.refresh_after_restart('receiver')
            assert observed==[{'operation':'refresh','container':'receiver'}]
        finally:thread.join();first.close();second.close()


def test_audit_events_have_operator_comparable_timestamps(tmp_path):
    from auditoria.privilege_broker import BrokerServer
    server=object.__new__(BrokerServer);server.audit_lock=threading.Lock()
    descriptor=os.open(tmp_path/'audit.jsonl',os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600)
    server.audit_fd=descriptor
    before=time.time()
    try:server.event({'event':'rejected','reason':'broker_peer_denied'})
    finally:os.close(descriptor)
    row=json.loads((tmp_path/'audit.jsonl').read_text())
    assert before<=row['time']<=time.time()
    assert row['event']=='rejected'
