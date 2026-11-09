"""Pruebas locales de las fronteras de rol; sin herramientas ni destinos de red."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from auditoria import tool_worker as worker
from auditoria.contracts import CredentialProfile, Task, Target, TaskResult, TaskStatus


def credentials(uid=65531,gid=None):
    gid=uid if gid is None else gid
    return {'Uid':' '.join([str(uid)]*4),'Gid':' '.join([str(gid)]*4),'Groups':'',
            'NoNewPrivs':'1',**{key:'0'*16 for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']},
            'start_time':'123','pid':42}


def task_profile():
    task=Task(task_id='test_credential',agent_type='ipv4_credenciales',protocol='ipv4',
        action_profile='hydra_ssh_single_v1',timeout_seconds=30,
        target=Target(asset_id='fixture',address='192.0.2.10',interface='lab0',ports=[22]))
    profile=CredentialProfile(ref='synthetic',service='ssh',port=22,username='fixture',password_env='LAB_TEST_PASSWORD')
    return task,profile


def stat_value(mode,uid=0):
    return SimpleNamespace(st_mode=mode,st_uid=uid)


class IdentityTests(unittest.TestCase):
    def test_complete_role_identity_is_accepted(self):
        self.assertTrue(worker.unprivileged(credentials(),65531))
        self.assertTrue(worker.unprivileged(credentials(gid=123),65531,123))

    def test_every_uid_gid_capability_and_group_is_checked(self):
        for field,value in [('Uid','65531 0 65531 65531'),('Gid','65531 0 65531 65531'),
                ('Groups','1'),('NoNewPrivs','0'),*[(key,'1') for key in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']]]:
            with self.subTest(field=field):
                data=credentials();data[field]=value
                self.assertFalse(worker.unprivileged(data,65531))
        for uid,data in [(0,credentials(0)),(True,credentials(1)),(65531,{}),(65531,{'Uid':None})]:
            with self.subTest(uid=uid,data=data):self.assertFalse(worker.unprivileged(data,uid))

    def test_same_uid_outside_pinned_pid_is_denied(self):
        policy={'controller_uid':65531,'controller_pid':42,'controller_start_time':'123'}
        with patch.object(worker,'identity',return_value=credentials()):
            worker._peer_allowed(policy,42,65531,65531)
            for pid,uid,gid in [(43,65531,65531),(42,65531,1000),(42,65532,65532)]:
                with self.subTest(pid=pid,uid=uid,gid=gid),self.assertRaises(worker.WorkerDenied):
                    worker._peer_allowed(policy,pid,uid,gid)

    def test_reused_pid_or_changed_boot_is_denied(self):
        policy={'controller_uid':65531,'controller_pid':42,'controller_start_time':'124'}
        with patch.object(worker,'identity',return_value=credentials()),self.assertRaises(worker.WorkerDenied):
            worker._peer_allowed(policy,42,65531,65531)
        policy.update(controller_start_time='123',controller_boot_id='wrong-boot')
        with patch.object(worker,'identity',return_value=credentials()),self.assertRaises(worker.WorkerDenied):
            worker._peer_allowed(policy,42,65531,65531)


class ProtectedPathsTests(unittest.TestCase):
    def test_socket_group_write_is_allowed_with_protected_ancestors(self):
        def info(path):
            if str(path)=='/var/tmp':return stat_value(stat.S_IFDIR|0o1777)
            if str(path).endswith('.sock'):return stat_value(stat.S_IFSOCK|0o660)
            return stat_value(stat.S_IFDIR|0o755)
        with patch.object(Path,'lstat',info):self.assertEqual(worker._endpoint('/var/tmp/root-stage/tool.sock'),'/var/tmp/root-stage/tool.sock')

    def test_writable_nonsticky_or_nonroot_ancestor_is_rejected(self):
        for mode,uid in [(stat.S_IFDIR|0o777,0),(stat.S_IFDIR|0o1777,1000),(stat.S_IFLNK|0o777,0)]:
            def info(path):
                return stat_value(mode,uid) if str(path)=='/stage' else stat_value(stat.S_IFSOCK|0o660 if str(path).endswith('.sock') else stat.S_IFDIR|0o755)
            with self.subTest(mode=mode,uid=uid),patch.object(Path,'lstat',info),self.assertRaises(worker.WorkerDenied):
                worker._endpoint('/stage/tool.sock')

    def test_relative_paths_and_world_socket_are_rejected(self):
        with self.assertRaises(worker.WorkerDenied):worker._protected_path('relative')
        def info(path):return stat_value(stat.S_IFSOCK|0o666 if str(path).endswith('.sock') else stat.S_IFDIR|0o755)
        with patch.object(Path,'lstat',info),self.assertRaises(worker.WorkerDenied):worker._endpoint('/run/tool.sock')

    def test_private_read_rejects_symlink_and_nonprivate_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'file';path.write_text('synthetic');path.chmod(0o600)
            self.assertEqual(worker._read_private(path,32,owner=os.geteuid()),b'synthetic')
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):worker._read_private(link,32)
            path.chmod(0o644)
            with self.assertRaises(worker.WorkerDenied):worker._read_private(path,32,owner=os.geteuid())
            with self.assertRaises(worker.WorkerDenied):worker._read_private(path,2)


class CommandAndPolicyTests(unittest.TestCase):
    def test_nmap_is_exact_allowlist_with_no_secret(self):
        policy={'role':'nmap','commands':[['nmap','-sT','192.0.2.10']]}
        worker.validate_command(policy,policy['commands'][0])
        for command,password in [(['nmap','-sS','192.0.2.10'],None),(['nmap','-sT','192.0.2.11'],None),
                (policy['commands'][0],'synthetic'),(['nmap','bad\narg'],None),([],None)]:
            with self.subTest(command=command),self.assertRaises(worker.WorkerDenied):worker.validate_command(policy,command,password)

    def test_hydra_changes_only_private_file_slots(self):
        template=['hydra','-l','fixture','-P','<private>','-o','<private>','ssh']
        policy={'role':'hydra','commands':[{'argv':template,'password_sha256':hashlib.sha256(b'synthetic').hexdigest()}]}
        command=list(template);command[4]='/private/password';command[6]='/private/output'
        worker.validate_command(policy,command,'synthetic')
        for command,password in [(command,'wrong'),([*command,'-V'],'synthetic'),([*command[:2],'admin',*command[3:]],'synthetic')]:
            with self.subTest(command=command,password=password),self.assertRaises(worker.WorkerDenied):worker.validate_command(policy,command,password)

    def test_timeouts_reject_nonfinite_and_bools(self):
        for value in [True,False,float('nan'),float('inf'),0,-1,181,'10',None]:
            with self.subTest(value=value),self.assertRaises(worker.WorkerDenied):worker._timeout(value)
        self.assertEqual(worker._timeout(30),30)

    def test_policy_pins_executable_and_optional_boot(self):
        executable='/usr/bin/true'
        policy={'version':1,'role':'nmap','controller_uid':65531,'controller_pid':42,
            'controller_start_time':'123','worker_uid':65532,'netns':123,'expires_at':time.time()+60,
            'executable':executable,'executable_sha256':hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            'commands':[['nmap','-sT','192.0.2.10']],'credential_profiles':[]}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'policy.json'
            for change,accepted in [({},True),({'controller_gid':65531,'worker_gid':65532,
                    'controller_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()},True),
                    ({'version':True},False),({'executable_sha256':'0'*64},False),
                    ({'controller_boot_id':'changed'},False),({'worker_uid':65531},False),({'extra':1},False)]:
                value=policy|change;path.write_text(json.dumps(value))
                with self.subTest(change=change),patch.object(worker,'_protected_path',side_effect=lambda path,**kwargs:Path(path)):
                    if accepted:self.assertEqual(worker.load_policy(path),value)
                    else:
                        with self.assertRaises(worker.WorkerDenied):worker.load_policy(path)

    def test_failed_identity_observation_kills_and_reaps_child(self):
        process=Mock(pid=54321,returncode=-9)
        policy={'executable':'/usr/bin/true','executable_sha256':hashlib.sha256(Path('/usr/bin/true').read_bytes()).hexdigest(),'worker_uid':65532}
        with patch.object(worker.subprocess,'Popen',return_value=process),patch.object(worker,'identity',side_effect=FileNotFoundError),patch.object(worker.os,'killpg') as kill:
            with self.assertRaises(FileNotFoundError):worker._execute(policy,['nmap'],1,'/private',Mock())
        kill.assert_called_once_with(54321,signal_number())
        process.wait.assert_called_once()


def signal_number():
    import signal
    return signal.SIGKILL


class EvidenceTransferTests(unittest.TestCase):
    def transfer(self,message,authorize=None):
        task,profile=task_profile();store=Mock()
        store.evidence.side_effect=lambda stem,extension,raw:(f'evidence/{stem}.{extension}',hashlib.sha256(raw).hexdigest())
        connection=Mock();connection.getsockopt.return_value=struct.pack('3i',20,65533,65533)
        context=Mock();context.__enter__=Mock(return_value=connection);context.__exit__=Mock(return_value=False)
        messages=message if isinstance(message,list) else [message]
        with patch.dict(os.environ,{'CENTINELA_HYDRA_SOCKET':'/run/test.sock','LAB_TEST_PASSWORD':'synthetic'}),patch.object(worker,'_endpoint',return_value='/run/test.sock'),patch.object(worker.socket,'socket',return_value=context),patch.object(worker,'_send') as send,patch.object(worker,'_receive',side_effect=messages):
            result=worker.run_credential(task,profile,store,timeout_seconds=30,authorize=authorize)
        return result,store,send

    def message(self):
        raw=b'{"outcome":"accepted"}'
        result=TaskResult(task_id='test_credential',status=TaskStatus.COMPLETED,evidence_ref='evidence/test_credential.json',evidence_sha256=hashlib.sha256(raw).hexdigest())
        return {'ok':True,'credential_result':result.model_dump(mode='json'),
                'files':[{'reference':result.evidence_ref,'data':base64.b64encode(raw).decode()}]}

    def test_verified_evidence_is_persisted(self):
        result,store,_=self.transfer(self.message())
        self.assertEqual(result.task_id,'test_credential');store.evidence.assert_called_once()

    def test_bad_hash_duplicate_or_extra_file_never_persisted(self):
        for kind in ['hash','duplicate','extra','traversal']:
            message=self.message()
            if kind=='hash':message['files'][0]['data']=base64.b64encode(b'changed').decode()
            elif kind=='duplicate':message['files']*=2
            elif kind=='extra':message['files'].append({'reference':'evidence/extra.json','data':'e30='})
            else:message['files'][0]['reference']='evidence/../private.json'
            with self.subTest(kind=kind),patch.object(worker,'_evidence_path',wraps=worker._evidence_path):
                with self.assertRaises(worker.WorkerDenied):self.transfer(message)

    def test_callback_revalidates_each_stage(self):
        callback=Mock()
        result,_,send=self.transfer([{'authorize':True},{'authorize':True},self.message()],callback)
        self.assertEqual(callback.call_count,2)
        self.assertEqual(sum(call.args[-1]=={'authorized':True} for call in send.call_args_list),2)

    def test_callback_revocation_is_propagated(self):
        with self.assertRaisesRegex(RuntimeError,'revoked'):
            self.transfer([{'authorize':True}],Mock(side_effect=RuntimeError('revoked')))

    def test_paths_are_canonical_and_single_component(self):
        for reference in ['../private','evidence/../x.json','evidence//x.json','/evidence/x.json','evidence/a.b.json','evidence/ñ.json']:
            with self.subTest(reference=reference),self.assertRaises(worker.WorkerDenied):worker._evidence_path(reference)
        self.assertEqual(worker._evidence_path('evidence/task_confirmation.json').name,'task_confirmation.json')


class CredentialOperationTests(unittest.TestCase):
    def test_worker_runs_local_without_reentry_and_restores_environment(self):
        from auditoria.agentes import agente_ipv4_credenciales as adapter
        task,profile=task_profile()
        key=task.model_dump(mode='json');key.pop('task_id');key.pop('dependencies')
        policy={'role':'hydra','expires_at':time.time()+60,'credential_profiles':[{
            'task':key,'profile':profile.model_dump(mode='json'),
            'password_sha256':hashlib.sha256(b'synthetic').hexdigest()}]}
        message={'operation':'credential','task':task.model_dump(mode='json'),
                 'profile':profile.model_dump(mode='json'),'password':'synthetic','timeout':30}
        original_subprocess=adapter.subprocess
        def backend(task,profile,store,*,timeout_seconds,authorize):
            self.assertFalse(worker.tool_runtime_enabled())
            self.assertEqual(os.environ[profile.password_env],'synthetic')
            self.assertIsNot(adapter.subprocess,original_subprocess)
            authorize()
            ref,digest=store.evidence(task.task_id,'json',b'{"outcome":"accepted"}')
            self.assertEqual((store.root/ref).stat().st_mode&0o077,0)
            return TaskResult(task_id=task.task_id,status=TaskStatus.COMPLETED,evidence_ref=ref,evidence_sha256=digest)
        records=[]
        with patch.dict(os.environ,{'CENTINELA_PROTECTED_RUNTIME':'1','LAB_TEST_PASSWORD':'old-value'}),patch.object(adapter,'run_hydra',side_effect=backend),patch.object(worker,'identity',return_value=credentials(65533)),patch.object(worker,'_send') as send,patch.object(worker,'_receive',return_value={'authorized':True}):
            worker.credential_operation(Mock(),policy,message,lambda event,**fields:records.append((event,fields)))
            self.assertEqual(os.environ['CENTINELA_PROTECTED_RUNTIME'],'1')
            self.assertEqual(os.environ['LAB_TEST_PASSWORD'],'old-value')
        self.assertIs(adapter.subprocess,original_subprocess)
        self.assertNotIn('synthetic',json.dumps(records))
        self.assertEqual(send.call_args.args[-1]['ok'],True)

    def test_worker_restores_state_when_adapter_raises(self):
        from auditoria.agentes import agente_ipv4_credenciales as adapter
        task,profile=task_profile();key=task.model_dump(mode='json');key.pop('task_id');key.pop('dependencies')
        policy={'role':'hydra','expires_at':time.time()+60,'credential_profiles':[{
            'task':key,'profile':profile.model_dump(mode='json'),'password_sha256':hashlib.sha256(b'synthetic').hexdigest()}]}
        message={'operation':'credential','task':task.model_dump(mode='json'),'profile':profile.model_dump(mode='json'),
            'password':'synthetic','timeout':30}
        original=adapter.subprocess
        with patch.dict(os.environ,{'CENTINELA_PROTECTED_RUNTIME':'1','LAB_TEST_PASSWORD':'old-value'}),patch.object(adapter,'run_hydra',side_effect=RuntimeError('backend-failed')),patch.object(worker,'identity',return_value=credentials(65533)):
            with self.assertRaisesRegex(RuntimeError,'backend-failed'):worker.credential_operation(Mock(),policy,message,Mock())
            self.assertEqual(os.environ['CENTINELA_PROTECTED_RUNTIME'],'1')
            self.assertEqual(os.environ['LAB_TEST_PASSWORD'],'old-value')
            self.assertIs(adapter.subprocess,original)


if __name__=='__main__':unittest.main()
