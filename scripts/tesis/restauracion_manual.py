"""Recibos locales de restauración: una restauración comprobada por corrida."""
from __future__ import annotations
import json
import fcntl
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

SCENARIOS={'integrado','sucursal','comercial','mixto','reforzado'}


class RestorationBook:
    def __init__(self,path,boot_id=None):
        self.path=Path(path)
        self.boot_id=boot_id or Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def read(self):
        try:
            if self.path.is_symlink() or self.path.stat().st_size>50_000:return {}
            value=json.loads(self.path.read_text())
            return value if isinstance(value,dict) else {}
        except (OSError,ValueError):return {}

    def write(self,value):
        from tesis.laboratorios import private_json
        if self.path.is_symlink():raise ValueError('Recibo de restauración no admitido.')
        private_json(self.path,value)

    def invalidate(self,scenario):
        data=self.read();data.pop(scenario,None);self.write(data)

    def restored(self,scenario,job_id):
        if scenario not in SCENARIOS:raise ValueError('Laboratorio no admitido.')
        data=self.read();data[scenario]={'id':uuid4().hex,'scenario':scenario,'boot_id':self.boot_id,
            'created_at':datetime.now(timezone.utc).isoformat(),'operation_id':job_id,
            'checked_at':None,'consumed_by':None}
        self.write(data)

    def checked(self,scenario):
        data=self.read();receipt=data.get(scenario,{})
        if receipt.get('boot_id')==self.boot_id and not receipt.get('consumed_by'):
            receipt['checked_at']=datetime.now(timezone.utc).isoformat();self.write(data)

    def public(self,scenario):
        receipt=self.read().get(scenario,{})
        ready=bool(receipt.get('id') and receipt.get('boot_id')==self.boot_id
            and receipt.get('checked_at') and not receipt.get('consumed_by'))
        return {'restoration_required':True,'restored':ready,'restoration':{
            k:receipt.get(k) for k in ['id','created_at','checked_at','consumed_by']}}

    def claim(self,scenario,job_id):
        if not self.public(scenario)['restored']:
            raise ValueError('Restaura este laboratorio y pulsa Comprobar antes de cada corrida registrada.')
        data=self.read();receipt=data[scenario];receipt['consumed_by']=job_id
        self.write(data)
        return {k:receipt[k] for k in ['id','scenario','created_at','checked_at','operation_id','consumed_by']}

    def verify_claim(self,scenario,job_id,receipt_id):
        receipt=self.read().get(scenario,{})
        if (receipt.get('boot_id')!=self.boot_id or receipt.get('consumed_by')!=job_id
            or receipt.get('id')!=receipt_id or not receipt.get('checked_at')):
            raise ValueError('No se acredita la restauración comprobada de esta posición.')
        return True

    def activate(self,scenario,job_id,receipt_id):
        """Una reserva admite un solo proceso ejecutor, también por terminal."""
        lock_path=self.path.with_suffix('.lock')
        with lock_path.open('a') as lock:
            os.chmod(lock_path,0o600)
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.verify_claim(scenario,job_id,receipt_id)
            data=self.read();receipt=data[scenario]
            if receipt.get('activation_id'):
                raise ValueError('El recibo de restauración ya fue utilizado por una corrida.')
            receipt['activation_id']=uuid4().hex
            receipt['activated_at']=datetime.now(timezone.utc).isoformat()
            self.write(data)
            return receipt['activation_id']


def assert_run_claim(output,options,book_path):
    """El hijo comprueba el protocolo y el recibo antes de usar la API."""
    from tesis.protocolo_manual import protocol
    proposal=protocol()
    if (proposal.get('status')!='frozen' or proposal.get('task_limit_status')!='confirmed'
        or proposal.get('execution_enabled') is not True or proposal.get('task_limit_applied') is not True):
        raise ValueError('El protocolo de detección sigue pendiente de confirmación.')
    path=Path(output)/'panel_job.json'
    try:
        if path.is_symlink() or path.stat().st_size>100_000:raise ValueError('Trabajo manual no admitido.')
        job=json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError('Trabajo manual no admitido.') from exc
    if not isinstance(job,dict) or not isinstance(job.get('manual_protocol'),dict):
        raise ValueError('Trabajo manual no admitido.')
    metadata=job['manual_protocol']
    receipt=metadata.get('restoration',{})
    if not isinstance(receipt,dict):raise ValueError('Recibo de restauración no admitido.')
    if (metadata.get('protocol_sha256')!=proposal['protocol_sha256']
        or options.get('tokens')!=proposal['tokens'] or options.get('ia')!='openai'
        or not options.get('expert_mode')):
        raise ValueError('La configuración o el protocolo del trabajo no son compatibles.')
    activation=RestorationBook(book_path).activate(options.get('scenario') or 'integrado',Path(output).name,receipt.get('id'))
    return {**metadata,'restoration':{**receipt,'activation_id':activation}}
