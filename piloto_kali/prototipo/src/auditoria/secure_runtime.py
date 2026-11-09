"""Identidad de una ejecución instalada y autorizada por el operador."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from .tool_worker import identity,unprivileged


class ProtectedRuntimeError(ValueError):
    pass


def protected_file(path):
    path=Path(path)
    if not path.is_absolute():raise ProtectedRuntimeError("La instalación protegida exige rutas absolutas.")
    for parent in [path,*path.parents]:
        st=parent.lstat()
        sticky=parent!=path and stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_mode&stat.S_ISVTX
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or (st.st_mode&0o022 and not sticky):
            raise ProtectedRuntimeError('La instalación protegida permite modificaciones ajenas.')
    return path


def require_protected_runtime(*,bank=None,options=None,output=None):
    value=os.environ.get('CENTINELA_RUNTIME_DESCRIPTOR')
    if not value:
        raise ProtectedRuntimeError('Inicia la auditoría desde el ejecutor protegido del operador; falta la separación de roles y red.')
    path=protected_file(value)
    if path.stat().st_size>1_000_000:raise ProtectedRuntimeError('Descriptor de ejecución inválido.')
    data=json.loads(path.read_text())
    own=identity()
    if (data.get('version')!=1 or time.time()>=data.get('expires_at',0)
        or not unprivileged(own,data.get('controller_uid'))
        or own['pid']!=data.get('principal',{}).get('pid')
        or own['start_time']!=str(data.get('principal',{}).get('start_time'))
        or own['netns']!=data.get('audit_netns')
        or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=data.get('principal',{}).get('boot_id')):
        raise ProtectedRuntimeError('La identidad o el aislamiento del controlador no coincide con la autorización instalada.')
    if bank is not None and data.get('bank')!=bank:
        raise ProtectedRuntimeError('El banco no pertenece a esta ejecución protegida.')
    if options is not None and options!=data.get('options'):
        raise ProtectedRuntimeError('Las opciones no coinciden con la ejecución autorizada por el operador.')
    if output is not None and Path(output).absolute()!=Path(data['output'])/'runs':
        raise ProtectedRuntimeError('El destino de evidencia no coincide con la ejecución autorizada.')
    if os.environ.get('CENTINELA_PROTECTED_RUNTIME')!='1':
        raise ProtectedRuntimeError('El transporte de herramientas protegido no está habilitado.')
    if not data.get('source_hashes'):
        raise ProtectedRuntimeError('Falta el manifiesto de componentes protegidos.')
    for name,digest in data['source_hashes'].items():
        source=protected_file(name)
        if hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
            raise ProtectedRuntimeError('Cambió un componente de la ejecución protegida.')
    if os.environ.get('CENTINELA_BROKER_SOCKET')!=data['broker_socket']:
        raise ProtectedRuntimeError('La frontera privilegiada no coincide con la instalada.')
    for role,endpoint in data['worker_sockets'].items():
        if os.environ.get('CENTINELA_'+role.upper()+'_SOCKET')!=endpoint:
            raise ProtectedRuntimeError('El trabajador no coincide con el rol instalado.')
    return data


def require_live_runtime(*,bank,options=None,output=None):
    """Punto común de entrada: nunca degrada a ejecución local privilegiada."""
    return require_protected_runtime(bank=bank,options=options,output=output)
