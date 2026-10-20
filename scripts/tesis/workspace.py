"""Historial activo y archivo recuperable; no elimina evidencia ni invoca modelos."""
from __future__ import annotations
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from auditoria.dashboard import collect_state


def archive_directory(root: Path) -> Path:
    return root.parent / 'archivo_corridas'


def archives(root: Path) -> list[dict]:
    parent = archive_directory(root)
    if not parent.is_dir() or parent.is_symlink(): return []
    values = []
    for item in sorted(parent.iterdir(), reverse=True):
        if item.is_symlink() or not (item/'corridas').is_dir() or not re.fullmatch(r'archivo_[0-9TZ_]+', item.name): continue
        try:
            path = item/'archivo.json'
            if path.is_symlink() or path.stat().st_size > 8_000_000: continue
            value = json.loads(path.read_text())
            values.append({k:value.get(k) for k in ['id','created_at','runs_count','files_count','label']})
        except (OSError, ValueError): continue
    return values


def archive_root(root: Path, identifier: str) -> Path:
    if not isinstance(identifier, str) or not re.fullmatch(r'archivo_[0-9TZ_]+', identifier):
        raise ValueError('Archivo no admitido.')
    parent = archive_directory(root)
    directory = parent/identifier
    if parent.is_symlink() or directory.is_symlink() or (directory/'corridas').is_symlink():
        raise ValueError('Archivo no admitido.')
    if not (directory/'archivo.json').is_file() or not (directory/'corridas').is_dir():
        raise ValueError('Archivo no disponible.')
    return directory/'corridas'


def archive_runs(root: Path) -> dict:
    """Solo fuera de servicio: rechaza corridas vivas y mueve la carpeta íntegra."""
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir(): raise ValueError('Historial no admitido.')
    state = collect_state(root)
    if any(r.get('status') == 'running' for r in state['runs']):
        raise ValueError('Existe una auditoría activa; no se puede archivar.')
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink(): raise ValueError('El historial contiene enlaces simbólicos.')
        if path.is_file(): files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    parent = archive_directory(root)
    if parent.is_symlink(): raise ValueError('Destino de archivo no admitido.')
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    identifier = 'archivo_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    destination = parent/identifier; destination.mkdir(mode=0o700)
    def visible(run):
        if run.get('tasks'):return True
        try:return json.loads((root/run['key']/'request.json').read_text()).get('bank') in {'personal','empresa'}
        except (OSError,ValueError,KeyError):return False
    visible_count=sum(visible(run) for run in state['runs'])
    receipt = {'id':identifier,'created_at':datetime.now(timezone.utc).isoformat(),
        'label':'Corridas anteriores a la reorganización de tesis','runs_count':visible_count,'diagnostic_records':len(state['runs'])-visible_count,
        'files_count':len(files),'sha256':files,'original_root':str(root),'schema_version':1}
    # Persistir recibo antes de mover. Renombrado atómico en el mismo volumen.
    (destination/'archivo.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n')
    (destination/'archivo.json').chmod(0o600)
    os.rename(root, destination/'corridas')
    try: root.mkdir(mode=0o700)
    except OSError:
        os.rename(destination/'corridas', root)
        raise
    return receipt


def restore_archive(root: Path, identifier: str) -> None:
    """Restauración manual solo sobre un historial vacío, sin sobrescrituras."""
    source = archive_root(root, identifier)
    if root.is_symlink() or any(root.iterdir()): raise ValueError('El historial activo debe estar vacío.')
    root.rmdir()
    try: os.rename(source, root)
    except OSError:
        root.mkdir(mode=0o700); raise
