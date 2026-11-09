"""Company deliveries: private staging, publisher ownership and coherent reads."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import threading
from datetime import datetime, timezone


class Publications:
    def __init__(self, workspaces, identity):
        self.workspaces = workspaces
        self.identity = identity
        self.lock = threading.RLock()

    def client(self, uid, *, publishing=False):
        user = next((u for u in self.identity.users() if u['id'] == uid), None)
        if not user or user['role'] == 'admin':
            raise ValueError('Elige una cuenta de empresa.')
        if publishing and not user['active']:
            raise ValueError('Activa la cuenta de empresa antes de publicar resultados.')
        return user

    def records(self, panel, admin, key=None):
        base = panel.root / 'publicadas'
        for marker in sorted([*base.glob('*/publicacion.json'), *base.glob('*/*/publicacion.json')]):
            value = panel.json_file(marker, {})
            if (isinstance(value, dict) and value.get('published_by') == admin['id']
                    and isinstance(value.get('source_key'), str)
                    and (key is None or value['source_key'] == key)):
                yield marker.parent, value

    def listing(self, admin):
        result = {}
        with self.lock:
            for user in self.identity.users():
                if user['role'] == 'admin':
                    continue
                panel = self.workspaces.for_id(user['id'])
                with panel.lock:
                    for folder, value in self.records(panel, admin):
                        result.setdefault(value['source_key'], []).append({
                            'user': user['id'], 'name': user['name'],
                            'published_at': value.get('published_at'),
                            'key': folder.relative_to(panel.root).as_posix()})
        return result

    @staticmethod
    def validate_tree(directory):
        # Neither follow links nor copy devices/FIFOs from audit artifacts.
        for parent, dirs, files in os.walk(directory, followlinks=False):
            for name in dirs + files:
                mode = (Path(parent) / name).lstat().st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError('La auditoría contiene enlaces o archivos no admitidos.')

    def publish(self, admin, key, uid):
        with self.lock:
            target = self.client(uid, publishing=True)
            source = self.workspaces.for_id(admin['id'])
            panel = self.workspaces.for_id(uid)
            # detail validates the exact scoped key and safe report readers.
            with source.lock:
                source.cached = None
                detail = source.detail(key)
                if not detail['brief']['final'] or detail['run']['status'] not in {'complete', 'partial'}:
                    raise ValueError('Publica una auditoría real cuando su informe esté cerrado.')
                directory = source.root / key
                self.validate_tree(directory)
                digest = hashlib.sha256((admin['id'] + '\0' + key).encode()).hexdigest()
                destination = panel.root / 'publicadas' / digest / directory.name
                # Staging stays outside runs so state/report readers cannot discover it.
                with tempfile.TemporaryDirectory(prefix='.publication-', dir=panel.root.parent) as temporary:
                    staging = Path(temporary) / 'new'
                    shutil.copytree(directory, staging, symlinks=True,
                                    ignore=shutil.ignore_patterns('.lab', 'publicacion.json'))
                    self.validate_tree(staging)
                    marker = {'source_key': key, 'published_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                              'published_by': admin['id']}
                    (staging / 'publicacion.json').write_text(json.dumps(marker), encoding='utf-8')
                    job = source.json_file(directory.parent / 'panel_job.json', {})
                    metadata = {'name': detail['run']['name'], 'created_at': job.get('created_at') if isinstance(job, dict) else None}
                    with panel.lock:
                        previous = list(self.records(panel, admin, key))
                        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        moved = []
                        try:
                            for index, (folder, _) in enumerate(previous):
                                backup = Path(temporary) / f'old-{index}'
                                folder.rename(backup)
                                moved.append((folder, backup))
                            (destination.parent / 'panel_job.json').write_text(json.dumps(metadata), encoding='utf-8')
                            staging.rename(destination)
                        except OSError:
                            for folder, backup in reversed(moved):
                                backup.rename(folder)
                            raise
                        finally:
                            panel.cached = None
            return {'user': target['id'], 'name': target['name']}

    def unpublish(self, admin, key, uid):
        with self.lock:
            self.client(uid)
            panel = self.workspaces.for_id(uid)
            with panel.lock:
                previous = list(self.records(panel, admin, key)) if isinstance(key, str) and key else []
                if not previous:
                    raise ValueError('Esa empresa no tenía publicada esta auditoría.')
                with tempfile.TemporaryDirectory(prefix='.publication-', dir=panel.root.parent) as temporary:
                    moved = []
                    try:
                        for index, (folder, _) in enumerate(previous):
                            backup = Path(temporary) / str(index)
                            folder.rename(backup)
                            moved.append((folder, backup))
                    except OSError:
                        for folder, backup in reversed(moved):
                            backup.rename(folder)
                        raise
                    finally:
                        panel.cached = None
                return {'removed': len(moved)}
