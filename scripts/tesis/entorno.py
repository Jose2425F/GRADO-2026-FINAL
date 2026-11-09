"""Identifica dependencias efectivas; un lock por sí solo no acredita su uso."""
from importlib import metadata
import hashlib
from pathlib import Path
import platform
import re
import tomllib


def dependency_receipt(prototype):
    prototype = Path(prototype)
    lock = prototype / 'uv.lock'
    locked = tomllib.loads(lock.read_text())['package']
    rows = []
    for item in locked:
        try:
            installed = metadata.version(item['name'])
        except metadata.PackageNotFoundError:
            installed = None
        rows.append({'name': item['name'], 'locked': item['version'],
                     'installed': installed, 'matches_lock': installed == item['version']})
    active = sorted({re.sub(r'[-_.]+', '-', d.metadata['Name']).lower(): d.version
                     for d in metadata.distributions() if d.metadata.get('Name')}.items())
    canonical = '\n'.join(f'{name}=={version}' for name, version in active)
    return {'python': platform.python_version(), 'platform': platform.platform(),
            'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest(),
            'installed_versions_sha256': hashlib.sha256(canonical.encode()).hexdigest(),
            'installed_packages': dict(active), 'lock_comparison': rows,
            'mismatched_installed': sum(r['installed'] is not None and not r['matches_lock'] for r in rows),
            'note': 'Identity receipt, not proof of a fresh installation or historical environment.'}
