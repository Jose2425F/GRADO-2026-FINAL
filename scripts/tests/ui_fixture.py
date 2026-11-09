"""Synthetic HTTP payloads for DOM tests; no server or audit tools are launched."""
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dualstack_panel import Panel
from auditoria.store import RunStore, write_json

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for key in ('first', 'second'):
        run = RunStore(root / key, key)
        write_json(run.root / 'request.json', {'bank': 'empresa', 'architecture': 'single'})
        write_json(run.root / 'manifest.json', {'mode': 'live'})
        write_json(run.root / 'plan.json', [])
        write_json(run.root / 'report.json', {'mode': 'live', 'status': 'complete', 'tasks': [], 'findings': []})
        run.close()
    panel = Panel(root)
    user = {'id': 'test-admin', 'name': 'Administrador', 'role': 'admin'}
    templates = {name: panel.environment.get_template(name + '.html').render(current_user=user, csrf='test-csrf', study={})
                 for name in ('index', 'cliente')}
    print(json.dumps({'templates': templates, 'state': panel.state(),
                      'details': {key: panel.detail(key) for key in ('first', 'second')}}))
