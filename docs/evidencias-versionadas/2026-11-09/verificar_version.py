"""Comprueba los archivos añadidos o revisados en esta entrega sin ejecutar auditorías."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
manifest = json.loads((HERE / 'integridad-version.json').read_text())
errors = []
for item in manifest['archivos']:
    path = REPO / item['ruta']
    if not path.is_file():
        errors.append({'ruta': item['ruta'], 'error': 'no existe'})
        continue
    content = path.read_bytes()
    if len(content) != item['bytes'] or hashlib.sha256(content).hexdigest() != item['sha256']:
        errors.append({'ruta': item['ruta'], 'error': 'tamaño o SHA-256 diferente'})
if errors:
    print(json.dumps({'valido': False, 'errores': errors}, ensure_ascii=False, indent=2))
    sys.exit(1)
print(json.dumps({'valido': True, 'archivos_de_version': len(manifest['archivos']),
                  'version': manifest['version']}, ensure_ascii=False))
subprocess.run([sys.executable, str(HERE / 'verificar.py')], check=True)
