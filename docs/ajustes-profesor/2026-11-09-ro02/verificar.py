"""Comprueba la continuación RO-02 sin ejecutar sus pruebas ni emitir tráfico."""
from pathlib import Path
from zipfile import ZipFile
import hashlib
import json

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
manifest=json.loads((HERE/'integridad-continuacion.json').read_text())
for item in manifest['archivos']:
    content=(REPO/item['ruta']).read_bytes()
    assert len(content)==item['bytes'],item['ruta']
    assert hashlib.sha256(content).hexdigest()==item['sha256'],item['ruta']
entries=json.loads((HERE/'integridad-evidencias-ro02.json').read_text())['entradas']
with ZipFile(HERE/'evidencias-ro02-20261109.zip') as archive:
    assert sorted(archive.namelist())==sorted(x['ruta'] for x in entries)
    for item in entries:
        content=archive.read(item['ruta'])
        assert len(content)==item['bytes'],item['ruta']
        assert hashlib.sha256(content).hexdigest()==item['sha256'],item['ruta']
summary=json.loads((HERE/'resumen-validacion.json').read_text())
assert summary['all_commands_successful'] and not summary['source_changes_during_validation']
print(json.dumps({'valido':True,'archivos_continuacion':len(manifest['archivos']),
                  'entradas_evidencia':len(entries),'sin_red_ni_sondas':True},ensure_ascii=False))
