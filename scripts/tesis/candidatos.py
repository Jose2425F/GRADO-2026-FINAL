"""RF-16: correlación local, acotada y versionada; jamás adjudica vulnerabilidades.

La versión observada no demuestra el paquete instalado, parches ni condiciones.
No hay explotación ni consultas externas durante la auditoría.
"""
import re

CATALOG_VERSION = 'tesis-cve-1'
SOURCES = [
 {'cve':'CVE-2024-6387','product':'OpenSSH Portable','url':'https://www.openssh.org/txt/release-9.8',
  'condition':'sshd Portable con condiciones de plataforma afectadas; comprobar parches del distribuidor y configuración.'},
 {'cve':'CVE-2023-5869','product':'PostgreSQL','url':'https://www.postgresql.org/support/security/CVE-2023-5869/',
  'condition':'Servidor PostgreSQL de rama y revisión afectadas; requiere comprobar versión efectiva y parches. No se ejecuta la operación SQL de explotación.'},
]


def correlate(services):
    values=[]
    for service in services:
        if not isinstance(service,dict) or service.get('state')!='open' or type(service.get('port')) is not int or not 1<=service['port']<=65535:continue
        product=service.get('product') or '';version=service.get('version') or ''
        if not isinstance(product,str) or not isinstance(version,str):continue
        if len(product)>100 or len(version)>160:continue
        match=re.match(r'^(\d{1,2})\.(\d{1,2})(p\d{1,2})?(?:\b|\s|$)',version)
        source=None
        if product=='OpenSSH' and match and match.group(3)=='p1' and (8,5)<=tuple(map(int,match.group(1,2)))<(9,8):
            source=SOURCES[0]
        if product in {'PostgreSQL','PostgreSQL DB'}:
            match=re.match(r'^(11|12|13|14|15|16)\.(\d{1,3})(?:\b|\s|$)',version)
            if match:
                major,minor=map(int,match.group(1,2))
                if minor<{11:22,12:17,13:13,14:10,15:5,16:1}[major]:source=SOURCES[1]
        if source:
            values.append({**source,'state':'candidate','catalog_version':CATALOG_VERSION,
                'port':service.get('port'),'observed_product':product,'observed_version':version,
                'limitation':'Coincidencia preliminar del catálogo local. Un backport puede corregir el defecto sin cambiar la versión principal; el banner no confirma vulnerabilidad.',
                'next_step':'Contrastar el paquete y su parche con el aviso del fabricante. Mantener pendiente hasta disponer de evidencia autorizada suficiente.'})
    return values


def for_results(tasks, results):
    by_id={t.task_id:t for t in tasks};candidates=[]
    for result in results:
        task=by_id.get(result.task_id)
        if task is None or result.status.value not in {'completed','completed_no_findings'}:continue
        for value in correlate([s.model_dump(mode='json') for s in result.services]):
            candidates.append({**value,'task_id':task.task_id,'asset_id':task.target.asset_id,
                'address':task.target.address,'evidence_ref':result.evidence_ref,'evidence_sha256':result.evidence_sha256})
    return candidates
