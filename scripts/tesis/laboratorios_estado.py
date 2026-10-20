"""Vista pública mínima de la aceptación de escenarios; sin Docker ni API."""
import json
from tesis.laboratorios import STATE


def acceptance_status():
    try:
        p=STATE/'acceptance.json'
        if p.is_symlink() or p.stat().st_size>200000:return {}
        data=json.loads(p.read_text())
        return {'status':data.get('status'),'scenarios':[{'id':r.get('id'),'status':r.get('status'),
          'expected_tasks':r.get('expected_tasks'),'evaluation':{k:r.get('evaluation',{}).get(k) for k in ['tasks_checked','tasks_valid','TP','FP','FN','TN','acceptance_passed','evidence_valid']}}
          for r in data.get('scenarios',[]) if isinstance(r,dict)],'new_api_generations':data.get('new_api_generations')}
    except (OSError,ValueError,TypeError):return {}
