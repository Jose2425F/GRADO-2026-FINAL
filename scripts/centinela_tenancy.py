"""Isolated run roots and a server-wide scheduler for shared Docker laboratories."""
import copy
import threading
from pathlib import Path

class Workspaces:
    def __init__(self,base,store):
        self.store=store;self.base=base;self.lock=threading.RLock();self.panels={}
        owner_file=store.directory/'legacy-owner'
        self.legacy_owner=owner_file.read_text().strip() if owner_file.exists() else None
        BasePanel=type(base); BaseOperations=type(base.operations); registry=self
        class SharedOperations(BaseOperations):
            def __init__(self,root):
                super().__init__(root);self.lock=registry.lock
            def snapshot(self):
                with self.lock:
                    result=super().snapshot()
                    from auditoria.dashboard import collect_state
                    for other in registry.panels.values():
                        if other.operations is self:continue
                        if other.operations.reserved or any(j['status'] in {'queued','running','stopping'} for j in other.operations.jobs) or any(r['status']=='running' for r in collect_state(other.root)['runs']):
                            result['busy']=True
                    return result
            def start(self,action,options=None):
                with self.lock:
                    # Starting an operation atomically reserves the shared laboratory.
                    job=super().start(action,options)
                    if action in {'audit','empresa_restore','empresa_down','suite_restore','suite_down','acceptance_all'}:
                        for other in registry.panels.values():
                            if other.operations is self:continue
                            ops=other.operations
                            ops.empresa_lab.update(status='unknown',message='Otro usuario ha utilizado el banco. Restaura y comprueba antes de auditar.')
                            ops.scenario_labs.clear()
                            for lab in ('integrado','sucursal','comercial','mixto','reforzado'):ops.restorations.invalidate(lab)
                    return job
        class PrivatePanel(BasePanel):
            def state(self):
                result=copy.deepcopy(super().state())
                result['evaluation_references']=[]
                result['kpi_study']={'active':False,'previous':{},'api_calls_started':0}
                result['study_progress']={'active':result['busy']}
                result['thesis']['study']={'note':'Evaluación individual del espacio actual.','formal_runs':0}
                return result
            def comparison(self,single,multi,reference=None):
                if reference:raise ValueError('Las referencias globales están reservadas al administrador.')
                return super().comparison(single,multi,reference)
        self.PrivatePanel=PrivatePanel;self.SharedOperations=SharedOperations
        # Load every workspace at startup so a surviving child process remains visible
        # to the global busy check after a service restart.
        for user in store.users():self.for_id(user['id'])
    def for_id(self,uid):
        with self.lock:
            if uid not in {u['id'] for u in self.store.users()}:raise ValueError('Espacio no disponible.')
            if uid not in self.panels:
                legacy=uid==self.legacy_owner
                root=self.base.root if legacy else self.store.directory/'workspaces'/uid/'runs'
                root.mkdir(parents=True,exist_ok=True,mode=0o700)
                cls=type(self.base) if legacy else self.PrivatePanel
                self.panels[uid]=cls(root,operations=self.SharedOperations(root),diagram=self.base.diagram)
            return self.panels[uid]
    def for_session(self,user):
        uid=user['workspace'] if user['role']=='admin' and user.get('workspace') else user['id']
        return self.for_id(uid)
