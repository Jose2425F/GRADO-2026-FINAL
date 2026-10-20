"""Cuatro bancos adicionales cerrados: direcciones, casos y verdad separados.

Se reutilizan copias en memoria de los motores existentes, con sustituciones
cerradas de direccionamiento. No se modifican los módulos ni despliegues base.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import secrets
import sys
import types
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[2]
PILOT=ROOT/'piloto_kali/prototipo'
STATE=PILOT/'.lab-suite'
DEPLOY=ROOT/'piloto_kali/despliegue'
PROFILES={
 'sucursal':{'index':1,'name':'NovaFlow · Sucursal Esencial','difficulty':'1 · Básico',
   'credentials':{'portal':True,'legacy':True},'apps':{'app_crm':'alpha','app_intranet':'strict'},'guarded_a':False,
   'detail':'Pocos activos, fallos evidentes y controles protegidos. Punto de partida.'},
 'comercial':{'index':2,'name':'NovaFlow · Operación Comercial','difficulty':'2 · Intermedio',
   'credentials':{'portal':True,'legacy':False,'records':True},'apps':{'app_crm':'beta','app_erp':'gamma','app_intranet':'strict'},'guarded_a':False,
   'detail':'Servicios mixtos; descarga codificada, permisos por familia y controles que rechazan acceso.'},
 'mixto':{'index':3,'name':'NovaFlow · Empresa Mixta','difficulty':'3 · Mixto',
   'credentials':{'portal':False,'legacy':True,'records':True,'bastion':False},
   'apps':{'app_crm':'gamma','app_erp':'beta','app_portal':'alpha','app_intranet':'strict'},'guarded_a':False,
   'detail':'Más activos y distribución diferente de credenciales, permisos web y confianza IPv6.'},
 'reforzado':{'index':4,'name':'NovaFlow · Entorno Reforzado','difficulty':'4 · Mayor carga y controles',
   'credentials':{'portal':False,'legacy':True,'records':False,'bastion':False,'portal_ops':False,'legacy_ops':False},
   'apps':{'app_crm':'strict','app_erp':'beta','app_portal':'gamma','app_intranet':'strict'},'guarded_a':True,
   'detail':'Más servicios y controles negativos; receptores IPv6 protegidos. No implica explotación más avanzada.'},
}
SERVICES={'portal':2,'legacy':1,'records':1,'bastion':2,'portal_ops':2,'legacy_ops':1}


def profile(name):
    if name not in PROFILES:raise ValueError('Selecciona uno de los cuatro laboratorios de la suite.')
    return PROFILES[name]


def catalog():
    return [{'id':key,'name':p['name'],'difficulty':p['difficulty'],'detail':p['detail'],
      'targets':len(p['credentials'])+len(p['apps'])+2,'containers':len(p['credentials'])+len(p['apps'])+4,
      'tasks':sum(1+SERVICES[a] for a in p['credentials'])+len(p['apps'])+18,
      'ipv4':[f'192.168.{110+10*(p["index"]-1)+j}.0/24' for j in range(3)]} for key,p in PROFILES.items()]


def translate(text,p):
    base=110+10*(p['index']-1);mac=f'a{p["index"]}'
    replacements={'192.168.69.':f'192.168.{base}.','192.168.70.':f'192.168.{base+1}.','192.168.71.':f'192.168.{base+2}.',
      'fd57:2026:69:':f'fd57:2026:{base}:','fd57:2026:70:':f'fd57:2026:{base+1}:',
      '02:57:20:26:70:':f'02:57:20:26:{mac}:','fe80::57:20ff:fe26:70':f'fe80::57:20ff:fe26:{mac}',
      'br-nova-corp':f'br-nf{p["index"]}-corp','br-nova-dmz':f'br-nf{p["index"]}-dmz','br-nova-dc':f'br-nf{p["index"]}-dc',
      'nova_datacenter':f'nf{p["index"]}_dc','nova_dmz':f'nf{p["index"]}_dmz','nova_corp':f'nf{p["index"]}_corp','nova-':f'nf{p["index"]}-'}
    for old,new in replacements.items():text=text.replace(old,new)
    return text


def clone(name,path,p):
    # Solo código del repositorio y sustituciones internas; ningún texto del usuario se ejecuta.
    module=types.ModuleType('auditoria._suite_'+name+'_'+str(p['index']))
    module.__file__=str(path);module.__package__='auditoria'
    sys.modules[module.__name__]=module
    exec(compile(translate(path.read_text(),p),str(path), 'exec'),module.__dict__)
    return module


def private_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n');tmp.chmod(0o600);tmp.replace(path)


class Context:
    def __init__(self,name,*,state_root=STATE):
        self.id=name;self.spec=profile(name);self.state=state_root/name
        self.lab=clone('lab',PILOT/'src/auditoria/lab_empresa.py',self.spec)
        self.agent=clone('agent',PILOT/'src/auditoria/empresa_agent.py',self.spec);self.agent.lab=self.lab
        lab=self.lab
        lab.VERSION='novaflow-suite-2/'+name;lab.COMPANY=self.spec['name']
        originals=copy.deepcopy(lab.CREDENTIALS)
        for asset,source,ip in [('portal_ops','portal',15),('legacy_ops','legacy',16)]:
            host=copy.deepcopy(originals[source]);host.update(container=f'nf{self.spec["index"]}-{asset.replace("_","-")}',
                address=originals[source]['address'].rsplit('.',1)[0]+'.'+str(ip),env='LAB_SUITE_'+asset.upper())
            originals[asset]=host
        lab.CREDENTIALS={k:{**originals[k],'expected':'accepted' if v else 'rejected'} for k,v in self.spec['credentials'].items()}
        lab.APPS={k:v for k,v in lab.APPS.items() if k in self.spec['apps']};lab.APP_SCENARIOS=dict(self.spec['apps'])
        lab.KNOWN_ENVS=tuple(sorted({h['env'] for h in lab.CREDENTIALS.values() if h['env']!='LAB_NOVA_BASTION_GUESS'}))
        lab.SERVICE_PORTS={a:sorted(port for _,port in h['services']) for a,h in lab.CREDENTIALS.items()}
        lab.ADDRESSES={v for a in lab.APPS.values() for v in [a['ipv4'],a['ipv6']]}|{r['address'] for r in lab.RECEIVERS.values()}
        for net,(bridge,subnets,members) in list(lab.NETWORKS.items()):
            if net.endswith('_dmz'):members={h['container'] for h in lab.CREDENTIALS.values()}
            elif net.endswith('_corp'):members={h['container'] for h in lab.APPS.values()}
            lab.NETWORKS[net]=(bridge,subnets,members)
        lab.COMPOSE=self.state/'compose.json'
        # La función policy original usa identificadores de segmento; mantener el tipo semántico al parametrizar.
        self.agent.policy=self.policy
        lab.source_hash=self.fingerprint

    def policy(self):
        from auditoria.contracts import LabPolicy,LabSegment
        segments=[]
        for network,(bridge,subnets,_) in self.lab.NETWORKS.items():
            ports=[21,22,5432,8080] if network.endswith('_dmz') else [8088] if network.endswith('_corp') else [8000,53000]
            segments.extend(LabSegment(name=network+'_'+str(i),network=subnet,interface=bridge,allowed_ports=ports) for i,subnet in enumerate(sorted(subnets)))
        return LabPolicy(policy_id='suite-'+self.id,allowed_categories=self.agent.CATEGORIES,max_token_budget=80000,segments=segments)

    def fingerprint(self):
        paths=[Path(__file__),PILOT/'src/auditoria/lab_empresa.py',PILOT/'src/auditoria/empresa_agent.py',ROOT/'scripts/laboratorio_empresa.py',ROOT/'scripts/tesis/evaluacion.py',ROOT/'scripts/laboratorio_suite.py']
        paths+=sorted(self.state.glob('protocol/*'))+[self.lab.COMPOSE,self.state/'http_target.py',self.state/'lab.env']
        h=hashlib.sha256(json.dumps(self.spec,sort_keys=True).encode())
        for path in paths:
            if path.is_file():h.update(path.name.encode()+b'\0'+path.read_bytes())
        return h.hexdigest()

    @property
    def metadata(self):
        entry=next(x for x in catalog() if x['id']==self.id)
        return {**entry,'version':self.lab.VERSION,'source_sha256':self.fingerprint()}

    def validation(self,directory,task,result):
        if task.action_profile=='nmap_tcp_services_v1':
            from laboratorio_empresa import validation_for
            return validation_for(directory,task,result)
        return self.agent.validation_record(directory,task,result),self.agent.adjudicate(directory,task,result)

    def prepare(self):
        self.state.mkdir(parents=True,exist_ok=True,mode=0o700);self.state.chmod(0o700)
        self.lab.prepare(self.state)
        env={k:v for line in (self.state/'lab.env').read_text().splitlines() if '=' in line for k,v in [line.split('=',1)]}
        for asset in self.lab.CREDENTIALS:
            env.setdefault('LAB_ACTUAL_'+asset.upper(),secrets.token_hex(24))
        # Credenciales positivas y controles realmente diferentes, no solo etiquetas.
        for asset,host in self.lab.CREDENTIALS.items():
            if self.spec['credentials'][asset]:env['LAB_ACTUAL_'+asset.upper()]=self.lab.BASTION_GUESS if asset=='bastion' else env[host['env']]
            elif env['LAB_ACTUAL_'+asset.upper()]==env.get(host['env'],self.lab.BASTION_GUESS):raise ValueError('Un control protegido coincide con el intento.')
        (self.state/'lab.env').write_text('\n'.join(k+'='+v for k,v in sorted(env.items()))+'\n');(self.state/'lab.env').chmod(0o600)
        protocol=self.state/'protocol';protocol.mkdir(exist_ok=True)
        for name in ['receiver.py','sender.py','radvd.conf']:
            (protocol/name).write_text(translate((DEPLOY/'empresa/datacenter'/name).read_text(),self.spec))
        http_source=(DEPLOY/'empresa/dmz/http_target.py').read_text()
        old='''            self._record("403")
            self.send_response(403)
            self.send_header("Content-Length", "0")'''
        new='''            self._record("401")
            self.send_response(401)
            self.send_header("WWW-Authenticate", f'Basic realm="{REALM}"')
            self.send_header("Content-Length", "0")'''
        if http_source.count(old)!=1:raise ValueError('Cambió la plantilla HTTP; revisar el adaptador antes de preparar.')
        (self.state/'http_target.py').write_text(http_source.replace(old,new))
        data=yaml.safe_load(translate((DEPLOY/'empresa/docker-compose.empresa.yml').read_text(),self.spec))
        data['name']='novaflow-suite-'+self.id
        services={}
        for key,value in data['services'].items():
            asset=key.replace('-','_')
            if asset in self.lab.CREDENTIALS:
                value['environment']['LAB_TARGET_PASSWORD' if asset in {'portal','bastion'} else 'LAB_HTTP_PASSWORD' if asset=='legacy' else 'POSTGRES_PASSWORD']='${LAB_ACTUAL_'+asset.upper()+'}'
            elif key.startswith('app-'):
                if asset not in self.lab.APPS:continue
                value['environment']['LAB_SCENARIO']=self.spec['apps'][asset]
            elif key=='receiver-a':value['environment']['LAB_GUARDED']='1' if self.spec['guarded_a'] else '0'
            elif key not in {'router','sender','receiver-b'}:continue
            value.pop('build',None);value['labels']={'novaflow.suite':'1','novaflow.scenario':self.id}
            if key in {'router','sender','receiver-a','receiver-b'}:
                value['volumes']=[str(protocol.resolve())+':/app/datacenter:ro']
            elif key=='legacy':value['volumes']=[str((self.state/'http_target.py').resolve())+':/app/http_target.py:ro']
            services[key]=value
        for asset,source in [('portal_ops','portal'),('legacy_ops','legacy')]:
            if asset not in self.lab.CREDENTIALS:continue
            value=copy.deepcopy(services[source]);host=self.lab.CREDENTIALS[asset]
            value['container_name']=host['container'];value['hostname']=host['container'];value['networks']['dmz']['ipv4_address']=host['address']
            value['environment']['LAB_TARGET_PASSWORD' if source=='portal' else 'LAB_HTTP_PASSWORD']='${LAB_ACTUAL_'+asset.upper()+'}'
            services[asset.replace('_','-')]=value
        data['services']=services
        for key in list(data):
            if key.startswith('x-'):del data[key]
        private_json(self.lab.COMPOSE,data)
        truth=json.loads((self.state/'ground_truth.json').read_text())
        for entry in truth['entries']:
            if entry['asset_id'] in self.lab.RECEIVERS:entry['present']=entry['asset_id']=='receiver_a' and not self.spec['guarded_a']
        private_json(self.state/'ground_truth.json',truth)
        private_json(self.state/'prepared.json',{'scenario':self.id,'source_sha256':self.fingerprint(),
            'ground_truth_sha256':hashlib.sha256((self.state/'ground_truth.json').read_bytes()).hexdigest()})
        return self.metadata

    def preflight(self):
        expected=json.loads((self.state/'prepared.json').read_text())
        if expected['source_sha256']!=self.fingerprint() or expected['ground_truth_sha256']!=hashlib.sha256((self.state/'ground_truth.json').read_bytes()).hexdigest():raise ValueError('Cambió el escenario preparado o su referencia.')
        return getattr(self,'preflight_base',self.lab.preflight)(self.state)
