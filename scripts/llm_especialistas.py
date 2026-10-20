"""Revisión especializada opcional con presupuesto compartido, fuera del núcleo congelado.

El LLM interpreta observaciones saneadas; no adjudica hallazgos ni ejecuta órdenes.
"""
from __future__ import annotations

import hashlib
import json
import time

from auditoria.openai_provider import OpenAIScheduler, ProviderError, normalize_usage, valid_int

from tesis.llm_contexto import ROLE_MAP, ROLE_NAMES, CONDITIONS, context_for, action_schema, validate_actions, bounded_text
from tesis.transporte_api import TracedOpenAITransport

REVIEW_TIMEOUT_SECONDS=60
REVIEW_MAX_OUTPUT_TOKENS=2048
REVIEW_VALIDATION_REASONS={'invalid_review','invalid_review_text','invalid_review_evidence',
    'invalid_actions','invalid_action','invalid_action_scope','invalid_action_text','invalid_action_evidence'}

class ExpertScheduler(OpenAIScheduler):
    def __init__(self,store,*,architecture,budget,deadline):
        super().__init__(store,architecture=architecture,budget=budget,deadline=deadline)
        self.transport=TracedOpenAITransport(self.config,store)
        self.full_budget=budget
        self.review_budget=budget*2//5
        self.budget=budget-self.review_budget
        self.reviews=[]
        self.review_seconds=0.0
        self.specialist_reviews_expected_roles=[]

    def select(self,ready,previous,all_tasks):
        before=len(self.calls)
        choice=super().select(ready,previous,all_tasks)
        used=self.calls[before:]
        self.store.event('planner','task_selected',task_id=choice.task_id,payload={
            'role':str(choice.agent_type),'profile':choice.action_profile,
            'source':'llm' if used and all(c['status']=='accepted' for c in used) else 'fallback' if used else 'single_ready_task'})
        return choice

    def review(self,tasks,results,findings):
        started=time.monotonic();initial_used=self.used
        roles=['generalist'] if self.architecture=='single' else list(dict.fromkeys(ROLE_MAP.get(str(t.agent_type),'network') for t in tasks))
        priority={'applications':0,'credentials':1,'ipv6':2,'fragmentation':3,'network':4,'generalist':0}
        def rank(role):
            context=context_for(tasks,results,findings,role)
            issues=sum(context['task_states'].get(k,0) for k in ['failed','blocked','cancelled'])
            return (-len(context['confirmed_conditions']),-issues,priority[role])
        roles.sort(key=rank)
        self.specialist_reviews_expected_roles=list(roles[:5])
        for role in roles[:5]:
            context=self._review_context(tasks,results,findings,role)
            if not context['evidence_tasks']:continue
            self._review(role,context,initial_used)
        self.review_seconds=round(time.monotonic()-started,6)

    def _review_context(self,tasks,results,findings,role):
        # El revisor recibe sólo tareas admitidas, pero sus alias siguen siendo
        # los del catálogo completo que usa el informe al resolver referencias.
        context=context_for(tasks,results,findings,role)
        catalogue=getattr(self,'catalogue_tasks',tasks)
        aliases={}
        global_tasks={task.task_id:'t'+str(i).zfill(3) for i,task in enumerate(catalogue)}
        for i,task in enumerate(tasks):aliases['t'+str(i).zfill(3)]=global_tasks[task.task_id]
        global_assets=list(dict.fromkeys(task.target.asset_id for task in catalogue))
        local_assets=list(dict.fromkeys(task.target.asset_id for task in tasks))
        for i,asset in enumerate(local_assets):aliases['a'+str(i).zfill(3)]='a'+str(global_assets.index(asset)).zfill(3)
        def remap(value):
            if isinstance(value,dict):return {aliases.get(key,key):remap(item) for key,item in value.items()}
            if isinstance(value,list):return [remap(item) for item in value]
            return aliases.get(value,value) if isinstance(value,str) else value
        return remap(context)

    def _review(self,role,context,initial_used):
        context={**context,'data_origin':getattr(self,'data_origin','audit')}
        prompt=('Eres '+ROLE_NAMES[role]+'. Revisa exclusivamente los hechos JSON siguientes de una auditoría autorizada. '
          'Responde en español, breve y comprensible. Redacta un informe para el cliente: explica la observación concreta, su impacto y la acción específica que se deriva de ella. '
          'Usa task_facts para citar una tarea y puertos/servicios cuando existan, sin repetir el inventario ni frases genéricas. '
          'Omite funciones desactivadas, estados de espera y roles que no intervinieron. Agrupa incidencias relevantes sin afirmar que un equipo esté apagado. '
          'En interpretation prioriza los hechos e impacto; en next_step la corrección y su comprobación; en limitation solo el límite que afecte esta conclusión. '
          'Un puerto abierto no es una vulnerabilidad; tool_authentication accepted no equivale a corroboración independiente. Solo confirmed_conditions son hallazgos confirmados. '
          'No inventes vulnerabilidades, resultados, porcentajes, comandos, direcciones ni métricas. '
          'Los hallazgos ya fueron adjudicados por validadores; tu texto es una interpretación, no evidencia. '
          'Propón hasta tres prioritized_actions para activos aNNN: usa solo acciones permitidas, explica por qué y cómo verificar la corrección, y cita tareas de ese mismo activo. Una acción es una recomendación, no una ejecución. '
          'Cada texto de interpretation, next_step y limitation debe tener de 1 a 600 caracteres en un solo párrafo sin saltos de línea. '
          'Cada why y verification debe tener de 1 a 250 caracteres sin saltos de línea. Máximo tres acciones y ocho referencias por acción, del mismo activo. '
          'No afirmes seguridad general. Cita solo IDs de evidence_tasks. No solicites ni reproduzcas secretos.\n'+json.dumps(context,sort_keys=True))
        schema={'type':'object','properties':{k:bounded_text(600) for k in ['interpretation','next_step','limitation']},
                'required':['interpretation','next_step','limitation','evidence_tasks'],'additionalProperties':False}
        schema['required'].append('prioritized_actions')
        schema['properties']['prioritized_actions']=action_schema(context)
        schema['properties']['evidence_tasks']={'type':'array','minItems':1,'maxItems':24,'items':{'type':'string','enum':context['evidence_tasks']}}
        body={'model':self.config.model,'input':prompt,'text':{'format':{'type':'json_schema','name':'specialist_review','strict':True,'schema':schema}}}
        call={'provider':'openai','phase':'specialist_review','role':role,'status':'not_sent',
              'prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
              'request_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),
              'input_tokens':None,'output_tokens':None,'provider_output_tokens':None,'thought_tokens':None,'total_tokens':None}
        call['prompt_ref'],_=self.store.evidence('llm_'+str(len(self.calls)).zfill(3)+'_review_'+role,'txt',prompt.encode())
        review={'role':role,'status':'not_sent','source':'llm','interpretation':'','next_step':'','limitation':'','evidence_tasks':[]}
        stamp=time.monotonic();sent=False
        try:
            if self.provider_blocked or not self.complete:raise RuntimeError('provider_or_usage_unavailable')
            remaining=self.deadline-time.monotonic()
            available=min(self.full_budget-self.used,self.review_budget-(self.used-initial_used))
            if remaining<2:raise RuntimeError('review_time_exhausted')
            if available<256:raise RuntimeError('review_budget_exhausted')
            counted=self.transport.post('responses/input_tokens',body,timeout=min(10,remaining))
            inputs=counted.get('input_tokens')
            if not valid_int(inputs):raise RuntimeError('input_usage_unavailable')
            cap=min(REVIEW_MAX_OUTPUT_TOKENS,self.config.max_output_tokens,available-inputs)
            if cap<256:raise RuntimeError('review_budget_exhausted')
            cap,reservation=self.affordable_generation(inputs,cap)
            call['cost_reservation_usd']=reservation
            remaining=self.deadline-time.monotonic()
            if remaining<1:raise RuntimeError('review_time_exhausted')
            call.update(counted_input_tokens=inputs,max_output_tokens=cap,generation_sent=True);sent=True
            self.store.event('llm','request_started',payload={'role':role,'phase':'specialist_review','provider':'openai',
                'cost_reservation_usd':reservation,'cost_limit_usd':self.max_cost_usd,
                'input_tokens_reserved':inputs,'max_output_tokens':cap})
            response=self.transport.post('responses',{**body,'max_output_tokens':cap,'reasoning':{'effort':self.config.reasoning_effort},
                      'store':False,'service_tier':'default'},timeout=min(REVIEW_TIMEOUT_SECONDS,remaining))
            usage=normalize_usage(response)
            if not usage:self.complete=False;raise RuntimeError('usage_unavailable')
            call.update(usage);self.used+=usage['total_tokens']
            call.update(response_model=response.get('model'),response_id=response.get('id'),response_status=response.get('status'))
            if self.used>self.full_budget or self.used-initial_used>self.review_budget:
                self.provider_blocked=True;raise RuntimeError('reported_budget_exceeded')
            if response.get('status')!='completed':raise RuntimeError('response_incomplete')
            output=''.join(item.get('text','') for message in response.get('output',[]) if message.get('type')=='message'
                           for item in message.get('content',[]) if item.get('type')=='output_text')
            call['response_sha256']=hashlib.sha256(output.encode()).hexdigest()
            value=json.loads(output)
            if not isinstance(value,dict) or set(value)!={'interpretation','next_step','limitation','evidence_tasks','prioritized_actions'}:raise ValueError('invalid_review')
            call['review_shape']={'text_lengths':{k:len(value[k]) if isinstance(value[k],str) else None for k in ['interpretation','next_step','limitation']},
                'actions':len(value['prioritized_actions']) if isinstance(value['prioritized_actions'],list) else None,
                'references':len(value['evidence_tasks']) if isinstance(value['evidence_tasks'],list) else None}
            for key in ['interpretation','next_step','limitation']:
                if not isinstance(value[key],str) or not 1<=len(value[key])<=600 or any(ord(c)<32 for c in value[key]):raise ValueError('invalid_review_text')
            if not isinstance(value['evidence_tasks'],list) or not 1<=len(value['evidence_tasks'])<=24 or any(not isinstance(i,str) or i not in context['evidence_tasks'] for i in value['evidence_tasks']):raise ValueError('invalid_review_evidence')
            validate_actions(value['prioritized_actions'],context)
            review.update(value,status='accepted');call['status']='accepted'
        except Exception as exc:
            reason=exc.reason if isinstance(exc,ProviderError) else str(exc) if isinstance(exc,RuntimeError) else 'invalid_specialist_response'
            if isinstance(exc,json.JSONDecodeError):reason='invalid_review_json'
            elif isinstance(exc,ValueError) and exc.args and isinstance(exc.args[0],str) and exc.args[0] in REVIEW_VALIDATION_REASONS:reason=exc.args[0]
            if sent and call['total_tokens'] is None:self.complete=False
            if isinstance(exc,ProviderError):self.provider_blocked=True
            call.update(status='fallback' if sent else 'not_sent',reason=reason)
            if sent:self.fallbacks+=1
            review.update(status='unavailable',reason=reason)
        finally:
            if getattr(self.transport,'last_trace',None):call['transport_trace']=dict(self.transport.last_trace)
            call['duration_seconds']=round(time.monotonic()-stamp,6)
            self.calls.append(call);self.reviews.append(review)
            self.store.event('llm','decision',payload=call)
            self.store.event('llm','specialist_review',payload={**review,'known_tokens':call.get('total_tokens'),'prompt_ref':call['prompt_ref']})

    def summary(self):
        value=super().summary()
        if not any(c.get('generation_sent') for c in self.calls):value['status']='not_started'
        value['configuration']['output_contract']='authorized_choice_and_specialist_review_json_schema'
        value['configuration'].update(transport_version='traced-no-retry-1',review_timeout_seconds=REVIEW_TIMEOUT_SECONDS,review_max_output_tokens=REVIEW_MAX_OUTPUT_TOKENS)
        value.update(specialist_prompt_version='specialist-review-4',budget=self.full_budget,expert_mode=True,planning_budget=self.budget,review_budget=self.review_budget,
                     specialist_reviews=self.reviews,specialist_review_seconds=self.review_seconds,
                     specialist_reviews_expected_roles=self.specialist_reviews_expected_roles)
        return value
