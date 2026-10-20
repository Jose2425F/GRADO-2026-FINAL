"""Cota estructural exacta para diseñar el presupuesto, reservada al evaluador.

No ejecuta tareas ni LLM. Encontrar una cobertura teórica no demuestra que un
agente sin acceso a la referencia pueda elegirla ni que las herramientas tengan
éxito. Esta función no debe incorporarse a los prompts o al planificador.
"""
from __future__ import annotations
from .evaluacion import conditions_for


def minimum_positive_cost(tasks,present,conditions=conditions_for):
    tasks=list(tasks);present=set(present)
    keys={task.task_id:i for i,task in enumerate(tasks)}
    if len(keys)!=len(tasks):raise ValueError('Identificador de tarea duplicado.')
    labels={key:i for i,key in enumerate(sorted(present))}
    covers=[]
    for task in tasks:
        cover=0
        for condition in conditions(task):
            key=(task.target.asset_id,condition)
            if key in labels:cover|=1<<labels[key]
        covers.append(cover)
    closures={};visiting=set()
    def closure(i):
        if i in visiting:raise ValueError('Ciclo de dependencias.')
        if i not in closures:
            visiting.add(i);mask=1<<i
            for dep in tasks[i].dependencies:
                if dep not in keys:raise ValueError('Dependencia inexistente.')
                mask|=closure(keys[dep])
            visiting.remove(i);closures[i]=mask
        return closures[i]
    for i in range(len(tasks)):closure(i)
    candidates=[i for i,cover in enumerate(covers) if cover]
    if len(candidates)>25:raise ValueError('La búsqueda exacta excede el tamaño admitido.')
    full=(1<<len(labels))-1;best=(len(tasks)+1,0)
    def search(position,selected,covered):
        nonlocal best
        if selected.bit_count()>=best[0]:return
        if covered==full:best=(selected.bit_count(),selected);return
        if position==len(candidates):return
        search(position+1,selected,covered)
        mask=closures[candidates[position]];next_coverage=covered
        for index,cover in enumerate(covers):
            if mask>>index&1:next_coverage|=cover
        search(position+1,selected|mask,next_coverage)
    search(0,0,0)
    if best[0]>len(tasks):return {'minimum_tasks':None,'covers_all_present':False,'task_ids':[]}
    return {'minimum_tasks':best[0],'covers_all_present':True,
            'task_ids':[task.task_id for i,task in enumerate(tasks) if best[1]>>i&1]}
