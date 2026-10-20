#!/usr/bin/env python3
"""Gráficos descriptivos del cierre, solo a partir de parejas IA elegibles.

No inicia herramientas ni API y no escribe en las corridas originales.
Ejecutar después de las mediciones con un Python que disponga de matplotlib.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohorte',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'estudio_novaflow_\d{8}T\d{6}',args.cohorte):parser.error('Identificador de cohorte inválido.')
    folder=ROOT/'piloto_kali/prototipo/corridas/kpi_novaflow'/args.cohorte
    if folder.is_symlink():raise ValueError('No se admiten cohortes enlazadas.')
    state=json.loads((folder/'state.json').read_text())
    if state.get('status') not in {'stopped','pilot_complete','complete'}:
        raise ValueError('Esperar al cierre de las mediciones antes de generar gráficos.')
    rows=json.loads((folder/'attempts.json').read_text())
    protocol=json.loads((folder/'protocol.json').read_text())
    destination=ROOT/'docs/cierre-final-2026-10-17/figuras'/args.cohorte
    destination.mkdir(parents=True,exist_ok=True)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
    receipt={'cohort':args.cohorte,'study_status':state['status'],
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'runtime':{'python':sys.version.split()[0],'matplotlib':matplotlib.__version__},
        'source_sha256':{},'figures':[],'individual_figures':[],'omitted':[],
        'limitations':'Exploratorio; solo parejas IA elegibles. Tareas y detecciones repetidas no son réplicas independientes. No se combinan fases ni cohortes.'}
    for name in ['attempts.json','pilot_analysis.json','formal_analysis.json','protocol.json']:
        receipt['source_sha256'][name]=hashlib.sha256((folder/name).read_bytes()).hexdigest()
    for phase,title in [('pilot','Piloto'),('formal','Evaluación')]:
        analysis=json.loads((folder/(phase+'_analysis.json')).read_text())
        pairs=[p for p in analysis['pairs'] if p.get('eligible_llm_pair') is True
               and all(type(p.get(key)) in {int,float} for key in ['TRTO_percent','ETV_ratio'])]
        if not pairs:
            receipt['omitted'].append({'phase':phase,'reason':'NO CALCULABLE: no hay parejas IA elegibles.'});continue
        blocks=[p['block'] for p in pairs]
        indexed={(r['block'],r['architecture']):r for r in rows if r['phase']==phase}
        fig,axes=plt.subplots(2,2,figsize=(12.4,8),layout='constrained')
        palette={'single':'#163e59','multiagent':'#09a1b8'}
        for ax,key,label in [(axes[0,0],'elapsed_seconds','Tiempo total (s)'),(axes[0,1],'known_tokens','Tokens medidos')]:
            for block in blocks:
                values=[indexed[block,arm][key] for arm in ['single','multiagent']]
                ax.plot([block-.12,block+.12],values,color='#bdcbd1',linewidth=1,zorder=1)
            for arm,offset,name in [('single',-.12,'Agente único'),('multiagent',.12,'Multiagente')]:
                ax.scatter([b+offset for b in blocks],[indexed[b,arm][key] for b in blocks],label=name,color=palette[arm],s=32,zorder=2)
            upper=max(indexed[b,arm][key] for b in blocks for arm in ['single','multiagent'])*1.12
            ax.set(ylabel=label,xlabel='Pareja',ylim=(0,upper));ax.set_xticks(blocks);ax.grid(axis='y',alpha=.18)
        axes[0,0].legend(frameon=False,loc='best')
        for ax,key,label,target in [(axes[1,0],'TRTO_percent','Reducción de tiempo (%)',30),(axes[1,1],'ETV_ratio','Razón de eficiencia de tokens',1.10)]:
            values=[p[key] for p in pairs]
            ax.bar(blocks,values,color='#09a1b8',width=.6)
            ax.axhline(target,color='#d58e24',linestyle='--',label='Meta de ingeniería')
            ax.axhline(0 if key=='TRTO_percent' else 1,color='#617784',linewidth=.8)
            low=min(0,min(values));high=max(target,max(values));padding=max(high-low,.1)*.1
            ax.set(ylabel=label,xlabel='Pareja',ylim=(low-padding if low<0 else 0,high+padding));ax.set_xticks(blocks);ax.grid(axis='y',alpha=.18)
            ax.legend(frameon=False,fontsize=8,loc='upper right')
            ax.yaxis.set_major_formatter(FuncFormatter(lambda x,_:f'{x:g}'.replace('.',',')))
        planned=protocol['planned_formal_pairs'] if phase=='formal' else len(protocol['pilot_order'])
        label='Evaluación parcial' if phase=='formal' and len(pairs)<planned else title
        fig.suptitle(f'{label} NovaFlow · {len(pairs)} de {planned} parejas IA elegibles',fontsize=15,fontweight='bold')
        fig.supxlabel('Mismo banco y versión; resultados descriptivos.\nRestauración fuera del tiempo; revisión LLM incluida.',fontsize=9)
        path=destination/(phase+'-comparacion.png');fig.savefig(path,dpi=180,facecolor='white');plt.close(fig)
        receipt['figures'].append({'phase':phase,'pairs':len(pairs),'path':path.relative_to(ROOT).as_posix(),
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'IDE_percent':analysis['metrics'].get('IDE_percent',{}),
            'IDE_denominator_note':'Este resumen IDE usa los intentos con adjudicación de la fase, incluidos los no elegibles para TRTO/ETV.',
            'denominator_note':'Los intentos no elegibles se conservan en el inventario y se excluyen de estas gráficas de TRTO/ETV.'})
        if phase=='formal':
            for key,ylabel,stem in [('elapsed_seconds','Tiempo total (s)','tiempo'),('known_tokens','Tokens medidos','tokens')]:
                with plt.rc_context({'font.size':11}):
                    single_fig,ax=plt.subplots(figsize=(6.5,4.5),layout='constrained')
                    for block in blocks:
                        ax.plot([block-.12,block+.12],[indexed[block,arm][key] for arm in ['single','multiagent']],color='#bdcbd1',linewidth=1,zorder=1)
                    for arm,offset,name in [('single',-.12,'Agente único'),('multiagent',.12,'Multiagente')]:
                        ax.scatter([b+offset for b in blocks],[indexed[b,arm][key] for b in blocks],label=name,color=palette[arm],s=28,zorder=2)
                    maximum=max(indexed[b,arm][key] for b in blocks for arm in ['single','multiagent'])
                    ax.set(xlabel='Pareja',ylabel=ylabel,ylim=(0,maximum*1.15));ax.set_xticks(blocks)
                    ax.tick_params(labelsize=10.5);ax.grid(axis='y',alpha=.18)
                    ax.legend(frameon=False,loc='upper right' if key=='known_tokens' else 'upper left',fontsize=10.5)
                    single_fig.suptitle(f'NovaFlow · evaluación parcial · {len(pairs)} de {planned} parejas',fontsize=12,fontweight='bold')
                    single_fig.supxlabel('Restauración fuera del tiempo; revisión LLM incluida.',fontsize=10)
                    individual=destination/f'formal-{stem}-por-pareja.png'
                    single_fig.savefig(individual,dpi=200,facecolor='white');plt.close(single_fig)
                receipt['individual_figures'].append({'phase':phase,'pairs':len(pairs),'planned_pairs':planned,'metric':key,
                    'path':individual.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(individual.read_bytes()).hexdigest(),
                    'print_width_inches':6.5,'minimum_font_points':10})
    (destination/'fuentes.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'figures':len(receipt['figures']),'omitted':receipt['omitted']},ensure_ascii=False))


if __name__=='__main__':main()
