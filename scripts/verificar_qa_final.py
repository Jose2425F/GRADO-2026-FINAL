#!/usr/bin/env python3
"""Recibo por prueba de la batería del panel; no inicia auditorías de usuario ni API.

Los casos existentes incluyen conexiones TCP a fixtures locales de prueba.
Los resultados crudos y trazas quedan en almacenamiento privado.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PRIVATE=ROOT/'piloto_kali/prototipo/.verificacion/cierre-final-20261017'
PUBLIC=ROOT/'docs/cierre-final-2026-10-17'


class ReceiptResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.rows=[];self.starts={}

    def startTest(self,test):
        self.starts[test.id()]=(datetime.now(timezone.utc).isoformat(),time.monotonic())
        super().startTest(test)

    def record(self,test,status):
        stamp,start=self.starts.get(test.id(),(None,time.monotonic()))
        self.rows.append({'id':test.id(),'at':stamp,'component':test.__class__.__module__,
            'objective':test.shortDescription() or test.id().rsplit('.',1)[-1],
            'procedure':'Método automatizado del mismo identificador en scripts/tests.',
            'expected':'Cumplir las aserciones del contrato bajo sus precondiciones y fixtures.',
            'obtained':status,'status':status,'elapsed_seconds':round(time.monotonic()-start,6),
            'limitations':'Prueba de software; no constituye una auditoría del estudio ni una llamada API real.'})

    def addSuccess(self,test):super().addSuccess(test);self.record(test,'APROBADA')
    def addFailure(self,test,err):super().addFailure(test,err);self.record(test,'FALLIDA')
    def addError(self,test,err):super().addError(test,err);self.record(test,'FALLIDA')
    def addSkip(self,test,reason):super().addSkip(test,reason);self.record(test,'NO EJECUTADA')
    def addExpectedFailure(self,test,err):super().addExpectedFailure(test,err);self.record(test,'PARCIAL')
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self.record(test,'FALLIDA')


def main():
    os.umask(0o077)
    PRIVATE.mkdir(parents=True,exist_ok=True);PUBLIC.mkdir(parents=True,exist_ok=True)
    if int(Path('/proc/sys/kernel/tainted').read_text())&((1<<7)|(1<<14)):
        raise SystemExit('BLOQUEADA: recuperar el kernel antes de la batería integral.')
    os.chdir(ROOT);sys.path[:0]=[str(ROOT),str(ROOT/'scripts')]
    log=PRIVATE/'qa-panel-final.log'
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    # Conservar todos los intentos, incluso fallos del propio lanzador de QA.
    if log.exists():shutil.copy2(log,PRIVATE/f'qa-panel-anterior-{stamp}.log')
    previous=PUBLIC/'qa-panel.json'
    if previous.exists():shutil.copy2(previous,PRIVATE/f'qa-panel-anterior-{stamp}.json')
    with log.open('w') as stream:
        original=sys.stdout,sys.stderr
        try:
            sys.stdout=sys.stderr=stream
            suite=unittest.defaultTestLoader.discover(str(ROOT/'scripts/tests'),pattern='test_*.py')
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=ReceiptResult).run(suite)
        finally:sys.stdout,sys.stderr=original
    source={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT/'scripts/tests').glob('test_*.py')}
    data={'at':datetime.now(timezone.utc).isoformat(),'suite':'panel y módulos externos',
        'executed':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'skipped':len(result.skipped),'passed':result.wasSuccessful(),
        'kernel_tainted_after':int(Path('/proc/sys/kernel/tainted').read_text()),
        'source_sha256':source,'private_log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
        'tests':result.rows}
    (PUBLIC/'qa-panel.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in data.items() if k not in {'source_sha256','tests'}},ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':raise SystemExit(main())
