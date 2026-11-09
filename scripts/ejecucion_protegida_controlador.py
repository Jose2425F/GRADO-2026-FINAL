"""Entrada sin privilegios para el catálogo instalado por el operador.

El descriptor y las políticas se generan fuera del controlador; este archivo
no crea redes, no altera cortafuegos y no abre el socket del daemon Docker.
"""
from pathlib import Path
import argparse
import json
import os
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'piloto_kali/prototipo/src')]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gate-fd',type=int,required=True)
    parser.add_argument('--descriptor',type=Path,required=True)
    args=parser.parse_args()
    if os.read(args.gate_fd,2)!=b'go':raise SystemExit('El operador no liberó la ejecución protegida.')
    os.close(args.gate_fd)
    os.environ['CENTINELA_RUNTIME_DESCRIPTOR']=str(args.descriptor)
    from auditoria.secure_runtime import require_protected_runtime
    data=require_protected_runtime()
    from auditoria.tool_worker import identity
    output=Path(data['output']);output.mkdir(parents=True,exist_ok=True)
    (output/'controller-identity.json').write_text(json.dumps(identity(),indent=2)+'\n')
    if data.get('acceptance_checks') is True:
        from tesis.pruebas_roles import controller_selftest
        checks=controller_selftest(data)
        if checks.get('passed') is not True:
            raise SystemExit('Fallaron las pruebas de separación de roles; no se inicia el catálogo.')
    from dualstack_panel import validate_options
    options=validate_options(data['options'])
    import laboratorio_empresa as driver
    from auditoria import empresa_agent,lab_empresa
    if data['bank']=='integrado':
        driver.STATE=Path(data['state'])
        return driver.run_panel(options,output/'runs')
    from tesis.laboratorios import Context
    context=Context(data['bank'],state_root=Path(data['state']).parent)
    return driver.run_panel(options,output/'runs',bank_context=context)


if __name__=='__main__':raise SystemExit(main())
