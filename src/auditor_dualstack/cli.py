"""Punto de entrada del prototipo: ejecuta una auditoría sobre un objetivo.

Uso (en Kali, con el entorno activado):

    auditor --host-ipv4 192.168.56.101 --prefijo-ipv6 fd00::/64 --interfaz eth0

En el incremento 0 el grafo corre de punta a punta con agentes stub: no toca la
red, pero valida que la orquestación, la validación cruzada y la generación del
informe funcionen. La lógica de red real entra en los incrementos 1–4.
"""
from __future__ import annotations

import argparse
import sys

from .estado import AuditState
from .modelos import ObjetivoAuditoria


def _parsear_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="auditor",
        description="Prototipo multi-agente de auditoría dual-stack IPv4/IPv6",
    )
    p.add_argument("--host-ipv4", default=None, help="IP o host IPv4 objetivo")
    p.add_argument("--subred-ipv4", default=None, help="Subred IPv4, p. ej. 192.168.56.0/24")
    p.add_argument("--host-ipv6", default=None, help="Dirección IPv6 objetivo")
    p.add_argument("--prefijo-ipv6", default=None, help="Prefijo IPv6, p. ej. fd00::/64")
    p.add_argument("--interfaz", default="eth0", help="Interfaz de red (Kali)")
    p.add_argument("--descripcion", default="", help="Nota libre de la corrida")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parsear_args(argv)

    objetivo = ObjetivoAuditoria(
        host_ipv4=args.host_ipv4,
        subred_ipv4=args.subred_ipv4,
        host_ipv6=args.host_ipv6,
        prefijo_ipv6=args.prefijo_ipv6,
        interfaz=args.interfaz,
        descripcion=args.descripcion,
    )

    from .grafo import construir_grafo

    grafo = construir_grafo()
    estado_inicial: AuditState = {"objetivo": objetivo}
    resultado = grafo.invoke(estado_inicial)

    validados = resultado.get("hallazgos_validados", [])
    no_verificados = resultado.get("bitacora_no_verificados", [])
    print(f"Auditoría completada.")
    print(f"  Hallazgos validados     : {len(validados)}")
    print(f"  Hallazgos no verificados: {len(no_verificados)}")
    print(f"  Informe                 : {resultado.get('ruta_informe', '(no generado)')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
