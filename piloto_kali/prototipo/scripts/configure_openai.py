#!/usr/bin/env python3
"""Guarda la clave para la integración OpenAI, sin efectuar llamadas API."""

import argparse
import getpass
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    root = Path(__file__).resolve().parents[1] / ".lab"
    if root.is_symlink():
        raise SystemExit("No se guardó: .lab no puede ser un enlace simbólico.")
    root.mkdir(mode=0o700, exist_ok=True)
    key = getpass.getpass("API key de OpenAI (entrada oculta): ").strip()
    if not key or any(character.isspace() for character in key):
        raise SystemExit("No se guardó: falta una API key válida.")
    model = input("Modelo [gpt-6.1-sol]: ").strip() or "gpt-6.1-sol"
    if any(character.isspace() for character in model):
        raise SystemExit("No se guardó: modelo inválido.")
    fd, temporary_name = tempfile.mkstemp(prefix=".openai-", dir=root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump({"api_key": key, "model": model}, stream)
        os.replace(temporary, root / "openai.json")
    finally:
        temporary.unlink(missing_ok=True)
    print("Configuración privada guardada con permisos 0600.")
    print("Este comando no consulta la API ni genera cargos.")
    print("Para una auditoría real: auditoria demo --autorizacion LAB-PROPIO --ejecutar --openai")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nConfiguración cancelada; no se guardaron cambios.")
        raise SystemExit(130)
