"""Crea un archivo local de secretos sintéticos sin mostrarlos ni sobrescribirlo."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


destination = Path(__file__).resolve().parents[1] / ".env"
content = ("LAB_SSH_PASSWORD=" + secrets.token_urlsafe(24) + "\n"
           "OPENAI_API_KEY=\n"
           "OPENAI_MODEL=gpt-6.1-sol\n"
           "LAB_OBSERVER_TOKEN=\n")
try:
    handle = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print(".env existente; se conservó sin cambios")
else:
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(content)
    print(".env creado con credencial SSH sintética y permisos 0600")
