"""Entorno explícito para pruebas de controladores con herramientas simuladas."""
from pathlib import Path

import pytest


@pytest.fixture
def healthy_kernel(monkeypatch):
    """Aísla solo /proc/.../tainted; no altera el kernel ni el código operativo.

    Los casos de rechazo por kernel tienen sus propias entradas y no usan esta
    fixture. El resto de lecturas de archivos conserva su comportamiento real.
    """
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        if path == Path('/proc/sys/kernel/tainted'):
            return '0\n'
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read_text)
