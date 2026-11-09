"""Límites de la nueva versión; no modifica políticas ni bancos congelados."""
DEFAULT_AUDIT_TOKENS=60_000


def token_limit(scope):
    # El modo por IP comparte el tope del laboratorio (pedido por José, 2026-11-07);
    # el banco histórico v2 conserva su límite original.
    return 80_000 if scope in {'empresa','personal'} else 20_000
