"""Límites de la nueva versión; no modifica políticas ni bancos congelados."""
DEFAULT_AUDIT_TOKENS=60_000


def token_limit(scope):
    return 80_000 if scope=='empresa' else 20_000
