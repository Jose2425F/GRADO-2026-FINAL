"""Autorizaciones privadas reales para los escenarios acotados de las pruebas.

El registro vive fuera del directorio de corridas. No sustituye el guard por un
doble permisivo: se utiliza el mismo emisor y validador que usa el aplicativo.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from unittest.mock import patch

from autorizacion_personal import AuthorizationGuard, issue_authorization


@contextmanager
def personal_authorization(options):
    reference = options.get('authorization', 'LAB-PROPIO')
    approved_options = {**options, 'authorization': reference}
    with tempfile.TemporaryDirectory(prefix='centinela-test-authorization-') as directory:
        registry = Path(directory) / 'authorizations.json'
        issue_authorization(
            registry, reference, approved_options,
            approved_by='Operador del arnés de pruebas',
            evidence_ref='fixture:tests-locales-autorizados',
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        with patch.dict('os.environ', {'CENTINELA_AUTHORIZATIONS_FILE': str(registry)}):
            yield AuthorizationGuard(approved_options, registry_path=registry)


def scope_options(config, *, credentials=False, applications=None):
    return {'scope': 'personal', 'authorization': 'LAB-PROPIO',
            'personal': config, 'creds': credentials,
            'applications': applications or []}
