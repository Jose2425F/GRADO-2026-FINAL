"""Permisos de laboratorio registrados por el operador antes de ejecutar sondas.

La referencia de una solicitud no constituye el permiso. Su alcance debe coincidir
con un registro privado del servidor. Este control no acredita por sí solo
consentimiento legal, privilegio mínimo ni aislamiento de paquetes en el anfitrión.

El servicio y la consola deben usar el mismo CENTINELA_DATA_DIR. Una ruta
CENTINELA_AUTHORIZATIONS_FILE del servidor tiene prioridad sobre ese directorio.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
from ipaddress import ip_address
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time


DEFAULT_REGISTRY = Path('/var/lib/centinela/authorizations.json')
MAX_REGISTRY_BYTES = 1_000_000
MAX_AUTHORIZATIONS = 1000
_REFERENCE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{2,119}')
_ENTRY_FIELDS = {'reference', 'approved_by', 'evidence_ref', 'issued_at',
                 'expires_at', 'revoked', 'scope'}
_OPTION_FIELDS = {'name', 'authorization', 'architecture', 'ia', 'tokens', 'mode',
                  'scope', 'personal', 'creds', 'applications', 'expert_mode'}


class AuthorizationError(ValueError):
    def __init__(self, reason_code, message=None):
        self.reason_code = reason_code
        super().__init__(message or reason_code)


def _fail(code, message):
    raise AuthorizationError(code, message)


def _reference(value):
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        _fail('authorization_reference_invalid', 'La referencia de autorización no es válida.')
    return value


def _text(value, field, maximum=256):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum or any(
            not char.isprintable() for char in value):
        _fail('authorization_registry_invalid', f'El campo {field} de la autorización no es válido.')
    return value.strip()


def _stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        _fail('authorization_time_invalid', 'La autorización requiere fechas con zona horaria.')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        _fail('authorization_time_invalid', 'La autorización requiere fechas válidas con zona horaria.')


def _now(source=None):
    value = source() if callable(source) else source
    if value is None:
        value = time.time()
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            _fail('authorization_time_invalid', 'El reloj debe incluir zona horaria.')
        return value.astimezone(timezone.utc)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        _fail('authorization_time_invalid', 'El reloj de autorización no es válido.')
    try:
        return datetime.fromtimestamp(value, timezone.utc)
    except (ValueError, OverflowError, OSError):
        _fail('authorization_time_invalid', 'El reloj de autorización no es válido.')


def _iso(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _scope(options):
    if not isinstance(options, dict) or set(options) - _OPTION_FIELDS:
        _fail('authorization_scope_invalid', 'La solicitud contiene opciones de autorización no admitidas.')
    if options.get('scope', 'personal') != 'personal':
        _fail('authorization_scope_invalid', 'Este registro solo admite el alcance por IP.')
    from laboratorio_personal import configuration
    from aplicaciones_personales import configure_applications
    try:
        personal = configuration(options.get('personal'))
        if personal['interface'] == 'auto':
            _fail('authorization_interface_required',
                  'Selecciona una interfaz explícita y registra su autorización antes de ejecutar.')
        credentials = options.get('creds', False)
        if type(credentials) is not bool:
            _fail('authorization_scope_invalid', 'La autorización de credenciales debe ser explícita.')
        applications = configure_applications(options.get('applications', []), personal)
    except AuthorizationError:
        raise
    except (ValueError, TypeError, KeyError):
        _fail('authorization_scope_invalid', 'El alcance registrado de la autorización no es válido.')
    return {'personal': personal, 'creds': credentials, 'applications': applications}


def _entry(value):
    if not isinstance(value, dict) or set(value) != _ENTRY_FIELDS:
        _fail('authorization_registry_invalid', 'El registro de autorización no cumple el esquema permitido.')
    reference = _reference(value['reference'])
    approved = _text(value['approved_by'], 'approved_by')
    evidence = _text(value['evidence_ref'], 'evidence_ref', 512)
    issued, expires = _stamp(value['issued_at']), _stamp(value['expires_at'])
    if expires <= issued or type(value['revoked']) is not bool:
        _fail('authorization_registry_invalid', 'La vigencia o revocación de la autorización no es válida.')
    scope = value['scope']
    if not isinstance(scope, dict) or set(scope) != {'personal', 'creds', 'applications'}:
        _fail('authorization_registry_invalid', 'El alcance de la autorización no cumple el esquema permitido.')
    normalized = _scope(scope)
    # Rechazar registros que dependan de valores implícitos o de una normalización
    # distinta de la que el operador aprobó.
    if normalized != scope:
        _fail('authorization_registry_invalid', 'El alcance debe guardarse en su forma normalizada.')
    return {'reference': reference, 'approved_by': approved, 'evidence_ref': evidence,
            'issued_at': _iso(issued), 'expires_at': _iso(expires),
            'revoked': value['revoked'], 'scope': normalized}


def _registry(value):
    if not isinstance(value, dict) or set(value) != {'version', 'authorizations'} or (
            type(value['version']) is not int or value['version'] != 1):
        _fail('authorization_registry_invalid', 'El archivo de autorizaciones no cumple la versión permitida.')
    entries = value['authorizations']
    if not isinstance(entries, list) or len(entries) > MAX_AUTHORIZATIONS:
        _fail('authorization_registry_invalid', 'El número de autorizaciones supera el límite permitido.')
    result = [_entry(entry) for entry in entries]
    refs = [entry['reference'] for entry in result]
    if len(refs) != len(set(refs)):
        _fail('authorization_reference_duplicate', 'Hay referencias de autorización duplicadas.')
    return {'version': 1, 'authorizations': result}


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail('authorization_registry_invalid', 'El archivo de autorizaciones contiene campos duplicados.')
        result[key] = value
    return result


def _path(registry_path=None):
    value = registry_path
    if value is None:
        value = os.environ.get('CENTINELA_AUTHORIZATIONS_FILE')
        if value is None:
            value = Path(os.environ.get('CENTINELA_DATA_DIR', str(DEFAULT_REGISTRY.parent))) / DEFAULT_REGISTRY.name
    try:
        if not os.fspath(value):
            raise ValueError
        path = Path(value).expanduser()
        if '..' in path.parts:
            raise ValueError
        return Path(os.path.abspath(path))
    except (ValueError, TypeError, OSError):
        _fail('authorization_registry_unsafe', 'La ruta privada de autorizaciones no es válida.')


def _trusted_directory(info, *, private=False):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
        _fail('authorization_registry_unsafe', 'El directorio de autorizaciones no tiene propietario de confianza.')
    if private:
        unsafe = info.st_mode & 0o077
    else:
        # /tmp puede contener un directorio privado del operador. El bit sticky
        # de un directorio de root impide que otros usuarios sustituyan su entrada.
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        unsafe = info.st_mode & 0o022 and not sticky_root
    if unsafe:
        _fail('authorization_registry_unsafe', 'El directorio de autorizaciones permite acceso o escritura ajenos.')


@contextmanager
def _parent(path, *, create=False):
    """Recorre por descriptores y O_NOFOLLOW para evitar enlaces y carreras."""
    current = None
    try:
        current = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        _trusted_directory(os.fstat(current))
        parts = path.parent.parts[1:]
        for index, part in enumerate(parts):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    _fail('authorization_registry_missing', 'No hay autorizaciones registradas para este servidor.')
                try:
                    os.mkdir(part, 0o700, dir_fd=current)
                except FileExistsError:
                    # Otro alta del operador puede haber creado el directorio;
                    # se abre sin seguir enlaces y se comprueban sus permisos.
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                _trusted_directory(os.fstat(child), private=index == len(parts)-1)
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        # Un archivo directamente en / no tiene un directorio privado válido.
        if not parts:
            _fail('authorization_registry_unsafe', 'La autorización requiere un directorio privado.')
        yield current
    except AuthorizationError:
        raise
    except OSError:
        _fail('authorization_registry_unsafe', 'No se pudo abrir de forma segura el directorio de autorizaciones.')
    finally:
        if current is not None:
            os.close(current)


def _trusted_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_REGISTRY_BYTES):
        _fail('authorization_registry_unsafe', 'El registro debe ser un archivo privado, regular y acotado.')


def _read_at(parent, name, *, missing=False):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        _trusted_file(os.fstat(fd))
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            content = stream.read(MAX_REGISTRY_BYTES + 1)
        if len(content) > MAX_REGISTRY_BYTES:
            _fail('authorization_registry_unsafe', 'El archivo de autorizaciones supera el límite permitido.')
        value = json.loads(content, object_pairs_hook=_json_object)
        return _registry(value)
    except FileNotFoundError:
        if missing:
            return {'version': 1, 'authorizations': []}
        _fail('authorization_registry_missing', 'No hay autorizaciones registradas para este servidor.')
    except AuthorizationError:
        raise
    except OSError:
        _fail('authorization_registry_unsafe', 'No se pudo abrir de forma segura el registro privado de autorizaciones.')
    except (ValueError, UnicodeError, TypeError):
        _fail('authorization_registry_invalid', 'No se pudo validar el archivo privado de autorizaciones.')
    finally:
        if fd is not None:
            os.close(fd)


def _read(path):
    with _parent(path) as parent:
        return _read_at(parent, path.name)


def _active(registry, reference, now):
    record = next((entry for entry in registry['authorizations'] if entry['reference'] == reference), None)
    if record is None:
        _fail('authorization_not_registered', 'La referencia no tiene una autorización registrada por el operador.')
    if record['revoked']:
        _fail('authorization_revoked', 'La autorización fue revocada por el operador.')
    if _stamp(record['issued_at']) > now:
        _fail('authorization_not_yet_valid', 'La autorización todavía no está vigente.')
    if _stamp(record['expires_at']) <= now:
        _fail('authorization_expired', 'La autorización ha caducado; solicita su revisión al operador.')
    return record


def _receipt(record):
    return {key: record[key] for key in ['reference', 'approved_by', 'evidence_ref', 'issued_at', 'expires_at']} | {
        'scope_sha256': _digest(record['scope']), 'grant_sha256': _digest(record)}


def authorized_options(reference, *, registry_path=None, now=None):
    """Recupera el alcance aprobado; no recibe objetivos desde el navegador."""
    reference = _reference(reference)
    record = _active(_read(_path(registry_path)), reference, _now(now))
    return {'authorization': reference, **json.loads(json.dumps(record['scope']))}


class AuthorizationGuard:
    def __init__(self, options, *, registry_path=None, now=None):
        if not isinstance(options, dict):
            _fail('authorization_scope_invalid', 'La solicitud no contiene un alcance válido.')
        self.reference = _reference(options.get('authorization'))
        self.path = _path(registry_path)
        self.now = now
        self.scope = _scope(options)
        self._grant_sha256 = None
        self.verify()

    def verify(self):
        record = _active(_read(self.path), self.reference, _now(self.now))
        if record['scope'] != self.scope:
            _fail('authorization_scope_mismatch', 'Los objetivos, puertos o pruebas no coinciden con la autorización registrada.')
        current = _digest(record)
        if self._grant_sha256 is not None and self._grant_sha256 != current:
            _fail('authorization_changed', 'La autorización cambió después de comprobarla; inicia una solicitud nueva.')
        self._grant_sha256 = current
        return _receipt(record)

    def require_feature(self, feature):
        receipt = self.verify()
        allowed = {'inventory': True, 'credentials': self.scope['creds'],
                   'applications': bool(self.scope['applications'])}
        if not isinstance(feature, str) or not allowed.get(feature, False):
            _fail('authorization_feature_denied', 'La autorización no permite ese tipo de prueba.')
        return receipt

    def check_application(self, application):
        receipt = self.require_feature('applications')
        from aplicaciones_personales import configure_applications
        try:
            normalized = configure_applications([application], self.scope['personal'])[0]
        except (ValueError, TypeError, KeyError, IndexError):
            _fail('authorization_application_denied', 'La aplicación no pertenece al alcance autorizado.')
        if normalized not in self.scope['applications']:
            _fail('authorization_application_denied', 'Las rutas o pruebas web no coinciden con la autorización.')
        return receipt

    def check_targets(self, targets):
        receipt = self.verify()
        from laboratorio_personal import scope_hosts
        permitted = {address for _, address in scope_hosts(self.scope['personal'])}
        expected_interface = self.scope['personal']['interface']
        ports = set(self.scope['personal']['ports'])
        automatic = self.scope['personal'].get('port_mode') == 'auto'
        if not isinstance(targets, (list, tuple)) or not targets:
            _fail('authorization_targets_invalid', 'La operación requiere objetivos autorizados explícitos.')
        for target in targets:
            if isinstance(target, dict):
                address, interface, selected = (target.get(key) for key in ['address', 'interface', 'ports'])
            else:
                address, interface, selected = (getattr(target, key, None) for key in ['address', 'interface', 'ports'])
            try:
                canonical = str(ip_address(address))
            except (ValueError, TypeError):
                _fail('authorization_target_denied', 'El objetivo no pertenece al alcance autorizado.')
            if canonical not in permitted or '%' in canonical or interface != expected_interface:
                _fail('authorization_target_denied', 'El objetivo o la interfaz no pertenecen al alcance autorizado.')
            if (not isinstance(selected, list) or (not automatic and not selected)
                    or any(type(port) is not int or not 1 <= port <= 65535 for port in selected)
                    or (not automatic and not set(selected).issubset(ports))):
                _fail('authorization_ports_denied', 'El objetivo contiene puertos fuera de la autorización.')
        return receipt


@contextmanager
def _locked(path):
    with _parent(path, create=True) as parent:
        fd = None
        try:
            fd = os.open('.authorizations.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            _trusted_file(os.fstat(fd))
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield parent
        except AuthorizationError:
            raise
        except OSError:
            _fail('authorization_registry_unsafe', 'No se pudo bloquear el registro privado de autorizaciones.')
        finally:
            if fd is not None:
                os.close(fd)


def _write_at(parent, name, registry):
    content = _canonical(_registry(registry)) + b'\n'
    if len(content) > MAX_REGISTRY_BYTES:
        _fail('authorization_registry_invalid', 'El archivo de autorizaciones supera el límite permitido.')
    temporary = '.authorization-' + secrets.token_hex(16)
    fd = None
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    except OSError:
        _fail('authorization_registry_unsafe', 'No se pudo conservar la autorización de forma atómica.')
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass


def issue_authorization(registry_path, reference, options, approved_by, evidence_ref, expires_at, *, now=None):
    """Consola del operador: registra una nueva referencia, sin reemplazar permisos."""
    reference = _reference(reference)
    current = _now(now)
    record = _entry({'reference': reference, 'approved_by': approved_by, 'evidence_ref': evidence_ref,
                     'issued_at': _iso(current), 'expires_at': _iso(_stamp(expires_at)),
                     'revoked': False, 'scope': _scope(options)})
    if _stamp(record['expires_at']) <= current:
        _fail('authorization_expired', 'La autorización nueva debe tener una fecha de vencimiento futura.')
    path = _path(registry_path)
    with _locked(path) as parent:
        registry = _read_at(parent, path.name, missing=True)
        if any(entry['reference'] == reference for entry in registry['authorizations']):
            _fail('authorization_reference_duplicate', 'Esa referencia ya está registrada; usa una referencia nueva.')
        registry['authorizations'].append(record)
        _write_at(parent, path.name, registry)
    return _receipt(record)


def revoke_authorization(registry_path, reference, *, now=None):
    """Conserva el registro y revoca futuros despachos, incluso de una corrida abierta."""
    reference = _reference(reference)
    path = _path(registry_path)
    with _locked(path) as parent:
        registry = _read_at(parent, path.name)
        record = next((entry for entry in registry['authorizations'] if entry['reference'] == reference), None)
        if record is None:
            _fail('authorization_not_registered', 'La referencia no tiene una autorización registrada.')
        record['revoked'] = True
        _write_at(parent, path.name, registry)
    return {'reference': reference, 'revoked': True, 'revoked_at': _iso(_now(now))}
