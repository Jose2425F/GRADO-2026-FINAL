"""Aplicación sintética dual-stack con fallos y controles de acceso reproducibles.

Solo maneja recursos ficticios en /tmp del contenedor; nunca recibe archivos del host.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

SCENARIO = os.environ.get('LAB_SCENARIO', 'strict')


def fixture_token(label, size=12):
    """Recursos reproducibles del banco; las sesiones conservan tokens aleatorios."""
    seed = os.environ.get('LAB_FIXTURE_SEED')
    if seed:
        return hashlib.sha256(f'{seed}:{SCENARIO}:{label}'.encode()).hexdigest()[:size * 2]
    return secrets.token_hex(size)


FAULTS = {'alpha': {'bola', 'traversal', 'ipv6_admin'},
          'beta': {'double_decode', 'ipv6_admin'},
          'gamma': {'bola'}, 'strict': set()}[SCENARIO]
ROOT = Path(os.environ.get('LAB_FIXTURE_ROOT', '/tmp/fixtures')).resolve()
if not ROOT.is_relative_to(Path('/tmp')):
    raise ValueError('Las fixtures ficticias deben permanecer en /tmp')
PUBLIC = ROOT / 'public'
PUBLIC.mkdir(parents=True, exist_ok=True)
(ROOT / 'private').mkdir(exist_ok=True)
(PUBLIC / 'guide.txt').write_text(json.dumps({'kind': 'public_document', 'value': 'laboratory-guide'}))
(ROOT / 'private' / 'audit_marker.txt').write_text(json.dumps({'kind': 'internal_configuration', 'marker': fixture_token('private')}))
TOKENS = set()
LOCK = threading.Lock()
EVENTS = []
OWN = fixture_token('own', 6)
OTHER = fixture_token('other', 6)
DECOY = fixture_token('decoy', 6)
OBJECTS = {OWN: {'kind': 'document', 'owner': 'viewer', 'marker': fixture_token('own-marker')},
           OTHER: {'kind': 'document', 'owner': 'other', 'marker': fixture_token('other-marker')}}


def log_event(nonce, method, path, status, kind=None):
    with LOCK:
        EVENTS.append({'nonce': nonce, 'method': method, 'path': path[:256], 'status': status, 'kind': kind})
        del EVENTS[:-256]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body):
        raw = json.dumps(body, sort_keys=True).encode()
        nonce = self.headers.get('X-Lab-Nonce', '')[:48]
        log_event(nonce, self.command, self.path, status, body.get('kind'))
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        return self.headers.get('Authorization', '').removeprefix('Bearer ') in TOKENS

    def do_POST(self):
        if self.path != '/session':
            return self.reply(404, {'error': 'not_found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 1024:
                raise ValueError('length')
            data = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            return self.reply(400, {'error': 'invalid_request'})
        if data != {'user': 'viewer', 'password': 'lab-viewer'}:
            return self.reply(403, {'error': 'authentication_denied'})
        token = secrets.token_hex(16)
        with LOCK:
            TOKENS.add(token)
            # La carga de prueba es finita; limitar sesiones conserva memoria acotada.
            if len(TOKENS) > 128:
                TOKENS.clear()
                TOKENS.add(token)
        self.reply(200, {'token': token, 'role': 'viewer'})

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == '/health':
            return self.reply(200, {'service': 'document-gateway', 'version': '2', 'ready': True})
        if parsed.path == '/trace':
            nonce = parse_qs(parsed.query).get('nonce', [''])[0]
            with LOCK:
                entries = [dict(e) for e in EVENTS if e['nonce'] == nonce]
            return self.reply(200, {'events': entries})
        if not self.authorized():
            return self.reply(401, {'error': 'session_required'})
        if parsed.path == '/catalog':
            return self.reply(200, {'handles': [DECOY, OTHER, OWN], 'downloads': ['guide.txt'], 'admin': '/admin'})
        if parsed.path.startswith('/objects/'):
            key = parsed.path.removeprefix('/objects/')
            if key == DECOY:
                # HTTP 200 con error no es evidencia de acceso a un recurso privado.
                return self.reply(200, {'error': 'not_found'})
            item = OBJECTS.get(key)
            if item is None:
                return self.reply(404, {'error': 'not_found'})
            if item['owner'] != 'viewer' and 'bola' not in FAULTS:
                return self.reply(403, {'error': 'ownership_denied'})
            return self.reply(200, item)
        if parsed.path == '/download':
            name = parse_qs(parsed.query).get('name', [''])[0]
            if 'double_decode' in FAULTS:
                name = unquote(name)
            candidate = (PUBLIC / name).resolve()
            boundary = ROOT if FAULTS & {'traversal', 'double_decode'} else PUBLIC
            # El fallo solo permite salir del directorio público dentro de fixtures.
            if not candidate.is_relative_to(boundary) or not candidate.is_file():
                return self.reply(403, {'error': 'file_boundary_denied'})
            return self.reply(200, json.loads(candidate.read_text()))
        if parsed.path == '/admin':
            if self.server.address_family == socket.AF_INET6 and 'ipv6_admin' in FAULTS:
                return self.reply(200, {'kind': 'admin_configuration', 'marker': 'synthetic-administration'})
            return self.reply(403, {'error': 'role_denied'})
        self.reply(404, {'error': 'not_found'})


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


if __name__ == '__main__':
    server4 = ThreadingHTTPServer(('0.0.0.0', 8088), Handler)
    server6 = IPv6Server(('::', 8088), Handler)
    threading.Thread(target=server4.serve_forever, daemon=True).start()
    server6.serve_forever()
