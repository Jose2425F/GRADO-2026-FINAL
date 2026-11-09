"""Descubrimiento dirigido de activos incluidos en una autorización del servidor.

IPv4 recibe únicamente las direcciones de la autorización; IPv6 utiliza ecos
unicast. La lectura de interfaces y vecinos es local y no amplía los objetivos.
Este control de admisión no sustituye el aislamiento de red del sistema operativo.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET

PROBES = (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080, 8088, 8443)
MAX_HOSTS = 256
MAX_DISCOVERY_SECONDS = 90
NAME = re.compile(r'[A-Za-z0-9_.:-]{1,32}')
REPLY = re.compile(r'from ([0-9A-Fa-f:]+)(?:%[^\s:]+)?:')


def _run(command, timeout):
    from auditoria.tool_worker import tool_runtime_enabled,run_tool
    runner=run_tool if command[0]=='nmap' and tool_runtime_enabled() else subprocess.run
    return runner(command, capture_output=True, timeout=timeout, check=False)


def _addresses(name):
    result = _run(['ip', '-j', 'addr', 'show', 'dev', name], 5)
    if result.returncode:
        return []
    items = []
    for link in json.loads(result.stdout or b'[]'):
        for info in link.get('addr_info', []):
            try:
                items.append(ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}"))
            except (KeyError, ValueError):
                continue
    return items


def interfaces():
    """Interfaces con un segmento privado auditable: IPv4 /24 o menor, o IPv6 global."""
    found = []
    for _, name in socket.if_nameindex():
        if name == 'lo' or not NAME.fullmatch(name):
            continue
        addresses = _addresses(name)
        ipv4 = [a for a in addresses if a.version == 4 and a.network.is_private and a.network.prefixlen >= 24]
        ipv6 = [a for a in addresses if a.version == 6 and not a.ip.is_link_local and a.ip.is_private]
        if ipv4 or ipv6:
            found.append({'name': name, 'ipv4': [str(a.network) for a in ipv4], 'ipv6': [str(a.network) for a in ipv6]})
    return found


def _neighbors(name):
    result = _run(['ip', '-j', 'neigh', 'show', 'dev', name], 5)
    table = {}
    for item in json.loads(result.stdout or b'[]') if not result.returncode else []:
        states = set(item.get('state') or [])
        if item.get('lladdr') and not states & {'FAILED', 'INCOMPLETE'}:
            table[item.get('dst')] = item['lladdr'].lower()
    return table


def discover(name, authorization=None):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('La interfaz de red no es válida.')
    if not isinstance(authorization, str) or not authorization.strip():
        raise ValueError('Selecciona una autorización de activos registrada en el servidor.')
    from autorizacion_personal import AuthorizationGuard, authorized_options
    from laboratorio_personal import configuration, parse_discovery, resolve_targets

    # El alcance se toma del registro privado, nunca del prefijo de la NIC ni de
    # una lista adicional enviada junto con la petición de descubrimiento.
    options = authorized_options(authorization)
    guard = AuthorizationGuard(options)
    config = configuration(options['personal'])
    if config['interface'] == 'auto' or config['interface'] != name:
        raise ValueError('La interfaz no coincide con la autorización registrada.')
    guard.verify()
    from auditoria.secure_runtime import require_live_runtime
    require_live_runtime(bank='personal')
    if not shutil.which('nmap'):
        raise ValueError('Nmap no está disponible en el servidor.')
    started = time.monotonic()
    deadline = started + MAX_DISCOVERY_SECONDS
    targets = resolve_targets(config, deadline=deadline)
    if not targets or len(targets) > MAX_HOSTS:
        raise ValueError('La autorización debe contener entre uno y 256 activos.')
    guard.check_targets(targets)
    if any(t.interface != name for t in targets):
        raise ValueError('La ruta no coincide con la interfaz autorizada.')
    allowed = {4: set(), 6: set()}
    for target in targets:
        address = ipaddress.ip_address(target.address)
        allowed[address.version].add(str(address))

    def admit(values, maximum):
        # Se vuelve a leer el registro antes de cada proceso que puede emitir
        # tráfico, incluidas las sondas utilizadas para completar la MAC.
        guard.check_targets(values)
        for target in values:
            version = ipaddress.ip_address(target.address).version
            selected = {**config, 'ipv4': target.address if version == 4 else '',
                        'ipv6': target.address if version == 6 else ''}
            if resolve_targets(selected, deadline=deadline) != [target]:
                raise ValueError('La ruta del activo cambió antes del descubrimiento autorizado.')
        guard.check_targets(values)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('El descubrimiento agotó su tiempo máximo.')
        return min(maximum, remaining)

    local = {str(a.ip) for a in _addresses(name)}
    found = {4: set(), 6: set()}
    ipv4 = [t for t in targets if ipaddress.ip_address(t.address).version == 4]
    if ipv4:
        probes = PROBES if config.get('port_mode') == 'auto' else config['ports']
        command = ['nmap', '--unprivileged', '-n', '-sn', '-T4', '-PS' + ','.join(map(str, probes)),
                   '--max-retries', '1', '--host-timeout', '4s', '-e', name, '-oX', '-',
                   *[t.address for t in ipv4]]
        try:
            result = _run(command, admit(ipv4, 60))
        except subprocess.TimeoutExpired:
            raise ValueError('El barrido IPv4 tardó demasiado.') from None
        guard.verify()
        if result.returncode:
            raise ValueError('El descubrimiento IPv4 no terminó correctamente.')
        try:
            states = parse_discovery(result.stdout, ipv4)
        except (ET.ParseError, TypeError, ValueError):
            raise ValueError('El resultado IPv4 no respeta el alcance autorizado o no está completo.') from None
        found[4].update(address for address, state in states.items() if state == 'up' and address not in local)

    for target in targets:
        address = ipaddress.ip_address(target.address)
        if address.version != 6 or str(address) in local:
            continue
        try:
            result = _run(['ping', '-6', '-c', '1', '-W', '1', '-I', name, str(address)],
                          admit([target], 3))
        except subprocess.TimeoutExpired:
            continue
        guard.verify()
        if result.returncode:
            continue
        for match in REPLY.finditer(result.stdout.decode(errors='replace')):
            try:
                source = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if source != address:
                raise ValueError('La respuesta IPv6 contiene un origen distinto del objetivo autorizado.')
        found[6].add(str(address))
    neighbors = _neighbors(name)
    # Sólo se completa la entrada de un activo autorizado que ya respondió.
    pending = [a for version in (4, 6) for a in sorted(found[version]) if a not in neighbors][:MAX_HOSTS]
    if pending:
        by_address = {t.address: t for t in targets}
        for address in pending:
            try:
                _run(['ping', '-6' if ':' in address else '-4', '-c', '1', '-W', '1', '-I', name, address],
                     admit([by_address[address]], 3))
            except subprocess.TimeoutExpired:
                continue
            guard.verify()
        neighbors = _neighbors(name)
    guard.check_targets(targets)
    hosts = {}
    for version in (4, 6):
        for address in found[version]:
            mac = neighbors.get(address)
            if not mac:
                continue
            entry = hosts.setdefault(mac or address, {'mac': mac, 'ipv4': [], 'ipv6': []})
            entry['ipv4' if version == 4 else 'ipv6'].append(address)
    ordered = sorted(hosts.values(), key=lambda h: (
        0 if h['ipv4'] else 1,
        int(ipaddress.ip_address(h['ipv4'][0])) if h['ipv4'] else int(ipaddress.ip_address(h['ipv6'][0]))))
    for entry in ordered:
        entry['ipv4'].sort(key=lambda a: int(ipaddress.ip_address(a)))
        entry['ipv6'].sort(key=lambda a: int(ipaddress.ip_address(a)))
    segment = {'name': name, 'ipv4': sorted(allowed[4]), 'ipv6': sorted(allowed[6])}
    return {'interface': name, 'segments': segment, 'hosts': ordered[:MAX_HOSTS],
            'seconds': round(time.monotonic() - started, 1),
            'authorization': guard.verify(), 'discovery_scope': 'registered_assets_only'}
