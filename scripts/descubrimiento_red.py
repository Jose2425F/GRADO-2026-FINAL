"""Descubrimiento de equipos en un segmento local, como lo haría un auditor conectado a la red.

IPv4: barrido del prefijo de la interfaz con Nmap sin privilegios (sondas TCP SYN/connect).
IPv6: un /64 no se puede barrer; se envía un eco a todos los nodos (ff02::1) con origen
global y se registran las direcciones que responden. Ambas familias se agrupan por la MAC
que el núcleo aprende en la tabla de vecinos; sin MAC resuelta, la respuesta se descarta. No ejecuta pruebas de vulnerabilidad.
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
NAME = re.compile(r'[A-Za-z0-9_.:-]{1,32}')
REPLY = re.compile(r'from ([0-9A-Fa-f:]+)(?:%[^\s:]+)?:')


def _run(command, timeout):
    return subprocess.run(command, capture_output=True, timeout=timeout, check=False)


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


def discover(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('La interfaz de red no es válida.')
    segment = next((i for i in interfaces() if i['name'] == name), None)
    if not segment:
        raise ValueError('Esa interfaz no tiene un segmento privado que se pueda auditar.')
    if not shutil.which('nmap'):
        raise ValueError('Nmap no está disponible en el servidor.')
    started = time.monotonic()
    local = {str(a.ip) for a in _addresses(name)}
    found = {4: set(), 6: set()}
    for network in segment['ipv4']:
        command = ['nmap', '--unprivileged', '-n', '-sn', '-T4', '-PS' + ','.join(map(str, PROBES)),
                   '--max-retries', '1', '--host-timeout', '4s', '-e', name, '-oX', '-', network]
        try:
            result = _run(command, 60)
        except subprocess.TimeoutExpired:
            raise ValueError('El barrido IPv4 tardó demasiado.') from None
        try:
            root = ET.fromstring(result.stdout or b'<nmaprun/>')
        except ET.ParseError:
            raise ValueError('No se pudo leer el resultado del barrido IPv4.') from None
        for host in root.iter('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue
            for address in host.iter('address'):
                if address.get('addrtype') == 'ipv4' and address.get('addr') not in local:
                    found[4].add(address.get('addr'))
    for network in segment['ipv6']:
        source = next((str(a.ip) for a in _addresses(name) if a.version == 6 and str(a.network) == network), None)
        if not source:
            continue
        try:
            result = _run(['ping', '-6', '-c', '2', '-W', '1', '-I', source, f'ff02::1%{name}'], 8)
        except subprocess.TimeoutExpired:
            continue
        for match in REPLY.finditer(result.stdout.decode(errors='replace')):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if ip.version == 6 and not ip.is_link_local and str(ip) not in local and ip in ipaddress.ip_network(network):
                found[6].add(str(ip))
    neighbors = _neighbors(name)
    # Una respuesta a multidifusión no siempre deja la MAC en la tabla: un eco unicast
    # fuerza el descubrimiento de vecinos (o ARP) de cada dirección que respondió.
    pending = [a for version in (4, 6) for a in sorted(found[version]) if a not in neighbors][:MAX_HOSTS]
    if pending:
        probes = [subprocess.Popen(['ping', '-6' if ':' in a else '-4', '-c', '1', '-W', '1', '-I', name, a],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for a in pending]
        for probe in probes:
            try:
                probe.wait(timeout=3)
            except subprocess.TimeoutExpired:
                probe.kill()
        neighbors = _neighbors(name)
    hosts = {}
    for version in (4, 6):
        for address in found[version]:
            mac = neighbors.get(address)
            # En un segmento conectado directamente, un equipo real siempre resuelve su MAC
            # (ARP o descubrimiento de vecinos). Sin MAC, la respuesta se descarta como espuria.
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
    return {'interface': name, 'segments': segment, 'hosts': ordered[:MAX_HOSTS],
            'seconds': round(time.monotonic() - started, 1)}
