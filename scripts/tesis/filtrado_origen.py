"""Políticas nft acotadas al laboratorio y al namespace del auditor.

El emisor Ethernet se vincula al puerto del bridge, MAC e IP aprobados. En el
auditor los permisos de TCP/UDP se vinculan además al UID de cada herramienta.
El módulo administra sólo sus dos tablas; no vacía el cortafuegos del anfitrión.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import subprocess


class FirewallError(ValueError):
    pass


_NAME = re.compile(r'[a-zA-Z][a-zA-Z0-9_-]{0,30}')
_IFACE = re.compile(r'[A-Za-z0-9_.:-]{1,15}')
_MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
_PROTOCOLS = {'tcp', 'udp', 'icmpv6', 'ipv6_fragment'}


def _checked_name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise FirewallError('Identificador de política o nodo no válido.')
    return value


def _iface(value):
    if not isinstance(value, str) or not _IFACE.fullmatch(value):
        raise FirewallError('Interfaz de red no válida.')
    return value


def _addresses(values, version, *, multicast=False):
    if not isinstance(values, list) or len(values) > 64:
        raise FirewallError('Lista de direcciones no válida.')
    result=[]
    for value in values:
        try:
            address=ip_address(value)
        except (ValueError, TypeError):
            raise FirewallError('La política requiere direcciones IP literales.') from None
        if (address.version != version or address.is_unspecified or '%' in str(value)
                or address.is_multicast and not multicast):
            raise FirewallError('Dirección fuera de la familia o del alcance permitido.')
        canonical=str(address)
        if canonical not in result:
            result.append(canonical)
    return result


def validate_policy(value):
    allowed={'version','name','nodes','flows','audit_uid','audit_uids'}
    if not isinstance(value,dict) or set(value)-allowed or value.get('version')!=1 or type(value.get('version')) is not int:
        raise FirewallError('Esquema de política de filtrado no válido.')
    name=_checked_name(value.get('name'))
    uid=value.get('audit_uid',1000)
    uids=value.get('audit_uids',[uid])
    if (type(uid) is not int or not 1<=uid<2**32-1 or not isinstance(uids,list) or not uids
            or any(type(x) is not int or not 1<=x<2**32-1 for x in uids)):
        raise FirewallError('Los roles del auditor deben utilizar UIDs no privilegiados.')
    if not isinstance(value.get('nodes'),list) or not 2<=len(value['nodes'])<=128:
        raise FirewallError('La política requiere nodos explícitos.')
    nodes=[]
    for row in value['nodes']:
        keys={'name','interface','bridge','mac','ipv4','ipv6','role','audit_interface'}
        if not isinstance(row,dict) or set(row)-keys or not {'name','interface','mac','ipv4','ipv6'}<=set(row):
            raise FirewallError('Nodo de origen no válido.')
        mac=row['mac'].lower() if isinstance(row['mac'],str) else ''
        if not _MAC.fullmatch(mac) or int(mac.split(':')[0],16)&1:
            raise FirewallError('La MAC del nodo debe ser unicast explícita.')
        role=row.get('role','target')
        if role not in {'controller','target','sender','router'}:
            raise FirewallError('Rol de red no admitido.')
        node={'name':_checked_name(row['name']),'interface':_iface(row['interface']),
              'bridge':_iface(row.get('bridge','lab0')),'mac':mac,
              'ipv4':_addresses(row['ipv4'],4),'ipv6':_addresses(row['ipv6'],6),'role':role}
        if role=='controller':
            node['audit_interface']=_iface(row.get('audit_interface',row['interface']))
        if not node['ipv4'] and not node['ipv6']:
            raise FirewallError('Un nodo necesita al menos una dirección autorizada.')
        nodes.append(node)
    if len({n['name'] for n in nodes})!=len(nodes) or len({n['interface'] for n in nodes})!=len(nodes):
        raise FirewallError('Los nombres y puertos de origen no pueden duplicarse.')
    if not any(n['role']=='controller' for n in nodes):
        raise FirewallError('Falta el origen explícito del controlador.')
    byname={n['name']:n for n in nodes}
    if not isinstance(value.get('flows'),list) or len(value['flows'])>1024:
        raise FirewallError('Flujos de laboratorio no válidos.')
    flows=[]
    for row in value['flows']:
        keys={'source','destination','protocol','ports','types','sources','destinations','uids'}
        if not isinstance(row,dict) or set(row)-keys:
            raise FirewallError('Esquema de flujo no válido.')
        source,dest=row.get('source'),row.get('destination')
        if source not in byname or dest not in byname or source==dest:
            raise FirewallError('Los flujos requieren nodos de origen y destino distintos.')
        if byname[source]['bridge']!=byname[dest]['bridge']:
            raise FirewallError('El flujo no puede atravesar segmentos distintos.')
        protocol=row.get('protocol')
        if protocol not in _PROTOCOLS:
            raise FirewallError('Protocolo no permitido en la política.')
        ports=row.get('ports',[]);types=row.get('types',[])
        if (not isinstance(ports,list) or len(ports)>64 or any(type(p) is not int or not 1<=p<=65535 for p in ports)
                or protocol in {'tcp','udp'} and not ports or protocol not in {'tcp','udp'} and ports):
            raise FirewallError('Puertos incompatibles con el perfil de red.')
        if (not isinstance(types,list) or any(type(t) is not int or not 1<=t<=255 for t in types)
                or protocol=='icmpv6' and not types or protocol!='icmpv6' and types):
            raise FirewallError('Tipos ICMPv6 incompatibles con el perfil.')
        flow={'source':source,'destination':dest,'protocol':protocol,'ports':sorted(set(ports)),'types':sorted(set(types))}
        for key,node in [('sources',byname[source]),('destinations',byname[dest])]:
            if key not in row:
                flow[key]=node['ipv4']+node['ipv6']
            else:
                if not isinstance(row[key],list) or not row[key]:
                    raise FirewallError('Selección de IP de flujo vacía.')
                flow[key]=[]
                for address in row[key]:
                    try:ip=ip_address(address)
                    except (ValueError,TypeError):raise FirewallError('IP de flujo no válida.') from None
                    canonical=str(ip)
                    exception=(key=='destinations' and protocol=='icmpv6' and ip.version==6
                               and canonical in {'ff02::1','ff02::2'})
                    if not exception and canonical not in node['ipv4']+node['ipv6']:
                        raise FirewallError('La IP del flujo no pertenece al nodo aprobado.')
                    if canonical not in flow[key]:flow[key].append(canonical)
        selected=row.get('uids',uids)
        if not isinstance(selected,list) or not selected or any(x not in uids or type(x) is not int for x in selected):
            raise FirewallError('UID de herramienta no aprobado.')
        flow['uids']=sorted(set(selected))
        flows.append(flow)
    return {'version':1,'name':name,'audit_uid':uid,'audit_uids':sorted(set(uids)),'nodes':nodes,'flows':flows}


def _q(value):
    return json.dumps(value)


def _set(values):
    values=list(values)
    if not values:
        raise FirewallError('No se puede emitir un conjunto vacío.')
    return str(values[0]) if len(values)==1 else '{ '+', '.join(map(str,values))+' }'


def _ips(values, version):
    return [a for a in values if ip_address(a).version==version]


def _iphex(values):
    return _set('0x'+format(int(ip_address(a)),'032x') for a in values)


def _solicited(address):
    return str(ip_address(int(ip_address('ff02::1:ff00:0')) | (int(ip_address(address))&0xffffff)))


def _ndp_rules(source,destination,prefix):
    """NS consulta una IP conocida; NA sólo puede anunciar una IP propia."""
    if not source['ipv6'] or not destination['ipv6']:
        return []
    own,peer=source['ipv6'],destination['ipv6']
    src=_set(own);peer_targets=_iphex(peer);own_targets=_iphex(own)
    ns_dst=_set(sorted(set(peer+[_solicited(a) for a in peer])))
    dad_dst=_set(sorted({_solicited(a) for a in own}))
    na_dst=_set(sorted(set(peer+['ff02::1'])))
    return [
        f'{prefix} ether type ip6 ip6 saddr {src} ip6 daddr {ns_dst} meta l4proto ipv6-icmp icmpv6 type 135 @th,64,128 {peer_targets} counter accept comment "ndp_ns_known"',
        f'{prefix} ether type ip6 ip6 saddr :: ip6 daddr {dad_dst} meta l4proto ipv6-icmp icmpv6 type 135 @th,64,128 {own_targets} counter accept comment "ndp_dad_own"',
        f'{prefix} ether type ip6 ip6 saddr {src} ip6 daddr {na_dst} meta l4proto ipv6-icmp icmpv6 type 136 @th,64,128 {own_targets} counter accept comment "ndp_na_own"',
    ]


def compile_bridge(value):
    policy=validate_policy(value);name='centinela_'+policy['name'];nodes=policy['nodes'];byname={n['name']:n for n in nodes}
    managed=_set(_q(n['interface']) for n in nodes)
    bridges=_set(_q(b) for b in sorted({n['bridge'] for n in nodes}))
    pin=[]
    for node in nodes:
        port=_q(node['interface']);mac=node['mac']
        pin.append(f'iifname {port} ether saddr != {mac} counter drop comment "source_mac_denied"')
        if node['ipv4']:
            pin.append(f'iifname {port} ether type ip ip saddr {_set(node["ipv4"])} return')
            pin.append(f'iifname {port} ether type arp arp saddr ether {mac} arp saddr ip {_set(node["ipv4"])} return')
        if node['ipv6']:
            pin.append(f'iifname {port} ether type ip6 ip6 saddr {_set(node["ipv6"])} return')
            pin.append(f'iifname {port} ether type ip6 ip6 saddr :: meta l4proto ipv6-icmp icmpv6 type 135 @th,64,128 {_iphex(node["ipv6"])} return')
        pin.append(f'iifname {port} counter drop comment "source_ip_denied"')
    pin.append('counter drop comment "unregistered_port_denied"')
    flows=[];untracked=[]
    for source in nodes:
        for dest in nodes:
            if source==dest or source['bridge']!=dest['bridge']:continue
            prefix=f'iifname {_q(source["interface"])} oifname {_q(dest["interface"])}'
            if source['ipv4'] and dest['ipv4']:
                flows.append(f'{prefix} ether type arp arp saddr ip {_set(source["ipv4"])} arp daddr ip {_set(dest["ipv4"])} counter accept comment "arp_known"')
            flows.extend(_ndp_rules(source,dest,prefix))
    for flow in policy['flows']:
        source,dest=byname[flow['source']],byname[flow['destination']]
        prefix=f'iifname {_q(source["interface"])} oifname {_q(dest["interface"])}'
        reverse=f'iifname {_q(dest["interface"])} oifname {_q(source["interface"])}'
        for version,family in [(4,'ip'),(6,'ip6')]:
            src,dst=_ips(flow['sources'],version),_ips(flow['destinations'],version)
            if not src or not dst:continue
            match=f'ether type {family} {family} saddr {_set(src)} {family} daddr {_set(dst)}'
            rmatch=f'ether type {family} {family} saddr {_set(dst)} {family} daddr {_set(src)}'
            proto=flow['protocol']
            if proto in {'tcp','udp'}:
                flows.append(f'{prefix} {match} {proto} dport {_set(flow["ports"])} ct state {{ new, established }} counter accept comment "flow_{proto}_allowed"')
                flows.append(f'{reverse} {rmatch} {proto} sport {_set(flow["ports"])} ct state {{ established, related }} counter accept comment "flow_reply_allowed"')
            elif version==6 and proto=='icmpv6':
                flows.append(f'{prefix} {match} meta l4proto ipv6-icmp icmpv6 type {_set(flow["types"])} counter accept comment "profile_icmpv6_allowed"')
            elif version==6 and proto=='ipv6_fragment':
                flows.append(f'{prefix} {match} ip6 nexthdr 44 frag nexthdr {{ 17, 60 }} counter accept comment "profile_frag_allowed"')
                # El filtro no debe reagrupar los fragmentos que evalúa el receptor.
                untracked.append(f'iifname {_q(source["interface"])} {match} ip6 nexthdr 44 frag nexthdr {{ 17, 60 }} counter notrack comment "profile_frag_notrack"')
    flows.append('counter drop comment "origin_flow_denied"')
    return (f'table bridge {name} {{\n'
            ' chain source_guard {\n  '+'\n  '.join(pin)+'\n }\n'
            f' chain pin_ingress {{ type filter hook prerouting priority -300; policy accept; iifname {managed} jump source_guard; meta ibrname {bridges} jump source_guard;\n  '+'\n  '.join(untracked)+'\n }\n'
            ' chain allowed_flows {\n  '+'\n  '.join(flows)+'\n }\n'
            f' chain forward_guard {{ type filter hook forward priority -20; policy accept; iifname {managed} jump allowed_flows; oifname {managed} jump allowed_flows; }}\n'
            f' chain input_guard {{ type filter hook input priority -20; policy accept; iifname {managed} counter drop comment "host_input_denied"; }}\n'
            f' chain output_guard {{ type filter hook output priority -20; policy accept; oifname {managed} counter drop comment "host_output_denied"; }}\n'
            '}\n')


def compile_auditor(value):
    policy=validate_policy(value);name='centinela_'+policy['name'];byname={n['name']:n for n in policy['nodes']}
    out=['oifname "lo" counter accept comment "loopback_allowed"']
    incoming=['iifname "lo" counter accept comment "loopback_allowed"']
    for source in policy['nodes']:
        if source['role']!='controller':continue
        iface=_q(source['audit_interface'])
        for peer in policy['nodes']:
            if peer['bridge']!=source['bridge'] or peer==source:continue
            for rule in _ndp_rules(source,peer,f'oifname {iface}'):
                out.append(rule.replace('ether type ip6 ','').replace('ether type ip ',''))
            for rule in _ndp_rules(peer,source,f'iifname {iface}'):
                incoming.append(rule.replace('ether type ip6 ','').replace('ether type ip ',''))
    for flow in policy['flows']:
        source,dest=byname[flow['source']],byname[flow['destination']]
        if source['role']!='controller':continue
        iface=_q(source['audit_interface']);uids=_set(flow['uids']);proto=flow['protocol']
        for version,family in [(4,'ip'),(6,'ip6')]:
            src,dst=_ips(flow['sources'],version),_ips(flow['destinations'],version)
            if not src or not dst:continue
            match=f'{family} saddr {_set(src)} {family} daddr {_set(dst)}'
            rmatch=f'{family} saddr {_set(dst)} {family} daddr {_set(src)}'
            if proto in {'tcp','udp'}:
                out.append(f'oifname {iface} meta skuid {uids} {match} {proto} dport {_set(flow["ports"])} counter accept comment "uid_flow_allowed"')
                incoming.append(f'iifname {iface} {rmatch} {proto} sport {_set(flow["ports"])} ct state {{ established, related }} counter accept comment "reply_allowed"')
            elif version==6 and proto=='icmpv6':
                out.append(f'oifname {iface} meta skuid {uids} {match} meta l4proto ipv6-icmp icmpv6 type {_set(flow["types"])} counter accept comment "uid_icmpv6_allowed"')
    out.append('counter drop comment "auditor_output_denied"')
    incoming.append('counter drop comment "auditor_input_denied"')
    return (f'table inet {name} {{\n'
            ' chain input_guard { type filter hook input priority -20; policy drop;\n  '+'\n  '.join(incoming)+'\n }\n'
            ' chain output_guard { type filter hook output priority -20; policy drop;\n  '+'\n  '.join(out)+'\n }\n'
            ' chain forward_guard { type filter hook forward priority -20; policy drop; counter drop comment "routing_denied"; }\n'
            '}\n')


def run_nft(script, *, json_output=False):
    """Ejecuta libnftables en el namespace actual del proceso llamador."""
    if not isinstance(script,str) or len(script.encode())>4_000_000:
        raise FirewallError('Lote nft fuera del tamaño permitido.')
    library=ctypes.CDLL('libnftables.so.1')
    library.nft_ctx_new.argtypes=[ctypes.c_int];library.nft_ctx_new.restype=ctypes.c_void_p
    library.nft_ctx_free.argtypes=[ctypes.c_void_p]
    library.nft_ctx_output_set_flags.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    library.nft_ctx_input_set_flags.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    for name in ['nft_ctx_buffer_output','nft_ctx_buffer_error']:
        getattr(library,name).argtypes=[ctypes.c_void_p]
    for name in ['nft_ctx_get_output_buffer','nft_ctx_get_error_buffer']:
        getattr(library,name).argtypes=[ctypes.c_void_p];getattr(library,name).restype=ctypes.c_char_p
    library.nft_run_cmd_from_buffer.argtypes=[ctypes.c_void_p,ctypes.c_char_p];library.nft_run_cmd_from_buffer.restype=ctypes.c_int
    ctx=library.nft_ctx_new(0)
    if not ctx:raise FirewallError('No se pudo crear el contexto nft.')
    try:
        library.nft_ctx_buffer_output(ctx);library.nft_ctx_buffer_error(ctx)
        library.nft_ctx_input_set_flags(ctx,1)  # NFT_CTX_INPUT_NO_DNS
        if json_output:library.nft_ctx_output_set_flags(ctx,1<<4)  # NFT_CTX_OUTPUT_JSON
        result=library.nft_run_cmd_from_buffer(ctx,script.encode())
        output=(library.nft_ctx_get_output_buffer(ctx) or b'').decode(errors='replace')
        error=(library.nft_ctx_get_error_buffer(ctx) or b'').decode(errors='replace')
        if result:
            raise FirewallError('nft rechazó la política: '+error[:6000])
        return output
    finally:
        library.nft_ctx_free(ctx)


def apply_policy(value,kind):
    policy=validate_policy(value)
    if kind not in {'bridge','auditor'}:raise FirewallError('Familia de política no admitida.')
    family='bridge' if kind=='bridge' else 'inet';name='centinela_'+policy['name']
    tables=run_nft('list tables\n')
    old=f'table {family} {name}' in tables.splitlines()
    rules=compile_bridge(policy) if kind=='bridge' else compile_auditor(policy)
    script=(f'delete table {family} {name}\n' if old else '')+rules
    run_nft(script)
    current=run_nft(f'list table {family} {name}\n')
    return {'family':family,'table':name,'policy_sha256':hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest(),
            'rules_sha256':hashlib.sha256(rules.encode()).hexdigest(),'ruleset':current,
            'namespace':os.readlink('/proc/self/ns/net'),'replaced':old}


def remove_policy(value,kind):
    policy=validate_policy(value);family={'bridge':'bridge','auditor':'inet'}.get(kind)
    if family is None:raise FirewallError('Familia de política no admitida.')
    name='centinela_'+policy['name'];tables=run_nft('list tables\n')
    if f'table {family} {name}' in tables.splitlines():
        run_nft(f'delete table {family} {name}\n')
    return {'family':family,'table':name,'removed':True,'namespace':os.readlink('/proc/self/ns/net')}


def endpoints_from_topology(topology):
    """Relaciona inspect y link_index con el puerto real del bridge del operador."""
    if (not isinstance(topology,dict) or topology.get('schema') not in
            {'centinela-isolated-topology/1','centinela-isolated-topology/2'}):
        raise FirewallError('La topología debe proceder de la inspección aislada del operador.')
    links={row['ifindex']:row for row in topology['namespace_links']}
    networks={row['name']:row for row in topology['networks']}
    result={}
    for container in topology['containers']:
        name=container['name'].removeprefix('/')
        attachments=container['networks']
        if len(attachments)!=1 or not container['running']:
            raise FirewallError('Cada activo debe estar encendido en una sola red de laboratorio.')
        net,attachment=next(iter(attachments.items()))
        network=networks[net]
        bridge=network['options'].get('com.docker.network.bridge.name')
        inside=next(row for row in container['links'] if row['ifname']=='eth0')
        peer=links.get(inside.get('link_index'))
        if not peer or peer.get('master')!=bridge:
            raise FirewallError('El veth del activo no pertenece al bridge inspeccionado.')
        if attachment['MacAddress'].lower()!=inside['address'].lower():
            raise FirewallError('La MAC de Docker no coincide con la interfaz efectiva.')
        ipv4=[];ipv6=[]
        for address in next(row for row in container['addresses'] if row['ifname']=='eth0')['addr_info']:
            ip=ip_address(address['local'])
            if ip.is_unspecified or ip.is_multicast or '%' in str(ip):continue
            (ipv4 if ip.version==4 else ipv6).append(str(ip))
        result[name]={'interface':peer['ifname'],'bridge':bridge,'mac':inside['address'].lower(),
                      'ipv4':sorted(set(ipv4)),'ipv6':sorted(set(ipv6)),
                      'configured_ipv4':attachment.get('IPAddress',''),
                      'configured_ipv6':attachment.get('GlobalIPv6Address',''),
                      'container_id':container['id'],'container_image':container['image']}
    return result


def _eui64(mac):
    parts=bytes.fromhex(mac.replace(':',''))
    return int.from_bytes(bytes([parts[0]^2])+parts[1:3]+b'\xff\xfe'+parts[3:],'big')


def policy_for_bank(bank,endpoints,controllers,*,name='bank113',role_uids=None):
    """Catálogo efectivo: sirve al integrado y a las cuatro variantes cerradas.

    endpoints es un mapa por nombre de contenedor de la inspección del operador.
    controllers relaciona cada bridge con su veth, MAC, IP y audit_interface.
    No descubre ni incorpora activos por su sola pertenencia a una red privada.
    """
    uids={'controller':1000,'nmap':65532,'hydra':65533}
    if role_uids is not None:
        if not isinstance(role_uids,dict) or set(role_uids)!=set(uids):
            raise FirewallError('Los tres roles de auditoría requieren UIDs explícitos.')
        uids=dict(role_uids)
    expected={member for _,(_,_,members) in bank.NETWORKS.items() for member in members}
    if not expected<=set(endpoints):raise FirewallError('Faltan endpoints del catálogo en la topología efectiva.')
    nodes=[];node_by_container={};controller_by_bridge={}
    for _,(bridge,_,members) in bank.NETWORKS.items():
        if bridge not in controllers:raise FirewallError('Falta la interfaz dedicada del auditor para un segmento.')
        ctl=controllers[bridge]
        node={'name':'ctl_'+bridge,'role':'controller','bridge':bridge,
              **{key:ctl[key] for key in ['interface','mac','ipv4','ipv6','audit_interface']}}
        nodes.append(node);controller_by_bridge[bridge]=node['name']
        for container in sorted(members):
            endpoint=endpoints[container]
            if endpoint['bridge']!=bridge:raise FirewallError('El activo se conectó a otro segmento.')
            role='sender' if container.endswith('-sender') else 'router' if container.endswith('-router') else 'target'
            node={'name':container,'role':role,'bridge':bridge,
                  **{key:endpoint[key] for key in ['interface','mac','ipv4','ipv6']}}
            node['ipv4']=list(node['ipv4']);node['ipv6']=list(node['ipv6'])
            # La observación no amplía la autorización. Sólo se añaden la
            # link-local derivada y las direcciones SLAAC/DAD del catálogo.
            approved4={endpoint.get('configured_ipv4')} - {None,''}
            approved6={endpoint.get('configured_ipv6')} - {None,''}
            known=next((x for x in [*bank.CREDENTIALS.values(),*bank.APPS.values(),*bank.RECEIVERS.values()]
                        if x['container']==container),None)
            if known is not None:
                for field in ['address','ipv4','ipv6','dad']:
                    address=known.get(field)
                    if address:
                        (approved4 if ip_address(address).version==4 else approved6).add(str(ip_address(address)))
            # Los mapas de endpoint suministrados directamente por el operador
            # pueden omitir los campos Docker; siguen siendo política explícita.
            if 'configured_ipv4' not in endpoint:approved4.update(node['ipv4'])
            if 'configured_ipv6' not in endpoint:approved6.update(node['ipv6'])
            if node['ipv6']:
                ll=str(ip_address(int(ip_address('fe80::'))|_eui64(node['mac'])))
                approved6.add(ll)
            if role=='sender' or any(x['container']==container for x in bank.RECEIVERS.values()):
                approved6.add(str(ip_address(int(ip_network(bank.SLAAC_PREFIX).network_address)|_eui64(node['mac']))))
            if not set(node['ipv4'])<=approved4 or not set(node['ipv6'])<=approved6:
                raise FirewallError('El activo tiene direcciones efectivas fuera del catálogo aprobado.')
            node['ipv4']=sorted(approved4);node['ipv6']=sorted(approved6)
            nodes.append(node);node_by_container[container]=node
    flows=[]
    def tcp(asset,ports,roles):
        node=node_by_container[asset['container']]
        flows.append({'source':controller_by_bridge[node['bridge']],'destination':node['name'],
                      'protocol':'tcp','ports':sorted(set(ports)),'uids':[uids[r] for r in roles]})
    for asset in bank.CREDENTIALS.values():
        ports=[port for _,port in asset['services']]
        tcp(asset,ports,['nmap']);tcp(asset,ports,['hydra'])
        health=[port for service,port in asset['services'] if service=='http-get']
        if health:tcp(asset,health,['controller'])
    for asset in bank.APPS.values():tcp(asset,[8088],['controller'])
    sender=next(node for node in nodes if node['role']=='sender')
    router=next(node for node in nodes if node['role']=='router')
    sender_ll=[a for a in sender['ipv6'] if ip_address(a).is_link_local]
    router_ll=[a for a in router['ipv6'] if ip_address(a).is_link_local]
    if not sender_ll or not router_ll:raise FirewallError('Los roles de protocolo requieren link-local efectivo.')
    # La dirección SLAAC se calcula a partir del prefijo y MAC aprobados. Se
    # conserva durante el cambio de veth del receptor sin abrir todo el prefijo.
    for asset in bank.RECEIVERS.values():
        node=node_by_container[asset['container']]
        for address in [asset['dad'],str(ip_address(int(ip_network(bank.SLAAC_PREFIX).network_address)|_eui64(node['mac'])))]:
            if address not in node['ipv6']:node['ipv6'].append(address)
        tcp(asset,[8000],['controller'])
        flows.extend([
            {'source':sender['name'],'destination':node['name'],'protocol':'udp','ports':[53000],
             'sources':[bank.SENDER],'destinations':[asset['address']]},
            {'source':sender['name'],'destination':node['name'],'protocol':'ipv6_fragment',
             'sources':[bank.SENDER],'destinations':[asset['address']]},
            {'source':sender['name'],'destination':node['name'],'protocol':'icmpv6','types':[134,136],
             'sources':sender_ll+[bank.SENDER],'destinations':[asset['address'],'ff02::1']},
        ])
    # Radvd es el único emisor de RA normal. El sender tiene su flujo explícito
    # de prueba hacia receptores; nunca se permite su RA al controlador.
    for node in nodes:
        if node['bridge']==router['bridge'] and node['name']!=router['name'] and node['role']!='controller':
            flows.extend([
                {'source':router['name'],'destination':node['name'],'protocol':'icmpv6','types':[134],
                 'sources':router_ll,'destinations':node['ipv6']+['ff02::1']},
                {'source':node['name'],'destination':router['name'],'protocol':'icmpv6','types':[133],
                 'destinations':router['ipv6']+['ff02::2']},
            ])
    return validate_policy({'version':1,'name':name,'audit_uid':uids['controller'],
                            'audit_uids':list(uids.values()),'nodes':nodes,'flows':flows})


def in_namespace(namespace,script):
    """CLI explícita: el operador elige un namespace ya preparado, no un shell."""
    if not isinstance(namespace,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}',namespace):
        raise FirewallError('Nombre de namespace no válido.')
    module=Path(__file__).resolve()
    command=['ip','netns','exec',namespace,os.sys.executable,str(module),'raw']
    result=subprocess.run(command,input=script,text=True,capture_output=True,timeout=30)
    if result.returncode:raise FirewallError(result.stderr[:6000] or 'No se pudo aplicar nft en el namespace.')
    return result.stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['compile','apply','remove','read','raw'])
    parser.add_argument('--policy',type=Path)
    parser.add_argument('--kind',choices=['bridge','auditor'],default='bridge')
    args=parser.parse_args()
    if args.action=='raw':
        print(run_nft(os.sys.stdin.read()),end='');return
    if not args.policy:parser.error('La operación requiere una política.')
    policy=json.loads(args.policy.read_text())
    if args.action=='compile':print(compile_bridge(policy) if args.kind=='bridge' else compile_auditor(policy),end='')
    elif args.action=='apply':print(json.dumps(apply_policy(policy,args.kind),ensure_ascii=False))
    elif args.action=='remove':print(json.dumps(remove_policy(policy,args.kind),ensure_ascii=False))
    else:
        value=validate_policy(policy);family='bridge' if args.kind=='bridge' else 'inet'
        print(run_nft(f'list table {family} centinela_{value["name"]}\n'),end='')


if __name__=='__main__':
    main()
