"""Compara PCAP del emisor con salida al veth receptor y observador independiente."""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import re
import shutil


def export_public(capture_directory,output_directory):
    """Copia identificada: elimina TCP y errores ICMP que puedan citar TCP."""
    from scapy.all import PcapReader,PcapWriter,IPv6,IPv6ExtHdrFragment,UDP
    capture=Path(capture_directory);out=Path(output_directory)
    if not (capture/'summary.json').exists():raise ValueError('La captura debe estar detenida antes de exportar.')
    out.mkdir(parents=True,exist_ok=False)
    senders=set();receivers=set()
    timeline=capture/'interface-timeline.jsonl'
    for line in timeline.read_text().splitlines():
        for role in json.loads(line)['roles']:
            if role['role']=='sender':senders.update(role['ipv6'])
            if '-receiver-' in role['name']:receivers.update(role['ipv6'])
    raw=capture/'lab-ipv6-any.pcap';target=out/'protocolos-ipv6-copia-publica.pcap'
    counts=Counter();total=0
    with PcapReader(str(raw)) as packets,PcapWriter(str(target),linktype=276,sync=True) as writer:
        for packet in packets:
            total+=1
            if IPv6 not in packet:continue
            ip=packet[IPv6];kind=None
            # Sólo ND exterior. Nunca ICMP de error con un TCP citado.
            if ip.nh==58 and bytes(ip.payload) and bytes(ip.payload)[0] in {133,134,135,136}:kind='neighbor_discovery'
            if ip.src in senders and ip.dst in receivers:
                if ip.nh==44 and IPv6ExtHdrFragment in packet and packet[IPv6ExtHdrFragment].nh in {17,60}:kind='approved_sender_fragment'
                elif ip.nh==17 and UDP in packet and packet[UDP].dport==53000:kind='approved_sender_udp_control'
            if kind:writer.write(packet);counts[kind]+=1
    shutil.copyfile(timeline,out/timeline.name)
    report={'schema':'centinela-public-capture-copy/1','identified_copy':True,'original_preserved_privately':True,
        'raw_capture_sha256':hashlib.sha256(raw.read_bytes()).hexdigest(),
        'public_copy_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
        'interface_timeline_sha256':hashlib.sha256(timeline.read_bytes()).hexdigest(),
        'original_packets':total,'retained_packets':sum(counts.values()),'retained_packet_kinds':dict(counts),
        'filter':'Outer ICMPv6 ND types 133-136; approved sender->receiver IPv6 fragment nh17/60; UDP53000 controls. TCP and ICMP errors excluded.',
        'scope':'La copia conserva los paquetes de protocolo necesarios para reproducir el cotejo; no reemplaza la captura original.'}
    (out/'public-copy-manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


def check(run_directory,capture_directory,output):
    from scapy.all import PcapReader,IPv6,IPv6ExtHdrFragment
    run=Path(run_directory);capture=Path(capture_directory)
    index_roles=defaultdict(dict)
    for line in (capture/'interface-timeline.jsonl').read_text().splitlines():
        sample=json.loads(line);links={row['ifname']:row['ifindex'] for row in sample['links']}
        for role in sample['roles']:
            if role['interface'] in links:
                index_roles[links[role['interface']]][(role['bank'],role['name'])]=role
    ambiguous={str(index):list(roles) for index,roles in index_roles.items() if len(roles)>1}
    captured=defaultdict(list);first_fragment=None
    pcap=capture/'lab-ipv6-any.pcap'
    if not pcap.exists():pcap=capture/'protocolos-ipv6-copia-publica.pcap'
    frozen=(capture/'summary.json').exists() or (capture/'public-copy-manifest.json').exists()
    with PcapReader(str(pcap)) as packets:
        for packet in packets:
            if IPv6 not in packet:continue
            if IPv6ExtHdrFragment in packet and first_fragment is None:first_fragment=float(packet.time)
            if packet.fields.get('pkttype')!=4:continue
            index=packet.fields.get('ifindex');roles=index_roles.get(index,{})
            if len(roles)!=1:continue
            role=next(iter(roles.values()))
            digest=hashlib.sha256(bytes(packet[IPv6])).hexdigest()
            captured[(role['name'],digest)].append({'time':float(packet.time),'ifindex':index,'interface':role['interface']})
    cases=[]
    for path in sorted((run/'evidence').glob('*_state.json')):
        state=json.loads(path.read_text());profile=state.get('profile')
        if profile not in {'ipv6_overlap_v2','ipv6_overlap_middle_v2','ipv6_atomic_v2','ipv6_incomplete_chain_v2'}:continue
        target=state['target'];matches={role['name'] for roles in index_roles.values() for role in roles.values()
                                       if target in role['ipv6'] and '-receiver-' in role['name']}
        if len(matches)!=1:raise ValueError('No se pudo vincular el destino con un único veth receptor.')
        receiver=matches.pop()
        for key,state_key in [('control_probe','control'),('probe','after')]:
            proof=state[key];reference=proof['pcap_ref']
            if not isinstance(reference,str) or not re.fullmatch(r'evidence/[A-Za-z0-9_.-]+\.pcap',reference):
                raise ValueError('Referencia PCAP fuera del directorio de evidencia.')
            source=run/reference;raw=source.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=proof['pcap_sha256']:raise ValueError('SHA de PCAP emisor no coincide.')
            geometry=[];expected_observer=[];all_seen=True
            with PcapReader(str(source)) as packets:
                for packet in packets:
                    ipv6=packet[IPv6];digest=hashlib.sha256(bytes(ipv6)).hexdigest();observations=captured.get((receiver,digest),[])
                    item={'source':ipv6.src,'destination':ipv6.dst,'ipv6_length':len(bytes(ipv6)),
                          'ipv6_sha256':digest,'egress_observations':observations}
                    if IPv6ExtHdrFragment in packet:
                        fragment=packet[IPv6ExtHdrFragment]
                        item.update(fragment_id=fragment.id,offset=fragment.offset,more=fragment.m,
                                    next_header=fragment.nh,fragment_payload_length=len(bytes(fragment.payload)))
                        expected_observer.append((fragment.id,fragment.offset,fragment.m))
                    geometry.append(item);all_seen=all_seen and bool(observations)
            # Un ICMP de error puede citar el primer fragmento en sentido
            # inverso. El observador usa búsqueda de capas y también lo lista;
            # la geometría recibida debe referirse al sentido emisor->receptor.
            same_id=[f for f in state[state_key]['observer']['fragments'] if f['id']==proof['fragment_id']]
            direct=[f for f in same_id if f['source']==geometry[0]['source'] and f['destination']==target]
            observed=Counter((f['id'],f['offset'],f['more']) for f in direct)
            observer_ok=(Counter(expected_observer)==observed) if expected_observer else True
            cases.append({'state_file':path.name,'phase':key,'profile':proof['profile'],'receiver':receiver,
                'sender_pcap_sha256':proof['pcap_sha256'],'packet_count':proof['packet_count'],
                'geometry':geometry,'all_ipv6_bytes_present_at_receiver_egress':all_seen,
                'observer_fragment_id_offset_more_exact':observer_ok,
                'observer_same_id_other_direction_not_counted':[f for f in same_id if f not in direct],
                'observed_fragment_geometry':[{'id':i,'offset':o,'more':m,'count':n} for (i,o,m),n in observed.items()],
                'passed':all_seen and observer_ok and len(geometry)==proof['packet_count']})
    report={'schema':'centinela-fragment-geometry-verification/1','scope':'PCAP emisor cotejado byte a byte con captura SLL2 PACKET_OUTGOING del veth receptor; se comprueba además id/offset/more del observador.',
        'run_directory_name':run.name,'capture_directory_name':capture.name,'capture_first_fragment_time':first_fragment,
        'ambiguous_interface_indices':ambiguous,'cases':cases,'case_count':len(cases),
        'source_capture_still_running':not frozen,
        'capture_filename':pcap.name,'capture_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest() if frozen else None,
        'passed':len(cases)==16 and not ambiguous and all(case['passed'] for case in cases),
        'limit':'Los PCAP del emisor por sí solos no acreditan lo recibido; los bytes de salida al veth receptor y el observador son evidencias separadas.'}
    Path(output).write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-directory',required=True,type=Path)
    parser.add_argument('--capture-directory',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();report=check(args.run_directory,args.capture_directory,args.output)
    print(json.dumps({'passed':report['passed'],'cases':report['case_count']}))
    if not report['passed']:raise SystemExit(1)
