#!/usr/bin/env python3
"""Dependency-free MAVLink wire fixtures replayed through the actual Zeek script."""
import json
import struct
from test_detector import checksum, run


def x25(data):
    crc=0xffff
    for b in data:
        tmp=b^(crc&0xff)
        tmp=(tmp^(tmp<<4))&0xff
        crc=((crc>>8)^(tmp<<8)^(tmp<<3)^(tmp>>4))&0xffff
    return crc


def message(seq, msgid=0, payload=None, extra=50, version=2, signed=False,
            sysid=1, compid=1, flags=0):
    if payload is None:payload=struct.pack('<IBBBBB',4,2,3,217,4,3)
    if version==2:
        payload=payload.rstrip(b'\0') or b'\0'
        hdr=bytes([len(payload),flags|(1 if signed else 0),0,seq,sysid,compid])+msgid.to_bytes(3,'little')
        magic=b'\xfd'
    else:
        hdr=bytes([len(payload),seq,sysid,compid,msgid]);magic=b'\xfe'
    data=hdr+payload
    packet=magic+data+struct.pack('<H',x25(data+bytes([extra])))
    return packet+(b'\x01'+b'\0'*12 if signed else b'')


def pcap(payloads, sport=40000, dport=14550, reverse=False, ipv6=False, times=None):
    import ipaddress
    frames=[]
    for n,p in enumerate(payloads):
        src,dst=('192.0.2.1','192.0.2.2') if not ipv6 else ('2001:db8::1','2001:db8::2')
        sp,dp=sport,dport
        if reverse and n%2:src,dst=dst,src;sp,dp=dp,sp
        a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
        udp=struct.pack('!HHHH',sp,dp,8+len(p),0)+p
        pseudo=a+b+(struct.pack('!I3xB',len(udp),17) if ipv6 else struct.pack('!BBH',0,17,len(udp)))
        udp=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
        if ipv6:
            ip=struct.pack('!IHBB16s16s',6<<28,len(udp),17,64,a,b);etype=b'\x86\xdd'
        else:
            ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(udp),n,0,64,17,0,a,b)
            ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:];etype=b'\x08\x00'
        frames.append(bytes.fromhex('00112233445566778899aabb')+etype+ip+udp)
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for i,f in enumerate(frames):
        t = times[i] if times is not None else i * .001
        data += struct.pack('<IIII',1700000000+int(t),round((t-int(t))*1000000),len(f),len(f))+f
    return data


def detected(payloads,settings='',**kw):
    rows,conns=run(pcap(payloads,**kw),settings)
    assert len(rows)==1,(rows,conns)
    r=rows[0]
    assert r['protocol']=='mavlink' and r['likely_manufacturer']=='unknown',r
    assert any(c.get('drone_protocol')=='mavlink' and c['uid']==r['uid'] for c in conns),conns
    return r


def main():
    good=[message(i) for i in range(3)]
    cases=0
    for version in (1,2):
        r=detected([message(i,version=version) for i in range(3)])
        assert r['mavlink_versions']==[version] and r['orig_messages']+r['resp_messages']==3,r
        assert r['autopilot_software']==['ArduPilot'] and r['vehicle_types']==['quadrotor'],r
        cases+=1
    r=detected(good,reverse=True);assert r['orig_messages']+r['resp_messages']==3,r;cases+=1
    r=detected(good,sport=14550,dport=40000);cases+=1
    r=detected(good,ipv6=True);cases+=1
    r=detected([b''.join(good)]);assert r['orig_messages']==3,r;cases+=1
    r=detected([message(i,signed=True) for i in range(3)])
    assert r['signed_messages']==3 and r['signature_validation']=='not-performed',r;cases+=1
    r=detected([message(0,version=1),message(1),message(2)])
    assert set(r['mavlink_versions'])=={1,2},r;cases+=1
    # Signed and unsigned packets are identified; no signature authentication claimed.
    negatives=[
        [b'HTTP/1.1 200 OK\r\n']*4,
        [good[0]]*5,
        good[:2],
        [p[:-1]+bytes([p[-1]^1]) for p in good],
        [message(i,extra=49) for i in range(3)],
        [message(i,flags=2) for i in range(3)],
        [message(i,sysid=0) for i in range(3)],
        [message(i,msgid=99999,extra=1,payload=b'abc') for i in range(3)],
        [good[0][:8],good[0][8:]]*3,
        [bytes.fromhex('fed4183fd9ce173f508d173ffed4183f')+struct.pack('<12f',*([-1.0]*12))]*4,
        [p[:-3] for p in good],
        # Valid non-heartbeat messages alone are not enough to classify a link.
        [message(i,msgid=11,extra=89,payload=struct.pack('<IBB',6,1,1)) for i in range(3)],
    ]
    for packets in negatives:
        rows,conns=run(pcap(packets))
        assert not rows and not any('drone_protocol' in c for c in conns),rows
        cases+=1
    rows,_=run(pcap(good,dport=12345));assert not rows;cases+=1
    detected(good,'redef DroneMAVLink::ports += { 12345/udp };\n',dport=12345);cases+=1
    detected([message(i,compid=0) for i in range(3)]);cases+=1
    r=detected([message(i,payload=struct.pack('<IBBBBB',0,10,3,0,3,3)) for i in range(3)])
    assert r['vehicle_types']==['ground-rover'],r;cases+=1
    detected([b'noise'+b''.join(good)]);cases+=1
    # Correctly restore truncated extension fields, and retain source-component-zero commands.
    mcount=message(3,44,struct.pack('<HBBB',60,1,0,0),221,compid=0)
    cmd=message(4,76,struct.pack('<7fHBBB',*([0.0]*7),300,1,0,0),152,compid=0)
    ack=message(5,77,struct.pack('<HB',300,0),143)
    mode=message(6,11,struct.pack('<IBB',6,1,1),89,compid=0)
    param=message(7,23,struct.pack('<fBB16sB',275.0,1,0,b'RTL_ALT',6),168,compid=0)
    r=detected(good+[mcount,cmd,ack,mode,param])
    assert r['mission_item_counts']==[60] and r['commands']==[300] and r['requested_modes']==[6],r
    assert r['parameter_ids']==['RTL_ALT'] and r['command_acks']==['command=300;result=0'],r
    assert 'value_bits=0x43898000' in r['parameter_updates'][0] and r['zero_component_messages']==4,r
    cases+=1
    r=detected(good+[message(4)],f'redef DroneMAVLink::max_inspected_bytes = {sum(map(len,good))};\n')
    assert r['inspection_limited'] and r['orig_messages']==3,r;cases+=1
    r=detected(good+[message(4,payload=struct.pack('<IBBBBB',0,6,8,0,0,3))],
               'redef DroneMAVLink::max_metadata_values = 1;\n')
    assert r['metadata_limited'] and len(r['vehicle_types'])==1,r;cases+=1
    print(f'PASS: {cases} MAVLink replay scenarios (valid checksums; no -C).')

if __name__=='__main__':main()
