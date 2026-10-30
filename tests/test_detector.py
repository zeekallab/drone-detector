#!/usr/bin/env python3
"""Offline TCP replay tests. Optional DJI_CAPTURE checks the supplied real capture."""
import gzip
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from functools import reduce

ROOT = Path(__file__).resolve().parents[1]
ZEEK = os.environ.get('ZEEK', 'zeek')


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return ~total & 65535


def frame(seq, response=False, command=4):
    b = b'\x55\xbb\x09' + bytes([0x48 if response else 8]) + struct.pack('<H',seq) + bytes([command, 0 if response else 1])
    return b + bytes([reduce(int.__xor__,b)])


def capture(chunks, port=2001):
    packets=[]
    seq=[100,900]
    def pkt(direction, payload=b'', flags=24):
        src,dst=('192.0.2.1','192.0.2.2') if direction==0 else ('192.0.2.2','192.0.2.1')
        sp,dp=(40000,port) if direction==0 else (port,40000)
        a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
        tcp=struct.pack('!HHIIBBHHH',sp,dp,seq[direction],seq[1-direction] if flags&16 else 0,80,flags,65535,0,0)+payload
        pseudo=a+b+struct.pack('!BBH',0,6,len(tcp))
        tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
        ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),len(packets),0,64,6,0,a,b)
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        packets.append(bytes.fromhex('00112233445566778899aabb0800')+ip+tcp)
        seq[direction]+=len(payload)+(1 if flags&3 else 0)
    pkt(0,flags=2);pkt(1,flags=18);pkt(0,flags=16)
    for direction,data in chunks:
        if data is None:
            seq[direction] += 5
            continue
        pkt(direction,data);pkt(1-direction,flags=16)
    pkt(0,flags=17);pkt(1,flags=17);pkt(0,flags=16)
    out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for i,p in enumerate(packets):out+=struct.pack('<IIII',1700000000,i*1000,len(p),len(p))+p
    return out


def run(data, settings=''):
    with tempfile.TemporaryDirectory(prefix='dji-detector-') as tmp:
        tmp=Path(tmp)
        (tmp/'input.pcap').write_bytes(data)
        (tmp/'package').symlink_to(ROOT/'scripts',target_is_directory=True)
        (tmp/'settings.zeek').write_text('@load ./package\nredef LogAscii::use_json = T;\n'+settings)
        r=subprocess.run([ZEEK,'-r','input.pcap','settings.zeek'],cwd=tmp,capture_output=True,text=True)
        assert r.returncode==0,r.stdout+r.stderr
        def read(name):
            p=tmp/(name+'.log')
            return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
        assert not read('reporter'),read('reporter')
        return read('drone'),read('conn')


def main():
    assert shutil.which(ZEEK),'Zeek executable required (or set ZEEK).'
    request=b''.join(frame(i) for i in range(3))
    response=b''.join(frame(i,True) for i in range(3))
    rows,conn=run(capture([(0,request),(1,response)]))
    assert len(rows)==1 and rows[0]['matched_responses']==3,rows
    assert rows[0]['orig_messages']==3 and rows[0]['resp_messages']==3,rows
    assert rows[0]['likely_manufacturer']=='DJI',rows
    assert conn[0]['uid']==rows[0]['uid'] and conn[0]['drone_protocol']=='dji-phantom-vision-legacy',conn
    rows,_=run(capture([(0,bytes([b])) for b in request]+[(1,bytes([b])) for b in response]))
    assert len(rows)==1 and rows[0]['matched_responses']==3,rows
    rows,_=run(capture([(0,request)]))
    assert rows[0]['evidence']=='framing+xor',rows
    for data in (request[:18],b'HTTP/1.1 200 OK\r\n\r\n'+b'x'*1000,
                 b''.join(frame(i)[:-1]+bytes([frame(i)[-1]^1]) for i in range(30)),
                 b'\x55\xbb\x01\x08'*100):
        rows,conn=run(capture([(0,data)]))
        assert not rows and 'drone_protocol' not in conn[0],(rows,conn)
    rows,_=run(capture([(0,request)],port=12345))
    assert not rows,rows
    rows,_=run(capture([(0,request)],port=12345),'redef DroneDetector::ports += { 12345/tcp };\n')
    assert len(rows)==1,rows
    rows,_=run(capture([(0,request*20)]),'redef DroneDetector::max_inspected_bytes = 27;\n')
    assert rows[0]['inspection_limited'] and rows[0]['orig_messages']==3,rows
    rows,_=run(capture([(0,b'garbage'+request)]))
    assert len(rows)==1 and rows[0]['skipped_bytes']==7,rows
    rows,_=run(capture([(0,request[:4]),(0,None),(0,request)]))
    assert len(rows)==1 and rows[0]['gaps']>=1 and rows[0]['orig_messages']==3,rows
    print('PASS: 12 synthetic capture scenarios (segmentation, checksums, negatives, port scope, resynchronization and budget).')
    real=os.environ.get('DJI_CAPTURE')
    if real:
        p=Path(real)
        data=gzip.decompress(p.read_bytes()) if p.suffix=='.gz' else p.read_bytes()
        rows,conns=run(data)
        assert len(rows)==1,rows
        r=rows[0]
        assert (r['orig_messages'],r['resp_messages'],r['matched_responses'])==(1230,1539,1220),r
        assert not r['inspection_limited'] and r['checksum_failures']==0 and r['skipped_bytes']==0,r
        assert sum('drone_protocol' in c for c in conns)==1,conns
        (ROOT/'validation').mkdir(exist_ok=True)
        (ROOT/'validation'/'real-capture-result.json').write_text(json.dumps(r,indent=2)+'\n')
        print('PASS: real DJI capture; 2769 valid messages, 1220 matched responses, one detected connection.')

if __name__=='__main__':main()
