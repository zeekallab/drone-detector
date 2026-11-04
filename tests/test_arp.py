#!/usr/bin/env python3
"""ARP correlation tests through actual Zeek using valid Ethernet/IP frames."""
import struct,ipaddress
from test_detector import run
from test_mavlink import pcap
from test_tello_binary import frame
A='192.0.2.1';B='192.0.2.2';M='c8787d9667d7'
def arp(t,src=A,dst=B,mac=M,op=2,eth=None):
    m=bytes.fromhex(mac)
    raw=bytes.fromhex('ffffffffffff')+(bytes.fromhex(eth) if eth else m)+b'\x08\x06'
    raw+=struct.pack('!HHBBH',1,0x800,6,4,op)+m+ipaddress.ip_address(src).packed+bytes(6)+ipaddress.ip_address(dst).packed
    return t,raw

def capture(extra,telemetry=True):
    packets=list(extra)
    if telemetry:
        raw=pcap([frame(i) for i in range(80)],sport=7777,dport=8889,times=list(range(80)))
        offset=24
        while offset<len(raw):
            sec,usec,n,_=struct.unpack_from('<IIII',raw,offset);offset+=16
            packets.append((sec-1700000000+usec/1e6,raw[offset:offset+n]));offset+=n
    out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for t,p in sorted(packets,key=lambda x:x[0]):out+=struct.pack('<IIII',1700000000+int(t),round(t%1*1e6),len(p),len(p))+p
    return out

def check(packets,expected,settings='',telemetry=True,enabled=True):
    rows,_=run(capture(packets,telemetry),('@load ./package/arp\n' if enabled else '')+settings,live=True)
    hits=[r for r in rows if any(a.startswith('ARP interception') for a in r.get('manipulation_detection',[]))]
    assert bool(hits)==expected,(expected,rows)
    assert all(b['ts']-a['ts']>=60 for a,b in zip(rows,rows[1:])),rows
    if hits:assert set(hits[-1]['arp_claimed_ips'])=={A,B} and hits[-1]['arp_claimant_macs']==['c8:78:7d:96:67:d7']
    return rows

def main():
    both=[arp(t,src=s,dst=d) for t in [10,12,14,40,42,44] for s,d in [(A,B),(B,A)]]
    check(both,True)
    check(both,False,enabled=False)
    check(both,False,telemetry=False)
    check([arp(t) for t in range(10,60,2)],False) # one-sided
    check([arp(t,src=s,dst=d,mac=M if s==A else '60601f58eccc') for t in [40,42,44] for s,d in [(A,B),(B,A)]],False)
    check([arp(40,src=s,dst=d) for _ in range(10) for s,d in [(A,B),(B,A)]],False) # duplicate burst
    check([arp(t,src=s,dst=d) for t in [0,.5,1] for s,d in [(A,B),(B,A)]],False) # inadequate span
    check([arp(t,src=s,dst=d) for t in [-80,-78,-76] for s,d in [(A,B),(B,A)]],False) # stale
    check([arp(t,src=s,dst=d,op=1) for t in [40,42,44] for s,d in [(A,B),(B,A)]],False)
    check([arp(t,src=s,dst=d,eth='60601f58eccc') for t in [40,42,44] for s,d in [(A,B),(B,A)]],False)
    check(both,False,'redef DroneARP::ignored_macs += { "c8:78:7d:96:67:d7" };\n')
    check(both,False,'redef DroneARP::minimum_claims = 100;\n')
    rows=check(both,False,'redef DroneARP::max_pairs = 1;\n');assert rows[-1]['arp_tracking_limited']
    check([arp(t,src=s,dst=d,mac='ffffffffffff') for t in [40,42,44] for s,d in [(A,B),(B,A)]],False)
    # Continuous claims must survive a 60-second boundary near the log timestamp.
    check([arp(t,src=s,dst=d) for t in range(1,65,2) for s,d in [(A,B),(B,A)]],True)
    check([arp(t,src=s,dst=d) for t in [40,42,44] for s,d in [('192.0.2.3','192.0.2.4'),('192.0.2.4','192.0.2.3')]],False)
    check([arp(t,src=s,dst=d) for t in [0,1,61] for s,d in [(A,B),(B,A)]],False)
    check([arp(t,src=s,dst=d) for t in [40,42,44] for s,d in [(A,A),(B,B)]],False)
    print('PASS: 18 ARP correlation scenarios (scope, timing, negatives, limits and optional loading).')
if __name__=='__main__':main()
