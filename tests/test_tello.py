#!/usr/bin/env python3
import json,struct
from test_detector import run
from test_mavlink import pcap

STATE=b'pitch:1;roll:-2;yaw:-7;vgx:0;vgy:0;vgz:0;templ:70;temph:72;tof:10;h:25;bat:47;baro:-27.79;time:12;agx:1.0;agy:0.0;agz:-999.0;\r\n'

def combined(items):
    # (time, payload, sport, dport, reverse). Alternate ports within the same host pair.
    output=pcap([])
    for when,payload,sp,dp,reverse in items:
        blob=pcap([b'ignored',payload] if reverse else [payload],sport=sp,dport=dp,reverse=reverse)
        offset=24
        if reverse:offset+=16+struct.unpack_from('<I',blob,offset+8)[0]
        _,_,length,wire=struct.unpack_from('<IIII',blob,offset)
        output+=struct.pack('<IIII',1700000000+int(when),round((when-int(when))*1e6),length,wire)+blob[offset+16:offset+16+length]
    return output

def main():
    cases=0
    rows,conns=run(pcap([STATE]*3,sport=8889,dport=8890),live=True)
    assert len(rows)==1 and rows[0]['protocol']=='tello-sdk' and rows[0]['orig_messages']==3,rows
    t=json.loads(rows[0]['telemetry'])[0]
    assert t['battery_remaining_pct']==47 and t['height_cm']==25 and t['yaw_deg']==-7,t
    assert 'latitude' not in t and conns[0]['drone_protocol']=='tello-sdk',conns;cases+=1
    for payloads in ([STATE]*2,[b'ok']*5,[b'command']*5,[b'takeoff']*5,[b'\xcc\xb0\x00\x7f']*5,
                     [STATE.replace(b'bat:47',b'bat:101')]*3,[STATE.replace(b'h:25;',b'')]*3,
                     [STATE.replace(b'h:25;',b'h:NaN;')]*3,[STATE+b'bat:47;']*3,
                     [STATE.replace(b'yaw:-7',b'yaw:1000')]*3):
        rows,_=run(pcap(payloads,sport=8889,dport=8890),live=True)
        assert not rows,rows;cases+=1
    rows,_=run(pcap([STATE,STATE,b'garbage',STATE,STATE],sport=8889,dport=8890),live=True)
    assert not rows,rows;cases+=1
    rows,_=run(pcap([STATE]*3,sport=4000,dport=4001),live=True)
    assert not rows,rows;cases+=1
    times=list(range(0,131,10))
    rows,_=run(pcap([STATE]*len(times),sport=8889,dport=8890,times=times),live=True)
    assert [r['ts']-1700000000 for r in rows]==[20,80],rows;cases+=1
    # A command on the reverse host pair is confirmed only after valid telemetry.
    items=[(i,STATE,8889,8890,False) for i in range(3)]+[(3,b'forward 20',8889,8889,True)]
    rows,_=run(combined(items),live=True)
    assert len(rows)==2 and json.loads(rows[-1]['control_activity'])[0]['command']=='forward 20',rows;cases+=1
    # Same port, unrelated sender/receiver direction must not inherit identity.
    rows,_=run(combined(items[:3]+[(3,b'forward 20',8889,8889,False)]),live=True)
    assert len(rows)==1,rows;cases+=1
    # Expired telemetry can't authorize new command-only detections.
    rows,_=run(combined(items[:3]+[(130,b'forward 20',8889,8889,True)]),live=True)
    assert len(rows)==1,rows;cases+=1
    # Unsupported/out-of-range commands are not interpreted as SDK evidence.
    for cmd in (b'forward 999',b'rc 0 0 0 101',b'rm -rf /',b'go 0 0 20 30'):
        rows,_=run(combined(items[:3]+[(3,cmd,8889,8889,True)]),live=True)
        assert len(rows)==1,rows
    cases+=1
    # SDK mission-pad prefixes are accepted without being misread as GPS.
    rows,_=run(pcap([b'mid:-1;x:0;y:0;z:0;mpry:0,0,0;'+STATE]*3,sport=8889,dport=8890),live=True)
    assert len(rows)==1,rows;cases+=1
    # Confirmed connection renews budget and retains rate limiting.
    rows,_=run(pcap([STATE]*14,sport=8889,dport=8890,times=list(range(0,140,10))),f'redef DroneTello::max_inspected_bytes = {len(STATE)*3};\n',live=True)
    assert len(rows)==2 and rows[-1]['inspection_limited'],rows;cases+=1
    print(f'PASS: {cases} Tello SDK scenarios (structure, negatives, identity correlation, expiry, units, timing and budget).')

if __name__=='__main__':main()
