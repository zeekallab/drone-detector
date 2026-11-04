#!/usr/bin/env python3
"""Binary Tello checksums, evidence thresholds and alert timing."""
import json,struct
from test_detector import run
from test_mavlink import pcap


def crc(data,seed,poly):
    for value in data:
        seed ^= value
        for _ in range(8):seed=(seed>>1)^poly if seed&1 else seed>>1
    return seed


def frame(n,command=80,kind=96,seq=0):
    body=n.to_bytes(6,'little')+b'\x0e\x12'+n.to_bytes(3,'little')
    hdr=b'\xcc'+struct.pack('<H',(11+len(body))<<3)
    data=hdr+bytes([crc(hdr,0x77,0x8c),kind])+struct.pack('<HH',command,seq)+body
    return data+struct.pack('<H',crc(data,0x3692,0x8408))


def replay(payloads,times=None,settings='',**kw):
    return run(pcap(payloads,sport=7777,dport=8889,times=times,**kw),settings,live=True)


def has(rows,word):return any(word in a for r in rows for a in r.get('manipulation_detection',[]))


def main():
    cases=0
    rows,conns=replay([frame(i) for i in range(3)])
    assert len(rows)==1 and rows[0]['protocol']=='tello-binary' and 'manipulation_detection' not in rows[0],rows
    assert conns[0]['drone_protocol']=='tello-binary',conns;cases+=1
    for packets in ([frame(0)]*8,[frame(0),frame(1)],
                    [p[:-1]+bytes([p[-1]^1]) for p in [frame(i) for i in range(5)]],
                    [b'\xcc'+b'garbage'*5]*10,[frame(i)[:10] for i in range(8)],
                    [frame(i)[:3]+b'\0'+frame(i)[4:] for i in range(8)]):
        rows,_=replay(packets);assert not rows,rows;cases+=1
    # Every whole message changes even though the joystick sequence stays zero.
    rows,_=replay([frame(i) for i in range(75)],times=list(range(75)))
    assert not has(rows,'Replay-like') and not has(rows,'Malformed'),rows;cases+=1
    rows,_=replay([frame(i%10) for i in range(75)],times=list(range(75)))
    assert has(rows,'Replay-like') and not has(rows,'Malformed'),rows
    assert all(b['ts']-a['ts']>=60 for a,b in zip(rows,rows[1:])),rows;cases+=1
    # Fast duplicates must not become delayed replay evidence.
    rows,_=replay([frame(i%10) for i in range(1000)],times=[i*.05 for i in range(1000)])
    assert not has(rows,'Replay-like'),rows;cases+=1
    packets=[frame(i) for i in range(3)]+[frame(9)[:-4]]*7
    rows,_=replay(packets,times=[0,1,2,10,20,30,40,50,60,70])
    assert has(rows,'Malformed') and not has(rows,'Replay-like'),rows;cases+=1
    # A single damaged frame is not an alert.
    rows,_=replay([frame(i) for i in range(3)]+[frame(9)[:-4]]+[frame(i+20) for i in range(7)],times=[0,1,2,10,20,30,40,50,60,70,80])
    assert not has(rows,'Malformed'),rows;cases+=1
    # Queries/replies can repeat legitimately; they are not joystick-control replay.
    rows,_=replay([frame(i%10,command=0x56,kind=0x48) for i in range(75)],times=list(range(75)))
    assert rows and not has(rows,'Replay-like'),rows;cases+=1
    rows,_=replay([frame(i%10) for i in range(75)],times=list(range(75)),settings='redef DroneTelloBinary::replay_min_frames = 1000;\n')
    assert not has(rows,'Replay-like'),rows;cases+=1
    rows,_=replay([frame(i) for i in range(75)],times=list(range(75)),settings='redef DroneTelloBinary::max_fingerprints = 4;\n')
    assert rows[-1]['binary_tracking_limited'],rows;cases+=1
    # Invalid header fields cannot drive the malformed-control alert.
    bad=frame(10)[:3]+b'\0'+frame(10)[4:]
    rows,_=replay([frame(i) for i in range(3)]+[bad]*7,times=[0,1,2,10,20,30,40,50,60,70])
    assert not has(rows,'Malformed'),rows;cases+=1
    # Both descriptions coexist, without extra records to bypass the minute gate.
    packets=[];times=[]
    for i in range(75):
        packets.extend([frame(i%10),frame(i)[:-4]]);times.extend([i,i+.1])
    rows,_=replay(packets,times=times)
    assert any(len(r.get('manipulation_detection',[]))==2 for r in rows),rows
    assert len(rows)==2,rows;cases+=1
    # Evidence from an unconfirmed direction can't create an alert.
    packets=[frame(i%10) if i%2==0 else frame(3)[:-4] for i in range(75)]
    rows,_=replay(packets,times=list(range(75)),reverse=True)
    assert not has(rows,'Malformed'),rows;cases+=1
    # Mixed SDK and binary evidence on one UID share the same emission gate.
    from test_tello import STATE
    rows,_=run(pcap([STATE]*3+[frame(i) for i in range(3)],sport=8889,dport=8890),live=True)
    assert len(rows)==1,rows;cases+=1
    print(f'PASS: {cases} binary Tello scenarios (CRC, replay, malformed control, thresholds, scope and bounds).')

if __name__=='__main__':main()
