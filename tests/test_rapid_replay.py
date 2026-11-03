#!/usr/bin/env python3
from test_tello_binary import frame,replay,has

def sample(n=25,gap=.05,step=.2,command=80,kind=96):
    packets=[frame(i,command,kind) for i in range(3)];times=[0,.1,.2]
    for i in range(n):
        f=frame(100+i,command,kind);packets.extend([f,f]);times.extend([1+i*step,1+i*step+gap])
    packets.append(frame(999,command,kind));times.append(max(65,times[-1]+1))
    return packets,times

def main():
    p,t=sample();rows,_=replay(p,times=t)
    assert has(rows,'Rapid replay-like') and not has(rows,'Replay-like control traffic:'),rows
    assert rows[-1]['binary_rapid_replayed_frames']==25 and rows[-1]['binary_rapid_replayed_distinct']==25;cases=1
    for kw in ({'gap':.001},{'n':19},{'step':1},{'command':0x56,'kind':0x48}):
        p,t=sample(**kw);rows,_=replay(p,times=t);assert not has(rows,'Rapid replay-like'),rows;cases+=1
    p,t=sample();rows,_=replay(p,times=t,settings='redef DroneTelloBinary::rapid_min_frames = 100;\n');assert not has(rows,'Rapid replay-like');cases+=1
    rows,_=replay(p,times=t,settings='redef DroneTelloBinary::rapid_max_entries = 4;\n');assert not has(rows,'Rapid replay-like') and rows[-1]['binary_tracking_limited'];cases+=1
    # Repeating one complete payload is not sufficient diversity.
    p=[frame(i) for i in range(3)]+[frame(100)]*80+[frame(999)];t=[0,.1,.2]+[1+i*.05 for i in range(80)]+[65]
    rows,_=replay(p,times=t);assert not has(rows,'Rapid replay-like');cases+=1
    # CRC-invalid duplicate frames cannot become replay evidence.
    p,t=sample();p=[x[:-1]+bytes([x[-1]^1]) if i>=3 and i<len(p)-1 else x for i,x in enumerate(p)]
    rows,_=replay(p,times=t);assert not has(rows,'Rapid replay-like');cases+=1
    # Responses travelling away from the candidate control port are excluded.
    from test_detector import run
    from test_mavlink import pcap
    p,t=sample();rows,_=run(pcap(p,sport=8889,dport=7777,times=t),live=True)
    assert rows and not has(rows,'Rapid replay-like');cases+=1
    # Partial pattern at the end is not flushed, even if the threshold was reached.
    p,t=sample();rows,_=replay(p[:-1],times=t[:-1]);assert not has(rows,'Rapid replay-like');cases+=1
    # Rapid fingerprints remain useful after the long-age cache saturates.
    p,t=sample();rows,_=replay(p,times=t,settings='redef DroneTelloBinary::max_fingerprints = 4;\n');assert has(rows,'Rapid replay-like');cases+=1
    p,t=sample()
    rows,_=replay(p,times=t,settings='redef DroneTelloBinary::rapid_min_age = 100msec;\n');assert not has(rows,'Rapid replay-like');cases+=1
    rows,_=replay(p,times=t,settings='redef DroneTelloBinary::rapid_max_age = 20msec;\n');assert not has(rows,'Rapid replay-like');cases+=1
    print(f'PASS: {cases} rapid replay scenarios (age, diversity, CRC, direction, limits and timing).')
if __name__=='__main__':main()
