#!/usr/bin/env python3
"""Correlated H.264 evidence and minute-limited video observations."""
from test_detector import run
from test_tello import combined,STATE
SPS=bytes.fromhex('00000001674d402895a03c05b9')
PPS=bytes.fromhex('0000000168ee3880')
def slice(n,idr=False):return b'\0\0\0\1'+(b'\x65' if idr else b'\x41')+bytes([0x80,n])+b'\x11'*20

def replay(payloads,times=None,state=True,reverse=False,port=11111,settings='',extra=()):
    items=[(i,STATE,8889,8890,False) for i in range(3)] if state else []
    if times is None:times=[3+i for i in range(len(payloads))]
    items += [(t,p,62515,port,reverse) for t,p in zip(times,payloads)]
    items += list(extra)
    rows,conns=run(combined(sorted(items,key=lambda x:x[0])),settings,live=True)
    video=[r for r in rows if r.get('video_active')]
    assert all(r['video_codec']=='H264' and r['protocol']=='tello-video' and 'manipulation_detection' not in r for r in video),rows
    assert all(b['ts']-a['ts']>=60 for a,b in zip(video,video[1:])),video
    return video,conns

def main():
    good=[SPS,PPS,slice(0,True),slice(1),slice(2)]
    rows,conns=replay(good);assert len(rows)==1 and rows[0]['drone_host']=='192.0.2.1',rows
    assert any(c.get('drone_protocol')=='tello-video' for c in conns);cases=1
    for kw in ({'state':False},{'reverse':True},{'port':22222},{'times':[130,131,132,133,134]}):
        assert not replay(good,**kw)[0];cases+=1
    for payloads in ([b'x'*1460]*10,[SPS,PPS]+[slice(1)]*5,[SPS,PPS,slice(1),slice(2)],
                     [PPS,slice(0,True),slice(1),slice(2)],[SPS,slice(0,True),slice(1),slice(2)],
                     [SPS,PPS,slice(0),slice(1),slice(2)],
                     [SPS[:4]+b'\xe7'+SPS[5:],PPS,slice(0,True),slice(1),slice(2)],
                     [SPS[:5]+b'\x01'+SPS[6:],PPS,slice(0,True),slice(1),slice(2)]):
        assert not replay(payloads)[0];cases+=1
    assert not replay(good,times=[3,4,5,20,21])[0];cases+=1 # old headers/slices
    rows,_=replay(good+good,times=[3,4,5,6,7,63,64,65,66,67]);assert len(rows)==2,rows;cases+=1
    # Three-byte start codes and multiple NAL prefixes within a datagram.
    rows,_=replay([SPS[1:]+PPS[1:]+slice(0,True)[1:],slice(1)[1:],slice(2)[1:]])
    assert len(rows)==1;cases+=1
    assert not replay([b'x'*128+p for p in good])[0];cases+=1 # bounded prefix
    assert not replay(good,settings='redef DroneVideo::max_inspected_bytes = 10;\n')[0];cases+=1
    rows,_=replay(good+good,times=[3,4,5,6,7,63,64,65,66,67],settings='redef DroneVideo::max_inspected_bytes = 105;\n')
    assert len(rows)==2;cases+=1
    # A streamon request without video bytes is not a video observation.
    rows,_=replay([],extra=[(3,b'streamon',8889,8889,True)]);assert not rows;cases+=1
    print(f'PASS: {cases} video scenarios (pair identity, H264 structure, freshness, timing, bounds and negatives).')
if __name__=='__main__':main()
