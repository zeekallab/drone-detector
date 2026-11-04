#!/usr/bin/env python3
"""Exercise production logging defaults using real Zeek and generated packets."""
from test_detector import run, capture, frame as legacy
from test_tello_binary import frame
from test_mavlink import pcap, message
from test_telemetry import position
from test_tello import STATE, combined


def check(data, settings=''):
    rows, _ = run(data, settings, live=True, lifecycle=True)
    for row in rows:
        assert 'alert' not in row and 'detection_type' not in row, row
        assert 'event_type' in row and 'evidence' in row, row
    regular = [r for r in rows if r['event_type'] in ('detection', 'update')]
    groups = {}
    for r in regular:
        key = (r['protocol'], r.get('uid'))
        if r.get('sdk_summary_scope') == 'host-pair':
            key = (r['protocol'], r['drone_host'], r['controller_host'])
        if key in groups:
            assert r['ts'] - groups[key] >= 60, rows
        groups[key] = r['ts']
    return rows


def main():
    good = b''.join(message(i) for i in range(3))
    rows = check(pcap([good]))
    assert [r['event_type'] for r in rows] == ['detection'], rows
    rows = check(pcap([good, position()], times=[0, 1]))
    assert [r['event_type'] for r in rows] == ['detection', 'final'], rows
    assert 'flight_telemetry' in rows[-1], rows
    rows = check(pcap([good] + [position()]*13, times=list(range(0, 140, 10))))
    assert [r['event_type'] for r in rows] == ['detection', 'update', 'update', 'final'], rows
    rows=check(pcap([good+position(),position(4,lat=382418612,alt=239580)],times=[0,1]))
    assert [r['event_type'] for r in rows]==['detection','manipulation'],rows
    assert set(rows[-1]['manipulation_detection'])=={
        'mavlink anomaly indicator - position discontinuity',
        'mavlink anomaly indicator - Altitude discontinuity'},rows
    # Malformed controls reach the threshold after initial confirmation, within a minute.
    packets = [frame(i) for i in range(3)] + [frame(9)[:-4]]*20
    rows = check(pcap(packets, sport=7777, dport=8889, times=[i*.1 for i in range(len(packets))]))
    prompts = [r for r in rows if r['event_type'] == 'manipulation']
    assert len(prompts) == 1 and any('Malformed' in x for x in prompts[0]['manipulation_detection']), rows
    assert prompts[0]['ts']-rows[0]['ts'] < 60, rows
    assert rows[-1]['event_type'] == 'final', rows
    # No repeat storm: two distinct findings each get at most one prompt.
    packets=[]; times=[]
    for i in range(150):
        packets.extend([frame(i%10), frame(i)[:-4]]); times.extend([i, i+.1])
    rows=check(pcap(packets,sport=7777,dport=8889,times=times))
    prompts=[r for r in rows if r['event_type']=='manipulation']
    assert 1 <= len(prompts) <= 3, rows
    assert any('Replay-like' in x for r in rows for x in r.get('manipulation_detection',[])), rows
    rows=check(pcap([STATE]*5,sport=8889,dport=8890,times=[0,1,2,3,4]))
    assert [r['event_type'] for r in rows]==['detection','final'],rows
    rows=check(capture([(0,b''.join(legacy(i) for i in range(3))), (1,legacy(0,True))]))
    assert [r['event_type'] for r in rows]==['detection','final'],rows
    # Shared SDK summaries flush once, preserving all commands across source ports.
    packets=[(i,STATE,8889,8890,False) for i in range(3)]
    packets += [(3+i*.1,b'command',8889,40000+i,True) for i in range(10)]
    rows=check(combined(packets))
    shared=[r for r in rows if r.get('sdk_summary_scope')=='host-pair']
    assert sum(r.get('sdk_command_count',0) for r in shared)==10,rows
    assert sum(r['event_type']=='final' for r in shared)==1,rows
    packets=[(i,STATE,8889,8890,False) for i in range(3)]
    packets += [(3+i*2,[b'forward 20',b'back 20'][i%2],8889,41000+i,True) for i in range(20)]
    rows=check(combined(packets))
    shared=[r for r in rows if r.get('sdk_summary_scope')=='host-pair']
    assert sum(r.get('sdk_command_count',0) for r in shared)==20,rows
    findings={x for r in shared for x in r.get('manipulation_detection',[])}
    assert any(x.startswith('Control source-port churn') for x in findings),rows
    assert any(x.startswith('Repetitive maneuver') for x in findings),rows
    assert 1 <= sum(r['event_type']=='manipulation' for r in shared) <= 2,rows
    # Video final summarizes further observed stream activity.
    from test_video import SPS, PPS, slice
    items=[(i,STATE,8889,8890,False) for i in range(3)]
    items += [(3+i,p,62515,11111,False) for i,p in enumerate([SPS,PPS,slice(0,True),slice(1),slice(2),slice(3)])]
    rows=check(combined(items))
    assert [r['event_type'] for r in rows if r['protocol']=='tello-video']==['detection','final'],rows
    # ARP findings can bypass the minute gate on the next validated drone packet.
    from test_arp import arp, capture as arp_capture, A, B
    claims=[arp(t,src=a,dst=b) for t in [10,12,14] for a,b in [(A,B),(B,A)]]
    rows=check(arp_capture(claims),'@load ./package/arp\n')
    assert any(r['event_type']=='manipulation' and r['ts']-rows[0]['ts']<60 for r in rows),rows
    # Wireless findings remain bounded and flush only unreported frames.
    from test_wifi import beacon, deauth, capture as wifi_capture
    rows=check(wifi_capture([beacon()]+[deauth(i) for i in range(25)]),'@load ./package/wifi\n')
    assert [r['event_type'] for r in rows]==['detection','final'],rows
    assert sum(r['wireless_deauth_frames'] for r in rows)==25,rows
    print('PASS: default lifecycle (short flows, prompt findings, repeat limits, final flush, shared SDK counts and schema).')

if __name__=='__main__': main()
