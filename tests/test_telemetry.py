#!/usr/bin/env python3
"""Check live snapshots, wire units, identity isolation, stale data and bounds."""
import json
import struct
from test_detector import run, capture, frame
from test_mavlink import message, pcap


def wire(seq, kind, payload, version=2, sysid=1, compid=1):
    return message(seq,kind,payload,{24:24,33:104,74:20,147:154,1:124}[kind],
                   version=version,sysid=sysid,compid=compid)


def position(seq=3, version=2, sysid=1, compid=1, lat=372418612, lon=-1157969175, alt=139580, rel=-151):
    return wire(seq,33,struct.pack('<IiiiihhhH',1234,lat,lon,alt,rel,0,0,0,0),version,sysid,compid)


def gps(fix=6, lat=372418612, lon=-1157969175, seq=4, version=2):
    return wire(seq,24,struct.pack('<QiiiHHHHBB',1234000,lat,lon,139580,121,200,0,0,fix,10),version)


def motion(speed=12.5, heading=123, climb=-1.25, version=2):
    return wire(5,74,struct.pack('<ffffhH',13.0,speed,139.58,climb,heading,20),version)


def battery(remaining=76, ident=0, version=2):
    return wire(6,147,struct.pack('<iih10HhBBBb',0,0,2500,*([4000]*10),100,ident,0,0,remaining),version)


def snapshots(rows):
    return [json.loads(r.get('flight_telemetry','[]')) for r in rows]


def main():
    good=b''.join(message(i) for i in range(3))
    cases=0
    # V1 and V2 exact units, signed coordinates, negative height/climb, battery ID.
    for version in (1,2):
        packet=b''.join(message(i,version=version) for i in range(3))+position(version=version)+motion(version=version)+battery(version=version)
        rows,_=run(pcap([packet]),live=True)
        assert len(rows)==1 and rows[0]['event_type']=='detection',rows
        t=snapshots(rows)[0][0]
        assert t['gps']['latitude']==37.2418612 and t['gps']['longitude']==-115.7969175,t
        assert t['altitude']==139.58 and 'height' not in t,t
        assert t['motion']['groundspeed_m_s']==12.5 and t['motion']['heading_deg']==123 and t['motion']['climb_m_s']==-1.25,t
        assert t['battery_status'][0]['remaining_pct']==76 and t['battery_status'][0]['battery_id']==0,t
        assert 'armed' not in t and t['mode']=='GUIDED',t
        assert 'message_types' not in rows[0] and 'checksum_failures' not in rows[0],rows
        cases+=1
    # One detection and updates at >=60 seconds, no flush at EOF. Keep UDP active.
    times=[0,10,20,30,40,50,59,60,61,70,80,90,100,110,120,121]
    packets=[good+position()]+[position(i+4,alt=140000+i) for i in range(len(times)-1)]
    rows,conns=run(pcap(packets,times=times),live=True)
    assert [r['event_type'] for r in rows]==['detection','update','update'],rows
    assert [r['ts']-rows[0]['ts'] for r in rows]==[0,60,120],rows
    assert len({r['uid'] for r in rows})==1 and conns[0]['drone_protocol']=='mavlink',conns
    cases+=1
    rows,_=run(pcap([good,position(),position(4)],times=[0,5,10]),'redef DroneDetector::log_interval = 10secs;\n',live=True)
    assert len(rows)==2 and rows[1]['ts']-rows[0]['ts']==10,rows;cases+=1
    # No valid new message -> no periodic update, even beyond the interval.
    rows,_=run(pcap([good]+[b'garbage']*7,times=list(range(0,80,10))),live=True)
    assert len(rows)==1,rows;cases+=1
    # Short session doesn't wait for its end and produces no end duplicate.
    rows,_=run(pcap([good,position()],times=[0,1]),live=True)
    assert len(rows)==1 and 'gps' not in snapshots(rows)[0][0],rows;cases+=1
    # Same system/different components and different systems remain separate.
    rows,_=run(pcap([good+position(sysid=1,compid=1)+position(sysid=1,compid=2,lat=-100000000)+position(sysid=2,compid=1,lat=100000000)]),live=True)
    byid={(t['system_id'],t['component_id']):t for t in snapshots(rows)[0]}
    assert len(byid)==3 and byid[1,1]['gps']['latitude']==37.2418612 and byid[1,2]['gps']['latitude']==-10 and byid[2,1]['gps']['latitude']==10,byid
    cases+=1
    # GPS needs a 3-D fix; (0,0) is a valid coordinate, not a missing-value marker.
    rows,_=run(pcap([good+gps(fix=1)]),live=True)
    assert 'gps' not in snapshots(rows)[0][0],rows
    rows,_=run(pcap([good+gps(lat=0,lon=0)]),live=True)
    assert snapshots(rows)[0][0]['gps']['latitude']==0,rows;cases+=1
    # Invalid positions, nonfinite motion and unknown battery cannot become measurements.
    rows,_=run(pcap([good+position(lat=910000000)+motion(float('nan'),-1,float('inf'))+battery(-1)]),live=True)
    t=snapshots(rows)[0][0]
    assert not any(k in t for k in ['gps','motion','battery_status']),t;cases+=1
    # Unknown new battery reading clears the old value; separate battery IDs persist.
    rows,_=run(pcap([good+battery(80,0)+battery(50,1)+battery(-1,0)]),live=True)
    batteries=snapshots(rows)[0][0]['battery_status']
    assert len(batteries)==1 and batteries[0]['battery_id']==1 and batteries[0]['remaining_pct']==50,batteries;cases+=1
    # Expired measurements aren't presented as current when only heartbeats continue.
    times=list(range(0,190,10))
    rows,_=run(pcap([good+position()+motion()+battery()]+[message(i+3) for i in range(len(times)-1)],times=times),live=True)
    t=snapshots(rows)[-1][0]
    assert 'mode' in t and not any(k in t for k in ['gps','altitude','motion','battery_status']),t;cases+=1
    # Confirmed streams continue after bounded inspection is exhausted and renewed.
    packets=[good]+[message(i+3) for i in range(7)]
    rows,_=run(pcap(packets,times=list(range(0,80,10))),f'redef DroneMAVLink::max_inspected_bytes = {len(good)};\n',live=True)
    assert len(rows)==2 and rows[-1]['inspection_limited'] and rows[-1]['orig_messages']>3,rows;cases+=1
    # Bound identities without merging or silently replacing an active source.
    rows,_=run(pcap([good+position(sysid=2)]),'redef DroneMAVLink::max_telemetry_sources = 1;\n',live=True)
    assert rows[0]['telemetry_limited'] and len(snapshots(rows)[0])==1,rows;cases+=1
    # Zero-truncated V2 VFR HUD restores all zero values, including 0% battery.
    rows,_=run(pcap([good+wire(8,74,b'\0'*20)+battery(0)]),live=True)
    t=snapshots(rows)[0][0]
    assert t['motion']['groundspeed_m_s']==0 and t['motion']['climb_m_s']==0 and t['battery_status'][0]['remaining_pct']==0,t;cases+=1
    # GPS fallback must not replace a fresh fused position.
    rows,_=run(pcap([good+position()+gps(lat=100000000)]),live=True)
    assert snapshots(rows)[0][0]['gps']['latitude']==37.2418612,rows;cases+=1
    # Mode numbers are never interpreted as copter modes for a rover or PX4.
    for vehicle,autopilot in ((10,3),(2,12)):
        hb=b''.join(message(i,payload=struct.pack('<IBBBBB',6,vehicle,autopilot,129,4,3)) for i in range(3))
        rows,_=run(pcap([hb]),live=True)
        assert snapshots(rows)[0][0]['mode']=='custom-mode-6',rows
    cases+=1
    # GCS and companion armed flags do not become flight state.
    hb=b''.join(message(i,payload=struct.pack('<IBBBBB',6,6,8,129,4,3)) for i in range(3))
    rows,_=run(pcap([hb]),live=True)
    assert 'flight_telemetry' not in rows[0] and 'autopilot_software' not in rows[0],rows;cases+=1
    # Legacy DJI detection is immediate, and EOF doesn't add a second record.
    request=b''.join(frame(i) for i in range(3))
    response=b''.join(frame(i,True) for i in range(3))
    rows,_=run(capture([(0,request),(1,response)]),live=True)
    assert len(rows)==1 and rows[0]['orig_messages']==3 and rows[0]['resp_messages']==0,rows;cases+=1
    # Legacy connections follow the same minute gate, even when FIN arrives later.
    data=capture([(0,request),(1,response),(0,request)])
    offset=24; packets=[]; n=0
    while offset<len(data):
        _,_,size,wirelen=struct.unpack_from('<IIII',data,offset)
        packets.append(struct.pack('<IIII',1700000000+n*30,0,size,wirelen)+data[offset+16:offset+16+size])
        offset+=16+size; n+=1
    rows,_=run(data[:24]+b''.join(packets),live=True)
    assert len(rows)==3 and all(b['ts']-a['ts']==60 for a,b in zip(rows,rows[1:])),rows;cases+=1
    # Stale identities release bounded slots; active sources never get mixed.
    times=list(range(0,150,10))
    packets=[good]+[message(i+3,11,struct.pack('<IBB',6,1,1),89) for i in range(len(times)-2)]+[position(sysid=2)]
    rows,_=run(pcap(packets,times=times),'redef DroneMAVLink::max_telemetry_sources = 1;\nredef DroneDetector::log_interval = 10secs;\n',live=True)
    t=snapshots(rows)[-1]
    assert len(t)==1 and 'system_id' not in t[0] and 'gps' in t[0],t;cases+=1
    # Battery identifiers are bounded independently from source identities.
    rows,_=run(pcap([good+b''.join(battery(50,i) for i in range(10))]),live=True)
    assert rows[0]['telemetry_limited'] and len(snapshots(rows)[0][0]['battery_status'])==8,rows;cases+=1
    # Presentation rounding preserves zero and tiny positive/negative motion.
    for speed,climb,expected_speed,expected_climb in [
            (0,0,0,0),(.004,-.00044,.01,-.01),(.0001,.0001,.01,.01),
            (12.346,-1.236,12.35,-1.24)]:
        rows,_=run(pcap([good+motion(speed=speed,climb=climb)]),live=True)
        t=snapshots(rows)[0][0]
        assert t['motion']['groundspeed_m_s']==expected_speed and t['motion']['climb_m_s']==expected_climb,t
        assert 'telemetry' not in rows[0] and 'telemetry_limited' not in rows[0],rows
        assert not any(k in t for k in ['system_id','component_id','armed','flight','height']),t
        assert 'observed_ts' not in json.dumps(t) and 'source' not in t,t
    cases+=1
    # Prefer fresh individual batteries; fall back to aggregate when unavailable/stale.
    status=wire(10,1,struct.pack('<IIIHHhHHHHHHb',0,0,0,0,12000,0,0,0,0,0,0,0,90))
    rows,_=run(pcap([good+status+battery(76)]),live=True)
    assert snapshots(rows)[0][0]['battery_status']==[{'battery_id':0,'remaining_pct':76}],rows
    times=list(range(0,140,10))
    rows,_=run(pcap([good+battery(76)]+[status]*(len(times)-1),times=times),
        'redef DroneDetector::log_interval = 10secs;\n',live=True)
    assert snapshots(rows)[-1][0]['battery_status']==[{'remaining_pct':90}],rows[-1]
    cases+=1
    print(f'PASS: {cases} telemetry/live-logging scenarios (actual Zeek, valid transport checksums).')

if __name__=='__main__':main()
