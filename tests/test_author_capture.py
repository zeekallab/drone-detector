#!/usr/bin/env python3
"""Real regression fixture shared by https://github.com/kresoin (see fixtures/README.md)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from fetch_fixture import DEST,SHA256,digest

ROOT=Path(__file__).resolve().parents[1]


def main():
    if not DEST.exists():raise SystemExit('Run python3 tests/fetch_fixture.py first (286,920,580-byte download).')
    assert digest(DEST)==SHA256,'Unexpected capture hash'
    for diagnostic in (False,True):
        with tempfile.TemporaryDirectory(prefix='drone-author-replay-') as tmp:
            tmp=Path(tmp)
            # Only this host-captured fixture needs -C: transport checksums are partial.
            # MAVLink CRC and CRC_EXTRA are still checked.
            settings=tmp/'settings.zeek'
            (tmp/'package').symlink_to(ROOT/'scripts',target_is_directory=True)
            settings.write_text('@load ./package\nredef LogAscii::use_json = T;\nredef DroneDetector::immediate_detections = F;\nredef DroneDetector::final_updates = F;\n' +
                                f'redef DroneDetector::include_diagnostics = {"T" if diagnostic else "F"};\n')
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(DEST),str(settings)],cwd=tmp,text=True,capture_output=True)
            assert r.returncode==0,r.stdout+r.stderr
            assert not (tmp/'reporter.log').exists(),(tmp/'reporter.log').read_text()
            rows=[json.loads(x) for x in (tmp/'drone.log').read_text().splitlines()]
            conns=[json.loads(x) for x in (tmp/'conn.log').read_text().splitlines()]
            assert len(rows)==4,rows
            grouped={}
            for row in rows:grouped.setdefault(row['uid'],[]).append(row)
            assert len(grouped)==2,grouped
            for uid,updates in grouped.items():
                assert [r['event_type'] for r in updates]==['detection','update'],updates
                assert 60<=updates[1]['ts']-updates[0]['ts']<61,updates
                assert any(c['uid']==uid and c.get('drone_protocol')=='mavlink' for c in conns),uid
                for i,row in enumerate(updates):
                    assert row['protocol']=='mavlink' and row['likely_manufacturer']=='unknown',row
                    assert row['mavlink_versions']==[2] and row['autopilot_software']==['ArduPilot'],row
                    assert row['simulation_observed'] and not row['signing_observed'],row
                    assert not any(row.get(k,False) for k in ['inspection_limited','metadata_limited','telemetry_limited']),row
                    t=json.loads(row['flight_telemetry'])
                    assert len(t)==1 and 'system_id' not in t[0] and 'component_id' not in t[0],t
                    t=t[0]
                    assert 37.2418<t['gps']['latitude']<37.2419 and -115.797<t['gps']['longitude']<-115.7969,t
                    assert 136<t['altitude']<141,t
                    assert 'height' not in t and 'flight' not in t,t
                    assert t['battery_status'] and all(b['remaining_pct']==100 for b in t['battery_status']),t
                    assert t['mode']==('GUIDED' if i==0 else 'RTL'),t
                    assert 'armed' not in t and 0<=t['motion']['heading_deg']<360,t
                    if diagnostic:
                        assert row['checksum_failures']==row['malformed_frames']==0,row
                    else:
                        assert 'message_types' not in row and 'reported_modes' not in row and 'matched_responses' not in row,row
                last=updates[-1]
                assert 16500<=last['orig_messages']<=17000,last
                if diagnostic and last['id.resp_h']=='10.13.0.4':
                    assert last['commands']==[300] and last['mission_item_counts']==[60],last
                    assert last['parameter_ids']==['RTL_ALT'] and last['requested_modes']==[6],last
                    assert last['zero_component_messages']==130,last
                    assert set(last['command_acks'])=={'command=300;result=0','command=11;result=0'},last
    print('PASS: kresoin capture, two connections, four rate-limited entries; coordinates, altitude, battery, motion and flight modes; diagnostics on/off.')

if __name__=='__main__':main()
