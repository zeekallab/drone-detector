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
    with tempfile.TemporaryDirectory(prefix='drone-author-replay-') as tmp:
        tmp=Path(tmp)
        # Only this host-captured fixture needs -C: its transport checksums are partial.
        # The detector still validates MAVLink's message CRC with CRC_EXTRA.
        r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(DEST),
                          str(ROOT/'scripts'),'LogAscii::use_json=T'],cwd=tmp,text=True,capture_output=True)
        assert r.returncode==0,r.stdout+r.stderr
        assert not (tmp/'reporter.log').exists(),(tmp/'reporter.log').read_text()
        rows=[json.loads(x) for x in (tmp/'drone.log').read_text().splitlines()]
        conns=[json.loads(x) for x in (tmp/'conn.log').read_text().splitlines()]
        assert len(rows)==2,rows
        total=0
        for row in rows:
            assert row['protocol']=='mavlink' and row['likely_manufacturer']=='unknown',row
            assert row['mavlink_versions']==[2] and 'ArduPilot' in row['autopilot_software'],row
            assert 'quadrotor' in row['vehicle_types'],row
            assert row['checksum_failures']==row['malformed_frames']==0,row
            assert not row['inspection_limited'] and not row['metadata_limited'],row
            assert row['signed_messages']==0 and row['signature_validation']=='not-performed',row
            assert any(c['uid']==row['uid'] and c.get('drone_protocol')=='mavlink' for c in conns),row
            total+=row['orig_messages']+row['resp_messages']
            if row['id.resp_h']=='10.13.0.4':
                assert (row['orig_messages'],row['resp_messages'])==(16986,268),row
                assert row['commands']==[300] and row['mission_item_counts']==[60],row
                assert row['parameter_ids']==['RTL_ALT'] and row['requested_modes']==[6],row
                assert row['zero_component_messages']==130,row
                assert set(row['command_acks'])=={'command=300;result=0','command=11;result=0'},row
            else:
                assert row['id.resp_h']=='172.17.0.1' and row['orig_messages']==16980,row
        assert total==34234,total
        print('PASS: kresoin capture, two MAVLink connections, 34,234 CRC-valid message observations, mission/parameter/mode evidence.')

if __name__=='__main__':main()
