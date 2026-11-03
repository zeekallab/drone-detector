#!/usr/bin/env python3
"""Real Tello SDK positive and unsupported binary-protocol negative regressions."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FIXTURES=ROOT/'tests/fixtures/uvic'

def main():
    entries=json.loads((FIXTURES/'manifest.json').read_text())
    if not all((FIXTURES/e['name']).exists() for e in entries):
        print('SKIP: optional UVic captures absent; see tests/fixtures/uvic/README.md.');return
    for e in entries:
        capture=FIXTURES/e['name']
        assert hashlib.sha256(capture.read_bytes()).hexdigest()==e['sha256'],e
        with tempfile.TemporaryDirectory(prefix='drone-uvic-') as tmp:
            tmp=Path(tmp);(tmp/'package').symlink_to(ROOT/'scripts',target_is_directory=True)
            (tmp/'settings.zeek').write_text('@load ./package\nredef LogAscii::use_json = T;\nredef DroneMAVLink::ports += {8889/udp,8890/udp};\n')
            # Force application inspection even if capture transport checksums are bad.
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(capture),'settings.zeek'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stdout+r.stderr
            assert not (tmp/'reporter.log').exists(),e
            drone=tmp/'drone.log'
            rows=[json.loads(line) for line in drone.read_text().splitlines()] if drone.exists() else []
            if e['name'].startswith('Instruction_injection'):
                assert len(rows)==9,rows
                assert all(row['protocol']=='tello-sdk' for row in rows),rows
                byuid={}
                commands=set()
                for row in rows:
                    byuid.setdefault(row['uid'],[]).append(row)
                    if 'telemetry' in row:
                        t=json.loads(row['telemetry'])[0]
                        assert 0<=t['battery_remaining_pct']<=100 and 'latitude' not in t,t
                        assert row['drone_host']=='192.168.10.1',row
                    if 'control_activity' in row:
                        commands.update(a['command'] for a in json.loads(row['control_activity']))
                assert {'command','forward 20','back 20','cw 10','ccw 10'} <= commands,commands
                for updates in byuid.values():
                    assert updates[0]['event_type']=='detection',updates
                    assert all(b['ts']-a['ts']>=60 for a,b in zip(updates,updates[1:])),updates
            else:
                assert not rows,(e,rows)
            conns=[json.loads(x) for x in (tmp/'conn.log').read_text().splitlines()]
            assert any(c['proto']=='udp' and c['id.resp_p']==8889 and c.get('orig_bytes',0)>0 for c in conns),e
    print('PASS: UVic SDK injection capture produces nine rate-limited Tello entries; three binary captures remain negative.')

if __name__=='__main__':main()
