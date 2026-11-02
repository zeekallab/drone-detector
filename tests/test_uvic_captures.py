#!/usr/bin/env python3
"""Coverage-gap regressions: Tello fixtures must not be mislabeled as MAVLink/DJI legacy."""
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
            assert not drone.exists() or not drone.read_text().strip(),e
            conns=[json.loads(x) for x in (tmp/'conn.log').read_text().splitlines()]
            assert any(c['proto']=='udp' and c['id.resp_p']==8889 and c.get('orig_bytes',0)>0 for c in conns),e
    print(f'PASS: {len(entries)} UVic Tello captures are not falsely classified as MAVLink or legacy DJI, including on candidate ports.')

if __name__=='__main__':main()
