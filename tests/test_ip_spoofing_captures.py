#!/usr/bin/env python3
"""Optional regression for existing Tello replay coverage in IP-spoofing captures."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get(
    'ISOT_CAPTURE_ROOT', str(Path.home() / 'Downloads/ISOT Drone Dataset/Raw Data')))
ALERT = 'Replay-like control traffic: repeated older, checksum-valid Tello joystick messages'


def main():
    manifest = json.loads((ROOT / 'tests/fixtures/uvic/ip-spoofing-manifest.json').read_text())
    files = [BASE / Path(item['member']).relative_to('Raw Data') for item in manifest]
    if not all(p.is_file() for p in files):
        print('SKIP: set ISOT_CAPTURE_ROOT to extracted Raw Data containing all ten IP Spoofing captures.')
        return
    for p, item in zip(files, manifest):
        assert hashlib.sha256(p.read_bytes()).hexdigest() == item['sha256'], p.name
        with tempfile.TemporaryDirectory(prefix='drone-ip-spoofing-') as tmp:
            result = subprocess.run(
                [os.environ.get('ZEEK', 'zeek'), '-C', '-r', str(p),
                 str(ROOT / 'scripts'), 'LogAscii::use_json=T','DroneDetector::immediate_detections=F','DroneDetector::final_updates=F'],
                cwd=tmp, capture_output=True, text=True)
            assert result.returncode == 0, (p.name, result.stderr)
            assert not (Path(tmp) / 'reporter.log').exists(), p.name
            log = Path(tmp) / 'drone.log'
            rows = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            binary = [row for row in rows if row['protocol'] == 'tello-binary']
            assert binary, p.name
            hits = sum(ALERT in row.get('manipulation_detection', []) for row in binary)
            assert hits, p.name
            groups = {}
            for row in rows:
                groups.setdefault(row['uid'], []).append(row['ts'])
            for times in groups.values():
                assert all(b - a >= 60 for a, b in zip(times, times[1:])), p.name
            print(f'{p.name}: PASS ({len(rows)} rows, {hits} existing replay-alert rows)', flush=True)


if __name__ == '__main__':
    main()
