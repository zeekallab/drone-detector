#!/usr/bin/env python3
"""Run synthetic tests, then the credited real fixture when available."""
from pathlib import Path
import subprocess
import sys
root=Path(__file__).resolve().parent
for name in ['test_detector.py','test_mavlink.py','test_telemetry.py','test_activity.py','test_tello.py','test_tello_binary.py','test_wifi.py','test_arp.py','test_uvic_captures.py']:
    subprocess.run([sys.executable,str(root/name)],check=True)
if (root/'fixtures'/'traffic.pcap').exists():
    subprocess.run([sys.executable,str(root/'test_author_capture.py')],check=True)
else:
    print('SKIP: author PCAP not downloaded. Run python3 tests/fetch_fixture.py, then rerun.')
