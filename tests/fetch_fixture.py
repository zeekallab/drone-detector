#!/usr/bin/env python3
"""Fetch the PCAP shared by kresoin and verify its published SHA-256."""
import hashlib
from pathlib import Path
import subprocess
import tempfile

URL='https://github.com/kresoin/drone-digital-forensics-lab/releases/download/flightlog/traffic.pcap'
SHA256='4afd864f1021062c454fb9b4eeac1001995cd26dfa7c614f8ebcfcbca3561478'
DEST=Path(__file__).resolve().parent/'fixtures'/'traffic.pcap'


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def main():
    DEST.parent.mkdir(parents=True,exist_ok=True)
    if DEST.exists():
        if digest(DEST)!=SHA256:raise SystemExit(f'Existing file has an unexpected hash; preserved: {DEST}')
        print(f'Already verified: {DEST}');return
    with tempfile.NamedTemporaryFile(dir=DEST.parent,suffix='.part',delete=False) as f:temp=Path(f.name)
    try:
        subprocess.run(['curl','--fail','--location','--retry','2',URL,'--output',str(temp)],check=True)
        if digest(temp)!=SHA256:raise SystemExit('Downloaded file hash mismatch; not installed.')
        temp.replace(DEST)
    finally:
        temp.unlink(missing_ok=True)
    print(f'Verified {DEST}\nCredit: https://github.com/kresoin')

if __name__=='__main__':main()
