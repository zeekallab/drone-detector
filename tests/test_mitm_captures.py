#!/usr/bin/env python3
"""Optional ISOT MITM and normal-flight regressions; no capture redistribution."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))
def main():
    files=sorted((BASE/'MITM').glob('*.pcap'))
    if len(files)!=12:print('SKIP: set ISOT_CAPTURE_ROOT to the extracted Raw Data directory.');return
    files += [BASE/'Regular'/n for n in ['regular_16_2_5_20.pcap','regular_16_1_5_20.pcap','regular_15_5_20.pcap']]
    for p in files:
        with tempfile.TemporaryDirectory(prefix='drone-mitm-') as tmp:
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(p),str(ROOT/'scripts/arp.zeek'),'LogAscii::use_json=T'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),p.name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            hits=[x for x in rows if any(a.startswith('ARP interception') for a in x.get('alert',[]))]
            expected=p.parent.name=='MITM' and p.name!='MITM_4_5_13_fly_5mins.pcap'
            assert bool(hits)==expected,(p.name,len(rows),len(hits))
            assert rows,p.name
            if p.parent.name=='Regular':assert not any(x.get('alert') for x in rows),p.name
            byuid={}
            for row in rows:byuid.setdefault(row['uid'],[]).append(row)
            for updates in byuid.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(updates,updates[1:])),p.name
            print(json.dumps({'capture':p.name,'rows':len(rows),'arp_alert_rows':len(hits),'protocols':sorted({x['protocol'] for x in rows})}),flush=True)
if __name__=='__main__':main()
