#!/usr/bin/env python3
"""Optional real injection regressions, with normal flight comparisons."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))
def main():
    files=sorted((BASE/'Injection').glob('*.pcap'))
    if len(files)!=8:print('SKIP: set ISOT_CAPTURE_ROOT to the extracted Raw Data directory.');return
    files += [BASE/'Regular'/n for n in ['regular_16_2_5_20.pcap','regular_16_1_5_20.pcap','regular_15_5_20.pcap']]
    files += sorted((BASE/'MITM').glob('mitm_station_mode_*.pcap'))
    for p in files:
        with tempfile.TemporaryDirectory(prefix='drone-injection-') as tmp:
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(p),str(ROOT/'scripts'),'LogAscii::use_json=T','DroneDetector::immediate_detections=F','DroneDetector::final_updates=F'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),p.name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            hits=[x for x in rows if any(a.startswith('Repetitive maneuver') for a in x.get('manipulation_detection',[]))]
            expected=p.parent.name=='Injection' and int(p.name.split('_')[2])>=3
            assert bool(hits)==expected,(p.name,len(rows),len(hits))
            assert rows,p.name
            if p.parent.name=='Regular':assert not any(x.get('manipulation_detection') for x in rows),p.name
            else:assert any(x.get('sdk_ok_responses',0)>0 for x in rows),p.name
            byuid={}
            for row in rows:byuid.setdefault(row['uid'],[]).append(row)
            for updates in byuid.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(updates,updates[1:])),p.name
            print(json.dumps({'capture':p.name,'rows':len(rows),'maneuver_alert_rows':len(hits),'axes':sorted({a for x in hits for a in x['sdk_repetitive_axes']}),'logged_ok':sum(x.get('sdk_ok_responses',0) for x in rows),'logged_error':sum(x.get('sdk_error_responses',0) for x in rows),'logged_unknown':sum(x.get('sdk_unknown_command_responses',0) for x in rows)}),flush=True)
if __name__=='__main__':main()
