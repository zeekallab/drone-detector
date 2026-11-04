#!/usr/bin/env python3
"""Six Replay captures, six Manipulation regressions, three normal comparisons."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))
def main():
    files=sorted((BASE/'Replay').glob('*.pcap'))
    if len(files)!=6:print('SKIP: set ISOT_CAPTURE_ROOT to extracted Raw Data.');return
    files+=sorted((BASE/'Manipulation').glob('*.pcap'))
    files += [BASE/'Regular'/n for n in ['regular_16_2_5_20.pcap','regular_16_1_5_20.pcap','regular_15_5_20.pcap']]
    for p in files:
        with tempfile.TemporaryDirectory(prefix='drone-replay-') as tmp:
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(p),str(ROOT/'scripts'),'LogAscii::use_json=T','DroneDetector::immediate_detections=F','DroneDetector::final_updates=F'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),p.name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            assert rows,p.name
            def hits(prefix):return sum(any(a.startswith(prefix) for a in x.get('manipulation_detection',[])) for x in rows)
            if p.parent.name=='Replay':assert hits('Rapid replay-like') and not hits('Malformed'),p.name
            elif p.parent.name=='Manipulation':assert hits('Replay-like') and hits('Malformed'),p.name
            else:assert not any(x.get('manipulation_detection') for x in rows),p.name
            groups={}
            for x in rows:groups.setdefault(x['uid'],[]).append(x)
            for g in groups.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(g,g[1:])),p.name
            print(json.dumps({'capture':p.name,'rows':len(rows),'rapid_replay_rows':hits('Rapid replay-like'),'older_replay_rows':hits('Replay-like'),'malformed_rows':hits('Malformed'),'rapid_repeat_observations':sum(x.get('binary_rapid_replayed_frames',0) for x in rows)}),flush=True)
if __name__=='__main__':main()
