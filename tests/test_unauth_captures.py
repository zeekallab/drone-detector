#!/usr/bin/env python3
"""Source-port churn captures and SDK/normal comparisons; originals stay external."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))
def main():
    files=sorted((BASE/'Unauth').glob('*.pcap'))
    if len(files)!=8:print('SKIP: set ISOT_CAPTURE_ROOT to extracted Raw Data.');return
    files+=sorted((BASE/'Injection').glob('*.pcap'))
    files+=sorted((BASE/'MITM').glob('mitm_station_mode_*.pcap'))
    files += [BASE/'Regular'/n for n in ['regular_16_2_5_20.pcap','regular_16_1_5_20.pcap','regular_15_5_20.pcap']]
    for p in files:
        with tempfile.TemporaryDirectory(prefix='drone-pair-') as tmp:
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(p),str(ROOT/'scripts'),'LogAscii::use_json=T','DroneDetector::immediate_detections=F','DroneDetector::final_updates=F'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),p.name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            assert rows,p.name
            summaries=[x for x in rows if x.get('sdk_summary_scope')=='host-pair']
            churn=[x for x in summaries if any(a.startswith('Control source-port churn') for a in x.get('manipulation_detection',[]))]
            maneuvers=[x for x in summaries if x.get('sdk_repetitive_axes')]
            assert bool(churn)==(p.parent.name=='Unauth'),(p.name,rows)
            if p.parent.name=='Unauth':
                assert sum(x.get('sdk_ok_responses',0)+x.get('sdk_error_responses',0) for x in summaries)>0,p.name
                assert all('orig_messages' not in x and x.get('sdk_related_uids') for x in summaries),p.name
            if p.parent.name=='Regular':assert not any(x.get('manipulation_detection') for x in rows),p.name
            if p.parent.name=='Injection':assert bool(maneuvers)==(int(p.name.split('_')[2])>=3),p.name
            groups={}
            for x in summaries:groups.setdefault((x['drone_host'],x['controller_host']),[]).append(x)
            for g in groups.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(g,g[1:])),p.name
            print(json.dumps({'capture':p.name,'rows':len(rows),'command_summaries':len(summaries),'churn_rows':len(churn),'maneuver_rows':len(maneuvers),'logged_response_count':sum(x.get('sdk_ok_responses',0)+x.get('sdk_error_responses',0)+x.get('sdk_unknown_command_responses',0) for x in summaries)}),flush=True)
if __name__=='__main__':main()
