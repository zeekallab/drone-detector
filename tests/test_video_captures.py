#!/usr/bin/env python3
"""Two selected real video captures; avoids scanning the entire large folder."""
import json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))
def main():
    names=['video_6_5_14_5mins.pcap','video_7_5_14_10mins.pcap']
    if not all((BASE/'Video'/n).exists() for n in names):print('SKIP: selected ISOT video captures absent.');return
    for name in names:
        with tempfile.TemporaryDirectory(prefix='drone-video-') as tmp:
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(BASE/'Video'/name),str(ROOT/'scripts'),'LogAscii::use_json=T'],cwd=tmp,capture_output=True,text=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            videos=[r for r in rows if r.get('video_active')]
            assert videos,name
            assert all(r['video_codec']=='H264' and r['drone_host']=='192.168.10.1' and r['controller_host']=='192.168.10.4' and 'alert' not in r for r in videos),videos
            groups={}
            for r in rows:groups.setdefault(r['uid'],[]).append(r)
            for g in groups.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(g,g[1:])),name
            print(json.dumps({'capture':name,'rows':len(rows),'video_rows':len(videos),'video_uids':len({r['uid'] for r in videos}),'video_times':[r['ts'] for r in videos],'inspection_limited':any(r['inspection_limited'] for r in videos)}),flush=True)
if __name__=='__main__':main()
