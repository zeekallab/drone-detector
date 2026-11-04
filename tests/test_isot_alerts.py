#!/usr/bin/env python3
"""Optional real-capture alert checks using the user's extracted ISOT archive."""
import os,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE=Path(os.environ.get('ISOT_CAPTURE_ROOT',str(Path.home()/'Downloads/ISOT Drone Dataset/Raw Data')))

def main():
    groups=[('Manipulation',f'manipulate_{n}_5_22_10mins.pcap') for n in range(1,7)]
    groups += [('Regular',n) for n in ['regular_16_2_5_20.pcap','regular_16_1_5_20.pcap','regular_15_5_20.pcap']]
    groups += [('Password Cracking',f'pwd_crack_deau_and_eqpol_{n}_5_6_{minutes}mins_raw.pcap') for n,minutes in [(1,30),(2,45)]]
    if not all((BASE/group/name).exists() for group,name in groups):
        print('SKIP: optional extracted ISOT archive missing; set ISOT_CAPTURE_ROOT to its Raw Data folder.');return
    for group,name in groups:
        with tempfile.TemporaryDirectory(prefix='drone-isot-alerts-') as tmp:
            module=ROOT/'scripts/wifi.zeek' if group=='Password Cracking' else ROOT/'scripts'
            r=subprocess.run([os.environ.get('ZEEK','zeek'),'-C','-r',str(BASE/group/name),str(module),'LogAscii::use_json=T','DroneDetector::immediate_detections=F','DroneDetector::final_updates=F'],cwd=tmp,text=True,capture_output=True)
            assert r.returncode==0,r.stderr
            assert not (Path(tmp)/'reporter.log').exists(),name
            f=Path(tmp)/'drone.log';rows=[json.loads(x) for x in f.read_text().splitlines()] if f.exists() else []
            alerts=[a for row in rows for a in row.get('manipulation_detection',[])]
            if group=='Manipulation':
                assert any(a.startswith('Replay-like control traffic:') for a in alerts),(name,alerts)
                assert any(a.startswith('Malformed control traffic:') for a in alerts),(name,alerts)
            elif group=='Regular':
                assert rows and not alerts,(name,alerts)
            else:
                assert alerts and all(a.startswith('Wireless deauthentication burst:') for a in alerts),name
                assert any(row.get('wireless_eapol_key_frames',0)>0 for row in rows),name
                assert all('uid' not in row for row in rows if row['protocol']=='802.11'),name
            groups_by_key={}
            for row in rows:groups_by_key.setdefault(row.get('uid',row.get('wireless_bssid')),[]).append(row)
            for updates in groups_by_key.values():
                assert all(b['ts']-a['ts']>=60 for a,b in zip(updates,updates[1:])),name
            print(f'PASS: {group}/{name}: {len(rows)} rows, {len(alerts)} alert descriptions.',flush=True)

if __name__=='__main__':main()
