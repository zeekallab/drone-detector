#!/usr/bin/env python3
"""Remote ID manufacturer/model file: FAA CSV -> tools/faa_to_zeek.py -> Input framework."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from test_detector import ZEEK

ROOT=Path(__file__).resolve().parent.parent
RANGES='''id,serial_start,serial_end,rid_tracking,description,status,make,model,mfr_serial,synced_at,faa_updated_at,deleted
1,1581F6Z9000000000000,1581F6Z9ZZZZZZZZZZZZ,R1,Remote ID (RID),accepted,DJI,Mini 4 Pro,,x,x,0
2,16335F0401,16335F2800,R2,Remote ID (RID),accepted,Wing Aviation LLC,Hummingbird,,x,x,0
3,1748C0000000000,1748CZZZZZZZZZZ,R3,Remote ID (RID),rescinded,Autel Robotics,Rescinded,,x,x,0
4,1588E0000000000,1588EZZZZZZZZZZ,R4,Remote ID (RID),accepted,PARROT,Deleted,,x,x,1
'''
EXACT='''serial_number,rid_tracking,description,status,make,model,mfr_serial,synced_at,faa_updated_at,deleted
1788520001,R5,Remote ID (RID),accepted,Vision Aerial,"SwitchBlade	Elite",,x,x,0
'''
PROBE='''@load ./package/wireless/manufacturers
redef DroneManufacturer::model_file = "serials.tsv";
redef exit_only_after_terminate = T;
event Input::end_of_data(name: string, source: string) &priority=-10
    {
    for ( _, s in vector("1581F6Z9C238D00323P4","16335F2439","16335F2801","1748C0000000ABC","1588E0000000ABC","1788520001","9999F0000000AAA","158") )
        {
        local i=DroneManufacturer::identify(s);
        print to_json([$serial=s,$manufacturer=i$manufacturer,$model=i?$model ? i$model : "",$source=i?$source ? i$source : ""]);
        }
    terminate();
    }
'''

def main():
    with tempfile.TemporaryDirectory(prefix='drone-mfr-') as tmp:
        tmp=Path(tmp)
        (tmp/'r.csv').write_text(RANGES);(tmp/'e.csv').write_text(EXACT)
        subprocess.run([sys.executable,'-I',str(ROOT/'tools'/'faa_to_zeek.py'),'--ranges',str(tmp/'r.csv'),'--exact',str(tmp/'e.csv'),'-o',str(tmp/'serials.tsv')],check=True,capture_output=True)
        lines=(tmp/'serials.tsv').read_text().splitlines()
        assert lines[1]=='#fields\tserial_start\tserial_end\tmake\tmodel' and len(lines)==5,lines  # rescinded + deleted dropped
        (tmp/'package').symlink_to(ROOT/'scripts',target_is_directory=True)
        (tmp/'probe.zeek').write_text(PROBE)
        r=subprocess.run([ZEEK,'probe.zeek'],cwd=tmp,capture_output=True,text=True,timeout=60)
        assert r.returncode==0,r.stdout+r.stderr
        got={d['serial']:d for d in map(json.loads,r.stdout.splitlines())}
    want={
        '1581F6Z9C238D00323P4':('DJI','Mini 4 Pro','faa-list'),
        '16335F2439':('Wing Aviation LLC','Hummingbird','faa-list'),
        '16335F2801':('Wing Aviation','','manufacturer-code'),   # outside the range: code only
        '1748C0000000ABC':('Autel Robotics','','manufacturer-code'),  # rescinded row ignored
        '1588E0000000ABC':('Parrot','','manufacturer-code'),          # deleted row ignored
        '1788520001':('Vision Aerial','SwitchBlade Elite','faa-list'),  # exact serial, tab cleaned
        '9999F0000000AAA':('','',''),
        '158':('','',''),
    }
    for s,(m,model,src) in want.items():
        g=got[s]
        assert (g['manufacturer'],g['model'],g['source'])==(m,model,src),(s,g)
    print(f'PASS: {len(want)} Remote ID manufacturer scenarios (FAA ranges/exact serials, status filtering, built-in codes, negatives).')

if __name__=='__main__':main()
