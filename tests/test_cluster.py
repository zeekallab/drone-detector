#!/usr/bin/env python3
"""Actual Broker relay: SDK state and video handlers run on separate workers.

Uses synthetic udp_contents events, not network packet injection. All processes
communicate over loopback; no sensor or external network traffic is generated.
"""
import json, os, random, socket, subprocess, tempfile
from pathlib import Path
from test_tello import STATE
from test_video import SPS, PPS, slice
ROOT = Path(__file__).resolve().parents[1]

def literal(data):
    return '"' + ''.join('\\x%02x' % b for b in data) + '"'

def main():
    names = ['manager', 'proxy', 'state-worker', 'video-worker']
    # Reserve distinct ephemeral ports until just before launching the cluster.
    reservations = [socket.socket() for _ in names]
    for sock in reservations:
        for attempt in range(100):
            try:
                sock.bind(('127.0.0.1', random.randint(20000,30000)))
                break
            except OSError:
                if attempt == 99: raise
    ports = [sock.getsockname()[1] for sock in reservations]
    layout = 'redef Cluster::nodes = {\n' + ',\n'.join(
        f'["{name}"] = [$node_type=Cluster::{kind}, $ip=127.0.0.1, $p={port}/tcp'+
        (', $manager="manager"' if name != 'manager' else '')+']'
        for name, kind, port in zip(names, ['MANAGER','PROXY','WORKER','WORKER'], ports)) + '\n};\n'
    script = '''@load policy/frameworks/cluster/backend/broker
@load PACKAGE
module DroneTello;
redef exit_only_after_terminate = T;
redef Log::enable_local_logging = T;
redef Log::enable_remote_logging = F;
redef Log::default_rotation_interval = 0secs;
redef Log::default_rotation_postprocessor_cmd = "";
redef LogAscii::use_json = T;
redef DroneTello::correlation_age = 3secs;
redef DroneTello::pair_publish_interval = 1sec;
redef DroneTello::max_known_pairs = 2;
global relayed: count = 0;
global videos: count = 0;
global expected_pair_ts: time;
global check_order: event();
global cstate: connection;
global cvideo: connection;
function check(ok: bool, msg: string) { if ( ! ok ) Reporter::fatal(msg); }
function conn(uid: string, sp: port, dp: port): connection
    {
    local ep = endpoint($size=0,$state=0,$flow_label=0);
    return connection($id=[$orig_h=192.0.2.1,$orig_p=sp,$resp_h=192.0.2.2,$resp_p=dp],
        $orig=ep,$resp=ep,$start_time=network_time(),$duration=0secs,
        $service=set(),$history="D",$uid=uid);
    }
event DroneTello::pair_confirmed(drone: addr, controller: addr, ts: time) &priority=-5
    { if ( Cluster::local_node_type() == Cluster::PROXY ) ++relayed; }
hook DroneDetector::enrich_log(rec: DroneDetector::Info)
    { if ( rec$protocol == "tello-video" ) ++videos; }
event video_probe()
    {
    event udp_contents(cvideo,T,SPS);
    event udp_contents(cvideo,T,PPS);
    event udp_contents(cvideo,T,SLICE0);
    event udp_contents(cvideo,T,SLICE1);
    event udp_contents(cvideo,T,SLICE2);
    }
event refresh() { event udp_contents(cstate,T,STATE); }
event send_state()
    {
    check(Cluster::get_active_node_count(Cluster::PROXY) == 1,"proxy unavailable");
    for ( i in vector(1,2,3,4,5,6,7,8,9,10) )
        for ( j in vector(1,2,3,4,5,6,7,8,9,10) ) event udp_contents(cstate,T,STATE);
    schedule 1.5secs { refresh() };
    }
event check_shared()
    {
    check(videos == 0,"video identified without SDK evidence");
    check(DroneTello::recent_pair(192.0.2.1,192.0.2.2),"pair did not cross workers");
    local old = DroneTello::known_pairs[192.0.2.1,192.0.2.2];
    expected_pair_ts=old;
    event DroneTello::pair_confirmed(192.0.2.1,192.0.2.2,old-1sec);
    event video_probe();
    schedule 0.2secs { check_order() };
    }
event check_order()
    { check(known_pairs[192.0.2.1,192.0.2.2] == expected_pair_ts,"older update replaced current evidence"); }
event finish()
    {
    if ( Cluster::node == "proxy" ) check(relayed == 2,"publication not throttled/refreshed");
    if ( Cluster::node == "video-worker" )
        {
        check(videos == 1,"expected exactly one correlated video record");
        check(! DroneTello::recent_pair(192.0.2.1,192.0.2.2),"stale pair remained valid");
        check(! DroneTello::receive_pair(192.0.2.9,192.0.2.2,network_time()-10secs),"accepted stale evidence");
        check(! DroneTello::receive_pair(192.0.2.9,192.0.2.2,network_time()+60secs),"accepted future evidence");
        known_pairs=table(); # Isolate capacity checks from expiry timer scheduling.
        check(DroneTello::receive_pair(192.0.2.10,192.0.2.2,network_time()),"fresh insert failed");
        check(DroneTello::receive_pair(192.0.2.11,192.0.2.2,network_time()),"fresh insert failed");
        check(! DroneTello::receive_pair(192.0.2.12,192.0.2.2,network_time()),"pair bound exceeded");
        check(DroneTello::control_tracking_limited_until > network_time(),"missing limit warning");
        }
    print fmt("PASS %s",Cluster::node);
    terminate();
    }
event zeek_init()
    {
    Log::add_filter(DroneDetector::LOG, [$name="cluster-test",$path="drone-test",$log_local=T,$log_remote=F]);
    cstate=conn("Cstate",8889/udp,8890/udp);
    cvideo=conn("Cvideo",62515/udp,11111/udp);
    if ( Cluster::node == "state-worker" ) schedule 3secs { send_state() };
    if ( Cluster::node == "video-worker" )
        {
        schedule 1sec { video_probe() };
        schedule 5secs { check_shared() };
        }
    schedule 9secs { finish() };
    }
'''
    for key, value in {'PACKAGE':str(ROOT/'scripts'), 'STATE':literal(STATE),
                       'SPS':literal(SPS),'PPS':literal(PPS),
                       'SLICE0':literal(slice(0,True)), 'SLICE1':literal(slice(1)), 'SLICE2':literal(slice(2))}.items():
        script=script.replace(key,value)
    with tempfile.TemporaryDirectory(prefix='drone-cluster-') as tmp:
        base=Path(tmp); (base/'package').symlink_to(ROOT/'scripts',target_is_directory=True)
        (base/'test.zeek').write_text(script.replace(str(ROOT/'scripts'),str(base/'package')))
        procs=[]
        try:
            for sock in reservations: sock.close()
            for name in names:
                dest=base/name; dest.mkdir(); (dest/'cluster-layout.zeek').write_text(layout)
                procs.append((name,subprocess.Popen([os.environ.get('ZEEK','zeek'),str(base/'test.zeek')],
                    cwd=dest, env=dict(os.environ,CLUSTER_NODE=name), stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)))
            for name,p in procs:
                out,err=p.communicate(timeout=25)
                assert p.returncode==0 and f'PASS {name}' in out,(name,out,err)
                print(out.strip())
            logs=list((base/'video-worker').glob('drone-test*.log'))
            assert logs, list((base/'video-worker').iterdir())
            rows=[json.loads(line) for p in logs for line in p.read_text().splitlines()]
            assert len(rows)==1 and rows[0]['video_active'] and rows[0]['video_codec']=='H264',rows
        finally:
            for _,p in procs:
                if p.poll() is None: p.kill();p.wait()
    print('PASS: real four-process cluster relay, separate SDK/video workers, throttling, refresh, expiry and receive bounds.')
if __name__=='__main__': main()
