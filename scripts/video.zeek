@load ./tello

module DroneVideo;

export {
    # Tello SDK Annex-B H.264 transport. This port is a delivery hint, not identity.
    const ports: set[port] = { 11111/udp } &redef;
    const evidence_age = 10secs &redef;
    const prefix_bytes: count = 128 &redef;
    const max_inspected_bytes: count = 4194304 &redef;
    redef record DroneDetector::Info += {
        video_active: bool &log &optional;
        video_codec: string &log &optional;
    };
}

type State: record {
    drone: addr;
    controller: addr;
    sps: time &optional;
    pps: time &optional;
    idr: time &optional;
    slices: table[string] of time;
    budget_start: time;
    inspected: count &default=0;
    limited: bool &default=F;
    logging: DroneDetector::LogState &default=DroneDetector::LogState();
    last_log: time &optional;
    confirmed: bool &default=F;
};
redef record connection += { drone_video: State &optional; };

function byte(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+1]); }

function observe_slice(s: State, data: string)
    {
    local key=sha256_hash(data);
    if ( key !in s$slices && |s$slices| >= 3 )
        {
        local oldest=""; local oldest_ts=network_time();
        for ( k in s$slices )
            if ( oldest == "" || s$slices[k] < oldest_ts ) { oldest=k; oldest_ts=s$slices[k]; }
        delete s$slices[oldest];
        }
    s$slices[key]=network_time();
    }

function evidence(s: State): bool
    {
    if ( ! s?$sps || ! s?$pps || ! s?$idr || |s$slices| < 3 ) return F;
    if ( network_time()-s$sps > evidence_age || network_time()-s$pps > evidence_age ||
         network_time()-s$idr > evidence_age ) return F;
    for ( k in s$slices ) if ( network_time()-s$slices[k] > evidence_age ) return F;
    return T;
    }

global emit: function(c: connection, final: bool);

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    local dp=is_orig ? c$id$resp_p : c$id$orig_p;
    if ( dp !in ports ) return;
    local source=is_orig ? c$id$orig_h : c$id$resp_h;
    local dest=is_orig ? c$id$resp_h : c$id$orig_h;
    # SDK telemetry establishes the source as a drone peer, not merely an IP/port.
    if ( ! DroneTello::recent_pair(source,dest) ) return;
    if ( ! c?$drone_video )
        c$drone_video=State($drone=source,$controller=dest,$slices=table(),$budget_start=network_time());
    local s=c$drone_video;
    if ( s$drone != source || s$controller != dest ) return;
    if ( network_time()-s$budget_start >= 60secs ) { s$budget_start=network_time(); s$inspected=0; }
    local size=|contents| < prefix_bytes ? |contents| : prefix_bytes;
    if ( size > max_inspected_bytes-s$inspected ) { s$limited=T; return; }
    s$inspected+=size;
    local data=contents[:size];
    local i: count=0; local slice=F;
    while ( i+6 <= |data| )
        {
        # Four-byte start codes also contain this three-byte suffix.
        if ( data[i:i+3] != "\x00\x00\x01" ) { ++i; next; }
        local n=i+3; local h=byte(data,n); local typ=h%32;
        if ( h >= 128 ) { i=n+1; next; } # forbidden_zero_bit
        if ( typ == 7 && h/32 > 0 && n+4 <= |data| &&
             byte(data,n+1) in set(44,66,77,83,86,88,100,110,118,122,128,134,135,138,139,244) &&
             byte(data,n+2)%4 == 0 && byte(data,n+3) >= 10 && byte(data,n+3) <= 62 )
            s$sps=network_time();
        else if ( typ == 8 && h/32 > 0 ) s$pps=network_time();
        else if ( typ == 5 && h/32 > 0 ) { s$idr=network_time(); slice=T; }
        else if ( typ == 1 ) slice=T;
        i=n+1;
        }
    if ( ! slice ) return;
    observe_slice(s,data);
    if ( ! evidence(s) ) return;
    s$confirmed=T;
    s$logging$dirty=T;
    emit(c,F);
    }

function emit(c: connection, final: bool)
    {
    local s=c$drone_video;
    local kind=DroneDetector::connection_log_kind(c,s$logging,set(),final);
    if ( kind == "" ) return;
    DroneDetector::write_state([$ts=network_time(),$event_type=s?$last_log ? "update" : "detection",
        $uid=c$uid,$id=c$id,$likely_manufacturer="DJI/Ryze",$protocol="tello-video",
        $evidence="recent-sdk-state-pair+h264-annex-b-sps-pps-idr+distinct-slice-prefixes",
        $inspection_limited=s$limited,$drone_host=s$drone,$controller_host=s$controller,
        $video_active=T,$video_codec="H264"],s$logging,kind);
    s$last_log=network_time(); c$drone_log_ts=network_time();
    }

event zeek_init() &priority=5
    { for ( p in ports ) add udp_content_ports[p]; }

event connection_state_remove(c: connection) &priority=0
    {
    if ( ! c?$drone_video || ! c$drone_video$confirmed ) return;
    emit(c,T);
    if ( ! c?$conn ) return;
    c$conn$drone_protocol="tello-video";
    c$conn$drone_likely_manufacturer="DJI/Ryze";
    c$conn$drone_evidence="recent-sdk-state-pair+h264-annex-b";
    }
