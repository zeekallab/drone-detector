@load ./main

module DroneTelloBinary;

export {
    const ports: set[port] = { 8889/udp } &redef;
    const minimum_valid_frames: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_fingerprints: count = 2048 &redef;
    const replay_min_age = 2secs &redef;
    const replay_max_age = 120secs &redef;
    const replay_min_frames: count = 20 &redef;
    const replay_min_distinct: count = 5 &redef;
    const replay_min_fraction = 0.5 &redef;
    const malformed_min_frames: count = 3 &redef;
    redef record DroneDetector::Info += {
        binary_control_frames: count &log &optional;
        binary_replayed_frames: count &log &optional;
        binary_replayed_distinct: count &log &optional;
        binary_malformed_control_frames: count &log &optional;
        binary_tracking_limited: bool &log &optional;
    };
}

global crc8_table: vector of count = vector();
global crc16_table: vector of count = vector();

type Direction: record {
    valid: count &default=0;
    evidence: set[string];
    seen: table[string] of time;
    replayed: set[string];
    controls: count &default=0;
    repeats: count &default=0;
    malformed: count &default=0;
};
type State: record {
    orig: Direction;
    resp: Direction;
    last_log: time &optional;
    budget_start: time;
    inspected: count &default=0;
    limited: bool &default=F;
    tracking_limited: bool &default=F;
};
redef record connection += { tello_binary: State &optional; };

function le(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+2],T); }

function header_ok(data: string): bool
    {
    local value: count = 119;
    local i: count = 0;
    while ( i < 3 )
        { value=crc8_table[value ^ bytestring_to_count(data[i:i+1])]; ++i; }
    return value == bytestring_to_count(data[3:4]);
    }

function frame_ok(data: string): bool
    {
    local value: count = 13970;
    local i: count = 0;
    while ( i < |data|-2 )
        { value=crc16_table[(value ^ bytestring_to_count(data[i:i+1])) % 256] ^ (value / 256); ++i; }
    return value == le(data,|data|-2);
    }

function confirmed(d: Direction): bool
    { return |d$evidence| >= minimum_valid_frames; }

global reset_window: function(d: Direction);

function emit(c: connection, s: State)
    {
    if ( c?$drone_log_ts && network_time()-c$drone_log_ts < DroneDetector::log_interval ) return;
    if ( ! confirmed(s$orig) && ! confirmed(s$resp) ) return;
    if ( s?$last_log && network_time()-s$last_log < DroneDetector::log_interval ) return;
    local alerts: set[string] = set();
    for ( d in vector(s$orig,s$resp) )
        {
        local dir = d == 0 ? s$orig : s$resp;
        if ( ! confirmed(dir) ) next;
        if ( dir$repeats >= replay_min_frames && |dir$replayed| >= replay_min_distinct &&
             dir$controls > 0 && count_to_double(dir$repeats)/count_to_double(dir$controls) >= replay_min_fraction )
            add alerts["Replay-like control traffic: repeated older, checksum-valid Tello joystick messages"];
        if ( dir$malformed >= malformed_min_frames )
            add alerts["Malformed control traffic: repeated Tello joystick length or checksum failures"];
        }
    local rec=DroneDetector::Info($ts=network_time(),$event_type=s?$last_log ? "update" : "detection",
        $uid=c$uid,$id=c$id,$likely_manufacturer="DJI/Ryze",$protocol="tello-binary",
        $evidence="length+header-crc8+frame-crc16",$orig_messages=s$orig$valid,$resp_messages=s$resp$valid,
        $inspection_limited=s$limited,$binary_tracking_limited=s$tracking_limited,
        $binary_control_frames=s$orig$controls+s$resp$controls,
        $binary_replayed_frames=s$orig$repeats+s$resp$repeats,
        $binary_replayed_distinct=|s$orig$replayed|+|s$resp$replayed|,
        $binary_malformed_control_frames=s$orig$malformed+s$resp$malformed);
    if ( |alerts| > 0 ) rec$alert=alerts;
    DroneDetector::write_log(rec);
    c$drone_log_ts=network_time();
    s$last_log=network_time();
    reset_window(s$orig); reset_window(s$resp);
    }

function reset_window(d: Direction)
    {
    d$controls=0; d$repeats=0; d$malformed=0; d$replayed=set();
    local expired: set[string] = set();
    for ( key in d$seen )
        if ( network_time()-d$seen[key] > replay_max_age ) add expired[key];
    for ( key in expired ) delete d$seen[key];
    }

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    if ( c$id$orig_p !in ports && c$id$resp_p !in ports ) return;
    if ( |contents| < 11 || |contents| > 2048 || contents[0:1] != "\xcc" ) return;
    if ( ! c?$tello_binary )
        c$tello_binary=State($orig=Direction($evidence=set(),$seen=table(),$replayed=set()),
            $resp=Direction($evidence=set(),$seen=table(),$replayed=set()),
            $budget_start=network_time());
    local s=c$tello_binary;
    if ( network_time()-s$budget_start >= 60secs && (confirmed(s$orig) || confirmed(s$resp)) )
        { s$budget_start=network_time(); s$inspected=0; }
    if ( |contents| > max_inspected_bytes-s$inspected )
        { s$inspected=max_inspected_bytes; s$limited=T; return; }
    s$inspected+=|contents|;
    local d=is_orig ? s$orig : s$resp;
    # Header integrity must establish the declared length/command before classifying damage.
    if ( ! header_ok(contents) ) return;
    local dp=is_orig ? c$id$resp_p : c$id$orig_p;
    local stick=dp in ports && le(contents,5)==80 && contents[4:5]=="\x60";
    local valid=le(contents,1)/8 == |contents| && frame_ok(contents);
    if ( ! valid )
        {
        if ( stick && confirmed(d) ) { ++d$malformed; emit(c,s); }
        return;
        }
    ++d$valid;
    local key=sha256_hash(contents);
    if ( |d$evidence| < minimum_valid_frames ) add d$evidence[key];
    if ( stick && confirmed(d) )
        {
        ++d$controls;
        if ( key in d$seen )
            {
            local age=network_time()-d$seen[key];
            if ( age >= replay_min_age && age <= replay_max_age )
                {
                ++d$repeats;
                if ( |d$replayed| < max_fingerprints ) add d$replayed[key];
                else s$tracking_limited=T;
                }
            }
        if ( key in d$seen || |d$seen| < max_fingerprints ) d$seen[key]=network_time();
        else s$tracking_limited=T;
        }
    emit(c,s);
    }

event zeek_init() &priority=5
    {
    local i: count = 0;
    while ( i < 256 )
        {
        local a=i; local b=i; local j: count=0;
        while ( j < 8 )
            {
            a=(a/2) ^ (a%2==1 ? 140 : 0);
            b=(b/2) ^ (b%2==1 ? 33800 : 0);
            ++j;
            }
        crc8_table[i]=a; crc16_table[i]=b; ++i;
        }
    for ( p in ports ) add udp_content_ports[p];
    }

event connection_flipped(c: connection)
    {
    if ( ! c?$tello_binary ) return;
    local old=c$tello_binary$orig; c$tello_binary$orig=c$tello_binary$resp; c$tello_binary$resp=old;
    }

event connection_state_remove(c: connection) &priority=0
    {
    if ( ! c?$tello_binary || ! c?$conn ) return;
    if ( ! confirmed(c$tello_binary$orig) && ! confirmed(c$tello_binary$resp) ) return;
    c$conn$drone_protocol="tello-binary";
    c$conn$drone_likely_manufacturer="DJI/Ryze";
    c$conn$drone_evidence="length+header-crc8+frame-crc16";
    }
