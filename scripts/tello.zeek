@load ./mavlink

module DroneTello;

export {
    const command_ports: set[port] = { 8889/udp } &redef;
    const state_ports: set[port] = { 8890/udp } &redef;
    const minimum_state_messages: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_known_pairs: count = 1024 &redef;
    const correlation_age = 120 secs &redef;
    redef record DroneDetector::Info += {
        drone_host: addr &log &optional;
        controller_host: addr &log &optional;
    };
}

# Worker-local pair learning. Never infer identity from a port or a generic "ok".
global known_pairs: table[addr,addr] of time &write_expire=correlation_age;
type Activity: record {
    command: string;
    source_host: addr;
    destination_host: addr;
    first_seen: time;
    last_seen: time;
    observations: count;
};
type State: record {
    valid: count &default=0;
    orig: count &default=0;
    resp: count &default=0;
    inspected: count &default=0;
    budget_start: time;
    confirmed: bool &default=F;
    limited: bool &default=F;
    activity_limited: bool &default=F;
    last_log: time &optional;
    drone: addr &optional;
    controller: addr &optional;
    telemetry: string &optional;
    telemetry_ts: time &optional;
    activity: table[string] of Activity;
};
redef record connection += { tello_state: State &optional; };

type Telemetry: record {
    drone_host: addr;
    observed_ts: time;
    source: string &default="TELLO_SDK_STATE";
    height_cm: double;
    tof_distance_cm: double;
    barometer_raw: double;
    battery_remaining_pct: double;
    pitch_deg: double;
    roll_deg: double;
    yaw_deg: double;
    velocity_x_raw: double;
    velocity_y_raw: double;
    velocity_z_raw: double;
    motor_time_raw: double;
};

function parse_state(data: string): table[string] of double
    {
    local empty: table[string] of double = table();
    local result: table[string] of double = table();
    if ( |data| == 0 || |data| > 2048 || data[|data|-1:] != ";" ) return empty;
    local parts = split_string(data, /;/);
    if ( |parts| > 33 ) return empty;
    local seen: set[string] = set();
    for ( i in parts )
        {
        if ( parts[i] == "" ) next;
        local pair = split_string(strip(parts[i]), /:/);
        if ( |pair| != 2 || pair[0] in seen ) return empty;
        add seen[pair[0]];
        if ( pair[0] in set("mid","x","y","z","mpry") ) next;
        if ( ! (/^-?[0-9]+(\.[0-9]+)?$/ == pair[1]) || |pair[1]| > 16 ) return empty;
        result[pair[0]] = to_double(pair[1]);
        }
    for ( key in set("pitch","roll","yaw","vgx","vgy","vgz","templ","temph","tof","h","bat","baro","time","agx","agy","agz") )
        if ( key !in result ) return empty;
    if ( result["bat"] < 0 || result["bat"] > 100 || result["h"] < 0 || result["tof"] < 0 || result["time"] < 0 ) return empty;
    for ( key in set("pitch","roll","yaw") )
        if ( result[key] < -180 || result[key] > 180 ) return empty;
    return result;
    }

function sdk_command(data: string): bool
    {
    if ( /^(command|takeoff|land|streamon|streamoff|emergency|stop|battery\?|time\?|height\?|speed\?|wifi\?|sdk\?|sn\?|attitude\?|baro\?|acceleration\?|temp\?|tof\?)$/ == data ) return T;
    local words = split_string(data, / /);
    if ( |words| == 2 && /^[0-9]+$/ == words[1] && |words[1]| <= 4 )
        {
        local value = to_count(words[1]);
        if ( words[0] in set("up","down","left","right","forward","back") ) return value >= 20 && value <= 500;
        if ( words[0] in set("cw","ccw") ) return value >= 1 && value <= 360;
        if ( words[0] == "speed" ) return value >= 10 && value <= 100;
        }
    if ( /^flip [lrfb]$/ == data ) return T;
    if ( |words| == 5 && words[0] == "rc" )
        {
        for ( i in words )
            {
            if ( i == 0 ) next;
            if ( ! (/^-?[0-9]+$/ == words[i]) || |words[i]| > 4 ) return F;
            local channel = to_double(words[i]);
            if ( channel < -100 || channel > 100 ) return F;
            }
        return T;
        }
    return F;
    }

function emit(c: connection, s: State)
    {
    if ( c?$drone_log_ts && network_time()-c$drone_log_ts < DroneDetector::log_interval ) return;
    if ( ! s$confirmed || (s?$last_log && network_time() - s$last_log < DroneDetector::log_interval) ) return;
    local rec = DroneDetector::Info($ts=network_time(),$event_type=s?$last_log ? "update" : "detection",
        $uid=c$uid,$id=c$id,$likely_manufacturer="DJI/Ryze",$protocol="tello-sdk",
        $evidence=s?$telemetry ? "repeated-sdk-state" : "sdk-command+recent-state-pair",
        $orig_messages=s$orig,$resp_messages=s$resp,$inspection_limited=s$limited,
        $drone_host=s$drone,$controller_host=s$controller,$activity_limited=s$activity_limited);
    if ( s?$telemetry && network_time() - s$telemetry_ts <= correlation_age ) rec$telemetry = s$telemetry;
    local activities: vector of Activity = vector();
    for ( command in s$activity ) activities[|activities|]=s$activity[command];
    if ( |activities| > 0 ) rec$control_activity = to_json(activities);
    DroneDetector::write_log(rec);
    c$drone_log_ts=network_time();
    s$activity = table();
    s$last_log = network_time();
    }

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    local sp = is_orig ? c$id$orig_p : c$id$resp_p;
    local dp = is_orig ? c$id$resp_p : c$id$orig_p;
    if ( sp !in command_ports && dp !in command_ports && dp !in state_ports ) return;
    if ( ! c?$tello_state ) c$tello_state = State($budget_start=network_time(),$activity=table());
    local s = c$tello_state;
    if ( s$confirmed && network_time() - s$budget_start >= 60secs )
        { s$inspected=0; s$budget_start=network_time(); }
    if ( |contents| > max_inspected_bytes - s$inspected )
        { s$limited=T; s$inspected=max_inspected_bytes; return; }
    s$inspected += |contents|;
    if ( |contents| > 2048 ) return;
    local data = strip(contents);
    local source = is_orig ? c$id$orig_h : c$id$resp_h;
    local destination = is_orig ? c$id$resp_h : c$id$orig_h;
    local state = dp in state_ports ? parse_state(data) : table();
    if ( |state| > 0 )
        {
        if ( s?$drone && s$drone != source ) return;
        s$drone=source; s$controller=destination;
        ++s$valid;
        if ( s$valid >= minimum_state_messages )
            {
            s$confirmed=T;
            if ( [source,destination] in known_pairs || |known_pairs| < max_known_pairs )
                known_pairs[source,destination]=network_time();
            else s$activity_limited=T;
            }
        local t = Telemetry($drone_host=source,$observed_ts=network_time(),
            $height_cm=state["h"],$tof_distance_cm=state["tof"],$barometer_raw=state["baro"],
            $battery_remaining_pct=state["bat"],$pitch_deg=state["pitch"],$roll_deg=state["roll"],
            $yaw_deg=state["yaw"],$velocity_x_raw=state["vgx"],$velocity_y_raw=state["vgy"],$velocity_z_raw=state["vgz"],
            $motor_time_raw=state["time"]);
        s$telemetry=to_json(vector(t)); s$telemetry_ts=network_time();
        }
    else
        {
        if ( dp in state_ports ) s$valid=0;
        if ( ! sdk_command(data) || dp !in command_ports || [destination,source] !in known_pairs ||
             network_time() - known_pairs[destination,source] > correlation_age ) return;
        s$confirmed=T; s$drone=destination; s$controller=source;
        if ( data in s$activity )
            { ++s$activity[data]$observations; s$activity[data]$last_seen=network_time(); }
        else if ( |s$activity| < 64 )
            s$activity[data]=Activity($command=data,$source_host=source,$destination_host=destination,
                $first_seen=network_time(),$last_seen=network_time(),$observations=1);
        else s$activity_limited=T;
        }
    if ( is_orig ) ++s$orig; else ++s$resp;
    emit(c,s);
    }

event zeek_init() &priority=5
    {
    for ( p in command_ports ) add udp_content_ports[p];
    for ( p in state_ports ) add udp_content_ports[p];
    }

event connection_flipped(c: connection)
    {
    if ( ! c?$tello_state ) return;
    local old=c$tello_state$orig;
    c$tello_state$orig=c$tello_state$resp; c$tello_state$resp=old;
    }

event connection_state_remove(c: connection) &priority=0
    {
    if ( ! c?$tello_state || ! c$tello_state$confirmed || ! c?$conn ) return;
    c$conn$drone_protocol="tello-sdk";
    c$conn$drone_likely_manufacturer="DJI/Ryze";
    c$conn$drone_evidence=c$tello_state?$telemetry ? "repeated-sdk-state" : "sdk-command+recent-state-pair";
    }
