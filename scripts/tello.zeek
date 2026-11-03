@load ./mavlink

module DroneTello;

export {
    global recent_pair: function(drone: addr, controller: addr): bool;
    const command_ports: set[port] = { 8889/udp } &redef;
    const state_ports: set[port] = { 8890/udp } &redef;
    const minimum_state_messages: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_known_pairs: count = 1024 &redef;
    const correlation_age = 120 secs &redef;
    const max_control_pairs: count = 1024 &redef;
    const churn_window = 60secs &redef;
    const churn_min_ports: count = 10 &redef;
    const churn_min_span = 10secs &redef;
    const max_source_ports: count = 128 &redef;
    const max_related_uids: count = 32 &redef;
    const maneuver_window = 60secs &redef;
    const maneuver_min_commands: count = 10 &redef;
    const maneuver_min_reversals: count = 8 &redef;
    const maneuver_min_each_direction: count = 4 &redef;
    const maneuver_min_span = 10secs &redef;
    const maneuver_max_samples: count = 128 &redef;
    redef record DroneDetector::Info += {
        drone_host: addr &log &optional;
        controller_host: addr &log &optional;
        sdk_summary_scope: string &log &optional;
        sdk_command_count: count &log &optional;
        sdk_source_port_count: count &log &optional;
        sdk_related_uids: set[string] &log &optional;
        sdk_repetitive_axes: set[string] &log &optional;
        sdk_ok_responses: count &log &optional;
        sdk_error_responses: count &log &optional;
        sdk_unknown_command_responses: count &log &optional;
    };
}

# Worker-local pair learning. Never infer identity from a port or a generic "ok".
global known_pairs: table[addr,addr] of time &write_expire=correlation_age;
function recent_pair(drone: addr, controller: addr): bool
    {
    return [drone,controller] in known_pairs &&
        network_time()-known_pairs[drone,controller] <= correlation_age;
    }

type Activity: record {
    command: string;
    source_host: addr;
    destination_host: addr;
    first_seen: time;
    last_seen: time;
    observations: count;
};
type Maneuver: record { ts: time; positive: bool; };
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
    maneuvers: table[string] of vector of Maneuver;
    repetitive_axes: set[string];
    has_commands: bool &default=F;
    command_ts: time &optional;
    command_count: count &default=0;
    source_ports: table[port] of time &optional;
    related_uids: set[string] &optional;
    churn: bool &default=F;
    peak_ports: count &default=0;
    ok_responses: count &default=0;
    error_responses: count &default=0;
    unknown_responses: count &default=0;
};
redef record connection += { tello_state: State &optional; };

# Command summaries and patterns are keyed by ordered host pair, not UDP socket.
global control_pairs: table[addr,addr] of State &write_expire=correlation_age;
global control_tracking_limited_until: time = double_to_time(0.0);

function track_uid(s: State, uid: string)
    {
    if ( ! s?$related_uids ) s$related_uids=set();
    if ( uid in s$related_uids || |s$related_uids| < max_related_uids ) add s$related_uids[uid];
    else s$activity_limited=T;
    }

function observe_port(s: State, p: port)
    {
    if ( ! s?$source_ports ) s$source_ports=table();
    local expired: set[port]=set();
    for ( k in s$source_ports )
        if ( network_time()-s$source_ports[k] > churn_window ) add expired[k];
    for ( k in expired ) delete s$source_ports[k];
    if ( p in s$source_ports || |s$source_ports| < max_source_ports ) s$source_ports[p]=network_time();
    else s$activity_limited=T;
    if ( |s$source_ports| > s$peak_ports ) s$peak_ports=|s$source_ports|;
    local oldest=network_time();
    for ( k in s$source_ports ) if ( s$source_ports[k] < oldest ) oldest=s$source_ports[k];
    if ( |s$source_ports| >= churn_min_ports && network_time()-oldest >= churn_min_span ) s$churn=T;
    }

type BatteryStatus: record { remaining_pct: double; };
type Telemetry: record {
    height_cm: double;
    tof_distance_cm: double;
    battery_status: vector of BatteryStatus;
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

# Runs only on grammar-validated commands correlated with recent SDK state.
function observe_maneuver(s: State, data: string)
    {
    local words=split_string(data, / /);
    if ( |words| != 2 ) return;
    local verb=words[0];
    local axis=verb in set("forward","back") ? "forward-back" :
        (verb in set("left","right") ? "left-right" :
        (verb in set("up","down") ? "up-down" :
        (verb in set("cw","ccw") ? "yaw" : "")));
    if ( axis == "" || maneuver_max_samples == 0 ) return;
    if ( axis !in s$maneuvers ) s$maneuvers[axis]=vector();
    local old=s$maneuvers[axis];
    # Suppress near-simultaneous packet duplicates; this is not flood detection.
    if ( |old| > 0 && network_time()-old[|old|-1]$ts < 250msec ) return;
    local recent: vector of Maneuver=vector();
    for ( i in old )
        if ( network_time()-old[i]$ts <= maneuver_window )
            {
            if ( |old|-i < maneuver_max_samples ) recent[|recent|]=old[i];
            else s$activity_limited=T;
            }
    recent[|recent|]=[$ts=network_time(),$positive=verb in set("forward","left","up","cw")];
    s$maneuvers[axis]=recent;
    if ( |recent| < maneuver_min_commands || network_time()-recent[0]$ts < maneuver_min_span ) return;
    local positive: count=0; local negative: count=0; local reversals: count=0;
    for ( i in recent )
        {
        if ( recent[i]$positive ) ++positive; else ++negative;
        if ( i > 0 && recent[i]$positive != recent[i-1]$positive ) ++reversals;
        }
    if ( positive >= maneuver_min_each_direction && negative >= maneuver_min_each_direction &&
         reversals >= maneuver_min_reversals ) add s$repetitive_axes[axis];
    }

function emit(c: connection, s: State, pair_summary: bool)
    {
    if ( c?$drone_log_ts && network_time()-c$drone_log_ts < DroneDetector::log_interval ) return;
    if ( ! s$confirmed || (s?$last_log && network_time() - s$last_log < DroneDetector::log_interval) ) return;
    local rec = DroneDetector::Info($ts=network_time(),$event_type=s?$last_log ? "update" : "detection",
        $uid=c$uid,$id=c$id,$likely_manufacturer="DJI/Ryze",$protocol="tello-sdk",
        $evidence=s?$telemetry ? "repeated-sdk-state" : "sdk-command+recent-state-pair",
        $orig_messages=s$orig,$resp_messages=s$resp,$inspection_limited=s$limited,
        $drone_host=s$drone,$controller_host=s$controller,$activity_limited=s$activity_limited);
    if ( network_time() < control_tracking_limited_until ) rec$activity_limited=T;
    if ( s?$telemetry && network_time() - s$telemetry_ts <= correlation_age ) rec$flight_telemetry = s$telemetry;
    local activities: vector of Activity = vector();
    for ( command in s$activity ) activities[|activities|]=s$activity[command];
    if ( |activities| > 0 ) rec$control_activity = to_json(activities);
    if ( |s$repetitive_axes| > 0 )
        {
        rec$alert=set("Repetitive maneuver commands: repeated opposing Tello SDK movement or rotation requests");
        rec$sdk_repetitive_axes=s$repetitive_axes;
        }
    if ( s$ok_responses+s$error_responses+s$unknown_responses > 0 )
        {
        rec$sdk_ok_responses=s$ok_responses;
        rec$sdk_error_responses=s$error_responses;
        rec$sdk_unknown_command_responses=s$unknown_responses;
        }
    if ( pair_summary )
        {
        # uid/id identify the packet that triggered emission, not every aggregated command.
        rec$sdk_summary_scope="host-pair";
        rec$sdk_command_count=s$command_count;
        rec$sdk_source_port_count=s$peak_ports;
        if ( s?$related_uids ) rec$sdk_related_uids=s$related_uids;
        delete rec$orig_messages; delete rec$resp_messages;
        if ( s$churn )
            {
            if ( ! rec?$alert ) rec$alert=set();
            add rec$alert["Control source-port churn: repeated Tello SDK commands from many source ports to the same drone"];
            }
        }
    DroneDetector::write_log(rec);
    c$drone_log_ts=network_time();
    s$activity = table();
    s$repetitive_axes=set();
    s$ok_responses=0; s$error_responses=0; s$unknown_responses=0;
    s$command_count=0; s$related_uids=set(); s$churn=F; s$peak_ports=0;
    s$last_log = network_time();
    }

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    local sp = is_orig ? c$id$orig_p : c$id$resp_p;
    local dp = is_orig ? c$id$resp_p : c$id$orig_p;
    if ( sp !in command_ports && dp !in command_ports && dp !in state_ports ) return;
    if ( ! c?$tello_state ) c$tello_state = State($budget_start=network_time(),$activity=table(),$maneuvers=table(),$repetitive_axes=set());
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
        local t = Telemetry($height_cm=state["h"], $tof_distance_cm=state["tof"],
            $battery_status=vector(BatteryStatus($remaining_pct=state["bat"])));
        s$telemetry=to_json(vector(t)); s$telemetry_ts=network_time();
        }
    else
        {
        if ( dp in state_ports ) s$valid=0;
        # Replies may return to an earlier port. Correlate at host-pair level,
        # but require a recent validated command, not just telemetry or generic text.
        if ( sp in command_ports && dp !in state_ports && recent_pair(source,destination) &&
             [source,destination] in control_pairs && |data| <= 256 &&
             (data == "ok" || /^error( |$)/ in data || /^unknown command:/ in data) )
            {
            local replies=control_pairs[source,destination];
            if ( ! replies?$command_ts || network_time()-replies$command_ts > correlation_age ) return;
            if ( data == "ok" ) ++replies$ok_responses;
            else if ( /^unknown command:/ in data ) ++replies$unknown_responses;
            else ++replies$error_responses;
            track_uid(replies,c$uid);
            s$confirmed=T; s$drone=source; s$controller=destination;
            control_pairs[source,destination]=replies;
            emit(c,replies,T); return;
            }
        if ( ! sdk_command(data) || dp !in command_ports || ! recent_pair(destination,source) ) return;
        s$has_commands=T; s$confirmed=T; s$drone=destination; s$controller=source;
        if ( [destination,source] !in control_pairs )
            {
            if ( |control_pairs| >= max_control_pairs )
                { s$activity_limited=T; control_tracking_limited_until=network_time()+correlation_age; return; }
            control_pairs[destination,source]=State($budget_start=network_time(),$activity=table(),
                $maneuvers=table(),$repetitive_axes=set(),$confirmed=T,$drone=destination,$controller=source);
            }
        local shared=control_pairs[destination,source];
        # A stale command context must not survive indefinitely on reply traffic.
        if ( shared?$command_ts && network_time()-shared$command_ts > correlation_age )
            {
            local previous=shared;
            shared=State($budget_start=network_time(),$activity=table(),$maneuvers=table(),
                $repetitive_axes=set(),$confirmed=T,$drone=destination,$controller=source);
            if ( previous?$last_log ) shared$last_log=previous$last_log;
            }
        shared$command_ts=network_time(); ++shared$command_count;
        if ( s$limited ) shared$limited=T;
        observe_maneuver(shared,data); observe_port(shared,sp); track_uid(shared,c$uid);
        if ( data in shared$activity )
            { ++shared$activity[data]$observations; shared$activity[data]$last_seen=network_time(); }
        else if ( |shared$activity| < 64 )
            shared$activity[data]=Activity($command=data,$source_host=source,$destination_host=destination,
                $first_seen=network_time(),$last_seen=network_time(),$observations=1);
        else shared$activity_limited=T;
        control_pairs[destination,source]=shared;
        emit(c,shared,T); return;
        }
    if ( is_orig ) ++s$orig; else ++s$resp;
    emit(c,s,F);
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
