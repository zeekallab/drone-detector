@load ./main
@load ./mavlink-metadata

module DroneMAVLink;

export {
    # Either endpoint may use a candidate UDP port. A port never proves identity.
    const ports: set[port] = { 14550/udp, 14540/udp } &redef;
    const minimum_evidence_messages: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_metadata_values: count = 64 &redef;
    const max_telemetry_sources: count = 16 &redef;
    const telemetry_max_age = 120 secs &redef;
    # Confirmed connections renew their inspection allowance each interval.
    const inspection_interval = 60 secs &redef;
    const detect_telemetry_anomalies = T &redef;
    const max_position_speed_m_s = 100.0 &redef;
    const min_position_jump_m = 100.0 &redef;
    const max_altitude_speed_m_s = 30.0 &redef;
    const min_altitude_jump_m = 20.0 &redef;
    const max_activity_values: count = 64 &redef;
    const controller_history_interval = 120 secs &redef;
    # Disabled until both sets are configured for the monitored network topology.
    const protected_drone_nets: set[subnet] = set() &redef;
    const trusted_controller_nets: set[subnet] = set() &redef;

    redef record DroneDetector::Info += {
        # JSON array, since Zeek log writers cannot log vectors of records.
        telemetry: string &log &optional;
        control_activity: string &log &optional;
        activity_limited: bool &log &optional;
        telemetry_limited: bool &log &optional;
        simulation_observed: bool &log &optional;
        signing_observed: bool &log &optional;
        mavlink_versions: set[count] &log &optional;
        system_ids: set[count] &log &optional;
        component_ids: set[count] &log &optional;
        # Each identity includes sysid/compid; one network flow can relay devices.
        heartbeat_identities: set[string] &log &optional;
        vehicle_types: set[string] &log &optional;
        autopilot_software: set[string] &log &optional;
        message_types: set[string] &log &optional;
        signed_messages: count &log &optional;
        unsigned_messages: count &log &optional;
        signature_validation: string &log &optional;
        reported_modes: set[string] &log &optional;
        requested_modes: set[count] &log &optional;
        mission_item_counts: set[count] &log &optional;
        parameter_ids: set[string] &log &optional;
        parameter_updates: set[string] &log &optional;
        zero_component_messages: count &log &optional;
        command_acks: set[string] &log &optional;
        unknown_message_ids: count &log &optional;
        malformed_frames: count &log &optional;
        metadata_limited: bool &log &optional;
    };
}

# Each observation group carries its own timestamp and source message type.
# Values are reported claims, not authenticated physical measurements.
type Position: record {
    observed_ts: time;
    source: string;
    latitude: double;
    longitude: double;
    altitude_msl_m: double;
};
type Height: record { observed_ts: time; relative_altitude_m: double; };
type Motion: record {
    observed_ts: time;
    groundspeed_m_s: double &optional;
    heading_deg: count &optional;
    climb_m_s: double &optional;
};
type Battery: record {
    observed_ts: time;
    source: string;
    battery_id: count &optional;
    remaining_pct: count;
};
type Flight: record {
    observed_ts: time;
    vehicle_type: string;
    autopilot_software: string;
    armed: bool;
    mode: string;
    custom_mode: count;
};
type Telemetry: record {
    system_id: count;
    component_id: count;
    position: Position &optional;
    height: Height &optional;
    motion: Motion &optional;
    batteries: vector of Battery &optional;
    flight: Flight &optional;
};

global emit: function(c: connection);

type Indicator: record {
    kind: string;
    system_id: count;
    component_id: count;
    first_seen: time;
    last_seen: time;
    observations: count;
    max_value: double;
    threshold: double;
};
type Control: record {
    first_seen: time;
    last_seen: time;
    observations: count;
    source_host: addr;
    destination_host: addr;
    system_id: count;
    component_id: count;
    message_type: string;
    target_system: count;
    target_component: count &optional;
    command_id: count &optional;
    command: string &optional;
    arm_requested: bool &optional;
    ack_result: count &optional;
    requested_mode: count &optional;
    parameter_id: string &optional;
    parameter_value_bits: string &optional;
    parameter_type: count &optional;
    mission_count: count &optional;
    unexpected_source: bool &optional;
};

type State: record {
    controllers: table[count,count] of time;
    controls: table[string] of Control;
    indicators: table[string] of Indicator;
    activity_limited: bool &default=F;
    last_log: time &optional;
    budget_start: time;
    telemetry: table[count, count] of Telemetry;
    telemetry_limited: bool &default=F;
    simulation: bool &default=F;
    orig: count &default=0;
    resp: count &default=0;
    inspected: count &default=0;
    limited: bool &default=F;
    metadata_limited: bool &default=F;
    bad_crc: count &default=0;
    malformed: count &default=0;
    unknown: count &default=0;
    skipped: count &default=0;
    signed_count: count &default=0;
    unsigned_count: count &default=0;
    heartbeat: bool &default=F;
    zero_component: count &default=0;
    evidence_frames: set[string];
    versions: set[count];
    systems: set[count];
    components: set[count];
    identities: set[string];
    vehicles: set[string];
    autopilots: set[string];
    types: set[string];
    modes: set[string];
    requests: set[count];
    missions: set[count];
    parameters: set[string];
    parameter_updates: set[string];
    commands: set[count];
    acks: set[string];
};
redef record connection += { mavlink_state: State &optional; };

function state(c: connection): State
    {
    if ( ! c?$mavlink_state )
        c$mavlink_state = State($controllers=table(), $controls=table(), $indicators=table(), $telemetry=table(), $budget_start=network_time(), $evidence_frames=set(), $versions=set(), $systems=set(),
            $components=set(), $identities=set(), $vehicles=set(), $autopilots=set(),
            $types=set(), $modes=set(), $requests=set(), $missions=set(),
            $parameters=set(), $parameter_updates=set(), $commands=set(), $acks=set());
    return c$mavlink_state;
    }

# MAVLink 2 omits trailing zero bytes. Reads beyond the transmitted payload
# reconstruct those zeros; they must never read into the CRC/signature trailer.
function le(data: string, offset: count, width: count): count
    {
    local result: count = 0;
    local scale: count = 1;
    local i: count = 0;
    while ( i < width )
        {
        if ( offset + i < |data| )
            result += bytestring_to_count(data[offset+i:offset+i+1]) * scale;
        scale = scale * 256;
        ++i;
        }
    return result;
    }

function accumulate(crc: count, b: count): count
    {
    local t = b ^ (crc % 256);
    t = (t ^ (t * 16)) % 256;
    return ((crc / 256) ^ (t * 256) ^ (t * 8) ^ (t / 16)) % 65536;
    }

function crc_ok(frame: string, end: count, extra: count): bool
    {
    local crc: count = 65535;
    local i: count = 1;
    while ( i < end )
        { crc = accumulate(crc, le(frame, i, 1)); ++i; }
    crc = accumulate(crc, extra);
    return crc == le(frame, end, 2);
    }

function add_string(s: State, values: set[string], value: string)
    {
    if ( value in values ) return;
    if ( |values| < max_metadata_values ) add values[value];
    else s$metadata_limited = T;
    }
function add_count(s: State, values: set[count], value: count)
    {
    if ( value in values ) return;
    if ( |values| < max_metadata_values ) add values[value];
    else s$metadata_limited = T;
    }

function vehicle_name(v: count): string
    {
    switch ( v ) {
    case 1: return "fixed-wing";
    case 2: return "quadrotor";
    case 3: return "coaxial";
    case 4: return "helicopter";
    case 6: return "ground-control-station";
    case 10: return "ground-rover";
    case 11: return "surface-boat";
    case 12: return "submarine";
    case 13: return "hexarotor";
    case 14: return "octorotor";
    case 15: return "tricopter";
    case 18: return "onboard-controller";
    case 26: return "gimbal";
    case 30: return "camera";
    default: return fmt("MAV_TYPE_%d", v);
    }
    }
function autopilot_name(v: count): string
    {
    if ( v == 3 ) return "ArduPilot";
    if ( v == 12 ) return "PX4";
    if ( v == 8 ) return "not-an-autopilot";
    return fmt("MAV_AUTOPILOT_%d", v);
    }

function signed32(payload: string, offset: count): double
    {
    local n = le(payload,offset,4);
    return n >= 2147483648 ? count_to_double(n) - 4294967296.0 : count_to_double(n);
    }

function finite_float(payload: string, offset: count): bool
    { return (le(payload,offset,4) / 8388608) % 256 != 255; }

function float32(payload: string, offset: count): double
    {
    local padded = payload + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    return bytestring_to_float(padded[offset+3:offset+4] + padded[offset+2:offset+3] +
                              padded[offset+1:offset+2] + padded[offset:offset+1]);
    }

function mode_name(autopilot: count, vehicle: count, base: count, custom: count): string
    {
    if ( base % 2 == 0 ) return "custom-mode-disabled";
    if ( autopilot == 3 && vehicle in set(2,3,4,13,14,15,29,35) )
        {
        switch ( custom ) {
        case 0: return "STABILIZE";
        case 1: return "ACRO";
        case 2: return "ALT_HOLD";
        case 3: return "AUTO";
        case 4: return "GUIDED";
        case 5: return "LOITER";
        case 6: return "RTL";
        case 9: return "LAND";
        case 16: return "POSHOLD";
        case 17: return "BRAKE";
        case 21: return "SMART_RTL";
        }
        }
    return fmt("custom-mode-%d",custom);
    }

function in_nets(host: addr, nets: set[subnet]): bool
    {
    for ( net in nets ) if ( host in net ) return T;
    return F;
    }

function indicator(s: State, kind: string, sys: count, comp: count, value: double, threshold: double)
    {
    local key = fmt("%s/%d/%d",kind,sys,comp);
    if ( key in s$indicators )
        {
        local a = s$indicators[key];
        ++a$observations;
        a$last_seen = network_time();
        if ( value > a$max_value ) a$max_value = value;
        return;
        }
    if ( |s$indicators| >= max_activity_values ) { s$activity_limited = T; return; }
    s$indicators[key] = Indicator($kind=kind,$system_id=sys,$component_id=comp,
        $first_seen=network_time(),$last_seen=network_time(),$observations=1,
        $max_value=value,$threshold=threshold);
    }

function compare_position(s: State, t: Telemetry, p: Position)
    {
    if ( ! detect_telemetry_anomalies || ! t?$position || t$position$source != p$source ) return;
    local old = t$position;
    local dt = time_to_double(p$observed_ts) - time_to_double(old$observed_ts);
    # Suppress tiny intervals, duplicate observations, long gaps and source switches.
    if ( dt < 0.1 || dt > 30.0 ) return;
    local distance = haversine_distance(old$latitude,old$longitude,p$latitude,p$longitude) * 1609.344;
    if ( distance >= min_position_jump_m && distance / dt > max_position_speed_m_s )
        indicator(s,"position_discontinuity",t$system_id,t$component_id,distance/dt,max_position_speed_m_s);
    local vertical = p$altitude_msl_m - old$altitude_msl_m;
    if ( vertical < 0.0 ) vertical = -vertical;
    if ( vertical >= min_altitude_jump_m && vertical / dt > max_altitude_speed_m_s )
        indicator(s,"altitude_discontinuity",t$system_id,t$component_id,vertical/dt,max_altitude_speed_m_s);
    }

function command_name(cmd: count): string
    {
    switch ( cmd ) {
    case 20: return "RETURN_TO_LAUNCH";
    case 21: return "LAND";
    case 22: return "TAKEOFF";
    case 176: return "DO_SET_MODE";
    case 179: return "DO_SET_HOME";
    case 183: return "DO_SET_SERVO";
    case 185: return "DO_FLIGHTTERMINATION";
    case 246: return "PREFLIGHT_REBOOT_SHUTDOWN";
    case 300: return "MISSION_START";
    case 400: return "COMPONENT_ARM_DISARM";
    default: return fmt("MAV_CMD_%d",cmd);
    }
    }

function control_activity(s: State, c: connection, is_orig: bool, id: count,
                          payload: string, sys: count, comp: count)
    {
    if ( id !in set(11,23,39,44,45,69,70,73,75,76,77,82,84,86) ) return;
    local source = is_orig ? c$id$orig_h : c$id$resp_h;
    local destination = is_orig ? c$id$resp_h : c$id$orig_h;
    local a = Control($first_seen=network_time(),$last_seen=network_time(),$observations=1,
        $source_host=source,$destination_host=destination,$system_id=sys,$component_id=comp,
        $message_type=messages[id]$name,$target_system=0);
    if ( id == 75 || id == 76 )
        {
        a$command_id = le(payload,28,2);
        a$command = command_name(a$command_id);
        a$target_system = le(payload,30,1);
        a$target_component = le(payload,31,1);
        if ( a$command_id == 400 && finite_float(payload,0) )
            {
            if ( float32(payload,0) == 0.0 ) a$arm_requested = F;
            else if ( float32(payload,0) == 1.0 ) a$arm_requested = T;
            }
        }
    else if ( id == 77 )
        {
        a$command_id = le(payload,0,2); a$command = command_name(a$command_id);
        a$ack_result = le(payload,2,1);
        a$target_system = le(payload,8,1); a$target_component = le(payload,9,1);
        }
    else if ( id == 11 )
        { a$target_system = le(payload,4,1); a$requested_mode = le(payload,0,4); }
    else if ( id == 23 )
        {
        a$target_system = le(payload,4,1); a$target_component = le(payload,5,1);
        local name = "";
        local i: count = 6;
        while ( i < 22 && i < |payload| && le(payload,i,1) != 0 )
            { name += payload[i:i+1]; ++i; }
        a$parameter_id = name;
        # Preserve exact bits; do not assume integer parameter encoding conventions.
        a$parameter_value_bits = fmt("0x%08x",le(payload,0,4));
        a$parameter_type = le(payload,22,1);
        }
    else if ( id == 44 )
        { a$target_system=le(payload,2,1); a$target_component=le(payload,3,1); a$mission_count=le(payload,0,2); }
    else if ( id == 45 )
        { a$target_system=le(payload,0,1); a$target_component=le(payload,1,1); }
    else if ( id == 69 ) a$target_system=le(payload,10,1);
    else if ( id == 70 )
        { a$target_system=le(payload,16,1); a$target_component=le(payload,17,1); }
    else if ( id == 82 )
        { a$target_system=le(payload,36,1); a$target_component=le(payload,37,1); }
    else if ( id == 84 || id == 86 )
        { a$target_system=le(payload,50,1); a$target_component=le(payload,51,1); }
    else if ( id == 39 || id == 73 )
        { a$target_system=le(payload,32,1); a$target_component=le(payload,33,1); }
    if ( id != 77 && a$target_system != 0 )
        {
        local expired: set[count,count] = set();
        for ( [target, sender] in s$controllers )
            if ( network_time() - s$controllers[target,sender] > controller_history_interval )
                add expired[target,sender];
        for ( [target, sender] in expired ) delete s$controllers[target,sender];
        if ( [a$target_system,sys] in s$controllers || |s$controllers| < max_activity_values )
            s$controllers[a$target_system,sys] = network_time();
        else s$activity_limited = T;
        local senders: set[count] = set();
        for ( [target, sender] in s$controllers )
            if ( target == a$target_system ) add senders[sender];
        if ( |senders| > 1 )
            indicator(s,"multiple_control_system_ids",a$target_system,0,count_to_double(|senders|),1.0);
        }
    if ( id != 77 && |trusted_controller_nets| > 0 && |protected_drone_nets| > 0 && in_nets(destination,protected_drone_nets) )
        a$unexpected_source = ! (in_nets(source,trusted_controller_nets));
    # Aggregate identical requests, retain changes to parameter values/mode/arm state.
    local key = fmt("%s/%s/%d/%d/%s/%d/%d/%s/%s/%s/%s",source,destination,sys,comp,
        a$message_type,a$target_system,a?$target_component ? a$target_component : 256,
        a?$command ? a$command : "",a?$parameter_id ? a$parameter_id : "",
        a?$parameter_value_bits ? a$parameter_value_bits : "",
        a?$requested_mode ? fmt("%d",a$requested_mode) : (a?$arm_requested ? fmt("%s",a$arm_requested) : ""));
    key += fmt("/%s/%s/%s", a?$mission_count ? fmt("%d",a$mission_count) : "",
        a?$ack_result ? fmt("%d",a$ack_result) : "",
        a?$parameter_type ? fmt("%d",a$parameter_type) : "");
    if ( key in s$controls )
        { ++s$controls[key]$observations; s$controls[key]$last_seen = network_time(); }
    else if ( |s$controls| < max_activity_values ) s$controls[key] = a;
    else s$activity_limited = T;
    }

function fresh(t: Telemetry): Telemetry
    {
    local now = network_time();
    if ( t?$position && now - t$position$observed_ts > telemetry_max_age ) delete t$position;
    if ( t?$height && now - t$height$observed_ts > telemetry_max_age ) delete t$height;
    if ( t?$motion && now - t$motion$observed_ts > telemetry_max_age ) delete t$motion;
    if ( t?$flight && now - t$flight$observed_ts > telemetry_max_age ) delete t$flight;
    if ( t?$batteries )
        {
        local batteries: vector of Battery = vector();
        for ( i in t$batteries )
            if ( now - t$batteries[i]$observed_ts <= telemetry_max_age )
                batteries[|batteries|] = t$batteries[i];
        if ( |batteries| > 0 ) t$batteries = batteries;
        else delete t$batteries;
        }
    return t;
    }

function decode_telemetry(s: State, id: count, payload: string, sys: count, comp: count)
    {
    if ( id == 164 || id == 108 ) s$simulation = T;
    if ( id !in set(0,1,24,33,74,147) ) return;
    # Flight state belongs to autopilots, not GCS/companion heartbeats.
    if ( id == 0 && (le(payload,8,1) != 3 || le(payload,5,1) == 8 || le(payload,4,1) == 6) ) return;
    if ( [sys,comp] !in s$telemetry )
        {
        if ( |s$telemetry| >= max_telemetry_sources )
            {
            local expired: set[count,count] = set();
            for ( [a,b] in s$telemetry )
                {
                local old = fresh(s$telemetry[a,b]);
                if ( ! old?$position && ! old?$height && ! old?$motion && ! old?$flight && ! old?$batteries )
                    add expired[a,b];
                }
            for ( [a,b] in expired ) delete s$telemetry[a,b];
            }
        if ( |s$telemetry| >= max_telemetry_sources ) { s$telemetry_limited = T; return; }
        s$telemetry[sys,comp] = Telemetry($system_id=sys,$component_id=comp);
        }
    local t = fresh(s$telemetry[sys,comp]);
    local now = network_time();
    if ( id == 0 )
        {
        local vehicle = le(payload,4,1);
        local ap = le(payload,5,1);
        local base = le(payload,6,1);
        local custom = le(payload,0,4);
        t$flight = Flight($observed_ts=now,$vehicle_type=vehicle_name(vehicle),
            $autopilot_software=autopilot_name(ap),$armed=base >= 128,
            $mode=mode_name(ap,vehicle,base,custom),$custom_mode=custom);
        }
    else if ( id == 24 || id == 33 )
        {
        # Prefer fused global position while fresh; fall back to a valid 3-D GPS fix.
        if ( id == 24 && t?$position && t$position$source == "GLOBAL_POSITION_INT" ) return;
        local offset: count = id == 24 ? 8 : 4;
        local lat = signed32(payload,offset) / 10000000.0;
        local lon = signed32(payload,offset+4) / 10000000.0;
        local fix = le(payload,28,1);
        if ( lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0 ||
             (id == 24 && (fix < 3 || fix > 8)) || le(payload,offset+8,4) == 2147483647 )
            {
            delete t$position;
            if ( id == 33 ) delete t$height;
            return;
            }
        local position = Position($observed_ts=now,$source=messages[id]$name,
            $latitude=lat,$longitude=lon,$altitude_msl_m=signed32(payload,offset+8)/1000.0);
        compare_position(s,t,position);
        t$position = position;
        if ( id == 33 )
            {
            if ( le(payload,16,4) != 2147483647 )
                t$height = Height($observed_ts=now,$relative_altitude_m=signed32(payload,16)/1000.0);
            else delete t$height;
            }
        }
    else if ( id == 74 )
        {
        local motion = Motion($observed_ts=now);
        if ( finite_float(payload,4) && float32(payload,4) >= 0.0 ) motion$groundspeed_m_s = float32(payload,4);
        if ( finite_float(payload,12) ) motion$climb_m_s = float32(payload,12);
        if ( le(payload,16,2) < 360 ) motion$heading_deg = le(payload,16,2);
        if ( motion?$groundspeed_m_s || motion?$climb_m_s || motion?$heading_deg ) t$motion = motion;
        else delete t$motion;
        }
    else if ( id == 1 || id == 147 )
        {
        local remaining = le(payload,id == 1 ? 30 : 35,1);
        local battery_id = le(payload,32,1);
        local source = messages[id]$name;
        local batteries: vector of Battery = vector();
        if ( t?$batteries )
            for ( i in t$batteries )
                {
                local entry = t$batteries[i];
                if ( entry$source == source && (id == 1 || (entry?$battery_id && entry$battery_id == battery_id)) ) next;
                batteries[|batteries|] = entry;
                }
        # -1/255 means unknown. Never report it as 255% or invent 0%.
        if ( remaining <= 100 )
            {
            local battery = Battery($observed_ts=now,$source=source,$remaining_pct=remaining);
            if ( id == 147 ) battery$battery_id = battery_id;
            if ( |batteries| < 8 ) batteries[|batteries|] = battery;
            else s$telemetry_limited = T;
            }
        if ( |batteries| > 0 ) t$batteries = batteries;
        else delete t$batteries;
        }
    }

function decode(s: State, id: count, payload: string, sys: count, comp: count)
    {
    if ( id == 0 && le(payload, 8, 1) == 3 )
        {
        s$heartbeat = T;
        local vehicle = le(payload, 4, 1);
        local autopilot = le(payload, 5, 1);
        local mode = le(payload, 0, 4);
        add_string(s, s$vehicles, vehicle_name(vehicle));
        if ( autopilot != 8 ) add_string(s, s$autopilots, autopilot_name(autopilot));
        add_string(s, s$identities, fmt("sys=%d;comp=%d;type=%d;autopilot=%d",sys,comp,vehicle,autopilot));
        # Numeric custom modes are stack/vehicle-specific; do not globally label 6 RTL.
        add_string(s, s$modes, fmt("sys=%d;comp=%d;type=%d;autopilot=%d;base=%d;custom=%d;status=%d",
            sys,comp,vehicle,autopilot,le(payload,6,1),mode,le(payload,7,1)));
        }
    else if ( id == 11 ) add_count(s, s$requests, le(payload,0,4));
    else if ( id == 44 ) add_count(s, s$missions, le(payload,0,2));
    else if ( id == 75 || id == 76 ) add_count(s, s$commands, le(payload,28,2));
    else if ( id == 77 )
        add_string(s, s$acks, fmt("command=%d;result=%d",le(payload,0,2),le(payload,2,1)));
    else if ( id == 23 )
        {
        local name = "";
        local i: count = 6;
        while ( i < 22 && i < |payload| )
            {
            if ( le(payload,i,1) == 0 ) break;
            name += payload[i:i+1];
            ++i;
            }
        if ( |name| > 0 )
            {
            add_string(s, s$parameters, name);
            local bits = le(payload,0,4);
            # Store raw bits and MAV_PARAM_TYPE; integer encoding conventions vary.
            add_string(s, s$parameter_updates, fmt("name=%s;type=%d;value_bits=0x%08x;target_sys=%d;target_comp=%d",
                name,le(payload,22,1),bits,le(payload,4,1),le(payload,5,1)));
            }
        }
    }

# udp_contents delivers complete UDP application data in either direction.
event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    if ( c$id$orig_p !in ports && c$id$resp_p !in ports ) return;
    local s = state(c);
    if ( s$heartbeat && |s$evidence_frames| >= minimum_evidence_messages &&
         network_time() - s$budget_start >= inspection_interval )
        { s$inspected = 0; s$budget_start = network_time(); }
    if ( |contents| > max_inspected_bytes - s$inspected )
        { s$limited = T; s$inspected = max_inspected_bytes; return; }
    s$inspected += |contents|;
    local before = s$orig + s$resp;
    local off: count = 0;
    while ( off < |contents| )
        {
        local magic = le(contents,off,1);
        if ( magic != 253 && magic != 254 )
            { ++off; ++s$skipped; next; }
        local v2 = magic == 253;
        local header: count = v2 ? 10 : 6;
        if ( |contents| - off < header + 2 )
            { ++s$malformed; break; }
        local length = le(contents,off+1,1);
        local flags = v2 ? le(contents,off+2,1) : 0;
        if ( flags > 1 )
            { ++s$malformed; ++off; ++s$skipped; next; }
        local signed_frame = flags == 1;
        local total = header + length + 2 + (signed_frame ? 13 : 0);
        if ( |contents| - off < total )
            { ++s$malformed; ++off; ++s$skipped; next; }
        local frame = contents[off:off+total];
        local id = v2 ? le(frame,7,3) : le(frame,5,1);
        if ( id !in messages )
            { ++s$unknown; off += total; next; }
        if ( ! v2 && (messages[id]$v1_length == 0 || length != messages[id]$v1_length) )
            { ++s$malformed; off += total; next; }
        if ( ! crc_ok(frame,header+length,messages[id]$crc) )
            { ++s$bad_crc; ++off; ++s$skipped; next; }
        local sys = v2 ? le(frame,5,1) : le(frame,3,1);
        local comp = v2 ? le(frame,6,1) : le(frame,4,1);
        if ( sys == 0 )
            { ++s$malformed; off += total; next; }
        # Some real GCS messages use source component 0 despite the specification.
        # Preserve CRC-valid evidence and expose the anomaly instead of hiding commands.
        if ( comp == 0 ) ++s$zero_component;
        if ( is_orig ) ++s$orig; else ++s$resp;
        if ( signed_frame ) ++s$signed_count; else ++s$unsigned_count;
        # Store only enough distinct evidence to reach the confirmation threshold.
        # Exclude signature bytes so re-signing identical messages adds no evidence.
        if ( |s$evidence_frames| < minimum_evidence_messages )
            add s$evidence_frames[frame[0:header+length+2]];
        add s$versions[v2 ? 2 : 1];
        add_count(s, s$systems, sys);
        add_count(s, s$components, comp);
        add_string(s, s$types, messages[id]$name);
        decode(s,id,frame[header:header+length],sys,comp);
        decode_telemetry(s,id,frame[header:header+length],sys,comp);
        control_activity(s,c,is_orig,id,frame[header:header+length],sys,comp);
        off += total;
        }
    if ( s$inspected >= max_inspected_bytes ) s$limited = T;
    if ( s$orig + s$resp > before ) emit(c);
    }

event zeek_init() &priority=5
    {
    for ( p in ports )
        {
        # Current Zeek supports these tables for either-endpoint candidate delivery.
        add udp_content_ports[p];
        }
    }

event connection_flipped(c: connection)
    {
    if ( ! c?$mavlink_state ) return;
    local previous = c$mavlink_state$orig;
    c$mavlink_state$orig = c$mavlink_state$resp;
    c$mavlink_state$resp = previous;
    }

function emit(c: connection)
    {
    if ( c?$drone_log_ts && network_time()-c$drone_log_ts < DroneDetector::log_interval ) return;
    local s = c$mavlink_state;
    if ( ! s$heartbeat || |s$evidence_frames| < minimum_evidence_messages ) return;
    if ( s?$last_log && network_time() - s$last_log < DroneDetector::log_interval ) return;
    local evidence = "framing+crc_extra+heartbeat";
    local rec = DroneDetector::Info($ts=network_time(), $event_type=s?$last_log ? "update" : "detection", $uid=c$uid, $id=c$id,
        $likely_manufacturer="unknown", $protocol="mavlink", $evidence=evidence,
        $orig_messages=s$orig, $resp_messages=s$resp, $matched_responses=0,
        $commands=s$commands, $checksum_failures=s$bad_crc, $skipped_bytes=s$skipped,
        $gaps=0, $inspection_limited=s$limited, $mavlink_versions=s$versions,
        $system_ids=s$systems, $component_ids=s$components, $heartbeat_identities=s$identities,
        $vehicle_types=s$vehicles, $autopilot_software=s$autopilots, $message_types=s$types,
        $signed_messages=s$signed_count, $unsigned_messages=s$unsigned_count,
        $signature_validation="not-performed", $reported_modes=s$modes,
        $requested_modes=s$requests, $mission_item_counts=s$missions, $parameter_ids=s$parameters,
        $parameter_updates=s$parameter_updates, $zero_component_messages=s$zero_component,
        $command_acks=s$acks, $unknown_message_ids=s$unknown, $malformed_frames=s$malformed,
        $metadata_limited=s$metadata_limited, $telemetry_limited=s$telemetry_limited,
        $simulation_observed=s$simulation, $signing_observed=s$signed_count > 0);

    local snapshots: vector of Telemetry = vector();
    for ( [sys, comp] in s$telemetry )
        {
        local t = fresh(s$telemetry[sys,comp]);
        if ( t?$position || t?$height || t?$motion || t?$batteries || t?$flight )
            snapshots[|snapshots|] = t;
        }
    if ( |snapshots| > 0 ) rec$telemetry = to_json(snapshots);
    local controls: vector of Control = vector();
    for ( key in s$controls ) controls[|controls|] = s$controls[key];
    if ( |controls| > 0 ) rec$control_activity = to_json(controls);
    for ( key in s$indicators )
        {
        local kind = s$indicators[key]$kind;
        local description = "";
        if ( kind == "position_discontinuity" )
            description = "mavlink anomaly indicator - position discontinuity";
        else if ( kind == "altitude_discontinuity" )
            description = "mavlink anomaly indicator - Altitude discontinuity";
        else if ( kind == "multiple_control_system_ids" )
            description = "mavlink anomaly indicator - Multiple control system IDs";
        if ( description != "" )
            {
            if ( ! rec?$alert ) rec$alert = set();
            add rec$alert[description];
            }
        }
    rec$activity_limited = s$activity_limited;
    if ( ! DroneDetector::include_diagnostics )
        {
        delete rec$system_ids;
        delete rec$component_ids;
        delete rec$heartbeat_identities;
        delete rec$message_types;
        delete rec$signed_messages;
        delete rec$unsigned_messages;
        delete rec$reported_modes;
        delete rec$requested_modes;
        delete rec$mission_item_counts;
        delete rec$parameter_ids;
        delete rec$parameter_updates;
        delete rec$zero_component_messages;
        delete rec$command_acks;
        delete rec$unknown_message_ids;
        delete rec$malformed_frames;
        }
    if ( |s$autopilots| == 0 ) delete rec$autopilot_software;
    DroneDetector::write_log(rec);
    c$drone_log_ts=network_time();
    s$controls = table();
    s$indicators = table();
    s$last_log = network_time();
    }

event connection_state_remove(c: connection) &priority=0
    {
    if ( ! c?$mavlink_state ) return;
    local s = c$mavlink_state;
    if ( ! s$heartbeat || |s$evidence_frames| < minimum_evidence_messages ) return;
    local evidence = "framing+crc_extra+heartbeat";
    if ( c?$conn )
        {
        c$conn$drone_protocol = "mavlink";
        c$conn$drone_likely_manufacturer = "unknown";
        c$conn$drone_evidence = evidence;
        }
    }
