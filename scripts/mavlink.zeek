@load ./main
@load ./mavlink-metadata

module DroneMAVLink;

export {
    # Either endpoint may use a candidate UDP port. A port never proves identity.
    const ports: set[port] = { 14550/udp, 14540/udp } &redef;
    const minimum_evidence_messages: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_metadata_values: count = 64 &redef;

    redef record DroneDetector::Info += {
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

type State: record {
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
        c$mavlink_state = State($evidence_frames=set(), $versions=set(), $systems=set(),
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

function decode(s: State, id: count, payload: string, sys: count, comp: count)
    {
    if ( id == 0 && le(payload, 8, 1) == 3 )
        {
        s$heartbeat = T;
        local vehicle = le(payload, 4, 1);
        local autopilot = le(payload, 5, 1);
        local mode = le(payload, 0, 4);
        add_string(s, s$vehicles, vehicle_name(vehicle));
        add_string(s, s$autopilots, autopilot_name(autopilot));
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
    if ( s$limited ) return;
    if ( |contents| > max_inspected_bytes - s$inspected )
        { s$limited = T; return; }
    s$inspected += |contents|;
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
        off += total;
        }
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
    Log::write(DroneDetector::LOG, [$ts=c$start_time, $uid=c$uid, $id=c$id,
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
        $metadata_limited=s$metadata_limited]);
    }
