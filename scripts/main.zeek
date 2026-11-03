@load base/protocols/conn

module DroneDetector;

export {
    redef enum Log::ID += { LOG };
    # Candidate selection only: the port itself never triggers detection.
    const ports: set[port] = { 2001/tcp } &redef;
    const minimum_consecutive_messages: count = 3 &redef;
    const max_inspected_bytes: count = 1048576 &redef;
    const max_pending_requests: count = 256 &redef;
    # Emit on validated traffic, never on a timer or at connection removal.
    const log_interval = 60 secs &redef;
    const include_diagnostics = F &redef;

    type Info: record {
        ts: time &log;
        event_type: string &log;
        uid: string &log &optional;
        id: conn_id &log &optional;
        likely_manufacturer: string &log;
        protocol: string &log;
        evidence: string &log;
        alert: set[string] &log &optional;
        orig_messages: count &log &optional;
        resp_messages: count &log &optional;
        matched_responses: count &log &optional;
        commands: set[count] &log &optional;
        checksum_failures: count &log &optional;
        skipped_bytes: count &log &optional;
        gaps: count &log &optional;
        inspection_limited: bool &log;
    };
    global write_log: function(rec: Info);
    redef record Conn::Info += {
        drone_protocol: string &log &optional;
        drone_likely_manufacturer: string &log &optional;
        drone_evidence: string &log &optional;
    };
}

redef record connection += { drone_log_ts: time &optional; };

function write_log(rec: Info)
    {
    if ( ! include_diagnostics )
        {
        delete rec$matched_responses;
        delete rec$commands;
        delete rec$checksum_failures;
        delete rec$skipped_bytes;
        delete rec$gaps;
        }
    Log::write(LOG, rec);
    }

global emit: function(c: connection);

type Direction: record {
    buffer: string &default="";
    consecutive: count &default=0;
    messages: count &default=0;
};
type State: record {
    orig: Direction;
    resp: Direction;
    confirmed: bool &default=F;
    last_log: time &optional;
    budget_start: time;
    inspected: count &default=0;
    limited: bool &default=F;
    checksum_failures: count &default=0;
    skipped: count &default=0;
    gaps: count &default=0;
    matched: count &default=0;
    commands: set[count];
    # Direction, sequence, command and component address. Consume matched requests.
    pending: set[bool, count, count, count];
};
redef record connection += { drone_state: State &optional; };

function state(c: connection): State
    {
    if ( ! c?$drone_state )
        c$drone_state = State($budget_start=network_time(), $orig=Direction(), $resp=Direction(),
                            $commands=set(), $pending=set());
    return c$drone_state;
    }

function valid_checksum(data: string): bool
    {
    local checksum: count = 0;
    local i: count = 0;
    while ( i < |data| )
        { checksum = checksum ^ bytestring_to_count(data[i:i+1]); ++i; }
    return checksum == 0;
    }

event zeek_init() &priority=5
    {
    for ( p in ports )
        {
        tcp_content_delivery_ports_orig[p] = T;
        tcp_content_delivery_ports_resp[p] = T;
        }
    Log::create_stream(LOG, [$columns=Info, $path="drone"]);
    }

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    if ( c$id$resp_p !in ports ) return;
    local s = state(c);
    if ( s$confirmed && network_time() - s$budget_start >= 60 secs )
        { s$inspected = 0; s$budget_start = network_time(); }
    if ( s$inspected >= max_inspected_bytes ) return;
    local before = s$orig$messages + s$resp$messages;
    local d = is_orig ? s$orig : s$resp;
    local remaining = max_inspected_bytes - s$inspected;
    local take = |contents| < remaining ? |contents| : remaining;
    s$inspected += take;
    # The temporary buffer is bounded by the inspection budget plus 254 bytes.
    d$buffer += contents[0:take];
    local offset: count = 0;
    while ( |d$buffer| - offset >= 3 )
        {
        local length = bytestring_to_count(d$buffer[offset+2:offset+3]);
        if ( d$buffer[offset:offset+2] != "\x55\xbb" || length < 8 )
            { ++offset; ++s$skipped; d$consecutive = 0; next; }
        if ( |d$buffer| - offset < length ) break;
        local frame = d$buffer[offset:offset+length];
        local flags = bytestring_to_count(frame[3:4]);
        # Limit v0.1 to the address/flag values verified in this protocol family.
        if ( flags !in set(8, 10, 11, 72, 74, 75) )
            { ++offset; ++s$skipped; d$consecutive = 0; next; }
        if ( ! valid_checksum(frame) )
            { ++s$checksum_failures; ++offset; ++s$skipped; d$consecutive = 0; next; }
        ++d$messages;
        ++d$consecutive;
        if ( d$consecutive >= minimum_consecutive_messages ) s$confirmed = T;
        local sequence = bytestring_to_count(frame[4:6], T);
        local command = bytestring_to_count(frame[6:7]);
        local component = flags % 64;
        add s$commands[command];
        if ( flags < 64 )
            {
            if ( |s$pending| >= max_pending_requests ) s$pending = set();
            add s$pending[is_orig, sequence, command, component];
            }
        else if ( [!is_orig, sequence, command, component] in s$pending )
            {
            ++s$matched;
            delete s$pending[!is_orig, sequence, command, component];
            }
        offset += length;
        }
    d$buffer = d$buffer[offset:];
    if ( take < |contents| || s$inspected >= max_inspected_bytes )
        {
        s$limited = T;
        s$orig$buffer = "";
        s$resp$buffer = "";
        }
    if ( s$orig$messages + s$resp$messages > before && s$confirmed ) emit(c);
    }

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
    {
    if ( ! c?$drone_state ) return;
    local s = c$drone_state;
    local d = is_orig ? s$orig : s$resp;
    d$buffer = "";
    d$consecutive = 0;
    s$pending = set();
    ++s$gaps;
    }

event connection_flipped(c: connection)
    {
    if ( ! c?$drone_state ) return;
    local previous = c$drone_state$orig;
    c$drone_state$orig = c$drone_state$resp;
    c$drone_state$resp = previous;
    c$drone_state$pending = set();
    }

function emit(c: connection)
    {
    if ( c?$drone_log_ts && network_time()-c$drone_log_ts < log_interval ) return;
    local s = c$drone_state;
    if ( s?$last_log && network_time() - s$last_log < log_interval ) return;
    local evidence = s$matched > 0 ? "framing+xor+request_response" : "framing+xor";
    write_log([$ts=network_time(), $event_type=s?$last_log ? "update" : "detection",
        $uid=c$uid, $id=c$id, $likely_manufacturer="DJI",
        $protocol="dji-phantom-vision-legacy", $evidence=evidence,
        $orig_messages=s$orig$messages, $resp_messages=s$resp$messages,
        $matched_responses=s$matched, $commands=s$commands,
        $checksum_failures=s$checksum_failures, $skipped_bytes=s$skipped,
        $gaps=s$gaps, $inspection_limited=s$limited]);
    c$drone_log_ts=network_time();
    s$last_log = network_time();
    }

event connection_state_remove(c: connection) &priority=0
    {
    if ( ! c?$drone_state || ! c$drone_state$confirmed || ! c?$conn ) return;
    c$conn$drone_protocol = "dji-phantom-vision-legacy";
    c$conn$drone_likely_manufacturer = "DJI";
    c$conn$drone_evidence = c$drone_state$matched > 0 ? "framing+xor+request_response" : "framing+xor";
    }
