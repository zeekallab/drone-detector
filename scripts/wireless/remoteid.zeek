# Loaded by default (off switch: redef DroneRadio::enabled = F;). ASTM F3411 / ASD-STAN Open Drone ID (Remote ID) over
# Wi-Fi Beacon (vendor IE, OUI FA:0B:BC type 0x0D) and Wi-Fi NAN (public action
# service discovery frames). Field layouts follow opendroneid-core-c; validate
# against a real broadcaster before relying on decoded positions.
@load ./radiotap

module DroneRemoteID;

export {
    const max_broadcasters: count = 256 &redef;
    redef record DroneDetector::Info += {
        remoteid_transport: string &log &optional;
        remoteid_transmitter: string &log &optional;
        remoteid_ua_id: string &log &optional;
        remoteid_id_type: string &log &optional;
        remoteid_ua_type: string &log &optional;
        remoteid_status: string &log &optional;
        remoteid_latitude: double &log &optional;
        remoteid_longitude: double &log &optional;
        remoteid_altitude_m: double &log &optional;
        remoteid_height_m: double &log &optional;
        remoteid_speed_mps: double &log &optional;
        remoteid_track_deg: count &log &optional;
        remoteid_operator_latitude: double &log &optional;
        remoteid_operator_longitude: double &log &optional;
        remoteid_operator_id: string &log &optional;
        remoteid_description: string &log &optional;
        remoteid_messages: count &log &optional;
        remoteid_signal_dbm: int &log &optional;
        remoteid_channel_mhz: count &log &optional;
    };
}

const id_types: table[count] of string = {
    [0]="none", [1]="serial-number", [2]="caa-registration", [3]="utm-uuid", [4]="specific-session",
} &default="unknown";
const ua_types: table[count] of string = {
    [0]="none", [1]="aeroplane", [2]="helicopter-or-multirotor", [3]="gyroplane", [4]="hybrid-lift",
    [5]="ornithopter", [6]="glider", [7]="kite", [8]="free-balloon", [9]="captive-balloon",
    [10]="airship", [11]="parachute", [12]="rocket", [13]="tethered-powered", [14]="ground-obstacle",
} &default="other";
const statuses: table[count] of string = {
    [0]="undeclared", [1]="ground", [2]="airborne", [3]="emergency", [4]="system-failure",
} &default="unknown";

type Broadcaster: record {
    transport: string;
    ua_id: string &optional;
    id_type: string &optional;
    ua_type: string &optional;
    status: string &optional;
    lat: double &optional;
    lon: double &optional;
    alt: double &optional;
    height: double &optional;
    speed: double &optional;
    track: count &optional;
    op_lat: double &optional;
    op_lon: double &optional;
    operator_id: string &optional;
    description: string &optional;
    messages: count &default=0;
    signal: int &optional;
    channel: count &optional;
    logging: DroneDetector::LogState &default=DroneDetector::LogState();
};

global emit: function(m: string, b: Broadcaster, final: bool);
function expire_broadcaster(t: table[string] of Broadcaster, m: string): interval
    { emit(m,t[m],T); return 0secs; }
global broadcasters: table[string] of Broadcaster &write_expire=5min &expire_func=expire_broadcaster;
global nan_service_id = "";

event zeek_init()
    { nan_service_id=hexstr_to_bytestring(sha256_hash("org.opendroneid.remoteid")[0:12]); }

function text(s: string): string
    {
    local p=strstr(s,"\x00");
    if ( p > 0 ) s=s[0:p-1];
    return /^[ -~]*$/ == s ? strip(s) : "";
    }

function decode_message(b: Broadcaster, m: string)
    {
    local type_=DroneRadio::byte(m,0)/16;
    local b1=DroneRadio::byte(m,1);
    if ( type_ == 0 )
        {
        local id=text(m[2:22]);
        if ( id == "" ) return;
        b$ua_id=id; b$id_type=id_types[b1/16]; b$ua_type=ua_types[b1%16];
        }
    else if ( type_ == 1 )
        {
        b$status=statuses[b1/16];
        local dir=DroneRadio::byte(m,2)+((b1/2)%2 == 1 ? 180 : 0);
        if ( dir <= 360 ) b$track=dir;
        local sp=DroneRadio::byte(m,3)+0.0;
        b$speed=b1%2 == 0 ? sp*0.25 : sp*0.75+255.0*0.25;
        local lat=DroneRadio::le32s(m,5)/10000000.0; local lon=DroneRadio::le32s(m,9)/10000000.0;
        if ( (lat != 0.0 || lon != 0.0) && lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 )
            { b$lat=lat; b$lon=lon; }
        # Encoded altitude/height: value*0.5-1000 m; 0 means unknown.
        local geo=DroneRadio::le16(m,15); local h=DroneRadio::le16(m,17);
        if ( geo != 0 ) b$alt=geo*0.5-1000.0;
        if ( h != 0 ) b$height=h*0.5-1000.0;
        }
    else if ( type_ == 3 )
        {
        local d=text(m[2:25]);
        if ( d != "" ) b$description=d;
        }
    else if ( type_ == 4 )
        {
        local olat=DroneRadio::le32s(m,2)/10000000.0; local olon=DroneRadio::le32s(m,6)/10000000.0;
        if ( (olat != 0.0 || olon != 0.0) && olat >= -90.0 && olat <= 90.0 && olon >= -180.0 && olon <= 180.0 )
            { b$op_lat=olat; b$op_lon=olon; }
        }
    else if ( type_ == 5 )
        {
        local op=text(m[2:22]);
        if ( op != "" ) b$operator_id=op;
        }
    else return;
    ++b$messages;
    }

# A single 25-byte message, or a message pack (type 0xF) of several.
function decode(b: Broadcaster, data: string): bool
    {
    if ( |data| < 25 ) return F;
    if ( DroneRadio::byte(data,0)/16 != 15 ) { decode_message(b,data[0:25]); return T; }
    if ( |data| < 3 ) return F;
    local size=DroneRadio::byte(data,1); local n=DroneRadio::byte(data,2);
    if ( size != 25 || n == 0 || n > 9 || |data| < 3+n*25 ) return F;
    local i: count=0;
    while ( i < n ) { decode_message(b,data[3+i*25:3+(i+1)*25]); ++i; }
    return T;
    }

function emit(m: string, b: Broadcaster, final: bool)
    {
    local kind=DroneDetector::log_kind(b$logging,set(),final);
    if ( kind == "" ) return;
    local rec=DroneDetector::Info($ts=network_time(),$event_type=kind,$protocol="remote-id",
        $likely_manufacturer="unknown",$evidence="astm-f3411-"+b$transport,$inspection_limited=F,
        $remoteid_transport=b$transport,$remoteid_transmitter=m,$remoteid_messages=b$messages);
    if ( b?$ua_id ) { rec$remoteid_ua_id=b$ua_id; rec$remoteid_id_type=b$id_type; rec$remoteid_ua_type=b$ua_type; }
    if ( b?$status ) rec$remoteid_status=b$status;
    if ( b?$lat ) { rec$remoteid_latitude=b$lat; rec$remoteid_longitude=b$lon; }
    if ( b?$alt ) rec$remoteid_altitude_m=b$alt;
    if ( b?$height ) rec$remoteid_height_m=b$height;
    if ( b?$speed ) rec$remoteid_speed_mps=b$speed;
    if ( b?$track ) rec$remoteid_track_deg=b$track;
    if ( b?$op_lat ) { rec$remoteid_operator_latitude=b$op_lat; rec$remoteid_operator_longitude=b$op_lon; }
    if ( b?$operator_id ) rec$remoteid_operator_id=b$operator_id;
    if ( b?$description ) rec$remoteid_description=b$description;
    if ( b?$signal ) rec$remoteid_signal_dbm=b$signal;
    if ( b?$channel ) rec$remoteid_channel_mhz=b$channel;
    DroneDetector::write_state(rec,b$logging,kind);
    }

function observe(rt: DroneRadio::Radiotap, transport: string, payload: string)
    {
    if ( ! rt?$transmitter ) return;
    local m=rt$transmitter;
    if ( m !in broadcasters )
        {
        if ( |broadcasters| >= max_broadcasters ) return;
        local fresh=Broadcaster($transport=transport);
        if ( ! decode(fresh,payload) || fresh$messages == 0 ) return;
        broadcasters[m]=fresh;
        }
    else if ( ! decode(broadcasters[m],payload) ) return;
    local b=broadcasters[m];
    if ( rt?$signal_dbm ) b$signal=rt$signal_dbm;
    if ( rt?$channel_mhz ) b$channel=rt$channel_mhz;
    b$logging$dirty=T;
    broadcasters[m]=b; # refresh &write_expire
    emit(m,b,F);
    }

event DroneRadio::frame(rt: DroneRadio::Radiotap, data: string)
    {
    local fc=DroneRadio::byte(data,0);
    if ( (fc/4)%4 != 0 ) return;
    local subtype=fc/16;
    if ( subtype == 8 && |data| > 36 )
        {
        local i: count=36;
        while ( i+2 <= |data| && i < 2048 )
            {
            local tag=DroneRadio::byte(data,i); local size=DroneRadio::byte(data,i+1); i+=2;
            if ( i+size > |data| ) return;
            # Vendor IE: OUI FA:0B:BC, type 0x0D, message counter, then message(s).
            if ( tag == 221 && size >= 30 && data[i:i+4] == "\xfa\x0b\xbc\x0d" )
                { observe(rt,"wifi-beacon",data[i+5:i+size]); return; }
            i+=size;
            }
        return;
        }
    # NAN service discovery: public action (4), vendor specific (9), OUI 50:6F:9A type 0x13.
    if ( subtype != 13 || |data| < 30 || data[24:30] != "\x04\x09\x50\x6f\x9a\x13" ) return;
    local a: count=30;
    while ( a+3 <= |data| )
        {
        local aid=DroneRadio::byte(data,a); local alen=DroneRadio::le16(data,a+1); a+=3;
        if ( a+alen > |data| ) return;
        if ( aid == 3 && alen >= 9 && data[a:a+6] == nan_service_id )
            {
            local ctl=DroneRadio::byte(data,a+8); local p=a+9; local limit=a+alen;
            if ( (ctl/64)%2 == 1 ) p+=2;                                   # binding bitmap
            if ( (ctl/4)%2 == 1 && p < limit ) p+=1+DroneRadio::byte(data,p); # matching filter
            if ( (ctl/8)%2 == 1 && p < limit ) p+=1+DroneRadio::byte(data,p); # response filter
            if ( (ctl/16)%2 == 0 || p >= limit ) return;                      # no service info
            local ilen=DroneRadio::byte(data,p); ++p;
            if ( ilen < 26 || p+ilen > limit ) return;
            # Service info: message counter, then message pack.
            observe(rt,"wifi-nan",data[p+1:p+ilen]);
            return;
            }
        a+=alen;
        }
    }

event zeek_done()
    { for ( m in broadcasters ) emit(m,broadcasters[m],T); }
