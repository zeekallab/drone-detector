# Loaded by default (off switch: redef DroneRadio::enabled = F;). Inventory of
# drone-like 802.11 transmitters.
# Matches access points by SSID pattern or vendor OUI (beacons and probe
# responses) and drone-vendor stations by their probe requests, then tracks
# channel, signal, associated stations and data volume, encrypted or not.
@load ./radiotap
@load ../wifi

module DroneInventory;

export {
    ## SSID patterns of drone access points. Extend with redef.
    const drone_ssids: set[pattern] = {
        /^TELLO-[0-9A-Fa-f]{6}$/,
        /^(DJI|Mavic|Spark|Phantom|Tello)[-_ ]/,
        /^(Anafi|Bebop|Disco|Skycontroller)/,
        /^Skydio/,
        /^Autel/,
    } &redef;
    ## OUI (first three octets, lowercase) -> vendor. 60:60:1f is confirmed by
    ## the ISOT Tello captures; verify the rest against the IEEE registry.
    const drone_ouis: table[string] of string = {
        ["60:60:1f"] = "DJI",
        ["34:d2:62"] = "DJI",
        ["48:1c:b9"] = "DJI",
        ["90:3a:e6"] = "Parrot",
        ["a0:14:3d"] = "Parrot",
        ["00:12:1c"] = "Parrot",
        ["00:26:7e"] = "Parrot",
        ["90:03:b7"] = "Parrot",
    } &redef;
    ## Downlink bytes in one minute that suggest a live video stream.
    const video_bytes_per_minute: count = 2000000 &redef;
    const max_emitters: count = 256 &redef;
    const max_stations: count = 8 &redef;

    redef record DroneDetector::Info += {
        wireless_role: string &log &optional;
        wireless_vendor: string &log &optional;
        wireless_channel_mhz: count &log &optional;
        wireless_signal_dbm_min: int &log &optional;
        wireless_signal_dbm_max: int &log &optional;
        wireless_signal_dbm_last: int &log &optional;
        wireless_protected: bool &log &optional;
        wireless_stations: set[string] &log &optional;
        wireless_downlink_frames: count &log &optional;
        wireless_uplink_frames: count &log &optional;
        wireless_downlink_bytes: count &log &optional;
        wireless_uplink_bytes: count &log &optional;
        wireless_video_suspected: bool &log &optional;
        wireless_first_seen: time &log &optional;
    };
}

type Emitter: record {
    role: string;
    ssid: string &optional;
    vendor: string &default="unknown";
    evidence: string;
    channel: count &optional;
    sig_min: int &optional;
    sig_max: int &optional;
    sig_last: int &optional;
    protected: bool &optional;
    stations: set[string] &default=set();
    down_frames: count &default=0;
    up_frames: count &default=0;
    down_bytes: count &default=0;
    up_bytes: count &default=0;
    window_start: time;
    window_down: count &default=0;
    video: bool &default=F;
    first_seen: time;
    logging: DroneDetector::LogState &default=DroneDetector::LogState();
};

global emit: function(m: string, e: Emitter, final: bool);
function expire_emitter(t: table[string] of Emitter, m: string): interval
    { emit(m,t[m],T); return 0secs; }
global emitters: table[string] of Emitter &write_expire=5min &expire_func=expire_emitter;

function vendor_of(m: string): string
    { return m[0:8] in drone_ouis ? drone_ouis[m[0:8]] : ""; }

function drone_ssid(ssid: string): bool
    {
    for ( p in drone_ssids ) if ( p == ssid ) return T;
    return F;
    }

function emit(m: string, e: Emitter, final: bool)
    {
    local kind=DroneDetector::log_kind(e$logging,set(),final);
    if ( kind == "" ) return;
    local rec=DroneDetector::Info($ts=network_time(),$event_type=kind,$protocol="802.11",
        $likely_manufacturer=e$vendor,$evidence=e$evidence,$inspection_limited=F,
        $wireless_bssid=m,$wireless_role=e$role,$wireless_vendor=e$vendor,
        $wireless_stations=e$stations,$wireless_downlink_frames=e$down_frames,
        $wireless_uplink_frames=e$up_frames,$wireless_downlink_bytes=e$down_bytes,
        $wireless_uplink_bytes=e$up_bytes,$wireless_video_suspected=e$video,
        $wireless_first_seen=e$first_seen);
    if ( e?$ssid ) rec$wireless_ssid=e$ssid;
    if ( e?$channel ) rec$wireless_channel_mhz=e$channel;
    if ( e?$sig_min ) { rec$wireless_signal_dbm_min=e$sig_min; rec$wireless_signal_dbm_max=e$sig_max; rec$wireless_signal_dbm_last=e$sig_last; }
    if ( e?$protected ) rec$wireless_protected=e$protected;
    DroneDetector::write_state(rec,e$logging,kind);
    }

function observe_signal(e: Emitter, rt: DroneRadio::Radiotap)
    {
    if ( rt?$channel_mhz ) e$channel=rt$channel_mhz;
    if ( ! rt?$signal_dbm ) return;
    local s=rt$signal_dbm;
    if ( ! e?$sig_min || s < e$sig_min ) e$sig_min=s;
    if ( ! e?$sig_max || s > e$sig_max ) e$sig_max=s;
    e$sig_last=s;
    }

function track(m: string, role: string, ssid: string, vendor: string, evidence: string): Emitter
    {
    if ( m !in emitters )
        {
        if ( |emitters| >= max_emitters ) return Emitter($role="",$evidence="",$window_start=network_time(),$first_seen=network_time());
        emitters[m]=Emitter($role=role,$evidence=evidence,$window_start=network_time(),$first_seen=network_time());
        }
    local e=emitters[m];
    if ( ssid != "" ) e$ssid=ssid;
    if ( vendor != "" ) e$vendor=vendor;
    return e;
    }

event DroneRadio::frame(rt: DroneRadio::Radiotap, data: string)
    {
    local fc=DroneRadio::byte(data,0); local flags=DroneRadio::byte(data,1);
    local kind=(fc/4)%4; local subtype=fc/16;
    if ( kind == 0 && (subtype == 8 || subtype == 5 || subtype == 4) )
        {
        local fixed: count=subtype == 4 ? 24 : 36;
        if ( |data| < fixed ) return;
        local ssid=""; local have_ssid=F;
        local i=fixed;
        while ( i+2 <= |data| && i < 1024 )
            {
            local tag=DroneRadio::byte(data,i); local size=DroneRadio::byte(data,i+1); i+=2;
            if ( i+size > |data| ) return;
            if ( tag == 0 && size <= 32 ) { ssid=data[i:i+size]; have_ssid=T; break; }
            i+=size;
            }
        local tx=DroneRadio::mac(data[10:16]);
        local vendor=vendor_of(tx);
        local e: Emitter;
        if ( subtype == 4 )
            {
            # Probe requests: only drone-vendor stations; ordinary phones probe constantly.
            if ( vendor == "" ) return;
            e=track(tx,"station",ssid,vendor,"drone-vendor-oui+probe-request");
            }
        else
            {
            local by_ssid=have_ssid && drone_ssid(ssid);
            if ( ! by_ssid && vendor == "" ) return;
            e=track(tx,"access-point",ssid,vendor,
                by_ssid ? (vendor != "" ? "drone-ssid+drone-vendor-oui" : "drone-ssid") : "drone-vendor-oui");
            # Capability field privacy bit: the network uses encryption.
            e$protected=(DroneRadio::le16(data,34)/16)%2 == 1;
            }
        if ( e$role == "" ) return;
        observe_signal(e,rt);
        e$logging$dirty=T;
        emitters[tx]=e; # refresh &write_expire
        emit(tx,e,F);
        return;
        }
    if ( kind != 2 || |data| < 24 ) return;
    # Data frames: BSSID position follows the ToDS/FromDS bits.
    local ds=flags%4;
    if ( ds == 3 ) return;
    local bssid=ds == 1 ? DroneRadio::mac(data[4:10]) : (ds == 2 ? DroneRadio::mac(data[10:16]) : DroneRadio::mac(data[16:22]));
    if ( bssid !in emitters ) return;
    local ap=emitters[bssid];
    local station=ds == 1 ? DroneRadio::mac(data[10:16]) : (ds == 2 ? DroneRadio::mac(data[4:10]) : "");
    if ( station != "" && station != bssid && station !in ap$stations && |ap$stations| < max_stations
         && station != "ff:ff:ff:ff:ff:ff" ) add ap$stations[station];
    if ( network_time()-ap$window_start >= 60secs )
        { ap$window_start=network_time(); ap$window_down=0; }
    if ( ds == 2 ) { ++ap$down_frames; ap$down_bytes+=|data|; ap$window_down+=|data|; observe_signal(ap,rt); }
    else { ++ap$up_frames; ap$up_bytes+=|data|; }
    # Flag as soon as one minute's downlink crosses the threshold.
    if ( ! ap$video && ap$window_down >= video_bytes_per_minute )
        { ap$video=T; ap$evidence+="+sustained-downlink"; }
    ap$logging$dirty=T;
    emitters[bssid]=ap; # refresh &write_expire
    emit(bssid,ap,F);
    }

event zeek_done()
    { for ( m in emitters ) emit(m,emitters[m],T); }
