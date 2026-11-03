# OPT-IN ONLY: raw 802.11/radiotap capture input. Do not load on a normal wired sensor.
@load ./__load__

module DroneWiFi;

export {
    const watched_ssid = /^TELLO-[0-9A-Fa-f]{6}$/ &redef;
    const burst_interval = 10secs &redef;
    const minimum_deauth_frames: count = 20 &redef;
    const max_networks: count = 64 &redef;
    const max_recent_frames: count = 1024 &redef;
    redef record DroneDetector::Info += {
        wireless_bssid: string &log &optional;
        wireless_ssid: string &log &optional;
        wireless_deauth_frames: count &log &optional;
        wireless_eapol_key_frames: count &log &optional;
        wireless_peak_burst: count &log &optional;
        wireless_tracking_limited: bool &log &optional;
    };
}

type Network: record {
    ssid: string;
    bucket_start: time;
    burst: count &default=0;
    peak: count &default=0;
    total: count &default=0;
    eapol: count &default=0;
    pending: bool &default=F;
    last_log: time &optional;
    seen: set[string];
    limited: bool &default=F;
};
global networks: table[string] of Network &write_expire=5min;

function byte(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+1]); }
function le16(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+2],T); }
function mac(data: string): string
    { return fmt("%02x:%02x:%02x:%02x:%02x:%02x",byte(data,0),byte(data,1),byte(data,2),byte(data,3),byte(data,4),byte(data,5)); }

function emit(bssid: string, n: Network)
    {
    if ( ! n$pending || (n?$last_log && network_time()-n$last_log < DroneDetector::log_interval) ) return;
    DroneDetector::write_log([$ts=network_time(),$event_type=n?$last_log ? "update" : "detection",
        $protocol="802.11",$likely_manufacturer="unknown",$evidence="observed-tello-named-ssid+deauthentication-burst",
        $inspection_limited=F,$wireless_bssid=bssid,$wireless_ssid=n$ssid,
        $wireless_deauth_frames=n$total,$wireless_eapol_key_frames=n$eapol,
        $wireless_peak_burst=n$peak,$wireless_tracking_limited=n$limited,
        $alert=set("Wireless deauthentication burst: repeated disconnect frames on a Tello-named Wi-Fi network")]);
    n$last_log=network_time(); n$pending=F; n$total=0; n$eapol=0; n$peak=0;
    n$burst=0; n$bucket_start=network_time();
    }

event raw_packet(p: raw_pkt_hdr)
    {
    if ( p$l2$encap == LINK_ETHERNET ) return;
    local raw=get_current_packet()$data;
    # Explicitly support radiotap only: version/pad, little-endian header size.
    if ( |raw| < 8 || raw[0:2] != "\x00\x00" ) return;
    local offset=le16(raw,2);
    if ( offset < 8 || offset > 4096 || |raw| < offset+24 ) return;
    local present=bytestring_to_count(raw[4:8],T);
    local bitmap=present; local cursor: count=8; local words: count=1;
    while ( bitmap >= 2147483648 )
        {
        if ( cursor+4 > offset || words >= 8 ) return;
        bitmap=bytestring_to_count(raw[cursor:cursor+4],T); cursor+=4; ++words;
        }
    if ( present%2 == 1 ) { cursor += (8-cursor%8)%8; cursor+=8; }
    if ( (present/2)%2 == 1 )
        {
        if ( cursor >= offset ) return;
        # Radiotap reports bad FCS: do not count corrupt wireless frames.
        if ( (byte(raw,cursor)/64)%2 == 1 ) return;
        }
    local data=raw[offset:];
    local fc=byte(data,0); local flags=byte(data,1);
    if ( fc%4 != 0 ) return;
    local kind=(fc/4)%4;
    local subtype=fc/16;
    if ( kind == 0 && subtype == 8 )
        {
        if ( |data| < 36 || data[10:16] != data[16:22] ) return;
        local bssid=mac(data[16:22]);
        local i: count=36;
        while ( i+2 <= |data| && i < 1024 )
            {
            local tag=byte(data,i); local size=byte(data,i+1); i+=2;
            if ( i+size > |data| ) return;
            if ( tag == 0 )
                {
                if ( size > 32 ) return;
                local ssid=data[i:i+size];
                if ( ! (watched_ssid == ssid) ) { if ( bssid in networks ) delete networks[bssid]; return; }
                if ( bssid !in networks )
                    {
                    if ( |networks| >= max_networks ) return;
                    networks[bssid]=Network($ssid=ssid,$bucket_start=network_time(),$seen=set());
                    }
                else networks[bssid]=networks[bssid]; # Refresh known network expiry.
                return;
                }
            i+=size;
            }
        return;
        }
    if ( ! (kind == 0 && subtype == 12) && ! (kind == 2 && (flags/64)%2 == 0) ) return;
    local bs = kind == 2 && flags%4 == 1 ? mac(data[4:10]) :
               (kind == 2 && flags%4 == 2 ? mac(data[10:16]) : mac(data[16:22]));
    if ( bs !in networks ) return;
    local n=networks[bs];
    if ( kind == 0 && subtype == 12 )
        {
        if ( |data| < 26 || (flags/64)%2 == 1 || (flags/8)%2 == 1 ) return;
        # Authentication/retry frames alone are not attack evidence.
        if ( network_time()-n$bucket_start >= burst_interval )
            { n$bucket_start=network_time(); n$burst=0; n$seen=set(); }
        local key=data[4:24];
        if ( key in n$seen ) return;
        if ( |n$seen| >= max_recent_frames ) { n$limited=T; return; }
        add n$seen[key]; ++n$burst; ++n$total;
        if ( n$burst > n$peak ) n$peak=n$burst;
        if ( n$burst >= minimum_deauth_frames ) n$pending=T;
        emit(bs,n);
        }
    else if ( kind == 2 && flags%4 != 3 && (flags/64)%2 == 0 )
        {
        local header: count=24;
        if ( subtype%8 >= 4 ) return;
        if ( subtype >= 8 )
            {
            if ( |data| < 26 || (byte(data,24)/128)%2 == 1 ) return; # A-MSDU unsupported.
            header+=2;
            if ( flags >= 128 ) header+=4;
            }
        if ( |data| < header+12 || data[header:header+8] != "\xaa\xaa\x03\x00\x00\x00\x88\x8e" ) return;
        local e=header+8;
        if ( byte(data,e)<1 || byte(data,e)>3 || byte(data,e+1)!=3 ) return;
        local length=bytestring_to_count(data[e+2:e+4]);
        if ( length < 95 || |data| < e+4+length ) return;
        ++n$eapol;
        emit(bs,n);
        }
    }
