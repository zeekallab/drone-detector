# Loaded by default: shared 802.11 frame input for the wireless modules.
#
# Two inputs, both raising DroneRadio::frame:
#   1. A monitor-mode (radiotap) capture interface, e.g. Zeek on the capture box.
#   2. Raw 802.11 forwarded inside GRE protocol 0x8200 (Aruba format) to a decoy
#      address and mirrored to the sensor. An optional GRE key carries channel
#      MHz (high 16 bits) and signal dBm (low 16 bits, two's complement).
# Uses raw_packet, which runs per packet. Disable with redef DroneRadio::enabled = F.
module DroneRadio;

export {
    type Radiotap: record {
        channel_mhz: count &optional;
        signal_dbm: int &optional;
        # Transmitter address (addr2) when the frame carries one.
        transmitter: string &optional;
        ## "radiotap" or "gre".
        source: string &default="radiotap";
    };
    ## One undamaged 802.11 frame. data starts at the frame control field;
    ## a trailing FCS, when radiotap reports one, is already removed.
    global frame: event(rt: Radiotap, data: string);

    ## Wireless input on/off. Loaded by default; set F on sensors that never see
    ## wireless frames, which disables the per-packet raw_packet handler.
    const enabled = T &redef;
    ## Accept GRE 0x8200 frames sent to these decoy addresses.
    const gre_decoys: set[addr] = { 10.254.200.1 } &redef;

    global byte: function(data: string, offset: count): count;
    global le16: function(data: string, offset: count): count;
    global mac: function(data: string): string;
    ## Signed little-endian 32-bit value as double.
    global le32s: function(data: string, offset: count): double;
}

function byte(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+1]); }
function le16(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+2],T); }
function be16(data: string, offset: count): count
    { return bytestring_to_count(data[offset:offset+2]); }
function mac(data: string): string
    { return fmt("%02x:%02x:%02x:%02x:%02x:%02x",byte(data,0),byte(data,1),byte(data,2),byte(data,3),byte(data,4),byte(data,5)); }
function le32s(data: string, offset: count): double
    {
    local v=bytestring_to_count(data[offset:offset+4],T)+0.0;
    return v >= 2147483648.0 ? v-4294967296.0 : v;
    }

function align(cursor: count, a: count): count
    { return cursor+(a-cursor%a)%a; }

global first_frame_reported = F;

function deliver(rt: Radiotap, data: string)
    {
    if ( |data| < 10 ) return;
    # One-time diagnostic: proves frames reach the wireless modules on this sensor.
    if ( ! first_frame_reported )
        {
        first_frame_reported=T;
        Reporter::info(fmt("drone-detector: first wireless frame received (%s)",rt$source));
        }
    local fc=byte(data,0);
    if ( fc%4 != 0 ) return;                                           # protocol version 0
    # Control frames (type 1) mostly lack addr2; everything else has it at 10.
    if ( (fc/4)%4 != 1 && |data| >= 16 ) rt$transmitter=mac(data[10:16]);
    event DroneRadio::frame(rt,data);
    }

function from_radiotap(raw: string)
    {
    if ( |raw| < 8 || raw[0:2] != "\x00\x00" ) return;
    local hlen=le16(raw,2);
    if ( hlen < 8 || hlen > 4096 || |raw| < hlen+10 ) return;
    local present=bytestring_to_count(raw[4:8],T);
    local bitmap=present; local cursor: count=8; local words: count=1;
    while ( bitmap >= 2147483648 )
        {
        if ( cursor+4 > hlen || words >= 8 ) return;
        bitmap=bytestring_to_count(raw[cursor:cursor+4],T); cursor+=4; ++words;
        }
    local rt=Radiotap();
    local fcs_at_end=F;
    # Fields of the first present word, in bit order, with their alignment.
    if ( present%2 == 1 ) cursor=align(cursor,8)+8;                    # TSFT
    if ( (present/2)%2 == 1 )                                          # Flags
        {
        if ( cursor >= hlen ) return;
        local flags=byte(raw,cursor);
        if ( (flags/64)%2 == 1 ) return;                               # bad FCS
        fcs_at_end=(flags/16)%2 == 1;
        cursor+=1;
        }
    if ( (present/4)%2 == 1 ) cursor+=1;                               # Rate
    if ( (present/8)%2 == 1 )                                          # Channel
        {
        cursor=align(cursor,2);
        if ( cursor+4 > hlen ) return;
        rt$channel_mhz=le16(raw,cursor); cursor+=4;
        }
    if ( (present/16)%2 == 1 ) cursor+=2;                              # FHSS
    if ( (present/32)%2 == 1 && cursor < hlen )                        # dBm signal
        {
        local s: int=byte(raw,cursor);
        rt$signal_dbm=s >= 128 ? s-256 : s;
        }
    local limit=|raw|;
    if ( fcs_at_end ) { if ( limit < hlen+14 ) return; limit-=4; }
    deliver(rt,raw[hlen:limit]);
    }

# Ethernet [VLAN...] IPv4 GRE(0x8200) raw 802.11. Only the first IP fragment is
# parsed: management frames fit in one, and data frames keep their header there.
function from_gre(raw: string)
    {
    local off: count=12;
    local et=be16(raw,off);
    while ( (et == 0x8100 || et == 0x88a8) && |raw| >= off+6 ) { off+=4; et=be16(raw,off); }
    off+=2;
    if ( et != 0x0800 || |raw| < off+20 ) return;
    local ihl=(byte(raw,off)%16)*4;
    if ( ihl < 20 || byte(raw,off+9) != 47 ) return;
    if ( be16(raw,off+6)%8192 != 0 ) return;                           # later fragment
    local limit=off+be16(raw,off+2);
    if ( limit > |raw| ) limit=|raw|;
    local g=off+ihl;
    if ( limit < g+4 || be16(raw,g+2) != 0x8200 ) return;
    local gflags=be16(raw,g);
    local h=g+4;
    if ( gflags >= 32768 ) h+=4;                                       # checksum present
    local rt=Radiotap($source="gre");
    if ( (gflags/8192)%2 == 1 )                                        # key present
        {
        if ( limit < h+4 ) return;
        local mhz=be16(raw,h); local sig: int=be16(raw,h+2);
        if ( mhz != 0 ) rt$channel_mhz=mhz;
        if ( sig != 0 ) rt$signal_dbm=sig >= 32768 ? sig-65536 : sig;
        h+=4;
        }
    if ( (gflags/4096)%2 == 1 ) h+=4;                                  # sequence present
    if ( limit < h+10 ) return;
    deliver(rt,raw[h:limit]);
    }

event raw_packet(p: raw_pkt_hdr) &group="drone-wireless"
    {
    if ( p$l2$encap != LINK_ETHERNET ) { from_radiotap(get_current_packet()$data); return; }
    # Cheap filter first: only GRE to a configured decoy.
    if ( ! p?$ip || p$ip$p != 47 || p$ip$dst !in gre_decoys ) return;
    from_gre(get_current_packet()$data);
    }

event zeek_init()
    {
    if ( ! enabled ) { disable_event_group("drone-wireless"); return; }
    Reporter::info(fmt("drone-detector: wireless input enabled (GRE decoys %s)",gre_decoys));
    }
