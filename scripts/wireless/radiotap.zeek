# Wireless profile only: shared radiotap parsing for monitor-mode captures.
# Parses the header once per packet and raises DroneRadio::frame for the
# wireless modules. Never load on a wired sensor: raw_packet runs per packet.
module DroneRadio;

export {
    type Radiotap: record {
        channel_mhz: count &optional;
        signal_dbm: int &optional;
        # Transmitter address (addr2) when the frame carries one.
        transmitter: string &optional;
    };
    ## One undamaged 802.11 frame. data starts at the frame control field;
    ## a trailing FCS, when radiotap reports one, is already removed.
    global frame: event(rt: Radiotap, data: string);

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
function mac(data: string): string
    { return fmt("%02x:%02x:%02x:%02x:%02x:%02x",byte(data,0),byte(data,1),byte(data,2),byte(data,3),byte(data,4),byte(data,5)); }
function le32s(data: string, offset: count): double
    {
    local v=bytestring_to_count(data[offset:offset+4],T)+0.0;
    return v >= 2147483648.0 ? v-4294967296.0 : v;
    }

function align(cursor: count, a: count): count
    { return cursor+(a-cursor%a)%a; }

event raw_packet(p: raw_pkt_hdr)
    {
    if ( p$l2$encap == LINK_ETHERNET ) return;
    local raw=get_current_packet()$data;
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
    local data=raw[hlen:limit];
    local fc=byte(data,0);
    if ( fc%4 != 0 ) return;                                           # protocol version 0
    # Control frames (type 1) mostly lack addr2; everything else has it at 10.
    if ( (fc/4)%4 != 1 && |data| >= 16 ) rt$transmitter=mac(data[10:16]);
    event DroneRadio::frame(rt,data);
    }
