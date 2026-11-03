# Opt-in: requires ARP and drone traffic from ONE IPv4 broadcast domain on the same worker.
@load ./__load__

module DroneARP;

export {
    const evidence_window = 60secs &redef;
    const minimum_claims: count = 3 &redef;
    const minimum_span = 2secs &redef;
    const max_pairs: count = 4096 &redef;
    const max_macs_per_pair: count = 4 &redef;
    # Known proxy ARP/router MACs can be excluded (lowercase colon notation).
    const ignored_macs: set[string] = {} &redef;
    redef record DroneDetector::Info += {
        arp_claimant_macs: set[string] &log &optional;
        arp_claimed_ips: set[addr] &log &optional;
        arp_tracking_limited: bool &log &optional;
    };
}

type Claim: record { last: time; samples: vector of time; };
type Claims: table[string] of Claim;
global claims: table[addr,addr] of Claims &write_expire=2min;
global limited_until: time = double_to_time(0.0);

function unicast_mac(m: string): bool
    {
    return m != "00:00:00:00:00:00" &&
        /^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/ == m;
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    local m=to_lower(SHA);
    if ( SPA == TPA || SPA == 0.0.0.0 || TPA == 0.0.0.0 ||
         ! is_v4_addr(SPA) || ! is_v4_addr(TPA) ||
         ! unicast_mac(m) || to_lower(mac_src) != m || m in ignored_macs ) return;
    if ( [SPA,TPA] !in claims )
        {
        if ( |claims| >= max_pairs ) { limited_until=network_time()+evidence_window; return; }
        claims[SPA,TPA]=table();
        }
    local entries=claims[SPA,TPA];
    # Drop stale alternatives before enforcing the per-pair bound.
    local stale: set[string]=set();
    for ( k in entries )
        if ( network_time()-entries[k]$last > evidence_window ) add stale[k];
    for ( k in stale ) delete entries[k];
    if ( m !in entries )
        {
        if ( |entries| >= max_macs_per_pair ) { limited_until=network_time()+evidence_window; return; }
        entries[m]=[$last=network_time(),$samples=vector(network_time())];
        }
    else
        {
        local c=entries[m];
        # At most one sample per second avoids treating duplicate bursts as evidence.
        if ( network_time()-c$last >= 1sec )
            {
            local recent: vector of time=vector();
            for ( i in c$samples )
                if ( network_time()-c$samples[i] <= evidence_window )
                    {
                    if ( |recent| < 127 ) recent[|recent|]=c$samples[i];
                    else limited_until=network_time()+evidence_window;
                    }
            recent[|recent|]=network_time(); c$samples=recent; c$last=network_time();
            }
        }
    claims[SPA,TPA]=entries;
    }

function sufficient(c: Claim): bool
    {
    local n: count=0; local first=network_time();
    for ( i in c$samples )
        if ( network_time()-c$samples[i] <= evidence_window )
            { if ( n == 0 ) first=c$samples[i]; ++n; }
    return n >= minimum_claims && c$last-first >= minimum_span;
    }

hook DroneDetector::enrich_log(rec: DroneDetector::Info)
    {
    if ( ! rec?$id ) return;
    rec$arp_tracking_limited=network_time() < limited_until;
    local a=rec$id$orig_h; local b=rec$id$resp_h;
    if ( [a,b] !in claims || [b,a] !in claims ) return;
    local matches: set[string]=set();
    for ( m in claims[a,b] )
        if ( m in claims[b,a] && sufficient(claims[a,b][m]) && sufficient(claims[b,a][m]) ) add matches[m];
    if ( |matches| == 0 ) return;
    if ( ! rec?$alert ) rec$alert=set();
    add rec$alert["ARP interception pattern: one MAC repeatedly claims both endpoints of a confirmed drone flow"];
    rec$arp_claimant_macs=matches;
    rec$arp_claimed_ips=set(a,b);
    }
