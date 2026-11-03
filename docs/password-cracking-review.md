# Password-cracking capture review

Reviewed 2026-11-03. These captures show wireless disruption and handshake
traffic consistent with possible handshake harvesting. They do not reveal
whether an offline password search occurred or succeeded.

## Source and credit

The captures belong to the University of Victoria ISOT dataset, credited to
Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset page](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Dataset description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)

Files are in `Raw Data/Password Cracking/` in the source archive. No PCAP
binaries are redistributed by this project.

## Observations

Both raw radiotap/802.11 captures contain beacons advertising `TELLO-58ECCC`
with BSSID `60:60:1f:58:ec:cc`.

| Capture | All deauthentication frames | Broadcast frames claiming drone BSSID | Peak deauthentication frames/second | Drone handshake M1/M2/M3/M4 observations |
| --- | ---: | ---: | ---: | --- |
| `pwd_crack_deau_and_eqpol_1_5_6_30mins_raw.pcap` | 29,359 | 28,928 | 269 | 529 / 78 / 116 / 63 |
| `pwd_crack_deau_and_eqpol_2_5_6_45mins_raw.pcap` | 85,524 | 83,968 | 273 | 1,886 / 174 / 614 / 159 |

Totals and peaks above are capture-wide analysis counts, not the detector's
filtered/deduplicated counters. The first capture additionally contains four M2
observations on another network. Repeated handshake messages are not counts of
unique sessions. Most disconnects use reason 7 (class 3 frame received from a
nonassociated station). Observed authentication status codes are success, not a
series of rejected password guesses. MAC addresses and SSIDs can be spoofed.

## Implemented signal

The optional `scripts/wifi.zeek` module adds this description to `alert`:

> Wireless deauthentication burst: repeated disconnect frames on a Tello-named Wi-Fi network

It requires an observed matching beacon and 20 distinct, unprotected, non-retry
deauthentication frames within a 10-second bucket. It excludes frames flagged
bad-FCS by radiotap and deduplicates management-frame identities within the bucket.
EAPOL key-frame counts supply context; a handshake alone never raises this alert.

The same `drone.log` carries SSID, BSSID, disconnect count, EAPOL count, peak burst
and tracking-limit status. Wireless rows have no fabricated IP connection/UID.
Updates occur at most once per minute per BSSID; short activity after an earlier
record may not be emitted if traffic stops before the next eligible update.

Offline replay produced 27 and 42 wireless alert rows respectively. Bounded
tracking can undercount heavy bursts: `wireless_tracking_limited` indicates that
limit was reached. This is not an exact packet-accounting tool.

## Visibility and interpretation

Explicitly load the optional module on radiotap input; it is excluded from the
normal package load. An ordinary wired mirror cannot supply these management
frames. Live Corelight compatibility and raw-handler performance are unvalidated.

A burst can indicate deliberate disruption, but capture duplication, network
faults or legitimate management behavior must also be considered. The detector
does not attribute the transmitter, authenticate manufacturer identity, detect
offline password computation, or prove successful takeover. Its default SSID
scope is Tello-specific; other manufacturers need separately validated coverage.
