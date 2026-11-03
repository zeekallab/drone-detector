# MITM capture review

Reviewed 2026-11-03. Twelve Ethernet captures from the UVic ISOT `Raw Data/MITM`
folder contain repeated ARP claims consistent with interception attempts.

## Credit and source

The captures belong to the University of Victoria ISOT research dataset, credited
to Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Dataset description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)

No source PCAPs are redistributed by this project.

## Evidence

Eleven captures repeatedly advertise both communicating peer IPs at the same MAC,
`c8:78:7d:96:67:d7`, using opposite-direction ARP replies. Neither this MAC nor
these IP addresses is hardcoded into the detector.

In the flight captures the peers are `192.168.10.1` and `.2` or `.3`. In the six
station-mode captures the peers are `192.168.0.104` and `.102`. Station-mode
captures also include replies advertising `.104` at `60:60:1f:58:ec:cc` and `.102`
at `e8:b1:fc:1e:2e:ae`, conflicting with the intermediate MAC's claims.

| Capture | Reciprocal claims by intermediate MAC (each direction) |
| --- | --- |
| `MITM_1_5_3_fly_10mins.pcap` | 345 / 345 |
| `MITM_2_5_3_fly_15mins.pcap` | 410 / 410 |
| `MITM_3_5_13_fly_10mins.pcap` | 286 / 285 |
| `MITM_4_5_13_fly_5mins.pcap` | One-sided: 147 claims for `.2` to `.1` |
| `MITM_4_5_5_fly_12mins.pcap` | 345 / 343 |
| `MITM_5_5_13_fly_8mins.pcap` | 237 / 236 |
| `mitm_station_mode_1_5_24.pcap` | 302 / 302 |
| `mitm_station_mode_2_5_24.pcap` | 316 / 315 |
| `mitm_station_mode_3_5_24.pcap` | 296 / 296 |
| `mitm_station_mode_4_5_24.pcap` | 297 / 297 |
| `mitm_station_mode_5_5_24.pcap` | 279 / 279 |
| `mitm_station_mode_6_5_24.pcap` | 315 / 315 |

These are raw capture counts, not independent attack counts. In station-mode
capture 1, inspected telemetry pairs have matching IP IDs/payloads and appear
first from the drone MAC to the intermediate MAC, then from that MAC to the
controller with TTL reduced from 255 to 254. This supports forwarding through
an intermediate host, not payload modification. Forwarding alone is also normal
router behavior, so it is not a separate attack alert.

The one-sided capture still identifies binary Tello traffic, but does not meet
the reciprocal-claim rule. Repeated claims alone cannot establish that a MAC is
unauthorized without baseline or additional evidence.

## Detection

The optional `scripts/arp.zeek` module enriches existing confirmed drone rows with:

> ARP interception pattern: one MAC repeatedly claims both endpoints of a confirmed drone flow

For A communicating with B, the same unicast MAC must send ARP replies claiming
A to B and B to A. Each direction needs three sampled replies in the last
60 seconds, spanning at least two seconds. At most one sample per second is
retained per claim. Ethernet source and ARP sender MAC must agree. Requests,
gratuitous self-claims, zero addresses, non-unicast MACs, isolated claims and
ARP traffic without a confirmed drone flow do not establish this alert.

`arp_claimant_macs` and `arp_claimed_ips` expose the evidence. These identify
advertised mappings, not authenticated owners or a proven attacker. The module
appends to `alert`; other control alerts remain intact. No new log stream or
extra emissions are created, preserving the per-connection minute limit.

## Deployment boundaries

Load explicitly on traffic from **one IPv4 broadcast domain**, with ARP and drone
packets available to the same Zeek worker. The ARP event interface used here does
not scope state by VLAN or capture interface. Do not enable it over merged
networks with overlapping addresses. Routed mirrors often omit ARP. Cluster
load balancing can split evidence; no cross-worker state exchange is implemented.
The script is not loaded by default and has not been deployed to a Corelight sensor.

Proxy ARP and other legitimate shared-MAC arrangements can trigger this pattern.
Known proxies can be excluded using `DroneARP::ignored_macs`. One-sided poisoning,
IPv6 neighbor discovery attacks, encrypted or unidentified drone traffic, and
payload manipulation without this ARP pattern are outside coverage. Capture
replays or duplication spread over time can also reproduce the evidence.

Tracking defaults to 4,096 directed IP pairs and four MACs per pair, with
128 time samples per claim. Idle pairs expire after two minutes; evidence older
than the configured window is ignored. `arp_tracking_limited` warns that a local
tracking bound was recently reached, so evidence may be incomplete. It is a
worker-wide warning, not attribution of the overflowing traffic to this drone.
See the [README](../EXTENDED_README.md#arp-interception-pattern-optional) for commands and
[validation](../validation/v0.6.0-results.md) for tested coverage.
