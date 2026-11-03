# IP-spoofing capture review

Reviewed 2026-11-03 against v0.10.0. All ten captures in `Raw Data/IP Spoofing`
already trigger the existing alert:

> Replay-like control traffic: repeated older, checksum-valid Tello joystick messages

No new runtime rule or fields are added. The detector identifies the repeated
drone controls; it does not assert that an IP address was spoofed.

## Observations

All ten contain binary Tello control traffic from `192.168.10.18:7777` to
`192.168.10.1:8889`. The existing detector validates framing and checksums and
recognizes repeated older joystick messages. Identification does not depend on
these particular IP addresses or MACs. Some files also contain ASCII SDK requests.

Eight files associate source MAC `c8:78:7d:96:67:d7` with ARP sender address
`192.168.10.4`, while its control packets use `192.168.10.18`. This is useful
network context, but multiple IPs per MAC can also result from aliases or network
topology. File 4 has only drone-side ARP and file 9 has no ARP. Within each file,
we found no identical UDP payload transmitted from multiple source IPs.

There is no trusted address/identity baseline here that establishes an unauthorized
sender. The folder label alone does not establish spoofing or successful takeover.
A generic MAC/IP consistency check would add ambiguity without new drone-protocol
coverage, so this review leaves detector behavior unchanged. Whether a Corelight
sensor separately alerts on spoofing depends on its visibility and enabled
rules; this review does not validate that capability.

## Capture validation

| Capture | drone.log rows | Existing replay-alert rows |
| --- | ---: | ---: |
| `IP_spoofing_1_5_17_5mins.pcap` | 6 | 5 |
| `IP_spoofing_2_5_17_6mins.pcap` | 6 | 5 |
| `IP_spoofing_3_5_17_3mins.pcap` | 3 | 2 |
| `IP_spoofing_4_5_17_1mins.pcap` | 2 | 1 |
| `IP_spoofing_5_5_17_8mins.pcap` | 8 | 7 |
| `IP_spoofing_6_5_17_10mins.pcap` | 11 | 10 |
| `IP_spoofing_7_5_17_10mins.pcap` | 10 | 9 |
| `IP_spoofing_8_5_17_8mins.pcap` | 8 | 7 |
| `IP_spoofing_9_5_17_6mins.pcap` | 6 | 5 |
| `IP_spoofing_10_5_17_3mins.pcap` | 3 | 2 |

All runs used the default package with transport checksum checking disabled
(`zeek -C`); application CRC validation remains active. No reporter errors were
observed. The optional regression checks classification, the existing replay
alert, and at least 60 seconds between records for each UID:

```sh
python3 tests/test_ip_spoofing_captures.py
```

By default it reads `~/Downloads/ISOT Drone Dataset/Raw Data`. Set
`ISOT_CAPTURE_ROOT` to another extracted `Raw Data` directory, and `ZEEK` to
another Zeek executable if needed. Missing captures produce an explicit skip.
These results cover this corpus, not every form of source spoofing. Encryption,
unsupported protocols, missing originals, or repetition outside the existing
rule's timing/volume limits can prevent an alert. Replay-like observations do not
prove acceptance, physical movement, or attacker intent; capture duplication can
also produce repeated controls.

## Source and credit

The captures belong to University of Victoria ISOT, credited to Z. Chen,
I. Traoré, M. Mamun and S. Saad, “Drone Anomaly Detection: Dataset and
Unsupervised Machine Learning,” FPS 2024.

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)
- [Capture sizes and SHA-256 hashes](../tests/fixtures/uvic/ip-spoofing-manifest.json)

No PCAP binaries are added to the repository by this review.
