# Replay capture review

Reviewed 2026-11-03. All six `Raw Data/Replay` captures were inspected and tested.
They contain rapid repetitions of complete, checksum-valid binary Tello joystick
messages. Their timing differs from the older-message reuse in the Manipulation
captures, so the previous two-second minimum replay age missed them.

## Source and credit

Original captures belong to University of Victoria ISOT, credited to Z. Chen,
I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)
- [Source member sizes and SHA-256 hashes](../tests/fixtures/uvic/replay-manifest.json)

No source PCAPs are redistributed.

## Findings

All six carry one-way control traffic from 192.168.10.2 to 192.168.10.1. The
binary frames validate against declared length, header CRC8 and full CRC16.
A few nonbinary datagrams occur in three files; these are not treated as malformed
binary controls. Joystick command 0x0050/type 0x60 messages recur with exactly
the same complete payload, usually tens of milliseconds after the preceding copy.
The repeated payloads include the full control data, not just unchanged stick axes.

| Capture | Joystick frames | Distinct complete payloads | Max rapid repeats / 10s | Max distinct repeated payloads / 10s | New alert rows |
| --- | ---: | ---: | ---: | ---: | ---: |
| `replay_1_5_22_10mins.pcap` | 9145 | 8584 | 94 | 38 | 2 |
| `replay_2_5_22_10mins.pcap` | 10442 | 9942 | 46 | 22 | 3 |
| `replay_3_5_22_10mins.pcap` | 10741 | 10456 | 32 | 17 | 2 |
| `replay_4_5_22_10mins.pcap` | 8821 | 8486 | 27 | 18 | 2 |
| `replay_5_5_22_10mins.pcap` | 9578 | 9377 | 21 | 11 | 1 |
| `replay_6_5_22_10mins.pcap` | 8750 | 8470 | 31 | 17 | 2 |

Window maxima are independent capture-analysis measurements for repeat gaps of
10 ms to under two seconds, not the detector's interval counters. The three
normal-flight comparisons contain 12,091, 13,691 and 17,146 joystick frames,
respectively, with no identical complete joystick payloads in these samples.
This is limited negative coverage, not a universal false-positive estimate.

The v0.9.0 detector identified all six binary streams but produced no replay or
malformed-control alerts. Simply lowering the older-replay age would mix different
patterns and weaken its intended safeguards, so v0.10.0 adds a separate rule.

## New detection

> Rapid replay-like control traffic: bursts of repeated checksum-valid Tello joystick messages

After same-direction binary confirmation, a complete joystick payload must recur
at least 10 ms and less than two seconds after its last observation. At least
20 repeat observations covering 10 distinct payloads must occur within a rolling
10-second window. Only traffic toward the configured control port qualifies.
Sequence zero, a backward sequence step, repeated queries, one repeated payload,
shorter-than-10-ms copies and corrupt checksums do not independently qualify.

A separate, short-lived, bounded fingerprint cache avoids interference from the
older-replay cache. The alert is retained until the next eligible record, without
bypassing the existing one-minute gate. `binary_rapid_replayed_frames` and
`binary_rapid_replayed_distinct` are interval observations, whereas the trigger
uses a rolling window which can overlap records. Limits are disclosed with
`binary_tracking_limited`. No session-end flush is added.

All six Replay captures now alert; six Manipulation captures retain their older
replay-like and malformed-control findings. Three normal flights remain free of
alerts. The Replay files retain exactly their prior row counts (9, 11, 11, 9, 10,
9); the update enriches existing rows rather than generating a separate log.
[Full validation and reproduction](../validation/v0.10.0-results.md).

## Interpretation limits

These are replay-like observations, not proof that commands were accepted or
that a drone was taken over. No drone replies are present in the reviewed Replay
files. Sender behavior, network/capture duplication, and replay infrastructure
can create the same evidence. In particular, excluding sub-10-ms copies does not
eliminate delayed mirror duplication. CRC checks establish integrity, not
freshness or authentication.

Changed payloads, originals outside the capture, repetitions on different
connections/workers, sparse bursts, insufficient diversity and other timing
patterns may evade the rule. Encrypted/unsupported protocols are outside this
coverage. The detector does not infer physical motion or authorization from the
folder label or from replay-like traffic alone.
