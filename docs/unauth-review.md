# Unauth capture review and v0.9.0 update

Reviewed 2026-11-03. All eight captures contain valid Tello SDK control commands
with rapidly changing UDP source ports. This is a useful behavioral signal but
does not independently establish unauthorized access.

## Credit and provenance

The original captures belong to the University of Victoria ISOT dataset, credited
to Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Dataset description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)
- [Reviewed member hashes](../tests/fixtures/uvic/unauth-manifest.json)

The eight files total 9,755,281 bytes. No PCAPs are redistributed.

## Evidence and coverage gap

The same host, 192.168.10.4, sends ordinary SDK movement/rotation commands to
192.168.10.1:8889 using a new UDP source port for almost every request. Each file
reaches 20–22 distinct command source ports in a rolling minute. There is one
observed source IP/MAC, not evidence of many physical controllers. Replies
continue to a single older port per file despite changing command source ports.

In v0.8.0, the per-connection maneuver history could not combine these sequences.
The per-connection logging limit also allowed a fresh row for each new source
port. Replies on the earlier connection were not counted by the command-flow
response logic. All eight files produced drone records but no alerts.

## Implemented update

The default SDK parser adds this exact description to `alert`:

> Control source-port churn: repeated Tello SDK commands from many source ports to the same drone

It requires supported commands and a recent SDK telemetry pair, with at least
10 distinct source ports whose retained last observations span at least 10
seconds within a rolling 60-second window. Maneuver history now uses the same
ordered controller/drone host-pair scope, so the existing opposing-maneuver
rule also detects the combined sequences.

Commands, recognized response counts and patterns are summarized at most once
per minute per pair. Telemetry, binary and video connections remain separately
logged. The new `sdk_summary_scope=host-pair` identifies the aggregation; the
record's UID and connection ID identify only the triggering event. A bounded
`sdk_related_uids` set provides contributing connection references. Directional
`orig_messages`/`resp_messages` fields are omitted from these summaries.

`sdk_command_count` counts commands since the preceding summary.
`sdk_source_port_count` is the peak rolling distinct-port count seen during that
summary interval; it can include ports seen before the previous summary. Histories
and summaries are bounded, with omissions reported by `activity_limited`.

Replies on an earlier port now contribute after a recent validated command for
the same pair. An `ok` is still an observed reply, not proof of physical execution;
error strings such as `error Not joystick` are not interpreted as authentication
failures. No one-to-one command/reply matching is claimed, and numeric battery
replies are not included in the three recognized reply categories.

## Replay results

| Capture | Commands / distinct ports | Old total rows | New total rows | Command summaries | Churn rows | Maneuver rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `unauthen_1_5_16_8mins.pcap` | 170 / 170 | 185 | 24 | 8 | 7 | 6 |
| `unauthen_2_5_16_9mins.pcap` | 189 / 188 | 208 | 30 | 10 | 9 | 9 |
| `unauthen_3_5_16_6mins.pcap` | 128 / 128 | 141 | 21 | 7 | 6 | 6 |
| `unauthen_4_5_16_6mins.pcap` | 150 / 149 | 166 | 24 | 8 | 7 | 7 |
| `unauthen_5_5_16_10mins.pcap` | 202 / 201 | 223 | 33 | 11 | 10 | 10 |
| `unauthen_6_5_16_10mins.pcap` | 200 / 200 | 220 | 31 | 10 | 9 | 9 |
| `unauthen_7_5_16_9mins.pcap` | 187 / 187 | 207 | 30 | 10 | 9 | 9 |
| `unauthen_8_5_16_3mins.pcap` | 52 / 52 | 57 | 9 | 3 | 2 | 2 |

Both alert descriptions occur in every Unauth file. Some early/late records do
not contain an alert. Total rows include telemetry and binary records, so they
exceed the command-summary count. Recognized replies are now logged in all eight.
Not all late commands/replies reach a summary because there is no session-end
flush. This is bounded monitoring, not a complete transaction audit.

## Limits and comparisons

Legitimate scripts can open one socket per command; NAT, reconnections and spoofed
addresses can also affect the pattern. The alert reports source-port churn, not
verified unauthorized access. No trusted-controller baseline was available.

All evidence must reach the same worker. Different controller/drone host pairs
are kept separate; NAT can merge real devices behind one address. Idle pair state
expires after the correlation interval, and stale command context does not
become valid just because generic replies continue. Bounds may omit evidence.

Eight injection captures and six station-mode MITM captures produce no new churn
alerts. The six previously detected injection maneuver patterns remain detected;
the two varied-command files remain unflagged. Three normal flights remain free
of alerts. These comparisons do not establish a universal false-positive rate.
[Validation and reproduction](../validation/v0.9.0-results.md).
