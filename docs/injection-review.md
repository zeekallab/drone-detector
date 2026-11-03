# Injection capture review

Reviewed 2026-11-03. The eight captures contain Tello SDK commands, telemetry and
responses. They support observing command activity and repeated maneuver patterns,
but network syntax alone does not establish whether the sender was authorized.

## Source and credit

These captures belong to the University of Victoria ISOT dataset, credited to
Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Dataset description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)

Members are under `Raw Data/Injection/`. Source PCAP binaries are not redistributed.

## What is visible

The source `192.168.10.4` sends ASCII commands to `192.168.10.1:8889`.
Its source port is 9000 in captures 1–2 and 8889 in captures 3–8. The drone sends
SDK state on UDP/8890 and additional binary traffic on UDP/8899. These addresses,
MACs and source ports are observations, not hardcoded attack identifiers.

| Capture | Direct command datagrams toward UDP/8889 | Pattern |
| --- | ---: | --- |
| `Instruction_injection_1_5_13_5mins.pcap` | 51 | Varied movements; below alert threshold |
| `Instruction_injection_2_5_13_7mins.pcap` | 86 | Varied movements; below alert threshold |
| `Instruction_injection_3_5_13_10mins.pcap` | 195 | Repeated forward/back and clockwise/counterclockwise |
| `Instruction_injection_4_5_13_6mins.pcap` | 143 | Repeated forward/back and clockwise/counterclockwise |
| `Instruction_injection_5_5_13_10mins.pcap` | 152 | Repeated opposing movements; forward/back meets threshold |
| `Instruction_injection_6_5_14_10mins.pcap` | 218 | Repeated forward/back and clockwise/counterclockwise |
| `Instruction_injection_7_5_14_7mins.pcap` | 144 | Repeated forward/back and clockwise/counterclockwise |
| `Instruction_injection_8_5_14_4mins.pcap` | 97 | Repeated forward/back and clockwise/counterclockwise |

Counts are capture datagrams, not unique actions or successful maneuvers. They
exclude UDP headers embedded in ICMP error quotations. Responses include `ok`,
`error No valid imu`, `error Auto land`, and `unknown command: ...`. Repeated
`forward 20`, `back 20`, `cw 10`, and `ccw 10` requests dominate captures 3–8.
These are valid command forms, so malformed-packet detection is not appropriate.

The files do not provide a trusted-controller baseline. One sender is visible
for these command flows. Neither a second controller nor unauthorized ownership
can be inferred merely from this host's address or the folder's attack label.

## Implemented behavior

The default SDK module now appends:

> Repetitive maneuver commands: repeated opposing Tello SDK movement or rotation requests

The rule evaluates one axis on one confirmed SDK command connection within a
rolling 60-second window: at least 10 sampled commands, eight direction changes,
four commands in each direction and a span of at least 10 seconds. Near-simultaneous
samples under 250 ms apart are excluded. It supports forward/back, left/right,
up/down and clockwise/counterclockwise. SDK state must establish the same recent
drone/controller pair before commands are evaluated.

`sdk_repetitive_axes` identifies the affected axes. Existing `control_activity`
retains command strings and counts. This is a behavioral signal compatible with
injection, authorized automation or deliberate pilot oscillation. It is not
labeled confirmed injection or takeover. The first two captures remain visible
as SDK command activity, with no new maneuver alert.

Recognized replies add interval counts in `sdk_ok_responses`,
`sdk_error_responses`, and `sdk_unknown_command_responses`. Replies are accepted
only on an already-confirmed SDK flow with recent peer-pair state. They cannot
establish identity alone. They are not matched one-to-one to commands, and `ok`
is not proof of physical motion. Missing or duplicated packets affect counts.
No raw error text is added to the log.

## Validation and limits

All six sustained-pattern captures alert; the two varied-command captures do
not. Three normal binary-flight captures remain free of alerts. Six MITM
station-mode captures provide additional SDK command comparisons; those labels
are not a benign ground truth. See [exact results](../validation/v0.7.0-results.md).

Authorized scripts can intentionally perform these maneuvers and trigger the
same alert. A single malicious command, other command forms, `rc` streaming,
encryption, spoofed identity, split-worker visibility and command-only captures
remain gaps. Peer-pair learning is worker-local; maneuver history does not span
connections. This rule does not assess whether the drone flew the requested path.

One `drone.log` remains, limited to one record per minute per connection. Findings
are retained until an eligible record; there is no session-end flush. Response
packets can now drive an eligible update, so row counts/timestamps may differ
from earlier versions while preserving the same rate limit. Not all late
commands or responses are necessarily emitted. Tracking is bounded and reports
`activity_limited` when command history is omitted. No live sensor deployment
or performance claim is made.
