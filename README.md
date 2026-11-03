# Drone protocol detector — 0.6.0

## What's new — v0.6.0

- **Optional MITM signal:** correlate repeated reciprocal ARP claims with a
  confirmed drone flow and append an **ARP interception pattern** to `alert`.
- **Evidence fields:** show the claiming MACs and affected IPs in the existing
  minute-limited `drone.log`; no trusted-controller list is required.
- **Capture validation:** reviewed all 12 UVic MITM captures; 11 meet the rule,
  with one one-sided case explicitly outside coverage. Three normal flights
  produce no alerts. See [MITM findings](docs/mitm-review.md).
- **Explicit opt-in:** load `scripts/arp.zeek` only when one local IPv4 broadcast
  domain's ARP and drone traffic reach the same worker. See requirements below.

## Earlier updates — v0.5.0

- **New `alert` field:** human-readable replay-like and malformed-control findings
  in the existing minute-limited `drone.log`.
- **Binary Tello identification:** validate declared length, header CRC8 and frame
  CRC16 before evaluating joystick replay/integrity patterns.
- **Optional wireless alert:** deauthentication bursts and EAPOL context from raw
  radiotap captures; not a claim of successful password cracking.
- **Documented alert definitions:** see the [alert reference](#alert-reference)
  for descriptions, thresholds, examples and input requirements.

## Earlier updates — v0.4.0 and v0.3.0

- **Tello SDK support:** detect repeated structured status messages and correlate
  commands with recently observed drone/controller pairs. Record battery, height,
  orientation and raw motion values. v0.5.0 adds separate binary Tello identification.
- **Earlier, quieter logging:** keep one `drone.log`, emit on protocol confirmation,
  then update at most once per minute per connection by default. No session-end duplicate.
- **MAVLink flight telemetry:** report coordinates, altitude, battery, groundspeed,
  heading, climb rate, armed status and flight mode, with source identities and
  observation timestamps. Missing or stale measurements are omitted.
- **Control and interference signals:** summarize MAVLink control requests and ACKs,
  including RC/manual/offboard inputs, and flag position/altitude discontinuities
  or multiple controller system IDs targeting one system. These are investigation
  signals, **not proof of takeover**; signature authentication is not implemented.
- **Cleaner output and more validation:** verbose diagnostics are optional;
  94 synthetic scenarios pass, alongside real-capture regressions. Capture sources
  are credited below and in the fixture documentation.

See the [changelog](CHANGELOG.md) for release details and
[v0.6.0 validation](validation/v0.6.0-results.md) for evidence and coverage limits.

## Overview

Zeek scripts that write manufacturer-neutral **`drone.log`** records for:

- **Legacy DJI Phantom Vision control/telemetry**, over configured TCP ports.
- **Tello SDK status and correlated commands**, over configured UDP ports.
- **Binary Tello control traffic**, with validated framing and replay/integrity alerts.
- **MAVLink 1 and 2**, over configured UDP ports, with message-specific CRC validation
  and heartbeat-based role information.

`likely_manufacturer` is **DJI** for the legacy detector and **unknown** for
MAVLink; Tello SDK uses **DJI/Ryze**. `autopilot_software` may identify ArduPilot or PX4; that is software,
not a hardware manufacturer. MAVLink also serves rovers, boats, cameras and
simulators. A protocol match does not prove that a physical aircraft is present,
airborne, or carrying out an attack.

## Alert reference

The optional **`alert`** field in `drone.log` is an array of human-readable
findings. It is omitted when no alert threshold is met; a record can contain
both control-traffic alerts. These are **suspected interference indicators**,
not proof that a drone accepted a command or that a takeover/password crack succeeded.

### Replay-like control traffic

**Description:** Repeated older, checksum-valid Tello joystick messages suggest
reuse of captured control traffic rather than newly generated input.

The binary parser first requires three distinct valid frames in the same direction,
with consistent length, header CRC8 and frame CRC16. For joystick messages (`0x0050`,
type `0x60`) sent toward a configured control port, the default threshold is
20 delayed repeat observations covering at least five distinct complete payloads,
representing at least 50% of eligible control frames since the preceding log entry.
An identical payload must have been last seen 2–120 seconds earlier. Immediate
retransmissions, sequence number zero, constant stick-axis values, repeated queries,
and responses alone do not trigger this alert.

### Malformed control traffic

**Description:** Repeated Tello joystick messages have inconsistent declared
lengths or fail the full-frame checksum within an already confirmed binary stream.

The default threshold is three malformed joystick frames since the preceding
record. A valid header CRC is required before interpreting command/length fields.
Malformed traffic by itself cannot establish Tello identity. Damaged captures or
faulty senders can also cause this condition; compare capture quality and other evidence.

Example when both conditions are met:

```json
"alert": [
  "Replay-like control traffic: repeated older, checksum-valid Tello joystick messages",
  "Malformed control traffic: repeated Tello joystick length or checksum failures"
]
```

Binary records use `protocol=tello-binary` and `likely_manufacturer=DJI/Ryze`.
The fields `binary_control_frames`, `binary_replayed_frames`,
`binary_replayed_distinct`, and `binary_malformed_control_frames` describe the
interval since the preceding log entry, while directional message totals remain
cumulative. `binary_tracking_limited` warns that bounded fingerprint tracking
omitted information. CRC validation does not authenticate a sender. The parser
identifies binary traffic but does not yet decode its flight-state measurements.

### Wireless deauthentication burst (optional)

**Description:** Repeated unprotected, non-retry Wi-Fi disconnect frames affect
a network whose observed beacon SSID matches `TELLO-` plus six hexadecimal digits.
This can indicate wireless disruption or an attempt to provoke WPA handshakes.

This alert requires **explicitly loading `scripts/wifi.zeek`** and raw radiotap
802.11 capture input. It is not loaded by the default package and cannot work
from an ordinary Ethernet/IP mirror lacking wireless management frames. The raw
packet handler has higher processing cost; live Corelight support/performance
has not been validated. It is tested offline on Zeek 9.0.1.

The default is 20 distinct deauthentication frames within a 10-second bucket,
after observing a matching beacon. Retry-marked frames, duplicate management-frame
identities within the bucket, protected management payloads and frames marked
bad-FCS by radiotap are excluded. EAPOL key frames are counted as supporting
context, **never as proof of password guessing**. Normal handshakes alone do not
trigger an alert. Offline password cracking cannot be inferred from these captures.

Wireless records contain BSSID/SSID and deauthentication/EAPOL counts. They omit
IP connection ID and UID because no IP connection exists for these management
frames. `likely_manufacturer=unknown`: an SSID is a claim and can be spoofed.
MAC transmitter addresses can also be spoofed and do not identify an attacker.
The rate limit is once per minute per BSSID. Tracking is bounded; a sticky
`wireless_tracking_limited` flag means counts may be incomplete.

```sh
# Explicit opt-in, from a separate output directory:
zeek -r /path/to/radiotap-capture.pcap /path/to/drone-detector/scripts/wifi.zeek LogAscii::use_json=T
```

### ARP interception pattern (optional)

**Description:** One MAC repeatedly claims both endpoints of an already-confirmed
IPv4 drone flow. This is consistent with ARP poisoning used for interception;
legitimate proxy ARP can produce the same pattern. It does not prove unauthorized
access, modified commands, or a successful takeover.

Load `scripts/arp.zeek` explicitly. For endpoints A and B, the same unicast MAC
must advertise A to B and B to A through ARP replies. Each direction requires
three sampled replies within the last 60 seconds, spanning at least two seconds.
The module retains at most one sample per second per claim and requires the
Ethernet source to match the advertised sender MAC. It does not infer drone
identity from ports, addresses, MAC vendors or ARP alone.

```json
"alert": ["ARP interception pattern: one MAC repeatedly claims both endpoints of a confirmed drone flow"],
"arp_claimant_macs": ["c8:78:7d:96:67:d7"],
"arp_claimed_ips": ["192.168.0.102", "192.168.0.104"]
```

The example addresses come from the research captures; they are not hardcoded.
This appends evidence to existing records, preserving other alerts and the
one-record-per-minute-per-connection limit. ARP alone does not cause a new row.

```sh
# Explicit opt-in, from a separate output directory:
zeek -r /path/to/single-lan-capture.pcap /path/to/drone-detector/scripts/arp.zeek LogAscii::use_json=T
```

```zeek
# After loading arp.zeek; use the real MAC of a known legitimate proxy:
redef DroneARP::ignored_macs += { "02:00:00:00:00:01" };
redef DroneARP::minimum_claims = 3;
redef DroneARP::evidence_window = 60secs;
redef DroneARP::minimum_span = 2secs;
```

**Visibility:** requires both ARP and drone traffic from **one IPv4 broadcast
domain on the same worker**. State is not VLAN/interface-scoped; do not enable
across merged networks with overlapping addresses. A routed mirror may omit ARP,
and cluster distribution may split the required evidence. This module is disabled
by default; live Corelight deployment/performance is unvalidated.

Tracking defaults to 4,096 directed IP pairs, four MACs per pair and 128 time
samples per claim. `arp_tracking_limited` is a worker-wide warning of recently
omitted evidence, not proof that this flow exhausted the bound. Keep thresholds
positive and within the sample capacity; a window longer than two minutes exceeds
the idle-pair lifetime. A known proxy can be excluded with `ignored_macs`.
One-sided poisoning, IPv6 neighbor discovery and payload-only manipulation are
not covered. [Capture findings and limitations](docs/mitm-review.md).

### Thresholds and limits

```zeek
redef DroneTelloBinary::replay_min_age = 2secs;
redef DroneTelloBinary::replay_max_age = 120secs;
redef DroneTelloBinary::replay_min_frames = 20;
redef DroneTelloBinary::replay_min_distinct = 5;
redef DroneTelloBinary::replay_min_fraction = 0.5;
redef DroneTelloBinary::malformed_min_frames = 3;
redef DroneTelloBinary::max_fingerprints = 2048;
# After explicitly loading wifi.zeek:
redef DroneWiFi::minimum_deauth_frames = 20;
redef DroneWiFi::burst_interval = 10secs;
```

All limits/intervals must be positive; fraction must be between 0 and 1. These
are configurable starting points, not a universal attack classifier. Binary
inspection is bounded at 1 MiB per connection before confirmation, renewing every
60 seconds on confirmed traffic. Fingerprints are bounded separately per direction
and expired during logging. A single fixed payload repeated rapidly can evade the
multi-payload delayed-repeat rule. Stateful comparisons are per connection/worker,
not cross-connection controller authentication. Altered payloads with recomputed
checksums may pass validation. Packet loss/capture damage can affect evidence.

IP protocols share the per-connection logging gate. The configured log interval
(default 60 seconds) is not bypassed for alerts, and there is no final-session
flush. Brief activity after the last record can therefore remain unreported if
traffic ends before the next eligible record. A shorter interval trades volume
for faster reporting and changes the amount of evidence accumulated per record.

[Validation results](validation/v0.5.0-results.md) describe positive captures,
normal comparisons and coverage limits. [Wireless capture findings](docs/password-cracking-review.md)
explain what is observable in the password-cracking folder.

## Credit for the real MAVLink capture

**Thank you to [kresoin](https://github.com/kresoin) for sharing the PCAP used to
validate MAVLink support. The capture belongs to their research contribution;
it was not created by this project.**

- Original project: [kresoin/drone-digital-forensics-lab](https://github.com/kresoin/drone-digital-forensics-lab)
- [Original `traffic.pcap` download](https://github.com/kresoin/drone-digital-forensics-lab/releases/download/flightlog/traffic.pcap)
- [Related article by Inda Kreso](https://www.linkedin.com/pulse/drone-digital-forensics-network-traffic-analysis-damn-inda-kreso-phd-4sqof/)
- [Capture provenance, hash and test instructions](tests/fixtures/README.md)

The 286 MB capture is kept locally in `tests/fixtures/traffic.pcap` and excluded
from Git. This repository links to the author's release rather than republishing
it. The included download helper verifies the published SHA-256.

## Installation

Requires **Zeek 9.0 or later**; validated on 9.0.1. Python 3 is needed for tests,
not for live detection. No pymavlink installation is required on the sensor.

```sh
git clone https://github.com/zeekallab/drone-detector.git
cd drone-detector
```

With the Zeek package manager:

```sh
zkg install https://github.com/zeekallab/drone-detector
```

Ensure your site configuration loads installed packages (`@load packages`).
Alternatively, load the local `scripts` directory directly. For Corelight,
create a zkg bundle on a packaging host and use the sensor package workflow;
check its embedded Zeek version first. This update has not been deployed or
load-tested on a Corelight sensor.

## Replay a capture

From the repository root:

```sh
mkdir -p replay
cd replay
zeek -r /absolute/path/to/capture.pcap ../scripts LogAscii::use_json=T
```

To test the original MAVLink capture shared by kresoin:

```sh
# Run from the repository root; downloads about 286 MB using curl.
python3 tests/fetch_fixture.py
python3 tests/test_author_capture.py
```

To inspect that fixture's logs yourself:

```sh
mkdir -p replay
cd replay
zeek -C -r ../tests/fixtures/traffic.pcap ../scripts LogAscii::use_json=T
```

**Why `-C` here?** This Linux host capture contains partial transport checksums
from checksum offload. Zeek otherwise rejects much of the traffic. `-C` is used
only for this offline fixture; the detector still validates MAVLink's application
CRC and CRC_EXTRA. Do not routinely disable checksums on live sensors. Synthetic
PCAPs have valid transport checksums and are tested without `-C`.

## Output and interpretation

A **detection** record is written on the first delivered chunk/datagram that
satisfies the existing protocol criteria. A confirmed connection then emits an
**update** only when another valid message arrives at least `log_interval`
(default **60 seconds**) after its previous record. There is no timer-driven
empty update and **no session-end flush or duplicate**. This applies to legacy DJI, MAVLink and Tello SDK. `ts` is the emission/observation time, not connection
start; `event_type` is `detection` or `update`. `uid` links records to `conn.log`.
The conn fields `drone_protocol`, `drone_likely_manufacturer` and `drone_evidence`
are still populated when the connection is removed.

The limit is **per connection**, not globally per drone: forwarded copies or a
new connection can produce additional entries. A single connection may relay
several vehicles; their measurements remain separated by system/component ID.
An initial record can lack position/battery if those messages have not arrived.
Exporter buffering or downstream ingestion can add latency after log generation.
Minute snapshots can miss short movements or mode transitions between updates.
Counters are cumulative observations **as of that snapshot**, not final session
totals or unique actions. They include forwarded/duplicate packets.

### Default fields

| Fields | Meaning |
|---|---|
| `ts`, `event_type`, `uid`, `id.*` | Observation time, detection/update and connection identity |
| `likely_manufacturer`, `protocol`, `evidence` | Detection and manufacturer evidence; MAVLink remains manufacturer unknown |
| `orig_messages`, `resp_messages` | Cumulative validated observations by direction |
| `mavlink_versions`, `vehicle_types`, `autopilot_software` | Observed versions/roles/software; non-autopilot heartbeats do not add `not-an-autopilot` |
| `simulation_observed` | A valid SIMSTATE or SIM_STATE message was observed; absence does not prove a physical aircraft |
| `signing_observed`, `signature_validation` | Signature trailer presence; authentication is **not performed** |
| `inspection_limited`, `metadata_limited`, `telemetry_limited`, `activity_limited` | Sticky indicators that inspection or bounded storage omitted information |
| `telemetry` | JSON array encoded as a string, with one object per source system/component |

Zeek's native log writers cannot store a vector of records. `telemetry` is
therefore a **JSON string**, not a native nested JSON array in the raw log.
Decode it once (e.g. Splunk `spath`) to access structured numeric measurements.
This preserves multiple sources within one rate-limited log record, without
parallel arrays or mixing measurements from unrelated components.

Each telemetry object has `system_id`, `component_id` and these optional groups:

| Group | Measurements / semantics |
|---|---|
| `position` | `latitude`, `longitude` in degrees; `altitude_msl_m` above reported mean sea level; `source` is GLOBAL_POSITION_INT or GPS_RAW_INT |
| `height` | `relative_altitude_m` from GLOBAL_POSITION_INT, relative to home—not height above the terrain underneath |
| `motion` | VFR_HUD `groundspeed_m_s`, `heading_deg` (vehicle heading, not necessarily track over ground), `climb_m_s` (positive upward) |
| `batteries` | Array of `remaining_pct`, `source`, and `battery_id` where provided by BATTERY_STATUS; SYS_STATUS is a separate aggregate reading |
| `flight` | `armed`, `vehicle_type`, `autopilot_software`, `mode`, `custom_mode`; only autopilot heartbeats supply flight state |

Every group/battery reading includes its own `observed_ts` in Unix seconds.
Unavailable measurements are omitted. Values older than `telemetry_max_age`
(default **120 seconds**) are omitted instead of silently appearing current.
A fresh GLOBAL_POSITION_INT estimate takes precedence over GPS_RAW_INT; GPS
fallback requires a reported 3-D or better fix. Zero coordinates and 0% charge
are valid values. Unknown battery percentage (-1), invalid coordinates, and
NaN/infinite VFR HUD floats are not emitted as valid measurements.

Mode labels such as GUIDED, AUTO, RTL and LAND are mapped only for recognized
ArduPilot copter vehicle types. Other stacks/types retain `custom-mode-N`; mode
numbers are not universal. `armed` does not establish that a vehicle is airborne.
No firmware identity, signature, position or battery measurement is authenticated.
The script does not infer takeoff/landing, proximity or confirmed malicious activity.
Legacy DJI still provides protocol evidence only, not these MAVLink measurements.

### Control activity and possible interference

`control_activity` is a JSON-encoded array of requests/responses observed **since
this connection's previous log entry**. Identical selected requests are grouped
with observation counts and first/last timestamps. Source IP, source system/component,
and target system/component are retained. It includes:

- COMMAND_LONG/INT, including arm/disarm intent, takeoff, land, RTL, mission start,
  mode/home changes, flight termination and reboot/shutdown requests.
- SET_MODE, PARAM_SET (parameter name, type and exact new value bits), MISSION_COUNT,
  MISSION_ITEM/INT and MISSION_CLEAR_ALL.
- RC_CHANNELS_OVERRIDE, MANUAL_CONTROL, SET_ATTITUDE_TARGET and local/global position
  setpoint requests. Their presence alone does not prove pilot control was overridden.
- COMMAND_ACK with numeric result (`0` = accepted). ACKs are observed separately;
  this is not transaction correlation or proof that the requested action occurred.

These are normal protocol functions as well as potential interference mechanisms.
Counts include duplicate/forwarded observations. Request parameters beyond those
listed are not decoded; changed mission items or setpoints can share a summary
bucket. This is a bounded activity summary, not a full command audit trail.

`anomaly_indicators` is a JSON-encoded array of **heuristic signals**, not a takeover
verdict. It currently supports:

| `kind` | Trigger / interpretation |
|---|---|
| `position_discontinuity` | Same source and position message type moves >=100 m with implied horizontal speed >100 m/s |
| `altitude_discontinuity` | Same source and position message type changes altitude >=20 m with implied vertical speed >30 m/s |
| `multiple_control_system_ids` | More than one source MAVLink system ID sends selected requests to the same non-broadcast target within 120 seconds, on this connection |

Position comparisons use successive observations 0.1–30 seconds apart, not just
the logged minute snapshots. Duplicate/tiny intervals, long gaps and changes
between GPS and fused position sources are excluded. Indicators accumulate
between log entries, preserving a brief inconsistency until the next eligible
update. Each has `observations`, `first_seen`, `last_seen`, `max_value` and
`threshold`. Values are m/s for position/altitude signals and a count of source
system IDs for controller signals. For the latter, `system_id` is the **target**
and `component_id=0` means component unspecified; otherwise they identify the
telemetry source. Different components of one controller system do not alone
trigger the multiple-controller signal.

Thresholds are starting points, **not calibrated attack classifiers**. Legitimate
GPS/estimator resets, simulation changes, fast aircraft or multiple ground stations
can trigger them. Smooth spoofing, spoofing an existing controller ID, replay
without a discontinuity and encrypted/unobserved links can evade them. Detection
requires a protocol-confirmed connection; an isolated one-way command flow without
a valid heartbeat may not qualify. No cryptographic signature/replay validation,
Wi-Fi deauthentication detection, containment or real-time alert bypass is added.

The minute limit also bounds how quickly suspicious activity appears. If a
connection ends before another eligible update, pending activity is **not flushed**.
This deliberately follows the no-session-end-record policy; use a shorter interval
if timely activity reporting is more important than volume. State and comparisons
are local to each connection/worker, not globally correlated across relay paths.

Optional network policy: when **both** `protected_drone_nets` and
`trusted_controller_nets` are configured, requests sent toward a protected IP
receive `unexpected_source=true/false`. This compares observed IP addresses, not
cryptographically authenticated identities. It is disabled by default; configure
for actual routing/NAT/relay topology before interpreting it as a policy signal.
`activity_limited` is a sticky flag that a bounded activity/history table overflowed.

```zeek
redef DroneMAVLink::detect_telemetry_anomalies = T;
redef DroneMAVLink::max_position_speed_m_s = 100.0;
redef DroneMAVLink::min_position_jump_m = 100.0;
redef DroneMAVLink::max_altitude_speed_m_s = 30.0;
redef DroneMAVLink::min_altitude_jump_m = 20.0;
redef DroneMAVLink::controller_history_interval = 120secs;
redef DroneMAVLink::max_activity_values = 64;
# No trusted-controller list is required for the other signals.
```

To examine signals in Splunk:

```spl
index=zee-corelight _path=drone anomaly_indicators=*
| spath input=anomaly_indicators path={} output=indicator
| mvexpand indicator
| spath input=indicator
| table _time uid kind system_id component_id observations max_value threshold
```

For control requests, apply the same expansion to `control_activity`. Correlate
with the controller/operator and flight context before concluding interference.

### Optional diagnostic fields

Set `redef DroneDetector::include_diagnostics = T;` to restore the verbose fields:
`matched_responses`, `commands`, `checksum_failures`, `skipped_bytes`, `gaps`,
`system_ids`, `component_ids`, `heartbeat_identities`, `message_types`,
`signed_messages`, `unsigned_messages`, `reported_modes`, `requested_modes`,
`mission_item_counts`, `parameter_ids`, `parameter_updates`,
`zero_component_messages`, `command_acks`, `unknown_message_ids`, `malformed_frames`.

These include raw mode histories, empty sets and protocol troubleshooting counts.
They are useful for analysis, but hidden by default to keep the operational log
focused on activity. `matched_responses` and TCP `gaps` are legacy-DJI metrics;
MAVLink's zero values do not measure sequence loss or transaction matching.
Parameter values remain raw bits/type, because encoding conventions vary.

### Splunk example

```spl
index=zee-corelight _path=drone protocol=mavlink
| spath input=telemetry path={} output=vehicle
| mvexpand vehicle
| spath input=vehicle
| table _time uid system_id component_id position.latitude position.longitude position.altitude_msl_m height.relative_altitude_m motion.groundspeed_m_s motion.heading_deg motion.climb_m_s flight.armed flight.mode
```

Use the log-path field your ingestion actually exposes (`path` versus `_path`).
For battery details, expand `batteries{}` within the selected vehicle. Proximity
calculations need your reference coordinates and should use observation freshness.
This detects traffic visible to the monitored network, not nearby drones on
unobserved radio links.

## Detection rules

### Legacy DJI

Default destination port: `2001/tcp`. TCP reassembly handles segmentation and
coalescing. At least three consecutive valid messages in either direction must
have `55 BB` magic, a consistent length, a recognized legacy address/flag byte,
and a valid XOR checksum. Matching sequence/command/component responses add
evidence. Ports, IP addresses, vendor MACs and video do not establish identity.

### MAVLink

Default candidate ports: `14550/udp` and `14540/udp`, on **either endpoint**.
Messages must pass MAVLink 1/2 framing and message-specific CRC_EXTRA/CRC checks.
Confirmation requires at least three distinct CRC-valid frames and a valid
HEARTBEAT. Merely matching FE/FD or a port is insufficient. Multiple messages
in one UDP datagram, MAVLink 2 trailing-zero truncation, and signed-message
trailers are supported. Messages are not assembled across separate UDP datagrams.

CRC metadata includes 301 message IDs from the ardupilotmega dialect, generated
with pymavlink 2.4.50. Unknown IDs are skipped and cannot confirm detection. A
private dialect reusing IDs with different CRC_EXTRA values is not supported.
Some GCS commands in the real fixture use source component ID 0 contrary to the
usual specification; they are retained and counted instead of silently losing
valid mission/configuration evidence. Signed trailers are recognized, not
cryptographically verified. Neither CRCs nor heartbeat claims authenticate devices.

### Tello SDK

Added in v0.4.0. Candidate ports are UDP/8890 for state and UDP/8889 for commands.
Confirmation requires three consecutive state datagrams with the expected 16
numeric SDK fields, delimiter structure and sanity checks. Repeated identical
valid state messages count because a stationary drone can emit identical state.
Ports, MAC addresses, video or generic `ok` responses never establish identity.

After state confirmation, recognized SDK commands on the same observed drone/
controller IP pair can identify the command connection. Pair knowledge expires
(default 120 seconds) and is bounded (default 1,024 pairs). It is **worker-local**:
if a cluster distributes the state and command flows to different workers,
state detection still works but command correlation may be unavailable. Command
traffic before state confirmation, or without recent state, is not classified.

Tello writes `protocol=tello-sdk`, `likely_manufacturer=DJI/Ryze`, `drone_host`,
and `controller_host` in the same rate-limited `drone.log`. Its `telemetry` JSON
array includes battery percentage, height/tof in cm, pitch/roll/yaw in degrees,
and raw barometer, axis velocity and motor-time values. The SDK state format
provides **no global GPS coordinates**, and yaw is not labeled as a true compass
heading. Raw fields deliberately avoid assuming units/reference frames absent
or ambiguous in the documentation. Tello telemetry uses host identity rather
than MAVLink system/component IDs.

`control_activity` groups recognized command text with source/destination IP,
first/last observation time and counts. Supported commands include SDK entry,
takeoff/land, emergency/stop, video on/off, selected queries, directional movement,
rotation, flips, speed and RC commands. Argument ranges are checked. This is not
a complete SDK command decoder: go/curve/jump, Wi-Fi credentials and mission-pad
commands are not logged. Generic responses do not trigger classification and
are not currently summarized. A normal command may be used maliciously, but
its presence is **not** a takeover verdict. MAVLink-specific anomaly indicators
are not applied to these different Tello measurements.

Binary Tello traffic is handled separately by `tello-binary.zeek` starting in
v0.5.0. The `cc` prefix alone is insufficient: framing and both checksums are validated. Neither SDK text nor learned host pairs are
authenticated; spoofed status can imitate this protocol.

Reference: [Ryze Tello SDK 2.0 User Guide](https://dl-cdn.ryzerobotics.com/downloads/Tello/Tello%20SDK%202.0%20User%20Guide.pdf).
Validation: [v0.4.0 results](validation/v0.4.0-results.md).

## Configuration

Place redefinitions after the package load:

```zeek
redef DroneDetector::ports += { 12345/tcp }; # additional legacy-DJI candidate
redef DroneMAVLink::ports += { 14551/udp };  # additional MAVLink candidate

# Defaults:
redef DroneTello::minimum_state_messages = 3;
redef DroneTello::max_inspected_bytes = 1048576;
redef DroneTello::max_known_pairs = 1024;
redef DroneTello::correlation_age = 120secs;
redef DroneDetector::log_interval = 60secs;
redef DroneDetector::include_diagnostics = F;
redef DroneMAVLink::telemetry_max_age = 120secs;
redef DroneMAVLink::max_telemetry_sources = 16;
redef DroneMAVLink::inspection_interval = 60secs;
redef DroneDetector::minimum_consecutive_messages = 3;
redef DroneDetector::max_inspected_bytes = 1048576;
redef DroneDetector::max_pending_requests = 256;
redef DroneMAVLink::minimum_evidence_messages = 3;
redef DroneMAVLink::max_inspected_bytes = 1048576;
redef DroneMAVLink::max_metadata_values = 64;
```

Use positive limits/intervals. Setting `log_interval=0secs` disables rate limiting
(for tests only). Each detector allows at most 1 MiB of inspection before
confirmation. Once confirmed, that allowance renews on traffic every 60 seconds
(configurable `DroneMAVLink::inspection_interval` for MAVLink). This supports
long-lived telemetry without unlimited per-window inspection. MAVLink skips a
whole datagram if it would exceed the allowance. Exhaustion is reflected by the
sticky `inspection_limited` flag in the next emitted snapshot; if no further valid
messages are inspected there is no additional record just to announce that flag.

Metadata sets are bounded independently, as are telemetry source identities
(default 16) and battery readings (8 per source). Expired telemetry is removed
before reusing source capacity. Candidate ports limit delivered payloads; there
is no all-traffic packet handler or arbitrary-port discovery.

## Tests and verified results

```sh
python3 tests/run_tests.py
```

Runs 12 legacy-DJI synthetic scenarios and 28 MAVLink parser scenarios, plus 21 telemetry/live-logging and 13 control/anomaly regressions (74 pre-Tello synthetic scenarios, plus the Tello suite). If the credited
fixture is present, it also runs its real-capture regression; otherwise it prints
an explicit skip. Download it first for the complete suite. An optional original
DJI capture can be supplied with `DJI_CAPTURE=/path/to/djiuav.pcap.gz`. Override the
Zeek executable with `ZEEK=/path/to/zeek` if needed.

Verified on Zeek 9.0.1; [v0.3.0 results and raw example](validation/v0.3.0-results.md):

- Original DJI capture: one connection; parser regression verifies 2,769 validated
  messages and 1,220 matched responses with rate limiting disabled. Normal logging
  now emits detection/update snapshots instead of a final summary.
- Capture shared by kresoin: two MAVLink connections and **four default log entries**
  (detection + update for each), with real position, altitude, battery, motion and
  GUIDED/RTL mode observations. Diagnostics-on replay also verifies mission, command,
  parameter and ACK evidence. The previous 34,234-observation total remains a capture
  baseline; rate-limited snapshots are not final session totals.
- Synthetic tests include bad CRCs/CRC_EXTRA, incomplete messages, unknown IDs,
  unsupported flags, repeated identical evidence, signed framing, v1/v2, IPv6,
  either-endpoint ports, truncated fields, component-zero messages, metadata/budget
  limits, and FE-prefixed simulator data as a negative case.

The first motor-speed packet in the simulator fixture starts FE, but contains
16 float values rather than MAVLink. It must not trigger a drone match.

## Additional research captures

[Dataset research notes](docs/dataset-research.md) cover the Kaggle flight-log
CSV/JSON dataset and UVic ISOT Tello PCAPs, with attribution and limitations.
The UVic SDK injection fixture is now a positive Tello test; three binary
Tello fixtures now verify binary protocol identification. Expanded ISOT tests
cover six manipulation captures, three normal flights and two wireless captures. The Kaggle files are not PCAPs and are not used to claim
network detector accuracy or calibrate the heuristic thresholds.

## Limits and next steps

No coverage claim is made for all DJI models, DUML, Remote ID, encrypted radio
links, every MAVLink dialect, or arbitrary ports. MAVLink TCP is not implemented.
Production load and false-positive rates on a broad unrelated-traffic corpus
remain unmeasured. The validation is offline; the code was not installed on a
sensor. ArduPilot/Gazebo simulation traffic is not proof of a real aircraft.

Future manufacturers/protocols can share `drone.log` while retaining separate
parsers, identity evidence and regression captures.

## Protocol references and maintainer tooling

- [MAVLink serialization and CRC_EXTRA](https://mavlink.io/en/guide/serialization.html)
- [MAVLink heartbeat roles](https://mavlink.io/en/services/heartbeat.html)
- [pymavlink](https://github.com/ArduPilot/pymavlink) and its XML-derived ardupilotmega metadata
- [Wireshark legacy DJI dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-dji-uav.c)
- [Phantom Vision protocol research](https://github.com/noahwilliamsson/dji-phantom-vision/blob/master/dji-phantom.c)

To regenerate the checked-in CRC/name/length facts, install `pymavlink==2.4.50`
in a separate development environment and run `tools/generate_mavlink_metadata.py`.
The detection scripts are independently implemented; pymavlink is a metadata
source and validation reference, not a runtime sensor dependency.
