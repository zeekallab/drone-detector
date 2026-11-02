# Drone protocol detector — 0.3.0

Zeek scripts that write manufacturer-neutral **`drone.log`** records for:

- **Legacy DJI Phantom Vision control/telemetry**, over configured TCP ports.
- **MAVLink 1 and 2**, over configured UDP ports, with message-specific CRC validation
  and heartbeat-based role information.

`likely_manufacturer` is **DJI** for the legacy detector and **unknown** for
MAVLink. `autopilot_software` may identify ArduPilot or PX4; that is software,
not a hardware manufacturer. MAVLink also serves rovers, boats, cameras and
simulators. A protocol match does not prove that a physical aircraft is present,
airborne, or carrying out an attack.

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
empty update and **no session-end flush or duplicate**. This applies to both
legacy DJI and MAVLink. `ts` is the emission/observation time, not connection
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

## Configuration

Place redefinitions after the package load:

```zeek
redef DroneDetector::ports += { 12345/tcp }; # additional legacy-DJI candidate
redef DroneMAVLink::ports += { 14551/udp };  # additional MAVLink candidate

# Defaults:
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

Runs 12 legacy-DJI synthetic scenarios and 28 MAVLink parser scenarios, plus 21 telemetry/live-logging and 13 control/anomaly regressions (74 synthetic scenarios total). If the credited
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
Four optional UVic fixtures are coverage-gap/negative tests; **Tello detection
is not implemented**. The Kaggle files are not PCAPs and are not used to claim
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
