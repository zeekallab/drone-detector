# Drone protocol detector — 0.2.0

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

A summary is written when a detected connection ends or offline analysis finishes.
Long-lived connections do not generate an immediate notification. The timestamp
is the connection start. `uid` links `drone.log` to `conn.log`, which also receives
`drone_protocol`, `drone_likely_manufacturer` and `drone_evidence`.

Common fields include manufacturer, protocol, evidence, directional validated
message counts, command IDs, checksum failures and inspection-limit status.
`matched_responses` is currently a legacy-DJI metric; MAVLink reports zero and
logs observed acknowledgements separately, without claiming transaction matching.
`gaps` describes TCP gaps for DJI; it is zero for the UDP detector and does not
measure MAVLink sequence loss.

MAVLink adds:

| Fields | Meaning |
|---|---|
| `mavlink_versions` | Observed wire versions, 1 and/or 2 |
| `system_ids`, `component_ids` | Reported protocol IDs; endpoints may relay multiple components |
| `heartbeat_identities` | Combined system/component/type/autopilot identities |
| `vehicle_types` | Reported quadrotor, ground station, rover, camera, etc. |
| `autopilot_software` | ArduPilot, PX4, not-an-autopilot, or numeric enum fallback |
| `message_types` | Names of CRC-validated message types |
| `commands`, `command_acks` | COMMAND_LONG/INT command IDs and observed ACK results |
| `reported_modes` | Heartbeat modes/status with identity and stack context |
| `requested_modes` | Custom-mode values in SET_MODE requests |
| `mission_item_counts` | Item counts announced by MISSION_COUNT |
| `parameter_ids`, `parameter_updates` | Changed parameter names, wire-value bits/type and target IDs |
| `signed_messages`, `unsigned_messages` | Presence/absence of the MAVLink 2 signature trailer |
| `signature_validation` | Always `not-performed`; a CRC does not authenticate a sender |
| `zero_component_messages` | CRC-valid messages with source component zero, retained as observed |
| `unknown_message_ids`, `malformed_frames` | Unsupported message observations and framing errors |
| `metadata_limited` | Whether a per-field metadata set reached its configured bound |

Sets summarize distinct values rather than chronology. Message counts include
repeated capture observations and forwarded messages. Never equate connection
counts with aircraft counts. Mode numbers are stack/vehicle-specific: mode 6
is not universally RTL. Parameter bits are reported without guessing integer
encoding conventions or units. For example, the fixture records `RTL_ALT`,
MAV_PARAM_TYPE 6 and value bits `0x43898000`; its ArduPilot float-cast value is
275, but this interpretation must not be generalized to every MAVLink system.
A command or parameter change is normal activity until a policy or context makes
it suspicious. The scripts do not create attack notices for routine commands.

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
redef DroneDetector::minimum_consecutive_messages = 3;
redef DroneDetector::max_inspected_bytes = 1048576;
redef DroneDetector::max_pending_requests = 256;
redef DroneMAVLink::minimum_evidence_messages = 3;
redef DroneMAVLink::max_inspected_bytes = 1048576;
redef DroneMAVLink::max_metadata_values = 64;
```

Use positive values. Each detector caps inspection at 1 MiB per connection;
MAVLink stops before a datagram would exceed the budget. Metadata sets are
bounded independently. Once a budget is exhausted, counters represent only
inspected data, not the full connection. Candidate ports limit delivered payloads;
there is no all-traffic packet event handler or arbitrary-port discovery.

## Tests and verified results

```sh
python3 tests/run_tests.py
```

Runs 12 legacy-DJI synthetic scenarios and 28 MAVLink scenarios. If the credited
fixture is present, it also runs its real-capture regression; otherwise it prints
an explicit skip. Download it first for the complete suite. An optional original
DJI capture can be supplied with `DJI_CAPTURE=/path/to/djiuav.pcap.gz`. Override the
Zeek executable with `ZEEK=/path/to/zeek` if needed.

Verified on Zeek 9.0.1:

- Original DJI capture: one connection, 2,769 validated messages, 1,220 response matches.
- Capture shared by kresoin: two MAVLink connections, 34,234 CRC-valid message
  observations, including the 60-item mission, mission-start command 300,
  acknowledgements, `RTL_ALT` update and requested mode 6.
- Synthetic tests include bad CRCs/CRC_EXTRA, incomplete messages, unknown IDs,
  unsupported flags, repeated identical evidence, signed framing, v1/v2, IPv6,
  either-endpoint ports, truncated fields, component-zero messages, metadata/budget
  limits, and FE-prefixed simulator data as a negative case.

The first motor-speed packet in the simulator fixture starts FE, but contains
16 float values rather than MAVLink. It must not trigger a drone match.

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
