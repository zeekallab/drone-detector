# Drone protocol detector — 0.1.0

A manufacturer-neutral `drone.log` with a first detector for the legacy DJI
Phantom Vision control/telemetry protocol. `likely_manufacturer` is `DJI` for
this detector; `protocol` identifies the exact format. Future manufacturers
can use the same log schema. This version does not detect all DJI models,
DUML, MAVLink, Remote ID, or video-only traffic.

## Detection

The script processes reassembled TCP streams on configured destination ports
(default: 2001/tcp). It requires at least three consecutive valid messages
in either direction, with:

- Binary `55 BB` magic and a valid one-byte message length (8–255 bytes).
- Address/flag bytes from the verified legacy set: 08, 0A, 0B, 48, 4A, 4B.
- XOR checksum validation across each complete message.

Reverse-direction responses matching request sequence, command and component
add `request_response` evidence. A one-sided capture can qualify with framing
and checksums alone. Ports only select candidates; they never establish identity.
There is no dependence on video, fixed IP addresses, vendor MACs or cloud domains.
This is protocol evidence, not proof of a physical aircraft or an aircraft in flight.

The script handles split/coalesced messages, skips invalid bytes to recover
framing, and discards incomplete message state after TCP gaps. Pending request
tracking is bounded to 256 entries; reaching the bound clears pending entries,
which may reduce match counts without changing protocol detection. Inspection
is capped at 1 MiB of stream data per connection, across both directions.

## Output

One summary is written to `drone.log` when a detected connection is removed
(or offline analysis finishes). Long-lived connections will not produce an
immediate alert. The `ts` field is the connection's start time. `uid` links
this record to `conn.log`.

Fields:

| Field | Meaning |
|---|---|
| likely_manufacturer | `DJI` for the initial detector |
| protocol | `dji-phantom-vision-legacy` |
| evidence | `framing+xor` or `framing+xor+request_response` |
| orig_messages / resp_messages | Validated messages in each direction |
| matched_responses | Responses matched to tracked requests |
| commands | Distinct command IDs, represented as decimal counts |
| checksum_failures | Candidate frames rejected for checksum failure |
| skipped_bytes | Bytes skipped during parser resynchronization |
| gaps | Observed TCP gaps after detector state was created |
| inspection_limited | Whether the per-connection inspection budget was reached |

`conn.log` also receives optional `drone_likely_manufacturer`, `drone_protocol`
and `drone_evidence` fields. Unmatched connections do not receive values.
The packet contents themselves are not written to the log.

## Get the detector

```sh
git clone https://github.com/zeekallab/drone-detector.git
cd drone-detector
```

Requires Zeek (tested with 9.0.1). Running the regression tests also requires
Python 3. This repository is public and can be cloned without authentication.

For a standalone Zeek installation with the Zeek package manager:

```sh
zkg install https://github.com/zeekallab/drone-detector
```

Ensure your Zeek site configuration loads installed packages (`@load packages`).
Alternatively, load the local `scripts` directory directly as shown below.
Corelight sensors use their package/bundle workflow described below.

## Offline use

With Zeek installed, from this package directory:

```sh
mkdir -p replay
cd replay
zeek -r /absolute/path/to/capture.pcap ../scripts LogAscii::use_json=T
```

For a gzip-compressed capture, decompress it to a separate file first:

```sh
gzip -dc /absolute/path/to/djiuav.pcap.gz > /tmp/djiuav-test.pcapng
```

Then use that file with `-r`. The original remains unchanged.

For a Zeek installation, load this package's `scripts` directory or install
through zkg. For Corelight, build a zkg bundle on a packaging host and use the
sensor's package workflow. The distributed source ZIP is not a zkg bundle.
No sensor has been configured or modified.

## Configuration

After the package load statement:

```zeek
# Additional candidate destination port, if your traffic requires it:
redef DroneDetector::ports += { 12345/tcp };

# Defaults; use positive values:
redef DroneDetector::minimum_consecutive_messages = 3;
redef DroneDetector::max_inspected_bytes = 1048576;
redef DroneDetector::max_pending_requests = 256;
```

This first version is port-scoped. Arbitrary-port discovery is not implemented.
It enables content delivery/reassembly only for the configured ports, although
other loaded scripts may independently enable broader content delivery.
A false magic header declaring a large message can delay resynchronization;
short, damaged captures may therefore fail to qualify. The bounded scanner
and checksum are intended for identification, not resistance to deliberate
protocol impersonation. Repeated valid messages can be forged.

## Validation

Tested on Zeek 9.0.1, 2026-10-30:

- 12 synthetic capture scenarios: TCP fragmentation/coalescing, matching
  responses, one-sided traffic, insufficient evidence, bad checksums, invalid
  lengths, unrelated data on port 2001, additional port configuration,
  inspection budget, leading noise and recovery after a TCP gap.
- User-supplied DJI capture: one detected connection, 1,230 originator messages,
  1,539 responder messages, 1,220 matched responses, no checksum failures,
  skipped bytes or gaps, and no inspection-budget exhaustion.
- Output saved in `validation/real-capture-result.json`.

Run synthetic tests with `python3 tests/test_detector.py`. Optionally set
`DJI_CAPTURE=/path/to/djiuav.pcap.gz` to repeat the exact real-capture regression.
Set `ZEEK=/path/to/zeek` if necessary. Tests need Python 3 and Zeek; no other
Python packages. Packet checksums are valid; tests do not bypass validation.

Not yet validated on a Corelight sensor, older Zeek runtime, representative
production load, or a broad negative-traffic corpus. The compatibility guard
for older Zeek reassembly options was not runtime-tested on older releases.
More captures are required to measure false positives and expand model coverage.

## Basis and next steps

The field layout is documented by the Wireshark legacy DJI dissector and
independent Phantom Vision research:

- https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-dji-uav.c
- https://github.com/noahwilliamsson/dji-phantom-vision/blob/master/dji-phantom.c

The detector is independently implemented from the observed framing. It does
not copy either implementation. Its initial scope intentionally excludes
other wire formats. Add DUML and additional manufacturers as separate validated
parsers with their own evidence, sharing the manufacturer-neutral log schema.
