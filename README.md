# Drone detector

A Zeek package that identifies supported drone protocols and writes observations
and suspicious activity to one manufacturer-neutral **`drone.log`**.

Supports legacy DJI Phantom Vision, Tello SDK/binary control, and MAVLink 1/2.
Logs on confirmation and then at most once per minute per connection (SDK command
summaries are limited per host pair). Traffic can also come from simulators or
replays; detection does not prove a drone is airborne or being taken over.

## Latest changes — v0.12.1

Tello `flight_telemetry` now contains only height, time-of-flight distance, and
battery percentage, preserving original units without conversions:

```json
[{"height_cm":70,"tof_distance_cm":103,"battery_status":[{"remaining_pct":92}]}]
```

The repeated host IP, timestamp and other SDK measurements are omitted from this
field. MAVLink telemetry and existing detections are unchanged.
[Full change history](CHANGELOG.md).

## What it reports

| Category | Information |
|---|---|
| Drone activity | Protocol, likely manufacturer, and available flight telemetry |
| Video | Corroborated Tello SDK H.264 stream presence |
| Control alerts | Older/rapid replay-like controls, malformed controls, repetitive opposing maneuvers, and source-port churn |
| MAVLink alerts | Position discontinuity, altitude discontinuity, and multiple control system IDs |
| Optional alerts | ARP interception patterns and wireless deauthentication bursts |

Alerts are investigation signals, not proof of malicious intent or successful
commands. [Definitions and limits](EXTENDED_README.md#alert-reference).

Example decoded MAVLink `flight_telemetry`:

```json
[{
  "gps": {"latitude": 37.241861, "longitude": -115.7969173},
  "altitude": 139.7,
  "motion": {"groundspeed_m_s": 0.03, "heading_deg": 0, "climb_m_s": -0.01},
  "battery_status": [{"battery_id": 0, "remaining_pct": 100}],
  "mode": "GUIDED"
}]
```

Altitude is meters above mean sea level. Speeds are meters/second; heading is
clockwise from north. Mode describes reported flight-control behavior, not proof
of motion. The field is a JSON-encoded string in the raw log; Tello SDK has its
own measurements. [Schema and Splunk examples](EXTENDED_README.md#output-and-interpretation).

## Install and try it

Requires **Zeek 9.0+**. Install using the Zeek package manager:

```sh
zkg install https://github.com/zeekallab/drone-detector
```

Load installed packages with `@load packages`. For a local checkout, replay a
capture from a separate output directory:

```sh
zeek -C -r /path/to/capture.pcap /path/to/drone-detector/scripts LogAscii::use_json=T
```

For Corelight, rebuild your custom bundle from the updated package using your
normal package workflow. Check the sensor's embedded Zeek version; live sensor
compatibility/performance has not been validated. [Installation details](EXTENDED_README.md#installation).

## Enable optional ARP or Wi-Fi alerts

Add the appropriate line to your local policy or bundle entry script, replacing
the path with your installation location, then reload/redeploy the policy:

```zeek
@load /path/to/drone-detector/scripts/arp.zeek
# Or, for raw wireless captures:
@load /path/to/drone-detector/scripts/wifi.zeek
```

**ARP** requires one IPv4 broadcast domain's ARP and drone traffic on the same
worker; avoid merged networks with overlapping addresses. **Wi-Fi** requires raw
radiotap/802.11 management frames, which ordinary Ethernet mirrors do not provide.
Our custom Wi-Fi module adds raw-packet processing overhead. Both are opt-in and
not live-validated on Corelight. Remove the load line to disable a module.
[Requirements and tuning](EXTENDED_README.md#enabling-optional-arp-and-wi-fi-alerts).

## Documentation and credits

- [Extended README](EXTENDED_README.md): configuration, alert thresholds, schemas,
  capture findings, limitations, protocol references and test instructions.
- [Validation results](validation/): automated checks and capture evidence.
- Research captures are credited to [kresoin](https://github.com/kresoin) and
  [University of Victoria ISOT](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/).
  See the extended documentation and fixture manifests for attribution.
