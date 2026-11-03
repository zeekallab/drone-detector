# Additional drone datasets reviewed (2026-11-02)

These sources informed investigation and future test selection. They do not
establish a validated takeover classifier or universal drone coverage.

## Kaggle: Drone Telemetry Tampering Dataset v2

Source and credit: [rasikaekanayakadevlk on Kaggle](https://www.kaggle.com/datasets/rasikaekanayakadevlk/drone-telemetry-tampering-dataset-v2).
Kaggle API metadata reports **CC BY-SA 4.0**, dataset version 1 (title contains v2).

The complete API file inventory contains **2,199 files: 1,453 CSV and 746 JSON**.
There are **no PCAP/PCAPNG files** in that inventory. Approximately 4 GB of decoded
flight data is organized into balanced/strong/subtle profiles and replicate cases.

Scenario names include normal, injection, deletion gaps, heading/speed
inconsistency, altitude spikes, timestamp drift, precision rounding, coordinate
jumps and combined changes. Downloaded representative normal and injection cases
contain `timestamp,latitude,longitude,altitude,speed,heading,source`, row labels,
and case metadata. Sources include decoded DJI flight records and `SYNTH_INJECT`.
These are flight-record transformations, not evidence of MAVLink packets or a
network command takeover. Turning rows into MAVLink would create **synthetic**
fixtures, not recover the original wire traffic.

Useful lessons for this project:

- Position and altitude discontinuities can be bounded, configurable signals.
  v0.3.0 compares successive same-source measurements before minute-level logging.
- Separate source identity and timestamps so asynchronous telemetry isn't mixed.
- Don't equate heading with GPS course: a vehicle can fly sideways/backwards.
- Gaps, duplicate timestamps and clock differences can arise from capture/decoding.
- Dataset label quality and conventions need independent validation before using
  accuracy claims or tuning attack thresholds.

Concrete quality cautions from downloaded samples:

- The normal case has 11,717 rows and all labels zero, but includes one Unix-epoch
  zero timestamp and 2,119 negative headings. Negative headings can be a convention,
  not malicious behavior; our VFR HUD range follows that message's specification.
- The injection case has 13,357 rows. Its metadata reports 1,640 applied labels,
  while `labels.csv` contains 4,276 positive rows. That discrepancy must be explained
  before treating metadata counts as benchmark truth.

No Kaggle data is redistributed here, and the new anomaly thresholds have **not**
been calibrated or scored against this dataset.

## University of Victoria ISOT: DJI Edu Tello

Source and credit: [UVic ISOT Drone Datasets](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/).

- [Dataset description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Author's analysis/scripts repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)
- [Official archive](https://drive.google.com/file/d/1ILTxl5p4j4zBnQNuEOTnyyviZEgHpDtF/view)

Requested citation: Z. Chen, I. Traoré, M. Mamun, and S. Saad, “Drone Anomaly
Detection: Dataset and Unsupervised Machine Learning,” FPS 2024, Montréal,
Canada, Dec. 9, 2024.

The description reports 14 hours of anomalous and 10 hours of benign data,
over 23 GB of PCAP and approximately 1.3 GB of derived CSV. The official ZIP is
18,545,613,820 bytes; its password is **drone**, published in the description.
Its central directory lists **137 PCAPs**, including 55 regular captures and
injection, replay, manipulation, spoofing, MITM, DoS, video and other scenarios.

HTTP byte ranges allowed retrieving the ZIP directory and selected small members
without downloading the full archive. Four credited local fixtures are documented
in [the fixture README](../tests/fixtures/uvic/README.md), with exact sizes/hashes.
Raw captures are gitignored and not republished.

Verified payload observations:

- `Instruction_injection_8_5_14_4mins.pcap` contains UDP/8889 SDK commands such as
  `command`, `forward 20`, `back 20`, `cw 10`, `ccw 10`, plus `ok` and `error Auto land`
  responses. It also contains semicolon-delimited Tello state with `pitch`, `roll`,
  `yaw`, velocity fields, `h`, `bat`, `baro`, `time`, and acceleration measurements.
- The replay and IP-spoofing samples contain binary UDP/8889 payloads beginning
  `cc`, not the legacy Phantom `55 bb` framing or MAVLink `fe`/`fd` framing.
- Capture category labels are research ground truth, not packet-level proof that
  every message is malicious. Ordinary SDK commands can also be used legitimately.

**Coverage gap:** v0.3.0 does not decode Tello SDK or binary control protocols.
Tests confirm these four samples do not falsely match MAVLink or legacy DJI,
including when the Tello UDP ports are explicitly added as MAVLink candidates.
This is negative/coverage-gap testing, not successful detection of those attacks.
A future Tello detector should validate repeated SDK state/command-response
structure, distinguish application modes, and avoid labeling port/MAC/video alone
as drone or attack evidence. Tello state in these examples has relative/local
measurements; it must not be treated as global GPS coordinates.

## v0.4.0 follow-up

The SDK state/command evidence above is now implemented in `scripts/tello.zeek`.
The instruction-injection fixture produces nine rate-limited Tello SDK entries.
The replay, manipulation and spoofing samples still produce no detections because
their binary Tello protocol has not been implemented. This supersedes only the
SDK portion of the v0.3.0 coverage-gap description; it is not an attack classifier.

## v0.5.0 follow-up

Binary Tello identification and replay-like/malformed control alerts now cover
the reviewed manipulation captures. Optional radiotap deauthentication alerts
cover the two password-cracking captures. These supersede the binary coverage
gaps described in the earlier research above; they do not prove takeover or
password cracking. See [validation](../validation/v0.5.0-results.md) and
[wireless findings](password-cracking-review.md).

## v0.7.0 injection follow-up

All eight injection captures were reviewed. The default SDK parser now reports
repetitive opposing maneuver requests and response counts; six captures meet
the behavioral threshold. The two varied-command captures remain unflagged
because command syntax does not establish authorization. See
[injection findings](injection-review.md).

## v0.8.0 video follow-up

Two selected Video-folder captures support Tello SDK Annex-B H.264 observation
when correlated with recent SDK state. Video presence is logged separately from
attack alerts, without asserting FPV piloting. See [video findings](video-review.md).

## v0.9.0 host-pair follow-up

SDK maneuver history and command summaries now span UDP connections within an
ordered drone/controller host pair. Earlier per-connection coverage statements
above describe the earlier release. Source-port churn and earlier-port response
context are now supported; see [Unauth review](unauth-review.md).

## v0.10.0 Replay follow-up

All six Replay captures now trigger the rapid replay-like control rule. Their
short-delay payload repetitions did not meet the older replay-age threshold.
See [Replay review](replay-review.md) for evidence, comparisons and limits.
