# Optional UVic ISOT captures

These captures belong to the **University of Victoria ISOT research group**.
They were not created by this project and are not republished in Git.

- [Dataset page](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Official archive](https://drive.google.com/file/d/1ILTxl5p4j4zBnQNuEOTnyyviZEgHpDtF/view)
- [Description and published archive password (`drone`)](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)

Citation: Z. Chen, I. Traoré, M. Mamun, and S. Saad, “Drone Anomaly Detection:
Dataset and Unsupervised Machine Learning,” FPS 2024, Montréal, Canada,
Dec. 9, 2024.

Place these archive members in this directory using their original basenames:

- `ISOT Drone Dataset/Raw Data/Injection/Instruction_injection_8_5_14_4mins.pcap`
- `ISOT Drone Dataset/Raw Data/Replay/replay_4_5_22_10mins.pcap`
- `ISOT Drone Dataset/Raw Data/Manipulation/manipulate_1_5_22_10mins.pcap`
- `ISOT Drone Dataset/Raw Data/IP Spoofing/IP_spoofing_4_5_17_1mins.pcap`

`manifest.json` records the exact size and SHA-256 of the extracted members.
Run `python3 tests/test_uvic_captures.py` from the repository root. Without the
optional files the test reports a skip. The test uses `-C` to ensure application
payloads are examined even if stored transport checksums are incomplete, and
explicitly includes UDP/8889 and UDP/8890 as MAVLink candidate ports.

Expected v0.5.0 outcome: nine SDK records plus binary telemetry records in the
instruction-injection capture; binary Tello identification in replay/manipulation/
spoofing samples. These tests do not equate classification with successful takeover.
Expanded optional tests use the extracted archive via `tests/test_isot_alerts.py`.
Never replay attack captures onto a live drone network; tests read files offline.

## Expanded injection review (v0.7.0)

`injection-manifest.json` records the eight source archive members, sizes and
SHA-256 hashes used for the expanded review. The files remain external; this
repository does not redistribute them. Run `tests/test_injection_captures.py`
with `ISOT_CAPTURE_ROOT` pointing to the extracted `Raw Data` directory. Six
files meet the repetitive-maneuver threshold; the first two are identified as
SDK activity but remain unflagged. See [findings](../../../docs/injection-review.md).

## Selected video review (v0.8.0)

`video-manifest.json` records the two selected Video captures. Run
`tests/test_video_captures.py` with `ISOT_CAPTURE_ROOT` pointing to the extracted
`Raw Data` directory. Both produce correlated H.264 video observations; the
other five Video files were not tested. Captures and footage are not redistributed.
See [video findings](../../../docs/video-review.md).

## Unauth review (v0.9.0)

`unauth-manifest.json` records the eight reviewed members. Run
`tests/test_unauth_captures.py` with `ISOT_CAPTURE_ROOT` pointing to `Raw Data`.
The suite also checks eight injection, six station-mode and three normal-flight
captures. See [findings](../../../docs/unauth-review.md). No PCAPs are redistributed.

## Expanded Replay review (v0.10.0)

`replay-manifest.json` records all six original Replay members. Run
`tests/test_replay_captures.py` with `ISOT_CAPTURE_ROOT` pointing to `Raw Data`.
It checks six Replay, six Manipulation and three normal-flight captures.
See [findings](../../../docs/replay-review.md). PCAPs are not redistributed.
