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
