# Capture credit and provenance

**The `traffic.pcap` capture was shared by [kresoin](https://github.com/kresoin).
It is their contributed research/test data, not a capture created by this project.**
Thank you to kresoin for making the PCAP available for testing and research.

- Original project: [kresoin/drone-digital-forensics-lab](https://github.com/kresoin/drone-digital-forensics-lab)
- Original release: [flightlog](https://github.com/kresoin/drone-digital-forensics-lab/releases/tag/flightlog)
- [Download the original traffic.pcap](https://github.com/kresoin/drone-digital-forensics-lab/releases/download/flightlog/traffic.pcap)
- Related article by Inda Kreso: [Drone Digital Forensics: Network Traffic Analysis in Damn Vulnerable Drone – Part I](https://www.linkedin.com/pulse/drone-digital-forensics-network-traffic-analysis-damn-inda-kreso-phd-4sqof/)
- Size: 286,920,580 bytes; 478,252 packet records; approximately 61 seconds.
- SHA-256: `4afd864f1021062c454fb9b4eeac1001995cd26dfa7c614f8ebcfcbca3561478`.

The original file is kept locally here as `tests/fixtures/traffic.pcap` and
ignored by Git. The repository links to the author's original release rather
than republishing the capture or implying ownership/licensing rights over it.

From the repository root:

```sh
python3 tests/fetch_fixture.py
python3 tests/test_author_capture.py
```

The fetch script requires curl, preserves an existing file with an unexpected
hash, and verifies the published SHA-256 before installing a download.

This Linux SLL2 host capture contains partial transport checksums attributable
to checksum offload and duplicate/forwarded observations. Its regression uses
Zeek's `-C` option **only for this offline fixture**. Application-level MAVLink
CRC verification remains enabled. Synthetic tests have valid network checksums
and run without `-C`. Never interpret packet-observation counts as distinct
commands or aircraft counts without further analysis.
