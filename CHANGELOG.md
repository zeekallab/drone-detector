# Changelog

## Unreleased

- Remove obsolete TCP reassembler port settings that trigger deprecation warnings
  on some Zeek builds. TCP stream delivery continues through the existing
  `tcp_content_delivery_ports_orig` and `tcp_content_delivery_ports_resp` settings.

## 0.2.0 — 2026-11-02

- Add MAVLink 1/2 over UDP, with message-specific CRC_EXTRA validation and
  heartbeat evidence, to the existing manufacturer-neutral drone.log.
- Separate reported autopilot software and vehicle/component roles from hardware
  manufacturer; MAVLink manufacturer remains unknown.
- Record mission, command/ACK, parameter and mode summaries; distinguish signature
  presence from signature verification, and retain component-zero GCS evidence.
- Add bounded inspection/metadata collection and 28 synthetic MAVLink regressions.
- Add a hash-verifying fetch helper and regression for the PCAP generously shared
  by [kresoin](https://github.com/kresoin), with explicit provenance and source links.
- Retain the legacy DJI detector and its regression coverage.
- Require Zeek 9.0+ for selective UDP delivery from either endpoint.

## 0.1.0 — 2026-10-30

- Initial legacy DJI Phantom Vision TCP detector, drone.log, conn.log linkage,
  bounded stream parsing, checksum validation and 12 synthetic regression scenarios.
