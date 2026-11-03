# Changelog

## 0.5.0 — 2026-11-03

- Add the optional `alert` array with replay-like and malformed-control descriptions.
- Identify binary Tello via repeated distinct frames with validated length, CRC8
  and CRC16; analyze delayed whole-message joystick reuse and integrity failures.
- Share a per-connection emission gate across IP protocols; retain minute-limited
  logging and no session-end duplicate.
- Add opt-in radiotap Wi-Fi deauthentication burst detection, with SSID/BSSID and
  EAPOL context. It is disabled in the default package; no password-cracking claim.
- Allow missing UID/IP IDs on wireless-only records instead of inventing connections.
- Add alert definitions, thresholds and coverage limits to README; test manipulation,
  additional normal flights and wireless captures with UVic ISOT attribution.

## 0.4.0 — 2026-11-02

- Add Tello SDK detection from repeated structured status messages, with battery,
  height, orientation and raw motion measurements in the existing drone.log.
- Correlate bounded SDK command summaries with recently observed drone/controller
  pairs. Keep the existing immediate confirmation and minute-level update policy.
- Add synthetic parser/correlation/timing tests and a positive regression against
  the UVic ISOT instruction-injection capture, with attribution. Binary Tello
  control/replay traffic remains unsupported; no takeover verdict is inferred.

## 0.3.0 — 2026-11-02

- Write immediately on protocol confirmation, followed by traffic-driven updates
  at most once per minute per connection, in the same drone.log. No session-end
  duplicate; timestamps now represent observation/emission time.
- Add bounded, source-separated MAVLink coordinates, altitude, battery remaining,
  VFR HUD movement, armed status and stack-aware flight-mode snapshots.
- Omit unavailable/stale measurements and attach per-measurement timestamps.
  Telemetry is a JSON-encoded array string for native Zeek writer compatibility.
- Make verbose parser counters, raw mode histories and message-type lists opt-in
  with include_diagnostics; retain identity/evidence and visibility-limit flags.
- Add bounded per-window control request/ACK summaries, including RC/manual/offboard
  inputs, plus configurable position/altitude discontinuity and multiple-controller
  system-ID indicators. These are signals to investigate, not proof of takeover.
- Keep IP-based controller trust checks optional and disabled without configuration.
- Recognize simulator-message evidence and avoid treating GCS/companion heartbeats
  as autopilot flight state. CRC validation is not sender authentication.
- Renew bounded inspection allowances for confirmed long-running connections.
- Add live-logging/telemetry regressions and replay the capture shared by
  [kresoin](https://github.com/kresoin) in default and diagnostic modes.


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
