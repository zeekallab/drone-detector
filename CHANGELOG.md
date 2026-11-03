# Changelog

## 0.12.2 — 2026-11-03

- Omit sdk_related_uids when empty or redundant with uid; retain the contributing
  set whenever it includes another connection. No detection or rate-limit changes.

## 0.12.1 — 2026-11-03

- Trim Tello SDK flight_telemetry to height_cm, tof_distance_cm and battery_status
  containing remaining_pct. Preserve original numeric values without conversions.
- Remove redundant identity/timestamp and other SDK measurements from presentation;
  preserve state validation, freshness, detection and rate limits. MAVLink is unchanged.

## 0.12.0 — 2026-11-03

- Replace the main README with a concise overview; preserve full documentation in EXTENDED_README.md.

- Rename the output field `telemetry` to `flight_telemetry` for MAVLink and Tello SDK.
- Simplify MAVLink output to GPS, sea-level altitude, motion, battery_status and mode;
  omit armed state, home-relative height, timestamps and message-source metadata.
- Show system/component IDs only for multi-source snapshots. Prefer fresh individual
  battery percentages, falling back to aggregate readings when unavailable.
- Round displayed motion speeds to two decimals with a signed 0.01 minimum for tiny
  nonzero readings. Keep original precision/timestamps for detection and freshness.
- Emit telemetry_limited only when true. Update schema, examples and regression tests.

## 0.11.0 — 2026-11-03

- Move all three MAVLink anomaly descriptions into the shared `alert` field.
- Remove the separate `anomaly_indicators` output field; migrate searches to `alert`.
- Preserve anomaly thresholds, bounded tracking, interval clearing and log rate limits.
- Add brief README enablement instructions and visibility requirements for optional
  ARP interception and Wi-Fi deauthentication modules.

## 0.10.0 — 2026-11-03

- Add default rapid replay-like binary Tello joystick detection for short-delay
  duplicates using a diverse-payload burst threshold and independent bounded cache.
- Add interval rapid-repeat counters; retain existing older-replay/malformed
  alerts and the shared minute logging gate without a session-end flush.
- Validate all six Replay captures plus six manipulation and three normal-flight
  comparisons; document capture-duplication ambiguity and lack of acceptance proof.

## 0.9.0 — 2026-11-03

- Add default control source-port churn alerts for recent, validated SDK peer pairs.
- Aggregate SDK command/maneuver history and reply context across UDP connections;
  rate-limit command summaries per ordered host pair while retaining trigger UID
  and bounded contributing UIDs. Omit misleading per-connection direction totals.
- Accept recognized replies on an earlier port only after a recent validated
  command; retain no unique request/outcome or authorization claim.
- Add bounded port/pair state, expiry and limit reporting; validate all eight
  Unauth captures plus injection, station-mode and normal-flight comparisons.

## 0.8.0 — 2026-11-03

- Add default-enabled Tello SDK Annex-B H.264 video observations, correlated with
  recent SDK telemetry and bounded structural video evidence.
- Add `video_active` and `video_codec` to video-flow rows in the existing drone.log;
  retain the shared minute gate and keep video presence separate from attack alerts.
- Test two selected Video captures and synthetic positive/negative cases; document
  codec/transport visibility, worker-local correlation and the limits of FPV inference.

## 0.7.0 — 2026-11-03

- Add default-enabled repetitive opposing Tello SDK maneuver detection and axis
  evidence in the existing `alert` field, with bounded rolling history.
- Record recognized SDK response counts on confirmed flows; replies alone do not
  establish identity and are not uniquely matched command execution outcomes.
- Retain minute-limited logging; responses can now drive an eligible update.
- Review all eight UVic injection captures, document the two unflagged cases and
  legitimate automation ambiguity, and add synthetic and real-capture checks.

## 0.6.0 — 2026-11-03

- Add optional ARP interception-pattern detection, correlated with confirmed drone
  flows, without a configured trusted-controller baseline.
- Append claimant MACs, claimed IPs and bounded-tracking status to drone.log;
  preserve existing alert descriptions and the shared logging rate limit.
- Require explicit loading and a single IPv4 broadcast domain on the same worker;
  document proxy-ARP false positives, one-sided gaps and capture visibility.
- Add 18 synthetic checks and all 12 MITM capture regressions, plus three normal
  comparisons. Credit UVic ISOT and publish the measured coverage limitations.

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
