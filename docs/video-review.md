# Video capture review

Reviewed 2026-11-03. Two of the smaller files in the seven-file Video folder were
selected: `video_6_5_14_5mins.pcap` (117,639,852 bytes) and
`video_7_5_14_10mins.pcap` (117,383,610 bytes). The other five were not examined.

## Credit

Original captures belong to the University of Victoria ISOT dataset, credited to
Z. Chen, I. Traoré, M. Mamun and S. Saad (FPS 2024).

- [Official dataset](https://onlineacademiccommunity.uvic.ca/isot/2024/12/05/drone-datasets/)
- [Description](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2024/12/Drone-Dataset-Description_l.pdf)
- [Research repository](https://github.com/isot-lab/Drone-Anomaly-Detection-Dataset-and-Unsupervised-Machine-Learning)

No source PCAP or extracted footage is redistributed by this repository.

## Observed evidence

Both captures show SDK state from `192.168.10.1` to `192.168.10.4`, ASCII
`streamon` requests, and raw H.264 video toward UDP/11111. Video source ports are
62515 and 62514 respectively. Host/port observations are not hardcoded identities.

| Capture | Video datagrams from drone | Video payload bytes | Observed video span | Video log rows |
| --- | ---: | ---: | ---: | ---: |
| video_6_5_14_5mins.pcap | 80,224 | 112,273,347 | 313.24 seconds | 6 |
| video_7_5_14_10mins.pcap | 87,169 | 110,950,403 | 588.33 seconds | 10 |

Counts exclude UDP headers quoted inside ICMP errors. Datagrams contain Annex-B
start codes and NAL types 7 (SPS), 8 (PPS), 5 (IDR slice) and 1 (non-IDR slice).
Repeated parameter sets often occur around a second apart. Video continuation
packets do not necessarily begin with a NAL header, so packet size alone is not
used as a signature.

An independent ffprobe check of a bounded, locally extracted payload sample from
each file identifies H.264 Main profile at 960×720. The samples start midstream
and end at a bounded cutoff; decoder diagnostics about missing initial parameter
sets/truncated data are expected. This verifies codec metadata, not that every
frame in the capture is intact or displayable. The Zeek detector does not decode
or retain footage and does not claim to measure resolution.

## Implemented observation

The default-loaded `scripts/video.zeek` module requires a recently established
SDK drone/receiver pair plus SPS/PPS/IDR evidence and three distinct slice-bearing
prefixes within ten seconds. It emits `protocol=tello-video`, `video_active=true`
and `video_codec=H264` in `drone.log`. Existing host fields link the video peer
pair to control/telemetry; its connection UID belongs to the video flow.

A `streamon` request alone establishes neither successful streaming nor drone
identity. A generic H.264 flow alone also remains unclassified. Evidence relies
on basic header structure and peer correlation, not full decoding or sender
authentication. Replay or crafted imitations can reproduce the same evidence.

Records are emitted at confirmation and at most once per minute per connection.
No stop event or final-session flush is emitted. A true value is an observation
at that timestamp; it does not remain current indefinitely. The absence of a
video row cannot establish that there was no video.

## Limits for FPV use

Video can support FPV flying, surveillance, recording or stationary camera use.
The network capture cannot establish that a person viewed the stream, wore
goggles, or used it to steer. `controller_host` is the correlated video receiver,
not proof of an authorized or currently active pilot.

Coverage initially targets this Tello SDK raw H.264 format. Proprietary/encrypted
radio links, analog FPV, RTP/RTSP, other codecs, the alternative binary Tello
video transport, and streams without visible SDK state are not covered. Since v0.13.0, SDK state
and video may reach different workers when the default cluster module and proxy
relay are operational. Previously they had to reach the same worker. See
[cluster requirements](../EXTENDED_README.md#cluster-correlation). Bounded prefix inspection can miss headers
outside the inspected prefix or split across datagrams. Identification uses up
to 128 bytes per packet and 4 MiB per connection per minute by default. Budget
exhaustion is reported with `inspection_limited`; it can cause missed evidence.

This is a normal observation, not an attack alert. No DoS detection was added.
See [validation](../validation/v0.8.0-results.md).
