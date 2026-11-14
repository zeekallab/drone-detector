# Wireless profile for monitor-mode (radiotap) capture, e.g. a Raspberry Pi
# running Zeek on a wlan interface in monitor mode:
#     @load packages/drone-detector/wireless
# Never load on a wired sensor: these modules use raw_packet, which runs per packet.
#
# The full wired package loads too. Zeek's built-in 802.11 analyzer decodes
# unencrypted data frames (for example Tello's default open network) into IP,
# so the Tello SDK, binary and video detectors also work on monitor captures.
@load ../__load__
@load ../wifi
@load ./radiotap
@load ./inventory
@load ./remoteid
