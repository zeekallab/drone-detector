@load ./main
@load ./mavlink

@load ./tello
@load ./cluster
@load ./tello-binary

@load ./video

# Cheap (arp_reply only). Fires only when ARP and the drone flow reach one worker.
@load ./arp

# Wireless input (radiotap capture or GRE 0x8200 forwarding): drone AP inventory
# (including deauthentication/disassociation bursts against drone networks) and
# Remote ID. General Wi-Fi telemetry belongs to the separate wifi-telemetry package.
# Turn off with: redef DroneRadio::enabled = F;
@load ./wireless/radiotap
@load ./wireless/inventory
@load ./wireless/remoteid
