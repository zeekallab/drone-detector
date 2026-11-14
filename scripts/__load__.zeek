@load ./main
@load ./mavlink

@load ./tello
@load ./cluster
@load ./tello-binary

@load ./video

# Cheap (arp_reply only). Fires only when ARP and the drone flow reach one worker.
@load ./arp

# Wireless input (radiotap capture or GRE 0x8200 forwarding): drone AP inventory,
# Remote ID and deauthentication bursts. Turn off with: redef DroneRadio::enabled = F;
@load ./wireless/radiotap
@load ./wifi
@load ./wireless/inventory
@load ./wireless/remoteid
