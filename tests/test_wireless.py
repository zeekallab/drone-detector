#!/usr/bin/env python3
"""Wireless profile: drone AP inventory and Remote ID (beacon + NAN), with negatives."""
import hashlib
import struct
from test_detector import run as _run


def run(data, settings='', live=False):
    # Inventory totals arrive in update/final records: use production logging defaults.
    return _run(data, settings, live=live, lifecycle=True)
from test_wifi import capture

AP=bytes.fromhex('60601f58eccc');STA=bytes.fromhex('5e9d58266748')
OTHER=bytes.fromhex('020000aabbcc');BCAST=b'\xff'*6
WIRELESS='@load ./package/wireless\n'

def radio(mhz=2437,dbm=-40):
    # Flags, Channel (2-byte aligned) and dBm antenna signal.
    return b'\0\0'+struct.pack('<HI',15,0x2a)+b'\0\0'+struct.pack('<HH',mhz,0xa0)+struct.pack('<b',dbm)

def beacon(ssid,src=AP,ies=b'',privacy=False,dbm=-40):
    fixed=b'\0'*8+struct.pack('<HH',100,0x10 if privacy else 0)
    return radio(dbm=dbm)+struct.pack('<HH',0x80,0)+BCAST+src+src+b'\0\0'+fixed+bytes([0,len(ssid)])+ssid+ies

def downlink(n):
    # FromDS data frame: addr1=station, addr2=BSSID, addr3=source.
    return radio(dbm=-45)+struct.pack('<HH',0x0208,0)+STA+AP+AP+struct.pack('<H',n<<4)+b'\xaa'*1200

def basic_id(uas=b'1581F5FKD229400000AA'):
    return bytes([0x02,0x12])+uas.ljust(20,b'\0')+b'\0'*3

def location():
    return (bytes([0x12,0x20,90,40,0])+struct.pack('<ii',450000000,-750000000)
            +struct.pack('<HHH',0,2200,2100)+b'\0'*6)

def system():
    return bytes([0x42,0])+struct.pack('<ii',449990000,-749990000)+b'\0'*15

def pack(*msgs):
    assert all(len(m)==25 for m in msgs)
    return bytes([0xf2,25,len(msgs)])+b''.join(msgs)

def rid_beacon():
    body=bytes.fromhex('fa0bbc0d')+b'\x07'+pack(basic_id(),location(),system())
    return beacon(b'anything',src=OTHER,ies=bytes([221,len(body)])+body)

def rid_nan():
    sid=hashlib.sha256(b'org.opendroneid.remoteid').digest()[:6]
    info=b'\x07'+pack(basic_id(),location())
    sda=sid+bytes([1,0,0x10,len(info)])+info
    body=bytes.fromhex('0409506f9a13')+bytes([3])+struct.pack('<H',len(sda))+sda
    return radio()+struct.pack('<HH',0xd0,0)+BCAST+OTHER+BCAST+b'\0\0'+body

def ip_checksum(h):
    s=sum(struct.unpack('!10H',h));s=(s>>16)+(s&0xffff);s+=s>>16
    return (~s)&0xffff

def gre(frame,key=None,dst='10.254.200.1'):
    # What the Pi forwarder sends: Ethernet / IPv4 / GRE 0x8200 / raw 802.11.
    g=struct.pack('!HH',0x2000 if key is not None else 0,0x8200)+(struct.pack('!I',key) if key is not None else b'')+frame
    d=bytes(int(x) for x in dst.split('.'))
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(g),1,0x4000,64,47,0,bytes([192,168,249,13]),d)
    ip=ip[:10]+struct.pack('!H',ip_checksum(ip))+ip[12:]
    return b'\x02\0\0\0\0\x01'+bytes.fromhex('dca632d54f7f')+b'\x08\x00'+ip+g

def key(mhz,dbm):
    return (mhz<<16)|(dbm&0xffff)

def eth_capture(packets):
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for i,p in enumerate(packets):
        t=i*.01
        data+=struct.pack('<IIII',1700000000+int(t),round((t-int(t))*1e6),len(p),len(p))+p
    return data

def by(rows,protocol):
    return [r for r in rows if r['protocol']==protocol]

def main():
    cases=0
    # Drone AP found by SSID and OUI; downlink volume and the station are tracked.
    frames=[beacon(b'TELLO-58ECCC')]+[downlink(i) for i in range(50)]
    rows,_=run(capture(frames),WIRELESS,live=True)
    ap=by(rows,'802.11')
    assert ap and ap[0]['event_type']=='detection' and ap[0]['wireless_role']=='access-point',rows
    assert ap[0]['wireless_vendor']=='DJI' and ap[0]['evidence']=='drone-ssid+drone-vendor-oui',ap
    assert ap[0]['wireless_channel_mhz']==2437 and ap[0]['wireless_signal_dbm_last']==-40,ap
    assert ap[0]['wireless_protected'] is False,ap
    last=ap[-1]
    assert last['wireless_downlink_frames']==50 and last['wireless_stations']==['5e:9d:58:26:67:48'],ap
    assert last['wireless_signal_dbm_min']==-45 and last['wireless_signal_dbm_max']==-40,ap
    cases+=1
    # Sustained downlink flags a possible video stream within the minute.
    rows,_=run(capture(frames),WIRELESS+'redef DroneInventory::video_bytes_per_minute = 30000;\n',live=True)
    ap=by(rows,'802.11')
    assert ap[-1]['wireless_video_suspected'] is True and ap[-1]['evidence'].endswith('+sustained-downlink'),ap
    assert ap[0]['wireless_video_suspected'] is False,ap
    cases+=1
    # Ordinary network from a non-drone OUI is ignored.
    rows,_=run(capture([beacon(b'home-wifi',src=OTHER)]+[downlink(i) for i in range(20)]),WIRELESS,live=True)
    assert not by(rows,'802.11'),rows;cases+=1
    # Remote ID over a Wi-Fi beacon.
    rows,_=run(capture([rid_beacon()]),WIRELESS,live=True)
    rid=by(rows,'remote-id')
    assert rid and rid[0]['remoteid_transport']=='wifi-beacon',rows
    r=rid[-1]
    assert r['remoteid_ua_id']=='1581F5FKD229400000AA' and r['remoteid_id_type']=='serial-number',r
    assert r['remoteid_ua_type']=='helicopter-or-multirotor' and r['remoteid_status']=='airborne',r
    assert abs(r['remoteid_latitude']-45.0)<1e-6 and abs(r['remoteid_longitude']+75.0)<1e-6,r
    assert r['remoteid_altitude_m']==100.0 and r['remoteid_height_m']==50.0,r
    assert r['remoteid_speed_mps']==10.0 and r['remoteid_track_deg']==90,r
    assert abs(r['remoteid_operator_latitude']-44.999)<1e-6 and r['remoteid_transmitter']=='02:00:00:aa:bb:cc',r
    cases+=1
    # Remote ID over Wi-Fi NAN service discovery.
    rows,_=run(capture([rid_nan()]),WIRELESS,live=True)
    rid=by(rows,'remote-id')
    assert rid and rid[-1]['remoteid_transport']=='wifi-nan' and rid[-1]['remoteid_ua_id']=='1581F5FKD229400000AA',rows
    cases+=1
    # A vendor IE with the wrong OUI type is not Remote ID.
    bad=bytes.fromhex('fa0bbc0e')+b'\x07'+pack(basic_id())
    rows,_=run(capture([beacon(b'x',src=OTHER,ies=bytes([221,len(bad)])+bad)]),WIRELESS,live=True)
    assert not by(rows,'remote-id'),rows;cases+=1
    # GRE 0x8200 input (Pi forwarder to the sensor decoy): radiotap stripped.
    strip=lambda f:f[15:]
    rows,_=run(eth_capture([gre(strip(beacon(b'TELLO-58ECCC')),key(2437,-52))]+[gre(strip(downlink(i))) for i in range(10)]),WIRELESS,live=True)
    ap=by(rows,'802.11')
    assert ap and ap[0]['wireless_channel_mhz']==2437 and ap[0]['wireless_signal_dbm_last']==-52,rows
    assert ap[-1]['wireless_downlink_frames']==10 and 'wireless_signal_dbm_min' in ap[-1],ap
    cases+=1
    # Without the key there is no channel or signal, but detection still works.
    rows,_=run(eth_capture([gre(strip(beacon(b'TELLO-58ECCC')))]),WIRELESS,live=True)
    ap=by(rows,'802.11')
    assert ap and 'wireless_channel_mhz' not in ap[0] and 'wireless_signal_dbm_last' not in ap[0],rows
    cases+=1
    rows,_=run(eth_capture([gre(strip(rid_beacon()))]),WIRELESS,live=True)
    assert by(rows,'remote-id') and by(rows,'remote-id')[-1]['remoteid_ua_id']=='1581F5FKD229400000AA',rows
    cases+=1
    # Deauthentication burst over GRE against a tracked drone AP (inventory).
    from test_wifi import beacon as tello_beacon, deauth
    rows,_=run(eth_capture([gre(tello_beacon()[8:])]+[gre(deauth(i)[8:]) for i in range(25)]),WIRELESS,live=True)
    assert any(r.get('wireless_deauth_frames')==20 for r in rows),rows
    cases+=1
    # GRE to an address that is not a configured decoy is ignored.
    rows,_=run(eth_capture([gre(strip(beacon(b'TELLO-58ECCC')),dst='10.9.9.9'),gre(strip(rid_beacon()),dst='10.9.9.9')]),WIRELESS,live=True)
    assert not by(rows,'802.11') and not by(rows,'remote-id'),rows
    cases+=1
    # The default package includes wireless input, with no extra load line.
    rows,_=run(capture([beacon(b'TELLO-58ECCC'),rid_beacon()]),live=True)
    assert by(rows,'802.11') and by(rows,'remote-id'),rows;cases+=1
    # The off switch disables it.
    rows,_=run(capture([beacon(b'TELLO-58ECCC'),rid_beacon()]),'redef DroneRadio::enabled = F;\n',live=True)
    assert not rows,rows;cases+=1
    print(f'PASS: {cases} wireless-profile scenarios (drone AP inventory, Remote ID beacon/NAN, negatives).')

if __name__=='__main__':main()
