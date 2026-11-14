#!/usr/bin/env python3
"""Wireless profile: drone AP inventory and Remote ID (beacon + NAN), with negatives."""
import hashlib
import struct
from test_detector import run
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
    # The default (wired) package never parses radiotap.
    rows,_=run(capture([beacon(b'TELLO-58ECCC'),rid_beacon()]),live=True)
    assert not rows,rows;cases+=1
    print(f'PASS: {cases} wireless-profile scenarios (drone AP inventory, Remote ID beacon/NAN, negatives).')

if __name__=='__main__':main()
