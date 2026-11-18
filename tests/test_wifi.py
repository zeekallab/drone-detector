#!/usr/bin/env python3
"""Disconnect bursts against tracked drone networks (inventory), with benign and non-drone negatives."""
import struct
from test_detector import run

AP=bytes.fromhex('60601f58eccc');STA=bytes.fromhex('5e9d58266748')
PLAIN=bytes.fromhex('001122334455')  # globally administered, not a drone-vendor OUI
RADIO=b'\0\0\x08\0\0\0\0\0'
DEAUTH='Wireless deauthentication burst: repeated disconnect frames on a drone Wi-Fi network'
DISASSOC='Wireless disassociation burst: repeated disconnect frames on a drone Wi-Fi network'

def beacon(ssid=b'TELLO-58ECCC',bssid=AP):
    return RADIO+struct.pack('<HH',0x80,0)+b'\xff'*6+bssid+bssid+b'\0\0'+b'\0'*12+bytes([0,len(ssid)])+ssid

def deauth(seq,retry=False,protected=False,subtype=12,bssid=AP):
    fc=(subtype<<4)+(0x800 if retry else 0)+(0x4000 if protected else 0)
    return RADIO+struct.pack('<HH',fc,0)+b'\xff'*6+bssid+bssid+struct.pack('<HH',seq<<4,7)

def eapol(seq):
    return RADIO+struct.pack('<HH',0x208,0)+STA+AP+AP+struct.pack('<H',seq<<4)+bytes.fromhex('aaaa03000000888e')+bytes([2,3,0,95])+b'\0'*95

def capture(frames,times=None):
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)
    for i,f in enumerate(frames):
        t=times[i] if times is not None else i*.01
        data+=struct.pack('<IIII',1700000000+int(t),round((t-int(t))*1e6),len(f),len(f))+f
    return data

def drone_rows(frames,times=None,settings=''):
    rows,_=run(capture(frames,times),settings,live=True,lifecycle=True)
    return [r for r in rows if r['protocol']=='802.11']

def findings(rows):
    return [a for r in rows for a in r.get('manipulation_detection',[])]

def main():
    cases=0
    # A burst against a drone AP is a prompt finding on that AP's inventory record.
    rows=drone_rows([beacon()]+[deauth(i) for i in range(25)])
    assert [r['event_type'] for r in rows]==['detection','manipulation','final'],rows
    assert {r['wireless_bssid'] for r in rows}=={'60:60:1f:58:ec:cc'},rows
    hit=rows[1]
    assert hit['wireless_deauth_frames']==20 and hit['wireless_peak_burst']==20 and hit['manipulation_detection']==[DEAUTH],hit
    assert hit['wireless_ssid']=='TELLO-58ECCC' and hit['wireless_vendor']=='DJI' and 'uid' not in hit,hit
    assert rows[2]['wireless_deauth_frames']==5,rows  # counts restart after each record
    assert 'wireless_deauth_frames' not in rows[0],rows  # no disconnect fields before any disconnect
    cases+=1
    # Disassociation is detected separately, with its own counter and finding text.
    rows=drone_rows([beacon()]+[deauth(i,subtype=10) for i in range(20)])
    assert findings(rows)==[DISASSOC] and any(r.get('wireless_disassoc_frames')==20 for r in rows),rows
    cases+=1
    # Every drone SSID pattern and drone-vendor OUI is covered, not only Tello names.
    for ssid,bssid in ((b'DJI-Mavic-123',PLAIN),(b'not-a-drone-name',AP)):  # by SSID pattern / by DJI OUI
        rows=drone_rows([beacon(ssid,bssid)]+[deauth(i,bssid=bssid) for i in range(20)])
        assert findings(rows)==[DEAUTH],(ssid,rows)
        cases+=1
    # Non-drone networks: general Wi-Fi activity never reaches drone.log.
    rows=drone_rows([beacon(b'ordinary-wifi',bssid=PLAIN)]+[deauth(i,bssid=PLAIN) for i in range(40)]+[deauth(i,subtype=10,bssid=PLAIN) for i in range(40)])
    assert not rows,rows;cases+=1
    # Negatives on a drone AP: no finding (the AP's own inventory records are allowed).
    for fs in ([beacon()]+[deauth(i) for i in range(19)],
               [deauth(i) for i in range(40)],                       # AP never seen: not tracked
               [beacon()]+[deauth(i,retry=True) for i in range(40)],
               [beacon()]+[deauth(i,protected=True) for i in range(40)],
               [beacon()]+[deauth(1)]*40,                            # duplicates count once
               [beacon()]+[deauth(i) for i in range(10)]+[deauth(i,subtype=10) for i in range(10)],
               [beacon()]+[eapol(i) for i in range(40)]):            # handshakes alone
        rows=drone_rows(fs);assert not findings(rows),rows;cases+=1
    rows=drone_rows([beacon()]+[deauth(i) for i in range(40)],times=[0]+list(range(1,41)))
    assert not findings(rows),rows;cases+=1                          # too slow for one bucket
    badradio=bytes.fromhex('000009000200000040')
    rows=drone_rows([beacon()]+[badradio+deauth(i)[8:] for i in range(40)])
    assert not findings(rows),rows;cases+=1                          # bad FCS is not evidence
    # EAPOL is supporting context; a later burst rides the minute-limited update.
    fs=[beacon()]+[deauth(i) for i in range(25)]+[eapol(30)]+[deauth(i+40) for i in range(25)]
    times=[0]+[1+i*.01 for i in range(25)]+[30]+[62+i*.01 for i in range(25)]
    rows=drone_rows(fs,times)
    assert [r['event_type'] for r in rows].count('manipulation')==1,rows
    later=[r for r in rows if r['event_type']=='update']
    assert later and later[0]['wireless_eapol_key_frames']==1 and later[0]['manipulation_detection']==[DEAUTH],rows
    cases+=1
    # Tuning and the wireless off switch.
    rows=drone_rows([beacon()]+[deauth(i) for i in range(10)],settings='redef DroneInventory::minimum_disconnect_frames = 10;\n')
    assert findings(rows)==[DEAUTH],rows;cases+=1
    rows=drone_rows([beacon()]+[deauth(i) for i in range(25)],settings='redef DroneRadio::enabled = F;\n')
    assert not rows,rows;cases+=1
    print(f'PASS: {cases} drone-network disconnect scenarios (deauth/disassoc findings, non-drone exclusion, benign handshake, retry/FCS/protected filtering, deduplication and rate).')

if __name__=='__main__':main()
