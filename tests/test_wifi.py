#!/usr/bin/env python3
"""Opt-in radiotap deauthentication detector, including benign handshake negatives."""
import struct
from test_detector import run

AP=bytes.fromhex('60601f58eccc');STA=bytes.fromhex('5e9d58266748')
RADIO=b'\0\0\x08\0\0\0\0\0'

def beacon(ssid=b'TELLO-58ECCC'):
    return RADIO+struct.pack('<HH',0x80,0)+b'\xff'*6+AP+AP+b'\0\0'+b'\0'*12+bytes([0,len(ssid)])+ssid

def deauth(seq,retry=False,protected=False):
    return RADIO+struct.pack('<HH',0xc0+(0x800 if retry else 0)+(0x4000 if protected else 0),0)+b'\xff'*6+AP+AP+struct.pack('<HH',seq<<4,7)

def eapol(seq):
    return RADIO+struct.pack('<HH',0x208,0)+STA+AP+AP+struct.pack('<H',seq<<4)+bytes.fromhex('aaaa03000000888e')+bytes([2,3,0,95])+b'\0'*95

def capture(frames,times=None):
    data=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,127)
    for i,f in enumerate(frames):
        t=times[i] if times is not None else i*.01
        data+=struct.pack('<IIII',1700000000+int(t),round((t-int(t))*1e6),len(f),len(f))+f
    return data

def main():
    settings='@load ./package/wifi\n'
    frames=[beacon()]+[deauth(i) for i in range(25)]
    rows,_=run(capture(frames),settings,live=True)
    assert len(rows)==1 and rows[0]['protocol']=='802.11' and rows[0]['wireless_deauth_frames']==20,rows
    assert rows[0]['wireless_ssid']=='TELLO-58ECCC' and 'uid' not in rows[0] and 'id.orig_h' not in rows[0],rows
    assert 'Wireless deauthentication burst' in rows[0]['alert'][0],rows
    cases=1
    for fs in ([beacon()]+[deauth(i) for i in range(19)],
               [beacon(b'ordinary-wifi')]+[deauth(i) for i in range(40)],
               [deauth(i) for i in range(40)],
               [beacon()]+[deauth(i,retry=True) for i in range(40)],
               [beacon()]+[deauth(i,protected=True) for i in range(40)],
               [beacon()]+[deauth(1)]*40,
               [beacon()]+[eapol(i) for i in range(40)]):
        rows,_=run(capture(fs),settings,live=True);assert not rows,rows;cases+=1
    rows,_=run(capture(frames),live=True);assert not rows,rows;cases+=1
    rows,_=run(capture([beacon()]+[deauth(i) for i in range(40)],times=[0]+list(range(1,41))),settings,live=True)
    assert not rows,rows;cases+=1
    # Bad-FCS flag in radiotap is not usable attack evidence.
    badradio=bytes.fromhex('000009000200000040')
    fs=[beacon()]+[badradio+deauth(i)[8:] for i in range(40)]
    rows,_=run(capture(fs),settings,live=True);assert not rows,rows;cases+=1
    # A second sustained burst is rate-limited; EAPOL is context, not "cracking".
    fs=[beacon()]+[deauth(i) for i in range(25)]+[eapol(30)]+[deauth(i+40) for i in range(25)]
    times=[0]+[1+i*.01 for i in range(25)]+[30]+[62+i*.01 for i in range(25)]
    rows,_=run(capture(fs,times),settings,live=True)
    assert len(rows)==2 and rows[1]['ts']-rows[0]['ts']>=60 and rows[1]['wireless_eapol_key_frames']==1,rows;cases+=1
    print(f'PASS: {cases} optional Wi-Fi scenarios (burst, benign handshake, retry/FCS/protected-frame filtering, deduplication and rate).')

if __name__=='__main__':main()
