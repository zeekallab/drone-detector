#!/usr/bin/env python3
"""Control evidence and anomaly indicators are not assertions of takeover."""
import json,struct
from test_detector import run
from test_mavlink import message,pcap
from test_telemetry import position,gps


def main():
    good=b''.join(message(i) for i in range(3))
    def control(command=400,arm=0.0):
        return message(7,76,struct.pack('<7fHBBB',arm,*([0.0]*6),command,1,1,0),152,sysid=255,compid=230)
    cases=0
    # Preserve activity between snapshots, including disarm intent and identities.
    payloads=[good,control(),control(),message(8,11,struct.pack('<IBB',6,1,1),89),message(9),message(10),message(11)]
    rows,_=run(pcap(payloads,times=[0,10,20,30,40,50,60]),live=True)
    assert len(rows)==2 and 'control_activity' not in rows[0],rows
    actions=json.loads(rows[-1]['control_activity'])
    disarm=next(a for a in actions if a.get('command_id')==400)
    assert disarm['observations']==2 and disarm['arm_requested'] is False and disarm['system_id']==255 and disarm['target_system']==1,actions
    assert 'unexpected_source' not in disarm and any(a.get('requested_mode')==6 for a in actions),actions;cases+=1
    # Trust checks apply only when both sets are configured and destination protected.
    for trusted,expected in [('192.0.2.1/32',False),('198.51.100.1/32',True)]:
        settings=f'redef DroneMAVLink::protected_drone_nets = {{192.0.2.2/32}};\nredef DroneMAVLink::trusted_controller_nets = {{{trusted}}};\n'
        rows,_=run(pcap([good+control()]),settings,live=True)
        assert json.loads(rows[0]['control_activity'])[0]['unexpected_source']==expected,rows
    cases+=1
    # Validate packet direction: reverse-side sender is checked as controller.
    settings='redef DroneMAVLink::protected_drone_nets = {192.0.2.1/32};\nredef DroneMAVLink::trusted_controller_nets = {192.0.2.2/32};\nredef DroneDetector::log_interval = 0secs;\n'
    rows,_=run(pcap([good,control()],reverse=True),settings,live=True)
    a=json.loads(rows[-1]['control_activity'])[0]
    assert a['source_host']=='192.0.2.2' and not a['unexpected_source'],a;cases+=1
    # A rapid geographic/altitude discontinuity is retained until the minute update.
    times=[0,1,10,20,30,40,50,60]
    rows,_=run(pcap([good+position(),position(4,lat=382418612,alt=239580)]+[message(i+10) for i in range(6)],times=times),live=True)
    assert set(rows[-1]['alert']) == {
        'mavlink anomaly indicator - position discontinuity',
        'mavlink anomaly indicator - Altitude discontinuity'}, rows
    assert 'alert' not in rows[0] and all('anomaly_indicators' not in r for r in rows), rows
    assert len(rows) == 2 and rows[1]['ts'] - rows[0]['ts'] >= 60, rows
    cases+=1
    # Alerts clear after emission rather than reappearing in a quiet interval.
    packets=[good+position(),position(4,lat=382418612,alt=239580)]+[message(i+10) for i in range(12)]
    rows,_=run(pcap(packets,times=[0,1]+list(range(10,130,10))),live=True)
    assert len(rows)==3 and 'alert' in rows[1] and 'alert' not in rows[2],rows
    cases+=1
    # Normal motion/rounding, source switches and long observation gaps don't trigger.
    for payloads,times in [([good+position(),position(4,lat=372418622,alt=139590)],[0,1]),
                           ([good+gps(),position(4,lat=382418612)],[0,1]),
                           ([good+position(),message(4),position(5,lat=382418612)],[0,20,40])]:
        rows,_=run(pcap(payloads,times=times),'redef DroneDetector::log_interval = 0secs;\n',live=True)
        assert all('alert' not in r for r in rows),rows
    cases+=1
    # Invalid CRC command contributes no activity. Normal signed framing isn't trusted.
    bad=control();bad=bad[:-1]+bytes([bad[-1]^1])
    rows,_=run(pcap([good+bad]),live=True)
    assert 'control_activity' not in rows[0],rows;cases+=1
    # Pending findings are cleared after emission; no replay in subsequent windows.
    packets=[good,control()]+[message(i+15) for i in range(11)]
    rows,_=run(pcap(packets,times=list(range(0,130,10))),live=True)
    assert len(rows)==3 and 'control_activity' in rows[1] and 'control_activity' not in rows[2],rows;cases+=1
    # Bound activity memory and expose overflow, rather than making unlimited entries.
    rows,_=run(pcap([good+control(20)+control(21)]),'redef DroneMAVLink::max_activity_values = 1;\n',live=True)
    assert rows[0]['activity_limited'] and len(json.loads(rows[0]['control_activity']))==1,rows;cases+=1
    # Parameter change requests retain the new wire value with target context.
    param=message(4,23,struct.pack('<fBB16sB',275.0,1,0,b'RTL_ALT',6),168,sysid=255)
    rows,_=run(pcap([good+param]),live=True)
    a=json.loads(rows[0]['control_activity'])[0]
    assert a['parameter_id']=='RTL_ALT' and a['parameter_value_bits']=='0x43898000' and a['target_system']==1,a;cases+=1
    # Indicators can be disabled without suppressing telemetry itself.
    rows,_=run(pcap([good+position(),position(4,lat=382418612)],times=[0,1]),'redef DroneDetector::log_interval = 0secs;\nredef DroneMAVLink::detect_telemetry_anomalies = F;\n',live=True)
    assert all('alert' not in r for r in rows) and 'flight_telemetry' in rows[-1],rows;cases+=1
    # RC override, manual input and offboard setpoints retain their true targets.
    control_messages=[
        message(30,70,struct.pack('<8HBB',1500,*([65535]*7),1,1),124,sysid=255),
        message(31,69,struct.pack('<hhhhHB',0,0,500,0,0,1),243,sysid=255),
        message(32,82,struct.pack('<I8fBBB',1000,1,0,0,0,0,0,0,.5,1,1,0),49,sysid=255),
        message(33,84,struct.pack('<I11fHBBB',1000,*([0.0]*11),0,1,1,1),143,sysid=255),
        message(34,86,struct.pack('<Iii9fHBBB',1000,372418612,-1157969175,*([0.0]*9),0,1,1,6),5,sysid=255)]
    rows,_=run(pcap([good+b''.join(control_messages)]),live=True)
    actions=json.loads(rows[0]['control_activity'])
    assert len(actions)==5 and all(a['target_system']==1 for a in actions),actions
    assert {a['message_type'] for a in actions}=={'RC_CHANNELS_OVERRIDE','MANUAL_CONTROL','SET_ATTITUDE_TARGET','SET_POSITION_TARGET_LOCAL_NED','SET_POSITION_TARGET_GLOBAL_INT'},actions
    cases+=1
    # Controller competition requires distinct system IDs, not merely component IDs.
    def mode(sysid,compid=230,target=1):
        return message(40,11,struct.pack('<IBB',6,target,1),89,sysid=sysid,compid=compid)
    rows,_=run(pcap([good+mode(255)+mode(255,0)]),live=True)
    assert 'alert' not in rows[0],rows
    rows,_=run(pcap([good+mode(255)+mode(254)]),live=True)
    assert rows[0]['alert']==['mavlink anomaly indicator - Multiple control system IDs'],rows
    rows,_=run(pcap([good+mode(255,target=1)+mode(254,target=2)]),live=True)
    assert 'alert' not in rows[0],rows;cases+=1
    # ACKs are response evidence, not requests or competing controllers.
    ack=message(9,77,struct.pack('<HB',400,0),143,sysid=1)
    rows,_=run(pcap([good+control()+ack]),live=True)
    actions=json.loads(rows[0]['control_activity'])
    assert any(a.get('ack_result')==0 and a['command_id']==400 for a in actions),actions
    assert 'alert' not in rows[0],rows;cases+=1
    print(f'PASS: {cases} control/anomaly scenarios (CRC, window aggregation, trust scope, thresholds and bounds).')

if __name__=='__main__':main()
