#!/usr/bin/env python3
"""SDK control aggregation across source ports with bounded recent pair evidence."""
from test_detector import run
from test_tello import STATE,combined

def cmd(t,payload,port):return (t,payload,8889,port,True)
def reply(t,payload,port):return (t,payload,8889,port,False)
def replay(items,settings='',state=True):
    prefix=[(i,STATE,8889,8890,False) for i in range(3)] if state else []
    rows,_=run(combined(sorted(prefix+items,key=lambda x:x[0])),settings,live=True)
    summaries=[r for r in rows if r.get('sdk_summary_scope')=='host-pair']
    assert all(b['ts']-a['ts']>=60 for a,b in zip(summaries,summaries[1:])),summaries
    assert all('orig_messages' not in r and 'resp_messages' not in r for r in summaries)
    return summaries,rows

def alert(rows,prefix):return any(any(x.startswith(prefix) for x in r.get('alert',[])) for r in rows)
def main():
    seq=[cmd(3,b'command',40000)]+[cmd(5+i*3,[b'forward 20',b'back 20'][i%2],40001+i) for i in range(20)]+[cmd(65,b'battery?',40100)]
    rows,_=replay(seq)
    assert len(rows)==2 and alert(rows,'Control source-port churn') and alert(rows,'Repetitive maneuver'),rows
    assert sum(r['sdk_command_count'] for r in rows)==22,rows
    assert len(rows[-1]['sdk_related_uids'])==21 and rows[-1]['sdk_source_port_count']>=20;cases=1
    fixed=[cmd(t,p,40000) for t,p,_,_,_ in seq]
    rows,_=replay(fixed);assert not alert(rows,'Control source-port churn') and alert(rows,'Repetitive maneuver');assert all('sdk_related_uids' not in r for r in rows),rows;cases+=1
    rows,_=replay(seq,state=False);assert not rows;cases+=1
    rows,_=replay([cmd(130+i*3,b'forward 20',40000+i) for i in range(20)]+[cmd(195,b'battery?',40100)])
    assert not rows;cases+=1
    # Earlier response port: no one-to-one association or connection confirmation required.
    rows,_=replay([cmd(3,b'command',40000),cmd(10,b'forward 20',40001),reply(12,b'ok',39999),reply(13,b'error No valid imu',39999),reply(14,b'unknown command: x',39999),reply(65,b'ok',39999)])
    assert rows[-1]['sdk_ok_responses']==2 and rows[-1]['sdk_error_responses']==1 and rows[-1]['sdk_unknown_command_responses']==1,rows;cases+=1
    rows,_=replay([reply(3,b'ok',39999),reply(65,b'error',39999)]);assert not rows;cases+=1
    # Telemetry refresh does not make very old commands authorize reply counts.
    rows,_=replay([cmd(3,b'command',40000),(123,STATE,8889,8890,False),(124,STATE,8889,8890,False),(125,STATE,8889,8890,False),reply(130,b'ok',39999)])
    assert len(rows)==1 and 'sdk_ok_responses' not in rows[0];cases+=1
    # Very rapid duplicate/burst observations fail the span requirement.
    rows,_=replay([cmd(3+i*.001,b'forward 20',40000+i) for i in range(20)]+[cmd(65,b'battery?',40100)])
    assert not alert(rows,'Control source-port churn');cases+=1
    rows,_=replay(seq,'redef DroneTello::churn_min_ports = 100;\n');assert not alert(rows,'Control source-port churn');cases+=1
    rows,_=replay(seq,'redef DroneTello::max_source_ports = 4;\n');assert not alert(rows,'Control source-port churn') and rows[-1]['activity_limited'];cases+=1
    rows,_=replay(seq,'redef DroneTello::max_related_uids = 2;\n');assert len(rows[-1]['sdk_related_uids'])==2 and rows[-1]['activity_limited'];cases+=1
    # A bounded singleton referring to another connection still adds information.
    rows,_=replay(seq,'redef DroneTello::max_related_uids = 1;\n')
    assert len(rows[-1]['sdk_related_uids'])==1 and rows[-1]['uid'] not in rows[-1]['sdk_related_uids'] and rows[-1]['activity_limited'],rows
    cases+=1
    rows,_=replay(seq,'redef DroneTello::max_related_uids = 0;\n')
    assert all('sdk_related_uids' not in r for r in rows) and rows[-1]['activity_limited'],rows
    cases+=1
    rows,allrows=replay(seq+[(20,STATE,8889,8890,False),(40,STATE,8889,8890,False),(66,STATE,8889,8890,False)],'redef DroneTello::max_control_pairs = 0;\n')
    assert not rows and any(r.get('activity_limited') for r in allrows);cases+=1
    # Pure queries can churn ports but are not movement: only the churn description applies.
    rows,_=replay([cmd(3+i*3,b'battery?',40000+i) for i in range(20)]+[cmd(65,b'time?',40100)])
    assert alert(rows,'Control source-port churn') and not alert(rows,'Repetitive maneuver');cases+=1
    # Separate fixed destination/source identities don't inherit the recent telemetry pair.
    wrong=[(t,p,8889,port,False) for t,p,_,port,_ in seq]
    rows,_=replay(wrong);assert not rows;cases+=1
    # Expired pattern history cannot accumulate slow reconnects into churn.
    rows,_=replay([cmd(3+i*8,b'forward 20',40000+i) for i in range(14)]+[cmd(115,b'battery?',40100)])
    assert not alert(rows,'Control source-port churn');cases+=1
    # Refreshing stale command history must preserve an active pair logging gate.
    items=[cmd(3,b'command',40000),reply(100,b'ok',39999),cmd(130,b'forward 20',40001),cmd(166,b'back 20',40002)]
    items += [(t,STATE,8889,8890,False) for t in range(20,161,20)]
    rows,_=replay(items);assert [r['ts']-1700000000 for r in rows]==[3,100,166],rows;cases+=1
    print(f'PASS: {cases} control-pair scenarios (cross-port history, reply scope, throttling, expiry and bounds).')
if __name__=='__main__':main()
