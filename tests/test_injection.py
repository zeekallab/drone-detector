#!/usr/bin/env python3
"""Behavioral Tello maneuver alerts and response context through real Zeek."""
from test_detector import run
from test_tello import STATE,combined


def replay(commands,times=None,settings='',state=True,replies=(),finish=65):
    items=[(i,STATE,8889,8890,False) for i in range(3)] if state else []
    items += [(3,b'command',8889,8889,True)]
    if times is None:times=[5+i*4 for i in range(len(commands))]
    items += [(t,c,8889,8889,True) for t,c in zip(times,commands)]
    items += [(t,c,8889,8889,False) for t,c in replies]
    if finish is not None:items += [(finish,b'battery?',8889,8889,True)]
    rows,_=run(combined(sorted(items,key=lambda x:x[0])),settings,live=True)
    groups={}
    for r in rows:groups.setdefault(r['uid'],[]).append(r)
    for group in groups.values():assert all(b['ts']-a['ts']>=60 for a,b in zip(group,group[1:])),rows
    return rows


def has(rows):return any(any(a.startswith('Repetitive maneuver') for a in r.get('alert',[])) for r in rows)


def main():
    cycle=[b'forward 20',b'back 20']*5
    rows=replay(cycle);assert has(rows),rows
    assert any(r.get('sdk_repetitive_axes')==['forward-back'] for r in rows)
    cases=1
    for pair,axis in [([b'left 20',b'right 20'],'left-right'),([b'up 20',b'down 20'],'up-down'),([b'cw 10',b'ccw 10'],'yaw')]:
        rows=replay(pair*5);assert has(rows) and any(axis in r.get('sdk_repetitive_axes',[]) for r in rows);cases+=1
    for commands in ([b'forward 20']*12,[b'forward 20']*6+[b'back 20']*6,
                     [b'battery?',b'time?']*6,[b'rc 0 0 0 0']*12,
                     [b'forward 999',b'back 999']*6,cycle[:8]):
        assert not has(replay(commands));cases+=1
    assert not has(replay(cycle,state=False));cases+=1
    assert not has(replay(cycle,times=[4+i*.001 for i in range(10)]));cases+=1
    assert not has(replay(cycle,times=[4+i*.5 for i in range(10)]));cases+=1 # insufficient span
    assert not has(replay(cycle,times=[4+i*8 for i in range(10)],finish=80));cases+=1 # window
    assert not has(replay(cycle,settings='redef DroneTello::maneuver_min_reversals = 100;\n'));cases+=1
    rows=replay(cycle,settings='redef DroneTello::maneuver_max_samples = 4;\n')
    assert not has(rows) and any(r.get('activity_limited') for r in rows);cases+=1
    rows=replay([],replies=[(10,b'ok'),(11,b'error No valid imu'),(12,b'unknown command: land`P'),(13,b'OK'),(14,b'noterror')])
    row=next(r for r in rows if 'sdk_ok_responses' in r)
    assert row['sdk_ok_responses']==1 and row['sdk_error_responses']==1 and row['sdk_unknown_command_responses']==1 and not has(rows),rows;cases+=1
    assert not replay([],state=False,replies=[(10,b'ok'),(11,b'error')]);cases+=1
    # Commands after stale telemetry cannot build maneuver evidence.
    assert not has(replay(cycle,times=[130+i*4 for i in range(10)],finish=175));cases+=1
    # No end-of-session flush bypasses the logging interval.
    assert not has(replay(cycle,finish=None));cases+=1
    state_items=[(i,STATE,8889,8890,False) for i in range(3)]
    # Telemetry alone does not turn arbitrary status-port text into a command reply.
    rows,_=run(combined(state_items+[(5,b'ok',8889,8890,False),(65,STATE,8889,8890,False)]),live=True)
    assert not any('sdk_ok_responses' in r for r in rows);cases+=1
    rows,_=run(combined(state_items+[(5,b'ok',8889,8889,False)]),live=True)
    assert len(rows)==1 and not any('sdk_ok_responses' in r for r in rows);cases+=1
    rows,_=run(combined(state_items+[(3,b'command',8889,8889,True),(10,b'ok',8889,8889,True),(65,b'battery?',8889,8889,True)]),live=True)
    assert not any('sdk_ok_responses' in r for r in rows);cases+=1
    print(f'PASS: {cases} injection-pattern scenarios (axes, thresholds, windows, negatives, response context and limits).')
if __name__=='__main__':main()
