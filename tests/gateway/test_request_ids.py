import base64
import concurrent.futures
from datetime import datetime, timezone, timedelta

from gateway.tools import Caller

ALICE = Caller('alice', frozenset({'jumphost:run'}))


def args(**kw):
    return {'xlsx_b64': base64.b64encode(b'synthetic workbook').decode(),
            'request_id': 'intent:1',
            'not_after': (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), **kw}


def test_request_is_recorded_before_lease_and_duplicate_is_serialized(fake_env, monkeypatch):
    gw = fake_env['gateway']
    seen = []
    def lease(caller, values):
        seen.append(gw.state.request_snapshot(values['request_id'], caller.subject)[0])
        from gateway.state import LeaseError
        raise LeaseError('synthetic lease refusal')
    monkeypatch.setattr(gw, '_lease', lease)
    values = args()
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        replies = list(pool.map(lambda _: gw.call(ALICE, 'case_submit', values), range(2)))
    assert len(seen) == 1
    assert seen[0]['state'] == 'received'
    assert replies[0] == replies[1]
    assert replies[0]['request_id'] == 'intent:1'


def test_request_parameters_are_paired(fake_env):
    for key in ('request_id', 'not_after'):
        values = args()
        values.pop(key)
        reply = fake_env['gateway'].call(ALICE, 'case_submit', values)
        assert not reply['ok'] and 'together' in reply['error']


def test_legacy_has_explicit_no_request_record(fake_env, monkeypatch):
    gw = fake_env['gateway']
    monkeypatch.setitem(gw.handlers, 'case_submit', lambda *_: {'task_id': 'synthetic'})
    reply = gw.call(ALICE, 'case_submit', {})
    assert reply['request_record'] == 'none'


def test_duplicate_conflicts_expiry_and_gc(fake_env, monkeypatch):
    import time
    from gateway.state import StateStore
    gw = fake_env['gateway']
    calls = []
    monkeypatch.setitem(gw.handlers, 'case_submit', lambda *_: calls.append(1) or {'task_id':'synthetic'})
    values = args()
    first = gw.call(ALICE,'case_submit',values)
    assert gw.call(ALICE,'case_submit',values) == first
    assert calls == [1]
    assert not gw.call(ALICE,'case_submit',args(xlsx_b64=base64.b64encode(b'changed').decode()))['ok']
    bob = Caller('bob', ALICE.scopes)
    assert not gw.call(bob,'case_submit',values)['ok']
    assert gw.call(ALICE,'case_submit',values) == first
    expired = args(request_id='expired',not_after='2001-01-01T00:00:00Z')
    reply = gw.call(ALICE,'case_submit',expired)
    assert not reply['ok'] and reply['stage'] == 'admission'
    assert gw.call(ALICE,'case_submit',expired) == reply
    assert gw.state.gc_requests(time.time()+1) == 1
    assert gw.state.request_snapshot('intent:1','alice')[0] is not None
    assert gw.state.request_snapshot('expired','alice')[0] is None
    assert StateStore(gw.cfg.state_dir).request_snapshot('expired','alice')[2] > 0
    assert calls == [1]


def submission(fake_env,tmp_path):
    from conftest import make_workbook
    gw=fake_env['gateway']
    lease=gw.call(ALICE,'lease_acquire',{})
    data=make_workbook(tmp_path/'case.xlsx',[('202610230000000001','APV_1','cmd','show slb real')])
    return args(xlsx_b64=base64.b64encode(data).decode(),lease_id=lease['lease_id'],token=lease['token'])


def test_reconcile_crashes_before_and_after_runner(fake_env,tmp_path,monkeypatch):
    import pytest
    from gateway import framework
    from gateway.tools import Gateway
    from gateway.audit_chain import verify
    gw=fake_env['gateway']
    values=submission(fake_env,tmp_path)
    class Crash(BaseException): pass
    def stop(cfg,task_id,*_):
        assert gw.state.task(task_id) is not None
        raise Crash()
    monkeypatch.setattr(framework,'launch_run',stop)
    with pytest.raises(Crash): gw.call(ALICE,'case_submit',values)
    restarted=Gateway(gw.cfg)
    row=restarted.reconcile_request('intent:1',ALICE.subject)
    assert row['state']=='not_started' and not row['reached_device']
    def started(cfg,task_id,*_):
        framework.task_paths(cfg,task_id)['start'].write_text('started')
        raise Crash()
    monkeypatch.setattr(framework,'launch_run',started)
    values['request_id']='intent:2'
    with pytest.raises(Crash): restarted.call(ALICE,'case_submit',values)
    again=Gateway(gw.cfg)
    row=again.reconcile_request('intent:2',ALICE.subject)
    assert row['state']=='started' and row['reached_device']
    assert verify(again.audit_path)['ok']


import pytest

@pytest.mark.parametrize('stage',['admission','lease','precheck','bed_busy','staging','launch'])
def test_refusals_record_stage_without_launch(fake_env,tmp_path,monkeypatch,stage):
    from gateway import framework, gates
    from gateway.state import LeaseError
    gw=fake_env['gateway']; values=submission(fake_env,tmp_path)
    launches=[]
    monkeypatch.setattr(framework,'launch_run',lambda *_: launches.append(1))
    def fail(*_,**kw): raise framework.FrameworkError('synthetic failure; fix injected condition and retry with a new id')
    if stage=='admission': values['xlsx_b64']='!'
    elif stage=='lease': values['token']=-1
    elif stage=='precheck': monkeypatch.setattr(gates,'check',fail)
    elif stage=='bed_busy': monkeypatch.setattr(gw.state,'try_bed_lock',lambda:None)
    elif stage=='staging': monkeypatch.setattr(framework,'stage_case',fail)
    elif stage=='launch': monkeypatch.setattr(framework,'launch_run',fail)
    out=gw.call(ALICE,'case_submit',values)
    assert not out['ok'] and out['stage']==stage and out['reached_device'] is False
    assert launches==[]
    if stage!='admission':
        assert gw.state.request_snapshot('intent:1','alice')[0]['state']=='rejected'


@pytest.mark.parametrize('reached',[False,True])
def test_probe_refusal_preserves_explicit_device_fact(fake_env,monkeypatch,reached):
    from gateway import framework
    gw=fake_env['gateway']; lease=gw.call(ALICE,'lease_acquire',{})
    monkeypatch.setattr(framework,'probe',lambda *_:{'error':'synthetic probe failure','reached_device':reached})
    reply=gw.call(ALICE,'probe_show',{'command':'show version','lease_id':lease['lease_id'],'token':lease['token']})
    assert not reply['ok'] and reply['reached_device'] is reached and reply['stage']=='probe'


@pytest.mark.parametrize('after_login',[False,True])
def test_agent_reports_connection_phase_without_real_ssh(monkeypatch,after_login):
    import sys
    from types import SimpleNamespace
    from gateway.agent.jumphost_agent import op_probe
    class SSH:
        def set_missing_host_key_policy(self,*_): pass
        def connect(self,**_):
            if not after_login: raise OSError('synthetic connect failure')
        def invoke_shell(self): raise OSError('synthetic shell failure')
        def close(self): pass
    monkeypatch.setitem(sys.modules,'paramiko',SimpleNamespace(SSHClient=SSH,AutoAddPolicy=lambda:None))
    out=op_probe({'command':'show version','ip':'192.0.2.1','user':'synthetic','passwd':'fake'})
    assert out['reached_device'] is after_login


@pytest.mark.parametrize('logged_in',[False,True])
def test_console_failure_retains_login_fact(monkeypatch,logged_in):
    from gateway import console
    class FakeConsole:
        def __init__(self,*_): pass
        def read_until(self,*_): return True,'Connected.'
        def send(self,*_): raise OSError('synthetic command failure')
        def close(self): pass
    monkeypatch.setattr(console,'Console',FakeConsole)
    monkeypatch.setattr(console,'_login',lambda *_:logged_in)
    out=console.init_one(0,console_argv=['fake'],tty='synthetic',hostname='synthetic',
                         user='fake',passwd='fake',commands=[],long_commands={},step_timeout=1,login_timeout=1)
    assert out.status=='error' and out.as_dict()['reached_device'] is logged_in


def test_readonly_request_query_and_retention_bounds(fake_env):
    from gateway.tools import TOOL_SPECS
    gw=fake_env['gateway']
    spec=next(s for s in TOOL_SPECS if s['name']=='case_request')
    assert spec['read_only'] and spec['scope']=='jumphost:run'
    missing=gw.call(ALICE,'case_request',{'request_id':'missing'})
    assert missing['found'] is False and missing['gateway_time'] > missing['gc_before']
    reply=gw.call(ALICE,'case_submit',args(not_after='2001-01-01T00:00:00Z'))
    row=gw.call(ALICE,'case_request',{'request_id':'intent:1'})
    assert row['found'] and row['state']=='rejected' and row['stage']=='admission'
    assert row['reached_device'] is False and 'task_id' not in row
    other=gw.call(Caller('bob',ALICE.scopes),'case_request',{'request_id':'intent:1'})
    assert set(other)==set(missing) and other['found'] is False
    gw.state.gc_requests(__import__('time').time()+1)
    deleted=gw.call(ALICE,'case_request',{'request_id':'intent:1'})
    assert not deleted['found'] and deleted['gc_before']>0


def test_query_clock_after_lock_prevents_late_launch(fake_env,monkeypatch):
    import sqlite3,time,threading
    gw=fake_env['gateway']; launches=[]
    monkeypatch.setitem(gw.handlers,'case_submit',lambda *_:launches.append(1) or {'task_id':'fake'})
    blocker=sqlite3.connect(gw.state.db_path,isolation_level=None)
    blocker.execute('BEGIN IMMEDIATE')
    deadline=time.time()+0.15
    values=args(not_after=datetime.fromtimestamp(deadline,timezone.utc).isoformat())
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        submit=pool.submit(gw.call,ALICE,'case_submit',values)
        query=pool.submit(gw.call,ALICE,'case_request',{'request_id':'intent:1'})
        time.sleep(0.2)
        blocker.commit();blocker.close()
        answer=submit.result(); observed=query.result()
    assert not answer['ok'] and answer['stage']=='admission' and launches==[]
    assert observed['gateway_time']>deadline
    assert not observed['found'] or observed['state'] in ('received','rejected')
