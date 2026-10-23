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
    conflict = gw.call(ALICE,'case_submit',args(xlsx_b64=base64.b64encode(b'changed').decode()))
    assert not conflict['ok'] and conflict['stage'] == 'admission' and conflict['reached_device'] is False
    bob = Caller('bob', ALICE.scopes)
    other = gw.call(bob,'case_submit',values)
    assert not other['ok'] and other['stage'] == 'admission' and other['reached_device'] is False
    assert other['error'] == conflict['error']
    assert gw.call(ALICE,'case_submit',values) == first
    expired = args(request_id='expired',not_after='2001-01-01T00:00:00Z')
    reply = gw.call(ALICE,'case_submit',expired)
    assert not reply['ok'] and reply['stage'] == 'admission'
    assert gw.call(ALICE,'case_submit',expired) == reply
    assert gw.state.gc_requests(time.time()+1) == 1
    assert gw.state.request_snapshot('intent:1','alice')[0] is not None
    assert gw.state.request_snapshot('expired','alice')[0] is None
    assert StateStore(gw.cfg.state_dir).request_snapshot('expired','alice')[2] == max(datetime.fromisoformat(expired['not_after'].replace('Z', '+00:00')).timestamp(), reply['journal_since'])
    assert calls == [1]


def submission(fake_env,tmp_path):
    from conftest import make_workbook
    from dataclasses import replace
    gw=fake_env['gateway']
    gw.cfg=replace(gw.cfg,build='SYNTHETIC_10_6')
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
    original_launch=framework.launch_run
    monkeypatch.setattr(framework,'launch_run',lambda *_: launches.append(1))
    def fail(*_,**kw): raise framework.FrameworkError('synthetic failure; fix injected condition and retry with a new id')
    if stage=='admission': values['xlsx_b64']='!'
    elif stage=='lease': values['token']=-1
    elif stage=='precheck': monkeypatch.setattr(gates,'check',fail)
    elif stage=='bed_busy': monkeypatch.setattr(gw.state,'try_bed_lock',lambda:None)
    elif stage=='staging':
        original=framework.stage_case
        monkeypatch.setattr(framework,'stage_case',lambda cfg,module,autoid,data,sha,task_id:
                            original(cfg,module,autoid,data,'0'*64,task_id))
    elif stage=='launch':
        monkeypatch.setattr(framework,'launch_run',original_launch)
        # Exercise process creation failure inside launch_run, after the alive lock is made.
        monkeypatch.setattr(framework.subprocess,'Popen',lambda *a,**kw: (_ for _ in ()).throw(OSError('synthetic process failure')))
    out=gw.call(ALICE,'case_submit',values)
    assert not out['ok'] and out['stage']==stage and out['reached_device'] is False
    assert launches==[]
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
    assert not deleted['found'] and deleted['gc_before'] == max(row['not_after'], deleted['journal_since'])


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


@pytest.mark.parametrize('fake_env', ['overwrite', 'append'], indirect=True)
def test_deliveries_own_results_logs_sessions_and_gc(fake_env,tmp_path):
    import json,time,os
    from pathlib import Path
    from gateway import framework,prune
    from test_gateway import _wait_done
    gw=fake_env['gateway']; values=submission(fake_env,tmp_path)
    cid='202610230000000001'
    verdicts=fake_env['apv']/'fake_verdicts.json'
    verdicts.write_text(json.dumps({cid:'FAIL'}))
    one=gw.call(ALICE,'case_submit',values)
    assert one['ok'],one
    _wait_done(gw,ALICE,one['task_id'])
    first=gw.call(ALICE,'case_results',{'task_id':one['task_id']})
    verdicts.write_text(json.dumps({cid:'ERROR'}))
    two=gw.call(ALICE,'case_submit',{**values,'request_id':'intent:2'})
    assert two['ok'],two
    _wait_done(gw,ALICE,two['task_id'])
    assert two['deliver_epoch']-one['deliver_epoch']<60
    # Put a newer, unrelated report and row under the same framework run name.
    second=gw.call(ALICE,'case_results',{'task_id':two['task_id']})
    outside=fake_env['apv']/'report'/second['run_dir']/'sdns'/'ist_staging_sdns'/cid/'test_xlsx'/'case.xlsx'/cid
    outside.mkdir(parents=True)
    (outside/(cid+'.txt')).write_text('UNOWNED LOG')
    rows=json.loads((fake_env['apv']/'fake_results.json').read_text())
    rows.append({'table':gw.cfg.build,'case_id':cid,'sub_module':'ist_staging_sdns','result':'PASS',
                 'url':'http://192.0.2.1/'+outside.relative_to(fake_env['apv']).as_posix()+'/'+cid+'/'})
    (fake_env['apv']/'fake_results.json').write_text(json.dumps(rows))
    reread=gw.call(ALICE,'case_results',{'task_id':one['task_id']})
    second=gw.call(ALICE,'case_results',{'task_id':two['task_id']})
    assert {k: v for k, v in reread['cases'][0].items() if k != 'result'} == {k: v for k, v in first['cases'][0].items() if k != 'result'}
    assert reread['cases'][0]['result'] == ('FAIL' if fake_env['result_retention'] == 'append' else None)
    assert second['cases'][0]['result'] == 'ERROR'
    for receipt,result in ((one,reread),(two,second)):
        task=gw.state.task(receipt['task_id'])
        assert receipt['task_id'] in Path(task['staging_dir']).parts
        assert Path(task['staging_dir']).name==cid
        assert result['request_id']==receipt['request_id']
        assert result['ownership']=='staging_directory'
        assert receipt['task_id'] in result['report_dir']
        assert 'UNOWNED' not in result['cases'][0]['log']
        assert receipt['task_id'] in str(result['cases'][0]['sessions'])
    old=time.time()-40*86400
    for root in (gw.cfg.staging_parent,gw.cfg.apv_src/'report',gw.cfg.state_dir/'tasks'):
        for path in [root,*root.rglob('*')]: os.utime(path,(old,old),follow_symlinks=False)
    with gw.state._conn() as conn: conn.execute('UPDATE tasks SET created_at=?',(old,))
    protected=prune.run(gw.cfg,30,apply=False)
    assert not protected['tasks'] and not protected['staging']
    # Expired records can now be removed, together with their owned trees.
    with gw.state._conn() as conn: conn.execute('UPDATE requests SET not_after=?,received_at=?',(old,old))
    plan=prune.run(gw.cfg,30,apply=False)
    assert len(plan['staging'])==2 and len(plan['tasks'])==2
    prune.run(gw.cfg,30,apply=True)
    assert not prune.run(gw.cfg,30,apply=False)['tasks']
    assert outside.exists()  # the unrelated local report is never gateway-owned


def test_duplicate_runs_runner_once_even_after_lease_expires(fake_env,tmp_path,monkeypatch):
    from gateway import framework
    from test_gateway import _wait_done
    gw=fake_env['gateway']; values=submission(fake_env,tmp_path)
    launch=framework.launch_run; calls=[]
    def counted(*a,**kw):
        calls.append(1)
        return launch(*a,**kw)
    monkeypatch.setattr(framework,'launch_run',counted)
    first=gw.call(ALICE,'case_submit',values)
    assert first['ok'],first
    _wait_done(gw,ALICE,first['task_id'])
    gw.state.expire_now_for_tests()
    assert gw.call(ALICE,'case_submit',{**values,'token':-1})==first
    assert calls==[1]
    row=gw.call(ALICE,'case_request',{'request_id':values['request_id']})
    assert row['state']=='started' and row['reached_device'] and row['task_id']==first['task_id']


def test_lost_launch_return_is_not_a_refusal(fake_env,tmp_path,monkeypatch):
    from gateway import framework
    from test_gateway import _wait_done
    gw=fake_env['gateway']; values=submission(fake_env,tmp_path)
    launch=framework.launch_run
    def lost(*a,**kw):
        launch(*a,**kw)
        raise OSError('synthetic lost return after spawn')
    monkeypatch.setattr(framework,'launch_run',lost)
    reply=gw.call(ALICE,'case_submit',values)
    assert reply['ok'] and reply['task_id']
    _wait_done(gw,ALICE,reply['task_id'])
    assert gw.call(ALICE,'case_submit',values)==reply


def test_active_starting_is_not_reconciled_to_not_started(fake_env,tmp_path,monkeypatch):
    import threading
    from gateway import framework
    gw=fake_env['gateway']; values=submission(fake_env,tmp_path)
    entered=threading.Event(); release=threading.Event()
    def waiting(*_):
        entered.set()
        assert release.wait(5)
        raise framework.FrameworkError('synthetic stop before launch')
    monkeypatch.setattr(framework,'launch_run',waiting)
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        future=pool.submit(gw.call,ALICE,'case_submit',values)
        try:
            assert entered.wait(5)
            observed=gw.call(ALICE,'case_request',{'request_id':'intent:1'})
            assert observed['state']=='starting' and observed['reached_device'] is None
            assert 'task_id' not in observed and 'next_action' in observed
        finally: release.set()
        assert future.result()['stage']=='launch'



def test_restart_recovers_audit_for_committed_request_transition(fake_env,monkeypatch):
    import json
    from gateway.tools import Gateway
    from gateway.audit_chain import verify
    gw=fake_env['gateway']
    reserve=gw.state.reserve_request
    class Crash(BaseException): pass
    def stop(*a,**kw):
        reserve(*a,**kw)
        raise Crash()
    monkeypatch.setattr(gw.state,'reserve_request',stop)
    with pytest.raises(Crash): gw.call(ALICE,'case_submit',args())
    restarted=Gateway(gw.cfg)
    answer=restarted.call(ALICE,'case_request',{'request_id':'intent:1'})
    assert answer['state']=='not_started' and answer['reached_device'] is False
    events=[json.loads(line) for line in restarted.audit_path.read_text().splitlines()]
    assert [e['state'] for e in events if e.get('event')=='request_state']==['received','not_started']
    assert verify(restarted.audit_path)['ok']



def test_console_setup_failure_after_login_is_not_prelogin(monkeypatch):
    from gateway import console
    class FakeConsole:
        def __init__(self,*_): pass
        def read_until(self,pattern,*_):
            return True, 'Connected.' if 'Connected' in pattern else 'APV#'
        def send(self,text):
            if text=='terminal length 0\n': raise OSError('synthetic terminal setup failure')
        def close(self): pass
    monkeypatch.setattr(console,'Console',FakeConsole)
    outcome=console.init_one(0,console_argv=['fake'],tty='synthetic',hostname='APV',
                             user='fake',passwd='fake',commands=[],long_commands={},step_timeout=1,login_timeout=1)
    assert outcome.reached_device is True



def test_legacy_report_without_delivery_id_is_not_owned(fake_env):
    from gateway import framework
    gw=fake_env['gateway']
    stage=gw.cfg.staging_parent/'ist_staging_sdns'/'202610230000000001'
    report=gw.cfg.apv_src/'report'/'legacy-run'/'sdns'/'ist_staging_sdns'/'202610230000000001'/'test_xlsx'/'case.xlsx'
    report.mkdir(parents=True)
    assert framework.delivery_report_base(gw.cfg,str(stage)) is None


def test_request_protocol_version_is_advertised():
    from ces_version import __version__
    from gateway.service import SERVER_INFO
    assert __version__=='0.4.0' and SERVER_INFO['version']==__version__
