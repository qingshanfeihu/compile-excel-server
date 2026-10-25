"""Synthetic protocol and monotonic lease regressions; no device operation."""
import time
import pytest
from gateway.state import StateStore, LeaseError, JournalError
from test_request_ids import ALICE, args


@pytest.mark.parametrize('offset', [-7*3600, 7*3600])
def test_remote_wall_clock_skew_never_rejects_admission(fake_env, monkeypatch, offset):
    from gateway import state
    gw=fake_env['gateway']; invoked=[]
    values=args(not_after='2001-01-01T00:00:00Z')
    now=time.time()
    monkeypatch.setattr(state.time,'time',lambda:now+offset)
    monkeypatch.setitem(gw.handlers,'case_submit',lambda *_:invoked.append(1) or {})
    reply=gw.call(ALICE,'case_submit',values)
    assert reply['ok'] and reply['not_after_ignored'] is True and invoked==[1]
    assert not gw.call(ALICE,'case_submit',values)['ok'] and invoked==[1]


def test_no_absolute_deadline_is_required(fake_env, monkeypatch):
    gw=fake_env['gateway']; values=args(); values.pop('not_after')
    monkeypatch.setitem(gw.handlers,'case_submit',lambda *_:{})
    assert gw.call(ALICE,'case_submit',values)['ok']
    malformed={**values};malformed.pop('request_id')
    assert not gw.call(ALICE,'case_submit',malformed)['ok'], 'sequence fields cannot silently fall back to untracked legacy execution'


def test_sequence_floor_survives_restart_and_rejects_retired_numbers(tmp_path):
    store=StateStore(tmp_path/'state')
    store.reserve_request('old','synthetic','a'*64,dispatch_sequence=5,sequence_scope='executor')
    with pytest.raises(JournalError,match='pending'):
        store.gc_requests(5,'synthetic','executor')
    store.update_request('old',state='rejected')
    assert store.gc_requests(5,'synthetic','executor')==1
    store=StateStore(tmp_path/'state')
    assert store.sequence_floor('synthetic','executor')==5
    for seq in [1,5]:
        row,fresh=store.reserve_request('new'+str(seq),'synthetic','a'*64,dispatch_sequence=seq,sequence_scope='executor')
        assert row['collected'] and not fresh
    assert store.reserve_request('new6','synthetic','a'*64,dispatch_sequence=6,sequence_scope='executor')[1]
    assert store.reserve_request('other','synthetic','a'*64,dispatch_sequence=1,sequence_scope='other-executor')[1]


def test_lease_expires_only_on_local_monotonic_clock(tmp_path,monkeypatch):
    from gateway import state
    wall=[100000.0]; mono=[100.0]
    monkeypatch.setattr(state.time,'time',lambda:wall[0])
    monkeypatch.setattr(state.time,'monotonic',lambda:mono[0])
    store=StateStore(tmp_path/'state',lease_ttl_s=30)
    lease=store.acquire('synthetic')
    for skew in [-7*3600,7*3600]:
        wall[0]=100000+skew
        assert store.check('synthetic',lease['lease_id'],lease['token'])['expires_in_s']==30
    store=StateStore(tmp_path/'state',lease_ttl_s=30)
    mono[0]=129
    assert store.check('synthetic',lease['lease_id'],lease['token'])['expires_in_s']==1
    mono[0]=130
    with pytest.raises(LeaseError,match='no active lease'):
        store.check('synthetic',lease['lease_id'],lease['token'])
    new=store.acquire('synthetic')
    assert new['token']>lease['token']
    store.clock_epoch='synthetic-different-boot'
    with pytest.raises(LeaseError):store.check('synthetic',new['lease_id'],new['token'])


def test_sequence_collection_cli_and_read_receipt_use_the_same_persisted_floor(fake_env,capsys):
    import json
    from gateway.cexg import main
    gw=fake_env['gateway']; scope='synthetic-executor'
    gw.state.reserve_request('gc-synthetic',ALICE.subject,'a'*64,dispatch_sequence=3,sequence_scope=scope)
    gw.state.update_request('gc-synthetic',state='rejected')
    assert main(['journal-gc','--config',str(fake_env['config']),'--holder',ALICE.subject,'--sequence-scope',scope,'--through-sequence','3','--apply'])==0
    receipt=json.loads(capsys.readouterr().out)
    assert receipt['requests']==1 and receipt['through_sequence']==3 and receipt['applied']
    observed=gw.call(ALICE,'case_request',{'request_id':'gc-synthetic','sequence_scope':scope})
    assert not observed['found'] and observed['sequence_floor']==3
