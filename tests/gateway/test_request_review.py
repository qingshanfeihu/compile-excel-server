"""Cross-family regressions using only the synthetic gateway fixtures."""
import json
import time
from datetime import datetime, timezone

from gateway.tools import Caller, Gateway
from test_request_ids import ALICE, args, submission


def test_lookup_echoes_resolved_subject_even_for_hidden_or_absent_records(fake_env):
    gw = fake_env['gateway']
    values = args(not_after='2001-01-01T00:00:00Z')
    gw.call(ALICE, 'case_submit', values)
    bob = Caller('synthetic-other', ALICE.scopes)
    for caller, rid in [(ALICE, values['request_id']), (bob, values['request_id']), (bob, 'missing')]:
        answer = gw.call(caller, 'case_request', {'request_id': rid})
        assert answer['subject'] == caller.subject
    hidden = gw.call(bob, 'case_request', {'request_id': values['request_id']})
    absent = gw.call(bob, 'case_request', {'request_id': 'missing'})
    assert set(hidden) == set(absent)
    assert hidden['found'] is False


def test_journal_identity_and_lower_bound_survive_restart_but_not_reset(fake_env):
    from dataclasses import replace
    from gateway.state import StateStore
    gw = fake_env['gateway']
    answer = gw.call(ALICE, 'case_request', {'request_id': 'missing'})
    assert isinstance(answer['journal_id'], str) and len(answer['journal_id']) >= 32
    assert 0 < answer['journal_since'] <= answer['gateway_time']
    assert answer['gc_before'] >= answer['journal_since']
    reopened = Gateway(gw.cfg).call(ALICE, 'case_request', {'request_id': 'missing'})
    assert (answer['journal_id'], answer['journal_since']) == (reopened['journal_id'], reopened['journal_since'])
    submit = gw.call(ALICE, 'case_submit', args(not_after='2001-01-01T00:00:00Z'))
    assert submit['journal_id'] == answer['journal_id']
    assert submit['journal_since'] == answer['journal_since']
    assert submit['subject'] == ALICE.subject
    before = time.time()
    reset = Gateway(replace(gw.cfg, state_dir=gw.cfg.state_dir / 'reset'))
    fresh = reset.call(ALICE, 'case_request', {'request_id': 'intent:1'})
    assert not fresh['found'] and fresh['journal_id'] != answer['journal_id']
    assert before <= fresh['journal_since'] <= fresh['gateway_time']
    assert StateStore(reset.cfg.state_dir).request_snapshot('missing', ALICE.subject)[2] == fresh['journal_since']


def test_request_clock_floor_survives_rollback_and_restart(fake_env, monkeypatch):
    from gateway import state
    gw = fake_env['gateway']
    deadline = time.time() + 10
    clock = [deadline + 1]
    monkeypatch.setattr(state.time, 'time', lambda: clock[0])
    first = gw.call(ALICE, 'case_request', {'request_id': 'clock-intent'})
    clock[0] = deadline - 5
    restarted = Gateway(gw.cfg)
    launches = []
    monkeypatch.setitem(restarted.handlers, 'case_submit', lambda *_: launches.append(1) or {})
    out = restarted.call(ALICE, 'case_submit', args(request_id='clock-intent', not_after=datetime.fromtimestamp(deadline, timezone.utc).isoformat()))
    assert not out['ok'] and out['stage'] == 'admission' and not launches
    snapshot = restarted.state.request_snapshot('clock-intent', ALICE.subject)
    assert snapshot[1] >= first['gateway_time']
    assert snapshot[0]['received_at'] >= first['gateway_time']


def test_collected_request_cannot_be_recreated_as_a_new_rejection(fake_env):
    gw = fake_env['gateway']
    row, _ = gw.state.reserve_request('collected', ALICE.subject, 'synthetic', time.time() - 1)
    gw.state.update_request('collected', state='started', reached_device=1)
    assert gw.state.gc_requests(time.time() + 1) == 1
    reply = gw.call(ALICE, 'case_submit', args(request_id='collected', not_after=datetime.fromtimestamp(row['not_after'], timezone.utc).isoformat()))
    assert not reply['ok'] and reply['stage'] == 'admission'
    assert reply['request_record'] == 'collected'
    observed = gw.call(ALICE, 'case_request', {'request_id': 'collected'})
    assert not observed['found'] and observed['gc_before'] >= row['not_after']
