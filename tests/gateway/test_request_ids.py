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
