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
