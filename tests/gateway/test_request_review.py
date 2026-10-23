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
