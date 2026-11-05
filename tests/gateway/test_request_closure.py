"""Convergence regressions over the fake framework and synthetic state only."""
import base64
import hashlib
import json
import shutil
import time
from datetime import datetime, timezone

import pytest

from gateway import framework
from gateway.tools import Gateway
from test_request_ids import ALICE, args, submission


def proof_of_nonexecution(answer, original, frozen):
    # Only an explicit bound no-start record can prove nonexecution; timestamps never can.
    return (answer.get('ok') is True and answer.get('found') is True
            and answer.get('state') == 'not_started' and answer.get('reached_device') is False
            and answer.get('journal_id') == frozen.get('journal_id') and answer.get('subject') == frozen.get('subject')
            and answer.get('request_id') == original['request_id']
            and answer.get('xlsx_sha256') == hashlib.sha256(base64.b64decode(original['xlsx_b64'])).hexdigest())


def test_restoring_old_state_db_cannot_hide_a_started_request(fake_env, tmp_path, monkeypatch):
    from gateway import state
    gw = fake_env['gateway']; values = submission(fake_env, tmp_path)
    deadline = time.time() + 30
    values['not_after'] = datetime.fromtimestamp(deadline, timezone.utc).isoformat()
    frozen = gw.call(ALICE, 'case_request', {'request_id': values['request_id']})
    backup = tmp_path / 'old-state.db'; shutil.copyfile(gw.state.db_path, backup)
    calls = []
    def started(cfg, task_id, *_):
        calls.append(task_id)
        framework.task_paths(cfg, task_id)['start'].write_text('fake runner reached target')
    monkeypatch.setattr(framework, 'launch_run', started)
    receipt = gw.call(ALICE, 'case_submit', values)
    assert receipt['ok'] and calls == [receipt['task_id']]
    assert gw.call(ALICE, 'case_request', {'request_id': values['request_id']})['reached_device'] is True
    shutil.copyfile(backup, gw.state.db_path)
    monkeypatch.setattr(state.time, 'time', lambda: deadline + 1)
    restored = Gateway(gw.cfg)
    query = restored.call(ALICE, 'case_request', {'request_id': values['request_id']})
    assert not proof_of_nonexecution(query, values, frozen), query
    assert query['found'] and query['state'] == 'started' and query['reached_device'] is True
    assert query['task_id'] == receipt['task_id']
    assert restored.call(ALICE, 'case_submit', values)['replayed']
    assert calls == [receipt['task_id']]


def test_interrupted_launch_survives_state_restore(fake_env, tmp_path, monkeypatch):
    gw = fake_env['gateway']; values = submission(fake_env, tmp_path)
    backup = tmp_path / 'old-state.db'; shutil.copyfile(gw.state.db_path, backup)
    calls = []
    class Crash(BaseException):
        pass
    def started(cfg, task_id, *_):
        calls.append(task_id)
        framework.task_paths(cfg, task_id)['start'].write_text('fake start')
        raise Crash()
    monkeypatch.setattr(framework, 'launch_run', started)
    with pytest.raises(Crash):
        gw.call(ALICE, 'case_submit', values)
    shutil.copyfile(backup, gw.state.db_path)
    restored = Gateway(gw.cfg)
    query = restored.call(ALICE, 'case_request', {'request_id': values['request_id']})
    assert query['found'] and query['reached_device'] is True
    assert query['task_id'] == calls[0]
    replay = restored.call(ALICE, 'case_submit', values)
    assert not replay['ok'] and replay['replayed']
    assert restored.state.task(calls[0])['holder'] == ALICE.subject
    assert restored.state.task_request(calls[0]) == values['request_id']
    assert len(calls) == 1


def test_request_journal_loss_or_mismatch_refuses_start(fake_env, tmp_path):
    import sqlite3
    from gateway.state import JournalError
    gw = fake_env['gateway']
    path = gw.state.request_db_path
    backup = tmp_path / 'requests.db'; shutil.copyfile(path, backup)
    path.unlink()
    with pytest.raises(JournalError, match='journal missing'):
        Gateway(gw.cfg)
    shutil.copyfile(backup, path)
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE request_meta SET value='unrelated' WHERE name='storage_id'")
    with pytest.raises(JournalError, match='identity mismatch'):
        Gateway(gw.cfg)


def test_legacy_migration_preserves_rows_and_rotates_proof_epoch(tmp_path):
    import sqlite3
    from gateway.state import StateStore, _SCHEMA
    directory = tmp_path / 'legacy'; directory.mkdir()
    with sqlite3.connect(directory / 'state.db') as conn:
        conn.executescript(_SCHEMA)
        conn.executemany('INSERT INTO request_meta VALUES(?,?)',
                         [('journal_id','old-journal'),('journal_since',1),('clock_floor',2)])
        conn.execute("INSERT INTO requests(request_id,holder,xlsx_sha256,not_after,received_at,state) "
                     "VALUES('old-request','alice','synthetic',10,2,'rejected')")
    before = time.time()
    store = StateStore(directory)
    row, now, floor = store.request_snapshot('old-request', 'alice')
    assert row['state'] == 'rejected'
    identity = store.journal_identity()
    assert identity['journal_id'] != 'old-journal'
    assert before <= identity['journal_since'] <= now
    assert floor >= identity['journal_since']
    assert StateStore(directory).journal_identity() == identity


def test_offline_journal_reset_rotates_identity_but_keeps_rows(fake_env, capsys):
    from gateway.cexg import main
    from gateway.state import JournalError
    gw = fake_env['gateway']
    values = args(not_after='2001-01-01T00:00:00Z')
    original = gw.call(ALICE, 'case_submit', values)
    with gw.state.bed_lock() as idle:
        assert idle
        with pytest.raises(JournalError, match='bed is busy'):
            gw.state.reset_journal_identity('synthetic restore')
    with pytest.raises(JournalError, match='requires an operator reason'):
        gw.state.reset_journal_identity(' ')
    assert main(['journal-reset', '--config', str(fake_env['config']), '--reason', 'synthetic restore']) == 0
    identity = json.loads(capsys.readouterr().out)
    assert identity['ok'] and identity['journal_id'] != original['journal_id']
    query = Gateway(gw.cfg).call(ALICE, 'case_request', {'request_id': values['request_id']})
    assert query['found'] and query['state'] == 'rejected'
    assert query['journal_id'] == identity['journal_id']
    assert query['journal_since'] >= original['journal_since']


@pytest.mark.parametrize('status,channel,reason', [
    ('lost', 'runner_lost', 'not_determined_runner_lost'),
    ('running', 'not_completed', 'not_determined_not_completed'),
])
def test_early_results_disclose_why_ownership_is_not_determined(fake_env, tmp_path, monkeypatch,
                                                              status, channel, reason):
    gw = fake_env['gateway']; values = submission(fake_env, tmp_path)
    monkeypatch.setattr(framework, 'launch_run', lambda *_: None)
    receipt = gw.call(ALICE, 'case_submit', values)
    assert receipt['ok']
    monkeypatch.setattr(framework, 'read_status', lambda *_: {'state': status})
    answer = gw.call(ALICE, 'case_results', {'task_id': receipt['task_id']})
    assert answer['channel'] == channel and answer['ownership'] == 'none'
    assert answer['ownership_reason'] == reason
    assert answer['next_action']


@pytest.mark.parametrize('rotate_epoch', [False, True])
def test_collected_id_cannot_launch_again_with_a_future_deadline(fake_env, tmp_path, monkeypatch, rotate_epoch):
    from gateway import state
    gw = fake_env['gateway']; values = submission(fake_env, tmp_path)
    start = time.time()
    values['not_after'] = datetime.fromtimestamp(start + 5, timezone.utc).isoformat()
    calls = []
    def launched(cfg, task_id, *_):
        calls.append(task_id)
        framework.task_paths(cfg, task_id)['start'].write_text('fake start')
    monkeypatch.setattr(framework, 'launch_run', launched)
    first = gw.call(ALICE, 'case_submit', values)
    assert first['ok'] and len(calls) == 1
    monkeypatch.setattr(state.time, 'time', lambda: start + 10)
    assert gw.state.gc_requests(values['dispatch_sequence'],ALICE.subject,values['sequence_scope']) == 1
    if rotate_epoch:
        gw.state.reset_journal_identity('synthetic complete backup restore')
    restored = Gateway(gw.cfg)
    absent = restored.call(ALICE, 'case_request', {'request_id': values['request_id']})
    assert absent['ok'] and absent['found'] is False
    assert restored.state.sequence_floor(ALICE.subject,values['sequence_scope']) == values['dispatch_sequence']
    assert not proof_of_nonexecution(absent, values, first)
    future = {**values, 'not_after': datetime.fromtimestamp(start + 100, timezone.utc).isoformat()}
    refused = restored.call(ALICE, 'case_submit', future)
    assert refused['ok'] is False and refused['stage'] == 'collected'
    assert refused['request_record'] == 'collected' and refused['reached_device'] is None
    assert len(calls) == 1
    assert restored.call(ALICE, 'case_request', {'request_id': values['request_id']})['found'] is False
    # Collection bars this ID, rather than all new dispatches with the same bytes.
    fresh = restored.call(ALICE, 'case_submit', {**future, 'request_id': 'intent:fresh', 'dispatch_sequence': future['dispatch_sequence']+1})
    assert fresh['ok'] and fresh['task_id'] != first['task_id'] and len(calls) == 2
