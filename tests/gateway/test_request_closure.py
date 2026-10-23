"""Convergence regressions over the fake framework and synthetic state only."""
import json
import shutil
import time
from datetime import datetime, timezone

import pytest

from gateway import framework
from gateway.tools import Gateway
from test_request_ids import ALICE, args, submission


def proof_of_absence(answer, original, frozen):
    deadline = datetime.fromisoformat(original['not_after'].replace('Z', '+00:00')).timestamp()
    return (answer['ok'] and not answer['found'] and answer['journal_id'] == frozen['journal_id']
            and answer['subject'] == frozen['subject']
            and answer['gateway_time'] > deadline > answer['gc_before'] >= answer['journal_since'])


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
    assert not proof_of_absence(query, values, frozen), query
    assert query['found'] and query['state'] == 'started' and query['reached_device'] is True
    assert query['task_id'] == receipt['task_id']
    assert restored.call(ALICE, 'case_submit', values) == receipt
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
    assert replay['ok'] and replay['task_id'] == calls[0]
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
