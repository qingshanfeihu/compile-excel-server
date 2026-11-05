"""CLI journal diagnostics over the fake framework and private synthetic state."""
import json
import sqlite3

import pytest

from gateway import cexg, service


@pytest.mark.parametrize('command', ['check', 'serve', 'gc'])
@pytest.mark.parametrize('fault', ['missing', 'mismatch'])
def test_cli_reports_journal_refusal_without_traceback(fake_env, capsys, monkeypatch, command, fault):
    store = fake_env['gateway'].state
    journal = store.request_db_path
    if fault == 'missing':
        journal.unlink()
        expected = 'independent request journal missing'
    else:
        with sqlite3.connect(journal) as conn:
            conn.execute("UPDATE request_meta SET value='synthetic-other-storage' WHERE name='storage_id'")
        expected = 'independent request journal identity mismatch'
    sentinel = store.dir / 'synthetic-keep'
    sentinel.write_text('keep synthetic state')
    monkeypatch.setattr(service, 'build_server', lambda *_: pytest.fail('must refuse before binding a listener'))
    argv = [command, '--config', str(fake_env['config'])]
    if command == 'gc':
        argv.append('--apply')
    assert cexg.main(argv) == 2
    captured = capsys.readouterr()
    if command == 'serve':
        assert captured.out == ''
        assert captured.err.startswith('请求日志错误：')
        assert expected in captured.err
    else:
        answer = json.loads(captured.out)
        assert answer['ok'] is False and expected in answer['error']
        assert captured.err == ''
        if command == 'check':
            check = next(row for row in answer['checks'] if row['check'] == 'request_journal')
            assert check['ok'] is False and check['path'] == str(journal)
    assert 'Traceback' not in captured.out + captured.err
    assert sentinel.read_text() == 'keep synthetic state'


def test_check_includes_the_authoritative_request_journal(fake_env, capsys):
    assert cexg.main(['check', '--config', str(fake_env['config'])]) == 0
    captured = capsys.readouterr()
    answer = json.loads(captured.out)
    assert answer['ok'] is True
    check = next(row for row in answer['checks'] if row['check'] == 'request_journal')
    assert check == {'check': 'request_journal', 'ok': True,
                     'path': str(fake_env['gateway'].state.request_db_path)}
