"""Bench preparation contracts using synthetic keys, framework and results only."""
from datetime import datetime
import json

import pytest

from conftest import RUN_TOKEN, ADMIN_TOKEN, write_secret_digest
from gateway.auth import RUN_SCOPES, AuthError, StaticSecretAuth
from gateway.config import load
from gateway.tools import Gateway
from gateway import framework
from test_gateway_auth import _http
from test_request_ids import ALICE, submission


def rotating_gateway(fake_env, tmp_path):
    previous = tmp_path / 'previous.sha256'
    config = tmp_path / 'rotating.toml'
    config.write_text(fake_env['config'].read_text().replace(
        '[hub]\n', f'[hub]\nprevious_secret_sha256_file = "{previous}"\n'))
    cfg = load(config)
    assert cfg.hub_previous_secret_file == previous
    return Gateway(cfg), previous


def test_overlap_survives_current_swap_and_explicit_previous_removal(fake_env, tmp_path, capsys):
    gw, previous = rotating_gateway(fake_env, tmp_path)
    httpd, post = _http(gw)
    listing = {'jsonrpc':'2.0','id':1,'method':'tools/list'}
    new = 'synthetic-next-run-key'
    try:
        assert post(listing, RUN_TOKEN)[0] == 200
        write_secret_digest(previous, RUN_TOKEN)
        write_secret_digest(fake_env['secret_file'], new)
        for token in (new, RUN_TOKEN):
            status, body = post(listing, token, 'synthetic-user/job')
            assert status == 200
            assert 'init_device' not in {t['name'] for t in body['result']['tools']}
            assert gw.auth.caller(token, 'synthetic-user/job').subject == 'circle-hub/synthetic-user/job'
            assert gw.auth.caller(token).scopes == RUN_SCOPES
        assert post(listing, 'synthetic-wrong-a')[0] == 401
        assert post(listing, 'synthetic-wrong-b')[0] == 401
        previous.unlink()
        assert post(listing, RUN_TOKEN)[0] == 401
        assert post(listing, new)[0] == 200
        capture = capsys.readouterr()
        logs = capture.out + capture.err
        if gw.audit_path.exists(): logs += gw.audit_path.read_text()
        for token in (new, RUN_TOKEN, ADMIN_TOKEN): assert token not in logs
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_both_run_candidates_are_compared_even_on_current_match(fake_env, tmp_path, monkeypatch):
    from gateway import auth
    gw, previous = rotating_gateway(fake_env, tmp_path)
    write_secret_digest(previous, 'synthetic-previous')
    original = auth.hmac.compare_digest
    calls = []
    def compare(a, b):
        calls.append((len(a),len(b)))
        return original(a,b)
    monkeypatch.setattr(auth.hmac, 'compare_digest', compare)
    for token in (RUN_TOKEN, 'synthetic-previous', 'synthetic-wrong'):
        calls.clear()
        gw.auth.caller(token)
        assert calls == [(64,64)] * 3


def test_bad_previous_is_configuration_error_but_removal_revokes_without_restart(fake_env, tmp_path):
    gw, previous = rotating_gateway(fake_env, tmp_path)
    write_secret_digest(previous, 'synthetic-previous')
    previous.chmod(0o644)
    with pytest.raises(AuthError): gw.auth.caller(RUN_TOKEN)
    previous.chmod(0o600)
    previous.write_text('not-a-digest\n')
    with pytest.raises(AuthError): gw.auth.caller(RUN_TOKEN)
    previous.unlink()
    assert gw.auth.caller('synthetic-previous') is None
    assert gw.auth.caller(RUN_TOKEN).scopes == RUN_SCOPES


@pytest.fixture
def result_task(fake_env, tmp_path, monkeypatch):
    gw = fake_env['gateway']
    values = submission(fake_env, tmp_path)
    monkeypatch.setattr(framework, 'launch_run', lambda cfg, task_id, *_:
                        framework.task_paths(cfg, task_id)['start'].write_text('synthetic start'))
    receipt = gw.call(ALICE, 'case_submit', values)
    assert receipt['ok']
    task = gw.state.task(receipt['task_id'])
    return gw, receipt, task


@pytest.mark.parametrize('state', ['running','lost','done'])
def test_result_identity_complete_and_original_submission_time_in_every_channel(result_task, monkeypatch, tmp_path, state):
    gw, receipt, task = result_task
    base = gw.cfg.apv_src/'report'/'synthetic-run'/'synthetic-module'
    base.mkdir(parents=True)
    cid = task['case_ids'][0]
    monkeypatch.setattr(framework,'read_status',lambda *_:{'state':state,'rc':1})
    monkeypatch.setattr(framework,'delivery_report_lookup',lambda *_:{'base':base,'reason':None})
    monkeypatch.setattr(framework,'query_results',lambda *a,**kw:{'results':{cid:'FAIL'}})
    monkeypatch.setattr(framework,'delivery_logs',lambda *_:{cid:{'stale':False,'log':'synthetic end case: '+cid}})
    monkeypatch.setattr(framework,'case_sessions',lambda *_:{})
    answer = gw.call(ALICE,'case_results',{'task_id':receipt['task_id']})
    assert answer['ok'] is True
    assert type(answer['complete']) is bool
    assert answer['complete'] is (state=='done'), 'a completed FAIL still has complete evidence'
    assert answer['task_id']==receipt['task_id'] and answer['request_id']==receipt['request_id']
    assert answer['xlsx_sha256']==receipt['sha256']
    stamp = datetime.fromisoformat(answer['submitted_at'].replace('Z','+00:00'))
    assert stamp.utcoffset().total_seconds()==0
    assert abs(stamp.timestamp()-task['deliver_epoch']) < 0.000002
    assert gw.call(ALICE,'case_results',{'task_id':receipt['task_id']})['submitted_at']==answer['submitted_at']


@pytest.mark.parametrize('gap',['missing_row','query_error','missing_report','missing_log','stale_log','unknown_verdict'])
def test_successful_result_read_does_not_claim_complete_when_evidence_is_missing(result_task, monkeypatch, gap):
    gw, receipt, task = result_task
    base = gw.cfg.apv_src/'report'/'synthetic-run'/'synthetic-module'
    base.mkdir(parents=True)
    cid = task['case_ids'][0]
    monkeypatch.setattr(framework,'read_status',lambda *_:{'state':'done','rc':0})
    monkeypatch.setattr(framework,'delivery_report_lookup',lambda *_:{'base':None if gap=='missing_report' else base,'reason':'missing' if gap=='missing_report' else None})
    queried = {'results':{} if gap=='missing_row' else {cid:'UNRECOGNIZED' if gap=='unknown_verdict' else 'PASS'}}
    if gap=='query_error': queried['error']='synthetic database failure'
    monkeypatch.setattr(framework,'query_results',lambda *a,**kw:queried)
    monkeypatch.setattr(framework,'delivery_logs',lambda *_:{} if gap=='missing_log' else {cid:{'stale':gap=='stale_log','log':'synthetic end case: '+cid}})
    monkeypatch.setattr(framework,'case_sessions',lambda *_:{})
    answer = gw.call(ALICE,'case_results',{'task_id':receipt['task_id']})
    assert answer['ok'] is True, answer
    assert answer['complete'] is False, 'RPC success is not result completeness'
    assert isinstance(answer['submitted_at'],str)


@pytest.mark.parametrize('verdict',['PASS','FAIL'])
def test_fake_runner_results_expose_hub_fields_without_turning_failure_into_incompleteness(fake_env, tmp_path, verdict):
    from test_gateway import _wait_done
    gw = fake_env['gateway']
    values = submission(fake_env, tmp_path)
    cid = '202610230000000001'
    (fake_env['apv']/'fake_verdicts.json').write_text(json.dumps({cid:verdict}))
    receipt = gw.call(ALICE,'case_submit',values)
    assert receipt['ok']
    _wait_done(gw, ALICE, receipt['task_id'])
    answer = gw.call(ALICE,'case_results',{'task_id':receipt['task_id']})
    assert answer['complete'] is True, answer
    assert answer['cases'][0]['result']==verdict
    assert answer['ownership']=='staging_directory' and answer['ownership_reason'] is None
    assert datetime.fromisoformat(answer['submitted_at']).timestamp() >= receipt['deliver_epoch']
    assert answer['xlsx_sha256']==receipt['sha256']


def test_receipt_recovery_and_result_share_microsecond_submission_time(result_task, monkeypatch):
    from decimal import Decimal
    from datetime import timezone
    gw, receipt, task = result_task
    recovered = gw._task_receipt(task)
    monkeypatch.setattr(framework, 'read_status', lambda *_: {'state':'running'})
    result = gw.call(ALICE,'case_results',{'task_id':task['task_id']})
    assert isinstance(receipt['deliver_epoch'],float)
    assert Decimal(str(receipt['deliver_epoch'])).as_tuple().exponent >= -6
    assert recovered['deliver_epoch'] == receipt['deliver_epoch']
    stamp = datetime.fromisoformat(result['submitted_at'])
    epoch = datetime(1970,1,1,tzinfo=timezone.utc)
    delta = stamp-epoch
    iso_us = (delta.days*86400+delta.seconds)*1_000_000+delta.microseconds
    assert Decimal(str(receipt['deliver_epoch']))*1_000_000 == iso_us
    assert receipt['deliver_epoch'] == round(task['deliver_epoch'],6)
