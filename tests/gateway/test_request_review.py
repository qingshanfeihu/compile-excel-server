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
    row, _ = gw.state.reserve_request('collected', ALICE.subject, 'synthetic', float(int(time.time()) - 1))
    gw.state.update_request('collected', state='started', reached_device=1)
    assert gw.state.gc_requests(time.time() + 1) == 1
    reply = gw.call(ALICE, 'case_submit', args(request_id='collected', not_after=datetime.fromtimestamp(row['not_after'], timezone.utc).isoformat()))
    assert not reply['ok'] and reply['stage'] == 'admission'
    assert reply['request_record'] == 'collected'
    observed = gw.call(ALICE, 'case_request', {'request_id': 'collected'})
    assert not observed['found'] and observed['gc_before'] >= row['not_after']


def test_busy_request_stripe_still_reports_positive_runner_marker(fake_env, tmp_path, monkeypatch):
    from gateway import framework
    gw = fake_env['gateway']
    values = submission(fake_env, tmp_path)
    monkeypatch.setattr(framework, 'launch_run', lambda *_: None)
    receipt = gw.call(ALICE, 'case_submit', values)
    assert receipt['ok']
    with gw.state.request_lock(values['request_id']):
        pending = gw.call(ALICE, 'case_request', {'request_id': values['request_id']})
        assert pending['state'] == 'starting' and pending['reached_device'] is None
        framework.task_paths(gw.cfg, receipt['task_id'])['start'].write_text('started')
        started = gw.call(ALICE, 'case_request', {'request_id': values['request_id']})
        assert started['state'] == 'started' and started['reached_device'] is True
        assert started['task_id'] == receipt['task_id']


import pytest

ADMIN = Caller('synthetic-admin', frozenset({'jumphost:run', 'jumphost:admin'}))

@pytest.mark.parametrize('tool', ['probe_show', 'bed_topology', 'init_device'])
def test_device_tool_busy_refusals_have_busy_stage(fake_env, tool):
    gw = fake_env['gateway']
    lease = gw.call(ADMIN, 'lease_acquire', {})
    values = {**lease, 'command': 'show version', 'refresh': True, 'step': 'confirm'}
    if tool == 'init_device':
        values['confirmation'] = gw.call(ADMIN, tool, {**lease, 'step': 'prepare'})['confirmation']
    with gw.state.bed_lock() as locked:
        assert locked
        out = gw.call(ADMIN, tool, values)
    assert not out['ok'] and out['stage'] == 'bed_busy' and out['reached_device'] is False

@pytest.mark.parametrize('tool,values', [
    ('env_prepare', {'device_build': 'OTHER_SYNTHETIC_BUILD'}),
    ('case_submit', {'module': '../invalid', 'xlsx_b64': 'eA=='}),
    ('init_device', {'step': 'prepare', 'device_count': 0}),
    ('init_device', {'step': 'confirm', 'confirmation': ''}),
])
def test_bad_device_parameters_are_rejected_at_admission_before_lease(fake_env, tool, values):
    out = fake_env['gateway'].call(ADMIN, tool, values)
    assert not out['ok'] and out['stage'] == 'admission' and out['reached_device'] is False


def test_probe_setup_failure_is_probe_before_contact(fake_env, monkeypatch):
    from gateway import framework
    gw = fake_env['gateway']; lease = gw.call(ALICE, 'lease_acquire', {})
    def fail(*_): raise framework.FrameworkError('synthetic probe setup failure')
    monkeypatch.setattr(framework, 'probe', fail)
    out = gw.call(ALICE, 'probe_show', {**lease, 'command': 'show version'})
    assert not out['ok'] and out['stage'] == 'probe' and out['reached_device'] is False


def test_constructing_a_checker_does_not_flush_or_break_service_audit(fake_env):
    from gateway.audit_chain import verify
    gw = fake_env['gateway']
    gw.audit('synthetic_before')
    gw.state.reserve_request('audit-intent', ALICE.subject, 'synthetic', time.time() + 60)
    before = gw.audit_path.read_bytes()
    Gateway(gw.cfg)  # The same constructor used by cexg check.
    assert gw.audit_path.read_bytes() == before
    gw.flush_request_audit()
    gw.audit('synthetic_after')
    assert verify(gw.audit_path)['ok']
    records = [json.loads(line) for line in gw.audit_path.read_text().splitlines()]
    assert any(r.get('request_id') == 'audit-intent' for r in records)


@pytest.mark.parametrize('values', [args(not_after='2001-01-01T00:00:00Z'), args(xlsx_b64='!')])
def test_admission_rejection_is_atomic_with_request_reservation(fake_env, monkeypatch, values):
    gw = fake_env['gateway']; reserve = gw.state.reserve_request
    class Crash(BaseException): pass
    def stopped(*a, **kw):
        reserve(*a, **kw)
        raise Crash()
    monkeypatch.setattr(gw.state, 'reserve_request', stopped)
    with pytest.raises(Crash): gw.call(ALICE, 'case_submit', values)
    restarted = Gateway(gw.cfg)
    query = restarted.call(ALICE, 'case_request', {'request_id': values['request_id']})
    duplicate = restarted.call(ALICE, 'case_submit', values)
    assert query['state'] == 'rejected' and query['stage'] == 'admission'
    assert duplicate['stage'] == query['stage'] and duplicate['reached_device'] is False


def test_interruption_retains_phase_and_query_agrees_with_duplicate(fake_env, tmp_path, monkeypatch):
    from gateway import gates
    gw = fake_env['gateway']; values = submission(fake_env, tmp_path)
    class Crash(BaseException): pass
    def stopped(*_): raise Crash()
    monkeypatch.setattr(gates, 'freeze', stopped)
    with pytest.raises(Crash): gw.call(ALICE, 'case_submit', values)
    assert gw.state.request_snapshot(values['request_id'], ALICE.subject)[0]['stage'] == 'precheck'
    restarted = Gateway(gw.cfg)
    query = restarted.call(ALICE, 'case_request', {'request_id': values['request_id']})
    duplicate = restarted.call(ALICE, 'case_submit', values)
    assert query['state'] == duplicate['state'] == 'not_started'
    assert query['stage'] == duplicate['stage'] == 'interrupted'
    assert duplicate['interrupted_stage'] == 'precheck'
    assert duplicate['ok'] and duplicate['reached_device'] is False


def test_duplicate_request_binds_the_resolved_module(fake_env, monkeypatch):
    gw = fake_env['gateway']; calls = []
    monkeypatch.setitem(gw.handlers, 'case_submit', lambda *_: calls.append(1) or {'task_id': 'synthetic'})
    values = args(module='synthetic_alpha')
    first = gw.call(ALICE, 'case_submit', values)
    changed = gw.call(ALICE, 'case_submit', {**values, 'module': 'synthetic_beta'})
    assert not changed['ok'] and changed['stage'] == 'admission' and changed['reached_device'] is False
    assert 'conflicts' in changed['error'] and calls == [1]
    assert gw.call(ALICE, 'case_submit', values) == first
    assert gw.state.request_snapshot(values['request_id'], ALICE.subject)[0]['module'] == 'synthetic_alpha'


def test_topology_keeps_other_devices_when_one_probe_fails(fake_env, monkeypatch):
    from gateway import bed, framework
    from test_bed_topology import SHOW_IP
    gw = fake_env['gateway']; lease = gw.call(ALICE, 'lease_acquire', {})
    seen = []
    monkeypatch.setattr(bed, '_local', lambda *_: '')
    monkeypatch.setattr(framework, 'bed_hosts', lambda *_: {})
    monkeypatch.setattr(framework, 'device_reachable', lambda *_: True)
    def probe(_cfg, _command, _build, index):
        seen.append(index)
        return {'error': 'synthetic login refusal', 'reached_device': True} if index == 0 else {'output': SHOW_IP, 'reached_device': True}
    monkeypatch.setattr(framework, 'probe', probe)
    answer = gw.call(ALICE, 'bed_topology', {**lease, 'refresh': True})
    assert answer['ok'] and seen == [0, 1]
    assert answer['observation']['unprobed_devices']
    assert (gw.cfg.state_dir / 'bed_topology.json').is_file()


@pytest.mark.parametrize('shape', ['legacy_layout', 'no_report', 'ambiguous_reports'])
def test_missing_report_ownership_has_a_concrete_reason_and_useful_exit(fake_env, shape):
    from gateway import framework
    gw = fake_env['gateway']; task_id = 'cex_' + 'b' * 32
    relative = ('ist_staging_synthetic/case' if shape == 'legacy_layout' else task_id + '/ist_staging_synthetic/case')
    stage = gw.cfg.staging_parent / relative
    stage.mkdir(parents=True)
    gw.state.record_task(task_id=task_id, lease_id='synthetic', token=1, holder=ALICE.subject,
                         module='synthetic', autoid='case', build=gw.cfg.build, case_ids=['case'],
                         xlsx_sha256='b' * 64, staging_dir=str(stage), deliver_epoch=time.time(), created_at=time.time())
    paths = framework.task_paths(gw.cfg, task_id)
    paths['status'].parent.mkdir(parents=True, exist_ok=True)
    paths['status'].write_text(json.dumps({'state': 'done', 'rc': 0}))
    for run in (['one', 'two'] if shape == 'ambiguous_reports' else ['legacy'] if shape == 'legacy_layout' else []):
        (gw.cfg.apv_src / 'report' / run / 'synthetic' / relative / 'test_xlsx' / 'case.xlsx').mkdir(parents=True)
    answer = gw.call(ALICE, 'case_results', {'task_id': task_id})
    assert answer['ok'] and answer['ownership'] == 'none'
    assert answer['ownership_reason'] == shape
    assert answer['cases'][0]['result'] is None
    assert 'Read case_results again' not in answer['next_action']
    assert 'inspect' in answer['next_action'].lower()


@pytest.mark.parametrize('delivery', [False, True])
def test_gc_never_removes_the_staging_or_report_root(fake_env, delivery):
    from gateway import prune
    from test_gc import _age
    gw = fake_env['gateway']; task = 'cex_' + 'd' * 32
    stage_rel = (task + '/' if delivery else '') + 'ist_staging_synthetic/case'
    report_rel = 'old-run/synthetic/' + (task + '/' if delivery else '') + 'ist_staging_synthetic'
    stage = gw.cfg.staging_parent / stage_rel
    report_root = gw.cfg.apv_src / 'report'
    report = report_root / report_rel
    stage.mkdir(parents=True); report.mkdir(parents=True)
    # Legacy reports are owned only when the matching legacy staging parent exists.
    if not delivery: assert stage.parent.exists()
    _age(gw.cfg.staging_parent); _age(report_root)
    plan = prune.run(gw.cfg, 30, apply=True)
    assert plan['staging'] and plan['reports']
    assert not stage.exists() and not report.exists()
    assert gw.cfg.staging_parent.is_dir() and report_root.is_dir()


@pytest.mark.parametrize('transport', ['no_json', 'timeout'])
def test_login_marker_preserves_contact_when_agent_reply_is_lost(fake_env, monkeypatch, transport):
    from pathlib import Path
    from types import SimpleNamespace
    from gateway import framework
    markers = []
    def lost(_argv, **kw):
        request = json.loads(kw['input'])
        marker = Path(request['login_marker']); markers.append(marker)
        marker.write_text('logged in')
        if transport == 'timeout': raise framework.subprocess.TimeoutExpired('synthetic agent', 90)
        return SimpleNamespace(stdout='synthetic lost JSON', stderr='')
    monkeypatch.setattr(framework.subprocess, 'run', lost)
    out = framework.probe(fake_env['gateway'].cfg, 'show version', 'SYNTHETIC_BUILD', 0)
    assert out['reached_device'] is True and 'error' in out
    assert markers and all(not path.exists() for path in markers)


@pytest.mark.parametrize('connected', [False, True])
def test_agent_login_marker_is_written_only_after_connect(tmp_path, monkeypatch, connected):
    import sys
    from types import SimpleNamespace
    from gateway.agent.jumphost_agent import op_probe
    marker = tmp_path / 'login.marker'
    class SSH:
        def set_missing_host_key_policy(self, *_): pass
        def connect(self, **_):
            assert not marker.exists()
            if not connected: raise OSError('synthetic connect refusal')
        def invoke_shell(self): raise OSError('synthetic shell failure')
        def close(self): pass
    monkeypatch.setitem(sys.modules, 'paramiko', SimpleNamespace(SSHClient=SSH, AutoAddPolicy=lambda: None))
    out = op_probe({'ip': '192.0.2.1', 'user': 'fake', 'passwd': 'fake', 'command': 'show version', 'login_marker': str(marker)})
    assert marker.exists() is connected and out['reached_device'] is connected


@pytest.mark.parametrize('tool', ['env_prepare', 'bed_topology', 'init_device'])
def test_device_setup_failures_keep_truthful_contact_fields(fake_env, monkeypatch, tool):
    from gateway import framework
    gw = fake_env['gateway']; lease = gw.call(ADMIN, 'lease_acquire', {})
    values = {**lease, 'refresh': True, 'step': 'confirm'}
    if tool == 'init_device':
        values['confirmation'] = gw.call(ADMIN, tool, {**lease, 'step': 'prepare'})['confirmation']
    def fail(*_): raise framework.FrameworkError('synthetic setup failure')
    monkeypatch.setattr(framework, 'read_conf', fail)
    out = gw.call(ADMIN, tool, values)
    assert out['reached_device'] is False
    if tool == 'env_prepare':
        assert out['ok'] and not out['ready'] and out['stage'] == 'precheck'
    else:
        assert not out['ok'] and out['stage'] == ('probe' if tool == 'bed_topology' else 'initialization')


def test_tool_advertisements_explain_the_request_protocol_and_ownership():
    from gateway.tools import TOOL_SPECS
    specs = {spec['name']: spec for spec in TOOL_SPECS}
    submit = specs['case_submit']
    for word in ['request_id', 'not_after', 'UTC', 'request_record', 'stage', 'reached_device', 'module', 'journal_id']:
        assert word in submit['description']
    deadline = submit['input_schema']['properties']['not_after']
    assert deadline['format'] == 'date-time' and 'UTC' in deadline['description']
    for word in ['found', 'gateway_time', 'gc_before', 'journal_id', 'journal_since', 'subject']:
        assert word in specs['case_request']['description']
    results = specs['case_results']['description']
    assert 'request_id' in results and 'ownership' in results and 'ownership_reason' in results
    assert 'marked stale' not in results
