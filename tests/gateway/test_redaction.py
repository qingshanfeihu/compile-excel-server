"""回给客户端的文字里不出现网关知道的口令字面值：
光秃秃的口令（不带 password= 前缀）scrub_text 认不出。

口令来源：框架 conf 口令项（夹具 conf 的 passwd = devpass）、结果库口令文件、框架源码凭据字面量。
"""

from __future__ import annotations

import base64

from conftest import CRED_LITERAL, make_workbook

from gateway import framework

from test_gateway import ALICE, _lease, _wait_done

MYSQL_PW = "Mq7resultsdbpw"
SECRETS = ("devpass", CRED_LITERAL, MYSQL_PW)


def _clean(value) -> bool:
    text = repr(value)
    return not any(secret in text for secret in SECRETS)


def _with_mysql_password(gw, tmp_path):
    pw_file = tmp_path / "mysql.pw"
    pw_file.write_text(MYSQL_PW + "\n", encoding="utf-8")
    object.__setattr__(gw.cfg, "mysql_password_file", pw_file)


def test_probe_output_and_probe_errors_are_redacted(fake_env, tmp_path, monkeypatch):
    gw = fake_env["gateway"]
    _with_mysql_password(gw, tmp_path)
    lease = _lease(gw)
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "command": cmd, "output": f"login admin devpass\nkey {CRED_LITERAL}\ndb {MYSQL_PW}\n"})
    out = gw.call(ALICE, "probe_show", {**lease, "command": "show version"})
    assert out["ok"] and "login admin ***" in out["output"] and _clean(out), out
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "error": "AuthenticationException: admin/devpass rejected"})
    failed = gw.call(ALICE, "probe_show", {**lease, "command": "show version"})
    assert failed["ok"] is False and "admin/***" in failed["error"] and _clean(failed), failed
    assert _clean(gw.audit_path.read_text(encoding="utf-8")), "审计原因也不落口令"


def test_run_log_tail_case_logs_and_query_error_are_redacted(fake_env, tmp_path, monkeypatch):
    gw, apv = fake_env["gateway"], fake_env["apv"]
    _with_mysql_password(gw, tmp_path)
    lease = _lease(gw)
    data = make_workbook(tmp_path / "c.xlsx", [
        ("202609260000000081", "APV_1", "cmd", "show version")])
    submitted = gw.call(ALICE, "case_submit",
                        {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert submitted["ok"], submitted
    task_id = submitted["task_id"]
    _wait_done(gw, ALICE, task_id)
    with open(gw.cfg.state_dir / "tasks" / f"{task_id}.log", "a", encoding="utf-8") as log:
        log.write(f"ssh admin@apv with devpass\nresult db {MYSQL_PW}\n")
    for case_log in apv.glob("report/**/202609260000000081.txt"):
        with open(case_log, "a", encoding="utf-8") as stream:
            stream.write(f"login devpass / {CRED_LITERAL}\n")
    status = gw.call(ALICE, "case_status", {"task_id": task_id})
    assert "with ***" in status["log_tail"] and _clean(status), status

    real_query = framework.query_results
    monkeypatch.setattr(framework, "query_results", lambda *a, **k: {
        **real_query(*a, **k), "error": f"(1045) Access denied: {MYSQL_PW}"})
    monkeypatch.setattr(framework, "mysql_password", lambda cfg: MYSQL_PW)
    object.__setattr__(gw.cfg, "mysql_password_file", None)   # 结果库仍借框架 Result_DB
    results = gw.call(ALICE, "case_results", {"task_id": task_id})
    assert results["channel"] == "query_error" and "Access denied: ***" in results["query_error"]
    assert "login *** / ***" in results["cases"][0]["log"] and _clean(results), results


def test_redact_replaces_longest_first_and_walks_nested_values():
    secrets = ("abcdef", "abcd")
    assert framework.redact({"a": ["xabcdefx", ("abcd",)], "n": 3}, secrets) == \
        {"a": ["x***x", ["***"]], "n": 3}


def test_log_tails_start_on_a_whole_line_so_no_half_secret_survives(fake_env):
    cfg = fake_env["gateway"].cfg
    case = "202609260000000082"
    base = fake_env["apv"] / "report" / "r1" / "x" / "ist_staging_sdns" / case / "test_xlsx" / \
        "case.xlsx" / case
    base.mkdir(parents=True)
    tail = "vpass\nsecond line\n"
    (base / f"{case}.txt").write_text("first line\nlogin de" + tail, encoding="utf-8")
    logs = framework.batch_logs(cfg, "sdns", case, 0, max_chars=len(tail))
    assert logs[case]["log"] == "second line\n", "半截的首行（口令的后半截）不回给客户端"


def test_failed_literal_refresh_keeps_last_success_and_retries(fake_env, tmp_path, monkeypatch):
    from gateway.tools import LITERALS_TTL_S
    from test_request_ids import submission
    gw = fake_env['gateway']
    values = submission(fake_env, tmp_path)
    receipt = gw.call(ALICE, 'case_submit', values)
    assert receipt['ok']
    _wait_done(gw, ALICE, receipt['task_id'])
    for log in fake_env['apv'].glob('report/**/*.txt'):
        log.write_text(log.read_text() + f'\nuser add tester {CRED_LITERAL}\n')
    successful = gw._literals
    assert successful and CRED_LITERAL in successful[1]
    gw._literals = (successful[0] - LITERALS_TTL_S - 1, successful[1])
    broken = fake_env['apv'] / 'lib' / 'synthetic_broken.py'
    broken.write_text('def broken(:\n')
    answer = gw.call(ALICE, 'case_results', {'task_id': receipt['task_id']})
    assert answer['ok'] and CRED_LITERAL not in repr(answer)
    assert CRED_LITERAL in gw._literals[1]
    assert gw._literals[0] == successful[0] - LITERALS_TTL_S - 1
    broken.unlink()
    calls = []
    original = gw.credential_literals
    def refreshed():
        calls.append(1)
        return original()
    monkeypatch.setattr(gw, 'credential_literals', refreshed)
    gw.call(ALICE, 'case_results', {'task_id': receipt['task_id']})
    assert calls and gw._literals[0] > successful[0] - LITERALS_TTL_S - 1


def test_device_text_is_withheld_until_a_successful_literal_scan(fake_env, monkeypatch):
    gw = fake_env['gateway']; lease = _lease(gw)
    gw._literals = None
    broken = fake_env['apv'] / 'lib' / 'synthetic_broken.py'
    broken.write_text('def broken(:\n')
    monkeypatch.setattr(framework, 'probe', lambda *_: {'output': f'user add tester {CRED_LITERAL}', 'reached_device': True})
    answer = gw.call(ALICE, 'probe_show', {**lease, 'command': 'show version'})
    assert answer['ok'] is False and answer['stage'] == 'redaction'
    assert answer['reached_device'] is True
    assert CRED_LITERAL not in repr(answer) and 'output' not in answer
    assert gw._literals is None
    assert 'framework' in answer['next_action']
