"""网关：租约与床锁、上机前闸、提交→状态→结果全流程、只读探测、两步确认的设备初始化、HTTP 层。

框架用假目录（真 pytest 跑假 test_xlsx，假 Result_DB），串口用假 cu；不碰真跳板机和设备。
"""

from __future__ import annotations

import base64
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from conftest import BUILD, CRED_LITERAL, GRAMMAR, make_workbook

from gateway import framework, gates
from gateway.config import ConfigError, load
from gateway.state import LeaseError, StateStore
from gateway.tools import Caller

ALICE = Caller("alice", frozenset({"jumphost:run"}))
BOB = Caller("bob", frozenset({"jumphost:run"}))
ROOT = Caller("root", frozenset({"jumphost:run", "jumphost:admin"}))


def _lease(gw, caller=ALICE):
    out = gw.call(caller, "lease_acquire", {})
    assert out["ok"], out
    return {"lease_id": out["lease_id"], "token": out["token"]}


def _wait_done(gw, caller, task_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = gw.call(caller, "case_status", {"task_id": task_id})
        if status.get("state") == "done":
            return status
        time.sleep(0.3)
    raise AssertionError(f"run did not finish: {status}")


# ── 配置 ──────────────────────────────────────────────────────────────
def test_config_refuses_non_loopback_without_tls_and_requires_conf_name(fake_env, tmp_path):
    text = fake_env["config"].read_text(encoding="utf-8")
    (tmp_path / "a.toml").write_text(text + "\n[listen]\nhost = \"0.0.0.0\"\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="TLS"):
        load(tmp_path / "a.toml")
    (tmp_path / "b.toml").write_text(text.replace('conf_name = "bed"', 'conf_name = ""'),
                                     encoding="utf-8")
    with pytest.raises(ConfigError, match="conf_name"):
        load(tmp_path / "b.toml")


# ── 租约与床锁 ────────────────────────────────────────────────────────
def test_lease_is_exclusive_renewable_and_fenced(tmp_path):
    store = StateStore(tmp_path / "s", lease_ttl_s=600)
    first = store.acquire("alice")
    with pytest.raises(LeaseError, match="leased by alice"):
        store.acquire("bob")
    again = store.acquire("alice")
    assert again["renewed"] and again["token"] == first["token"]
    store.check("alice", first["lease_id"], first["token"])
    with pytest.raises(LeaseError):
        store.check("bob", first["lease_id"], first["token"])
    store.expire_now_for_tests()
    bob = store.acquire("bob")
    assert bob["token"] > first["token"]
    with pytest.raises(LeaseError):
        store.check("alice", first["lease_id"], first["token"])
    store.release("bob", bob["lease_id"], bob["token"])
    assert store.status()["leased"] is False


def test_bed_lock_follows_the_process_that_holds_it(tmp_path):
    store = StateStore(tmp_path / "s")
    fd = store.try_bed_lock()
    assert fd is not None and store.bed_busy()
    child = subprocess.Popen(["sleep", "30"], pass_fds=(fd,), start_new_session=True)
    os.close(fd)
    try:
        assert store.bed_busy(), "锁跟着子进程走，父进程关掉自己的 fd 不释放"
    finally:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    assert not store.bed_busy(), "子进程死了内核自动放锁，不需要删锁文件"
    assert store.lock_path.exists()


# ── 上机前闸 ──────────────────────────────────────────────────────────
def test_gates_freeze_and_reject(tmp_path):
    good = make_workbook(tmp_path / "g.xlsx", [
        ("202609240000000001", "APV_1", "cmd_config", "slb real http r1 10.0.0.1 80"),
        ("", "check_point", "found", "r1")])
    frozen = gates.freeze(good)
    assert frozen.autoids == ("202609240000000001",)
    gates.check(frozen, grammar=GRAMMAR, credential_literals=frozenset({CRED_LITERAL}))

    bad = gates.freeze(make_workbook(tmp_path / "b.xlsx", [
        ("202609240000000002", "APV_1", "cmd", "system reboot"),
        ("", "APV_1", "cmd_config", f"user admin password {CRED_LITERAL}")]))
    with pytest.raises(gates.GateError) as exc:
        gates.check(bad, grammar=GRAMMAR, credential_literals=frozenset({CRED_LITERAL}))
    text = " ".join(exc.value.problems)
    assert "destructive" in text and "credential literal" in text
    assert CRED_LITERAL not in text, "报告只给单元格位置，不回显字面量"

    with pytest.raises(gates.GateError, match="unavailable"):
        gates.check(frozen, grammar={}, credential_literals=frozenset())
    for junk in (b"", b"not a zip", good[:200]):
        with pytest.raises(gates.GateError):
            gates.freeze(junk)


# ── 全流程 ────────────────────────────────────────────────────────────
def test_submit_status_results_end_to_end(fake_env, tmp_path):
    gw = fake_env["gateway"]
    apv = fake_env["apv"]
    lease = _lease(gw)
    data = make_workbook(tmp_path / "c.xlsx", [
        ("202609240000000011", "APV_1", "cmd_config", "slb real http r1 10.0.0.1 80"),
        ("202609240000000012", "APV_1", "cmd", "show slb real")])
    # 上一轮留下的旧日志：必须判 stale
    old = apv / "report" / "r0" / "x" / "ist_staging_sdns" / "202609240000000011" / \
        "test_xlsx" / "case.xlsx" / "202609240000000012"
    old.mkdir(parents=True)
    (old / "202609240000000012.txt").write_text("old run", encoding="utf-8")
    past = time.time() - 3600
    os.utime(old / "202609240000000012.txt", (past, past))
    for parent in list(old.parents)[:4]:
        os.utime(parent, (past, past))

    submitted = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert submitted["ok"], submitted
    assert submitted["case_ids"] == ["202609240000000011", "202609240000000012"]
    staged = apv / "smoke_test" / "sdns" / "ist_staging_sdns" / "202609240000000011" / "case.xlsx"
    assert stat.S_IMODE(staged.stat().st_mode) == 0o444
    assert (staged.parent / "test_xlsx.py").is_symlink()

    assert gw.call(BOB, "case_status", {"task_id": submitted["task_id"]})["ok"] is False
    _wait_done(gw, ALICE, submitted["task_id"])
    results = gw.call(ALICE, "case_results", {"task_id": submitted["task_id"]})
    assert results["ok"] and results["channel"] == "ready", results
    assert {c["case_id"]: c["result"] for c in results["cases"]} == {
        "202609240000000011": "PASS", "202609240000000012": "PASS"}
    assert all(not c["log_stale"] for c in results["cases"])
    assert "#######   end case: 202609240000000011" in results["cases"][0]["log"]
    assert not gw.state.bed_busy(), "runner 结束后锁自动释放"


def test_second_submit_while_running_is_busy_and_lock_frees_after(fake_env, tmp_path):
    gw = fake_env["gateway"]
    (fake_env["apv"] / "slow_run").write_text("3", encoding="utf-8")
    lease = _lease(gw)
    data = make_workbook(tmp_path / "c.xlsx", [
        ("202609240000000021", "APV_1", "cmd", "show version")])
    first = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert first["ok"], first
    busy = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert busy["ok"] is False and "busy" in busy["error"]
    probe = gw.call(ALICE, "probe_show", {**lease, "command": "show version"})
    assert probe["ok"] is False and "busy" in probe["error"]
    _wait_done(gw, ALICE, first["task_id"])
    assert not gw.state.bed_busy()


def test_submit_needs_a_current_lease_and_rejects_gated_workbooks(fake_env, tmp_path):
    gw = fake_env["gateway"]
    data = make_workbook(tmp_path / "c.xlsx", [
        ("202609240000000031", "APV_1", "cmd_config", "clear config all")])
    b64 = base64.b64encode(data).decode()
    assert "lease_acquire" in gw.call(ALICE, "case_submit",
                                      {"lease_id": "x", "token": 1, "xlsx_b64": b64})["error"]
    lease = _lease(gw)
    refused = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": b64})
    assert refused["ok"] is False and refused["problems"]
    assert not list((fake_env["apv"] / "smoke_test" / "sdns").rglob("case.xlsx")), "被拒的不落位"
    # 服务端不可达：有上次取到的规则缓存就用缓存；缓存也没有就拒绝
    fake_env["server"].grammar = None
    cache = gw.cfg.state_dir / "domain_grammar.json"
    assert cache.is_file()
    cache.unlink()
    clean = make_workbook(tmp_path / "d.xlsx", [
        ("202609240000000032", "APV_1", "cmd", "show version")])
    no_rules = gw.call(ALICE, "case_submit", {**lease,
                                              "xlsx_b64": base64.b64encode(clean).decode()})
    assert no_rules["ok"] is False and "unreachable" in no_rules["error"]
    assert gw.call(BOB, "lease_acquire", {})["ok"] is False


def test_stage_refuses_sha_mismatch(fake_env):
    cfg = fake_env["gateway"].cfg
    with pytest.raises(framework.FrameworkError, match="sha"):
        framework.stage_case(cfg, "sdns", "202609240000000041", b"bytes", "0" * 64)


def test_probe_show_validation(fake_env):
    gw = fake_env["gateway"]
    lease = _lease(gw)
    for bad in ("conf t", "show version; reboot", "show version\nreboot", "show\x1bversion", ""):
        out = gw.call(ALICE, "probe_show", {**lease, "command": bad})
        assert out["ok"] is False and "show/get" in out["error"], bad
    out = gw.call(ALICE, "probe_show", {"lease_id": "nope", "token": 0,
                                        "command": "show version"})
    assert out["ok"] is False and "lease" in out["error"]


def test_init_device_two_step_confirmation(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw, ROOT)
    assert gw.call(ALICE, "init_device", {**lease, "step": "prepare"})["ok"] is False
    prepared = gw.call(ROOT, "init_device", {**lease, "step": "prepare", "device_index": 1})
    assert prepared["ok"], prepared
    commands = prepared["plan"]["devices"][0]["commands"]
    assert commands == ["no page", "clear config all", "ip add eth1 192.0.2.71 24"]
    assert gw.call(ROOT, "init_device", {**lease, "step": "confirm",
                                         "confirmation": "wrong"})["ok"] is False
    done = gw.call(ROOT, "init_device", {**lease, "step": "confirm",
                                         "confirmation": prepared["confirmation"]})
    assert done["ok"] and done["initialized"] == 1, done
    assert gw.call(ROOT, "init_device", {**lease, "step": "confirm",
                                         "confirmation": prepared["confirmation"]})["ok"] is False

    monkeypatch.setenv("FAKE_CU_HANG_ON", "clear config all")
    again = gw.call(ROOT, "init_device", {**lease, "step": "prepare", "device_index": 0})
    failed = gw.call(ROOT, "init_device", {**lease, "step": "confirm",
                                           "confirmation": again["confirmation"]})
    assert failed["ok"] and failed["initialized"] == 0
    assert failed["details"][0]["failed_step"] == "clear config all"


def test_env_prepare_reports_each_check(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw)
    monkeypatch.setattr(framework, "device_reachable", lambda ip, **_: True)
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "output": f"Software Version : {BUILD}\n"})
    out = gw.call(ALICE, "env_prepare", lease)
    assert out["ok"] and out["ready"] is True, out
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "output": "Software Version : OTHER_BUILD_9\n"})
    out = gw.call(ALICE, "env_prepare", lease)
    assert out["ready"] is False
    assert next(c for c in out["checks"] if c["check"] == "device_build")["ok"] is False


def _row(cid: str, result: str, run: str, *, bed: str = "jumphost", sub: str = "ist_staging_sdns") -> dict:
    module = sub[len("ist_staging_"):]
    return {"table": BUILD, "case_id": cid, "sub_module": sub, "result": result,
            "url": f"http://{bed}/test/fw/report/{run}/{module}/{sub}/x/test_xlsx/case.xlsx/{cid}/{cid}/"}


def test_agent_results_keep_only_rows_of_this_run(fake_env):
    """结果库一案多行（别的床、上一轮）：只认 url 指向本次运行报告目录的那一行。"""
    apv = fake_env["apv"]
    rows = [_row("202609240000000051", "FAIL", "run-this"),
            _row("202609240000000051", "PASS", "run-old", bed="other-bed", sub="ist_staging_slb")]
    (apv / "fake_results.json").write_text(json.dumps(rows), encoding="utf-8")
    out = framework.query_results(fake_env["gateway"].cfg, BUILD,
                                  ["202609240000000051", "202609240000000052"], run_dir="run-this")
    assert out == {"results": {"202609240000000051": "FAIL"}, "ignored_rows": 1}


def test_results_come_from_this_run_not_other_beds_or_rounds(fake_env, tmp_path):
    """别的床与上一轮在同一张构建表里留下的 PASS 不能顶替本次的判定。"""
    gw, apv = fake_env["gateway"], fake_env["apv"]
    a, b = "202609240000000071", "202609240000000072"
    (apv / "fake_results.json").write_text(json.dumps(
        [_row(a, "PASS", "run-old", bed="other-bed", sub="ist_staging_slb"),
         _row(b, "PASS", "run-old", bed="other-bed", sub="ist_staging_slb")]), encoding="utf-8")
    data = make_workbook(tmp_path / "c.xlsx", [(a, "APV_1", "cmd", "show slb real"),
                                              (b, "APV_1", "cmd", "show slb real")])

    def run_round(verdicts: dict) -> dict:
        (apv / "fake_verdicts.json").write_text(json.dumps(verdicts), encoding="utf-8")
        lease = _lease(gw)
        submitted = gw.call(ALICE, "case_submit",
                            {**lease, "xlsx_b64": base64.b64encode(data).decode()})
        assert submitted["ok"], submitted
        _wait_done(gw, ALICE, submitted["task_id"])
        gw.call(ALICE, "lease_release", lease)
        return gw.call(ALICE, "case_results", {"task_id": submitted["task_id"]})

    first = run_round({a: "FAIL"})
    assert {c["case_id"]: c["result"] for c in first["cases"]} == {a: "FAIL", b: "PASS"}
    assert first["channel"] == "ready"
    time.sleep(0.05)
    second = run_round({"skip": [b]})     # 这一轮 b 没跑：上一轮与别的床的 PASS 都不算数
    assert {c["case_id"]: c["result"] for c in second["cases"]} == {a: "PASS", b: None}
    assert second["channel"] == "missing_after_done"

    # 紧接着又跑了一轮，再取第一轮的结果：报告目录与日志仍是第一轮自己的。结果库每案只留
    # 最新一行——a 的行已被第二轮覆盖，第一轮的 a 就是缺失，不拿第二轮的 PASS 顶替
    again = gw.call(ALICE, "case_results", {"task_id": first["task_id"]})
    assert first["run_dir"] != second["run_dir"]
    assert again["run_dir"] == first["run_dir"]
    assert {c["case_id"]: c["result"] for c in again["cases"]} == {a: None, b: "PASS"}
    logs = {c["case_id"]: c["log"] for c in again["cases"]}
    assert first["run_dir"] in logs[a] and second["run_dir"] not in logs[a]


def test_agent_is_python38_syntax():
    import ast

    source = (framework.AGENT).read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 8))


# ── HTTP 层 ───────────────────────────────────────────────────────────
def test_http_mcp_auth_and_scoped_tool_list(fake_env):
    from gateway.service import build_server

    gw = fake_env["gateway"]
    object.__setattr__(gw.cfg, "port", 0)
    httpd = build_server(gw)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(base + "/mcp", data=json.dumps(body).encode(),
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, None

    try:
        assert post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})[0] == 401
        assert post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "revoked")[0] == 401
        status, listed = post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "run-token")
        names = {t["name"] for t in listed["result"]["tools"]}
        assert status == 200 and "init_device" not in names and "case_submit" in names
        _, admin = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "admin-token")
        assert "init_device" in {t["name"] for t in admin["result"]["tools"]}
        _, called = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                          "params": {"name": "lease_acquire", "arguments": {}}}, "run-token")
        assert called["result"]["structuredContent"]["ok"] is True
        with urllib.request.urlopen(base + "/healthz", timeout=5) as resp:
            assert json.loads(resp.read()) == {"ok": True, "service": "compile-excel-gateway"}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_vendor_matches_sources():
    from conftest import REPO_ROOT

    skills = REPO_ROOT.parent / "compile-excel-skills" / "cex_core"
    infotest = REPO_ROOT.parent / "InfoTest_Engine" / "main"
    if not skills.is_dir() or not infotest.is_dir():
        pytest.skip("需要同级的 compile-excel-skills 与 InfoTest_Engine 检出")
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "sync_gateway_vendor.py"),
                           "--check"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, "运行 tools/sync_gateway_vendor.py 重新同步：\n" + proc.stdout


def test_batch_logs_marks_logs_older_than_delivery_as_stale(fake_env):
    cfg = fake_env["gateway"].cfg
    base = fake_env["apv"] / "report" / "r1" / "x" / "ist_staging_sdns" / "202609240000000061" / \
        "test_xlsx" / "case.xlsx"
    for case_id, age in (("202609240000000061", 0), ("202609240000000062", 3600)):
        (base / case_id).mkdir(parents=True)
        log = base / case_id / f"{case_id}.txt"
        log.write_text("password=hunter2 run " + case_id, encoding="utf-8")
        stamp = time.time() - age
        os.utime(log, (stamp, stamp))
    logs = framework.batch_logs(cfg, "sdns", "202609240000000061", time.time() - 60)
    assert logs["202609240000000061"]["stale"] is False
    assert "hunter2" not in logs["202609240000000061"]["log"], "日志经脱敏再返回"
    assert logs["202609240000000062"] == {"mtime": logs["202609240000000062"]["mtime"],
                                          "stale": True, "log": ""}


def test_lease_status_shows_the_token_only_to_the_holder(fake_env):
    gw = fake_env["gateway"]
    _lease(gw, ALICE)
    mine = gw.call(ALICE, "lease_status", {})
    theirs = gw.call(BOB, "lease_status", {})
    assert mine["holder"] == "alice" and "token" in mine and "lease_id" in mine
    assert theirs["holder"] == "alice" and "token" not in theirs and "lease_id" not in theirs
    assert theirs["expires_in_s"] > 0


def test_gateway_audit_is_a_verifiable_hash_chain(fake_env):
    from gateway.audit_chain import verify

    gw = fake_env["gateway"]
    lease = _lease(gw, ALICE)
    gw.call(BOB, "lease_acquire", {})
    gw.call(ALICE, "lease_release", lease)
    result = verify(gw.audit_path)
    assert result["ok"] and result["chained"] >= 3, result
    lines = gw.audit_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("alice", "mallory") if "alice" in lines[1] else lines[1] + " "
    gw.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify(gw.audit_path) == {"ok": False, "line": 3,
                                     "reason": "prev does not match the previous line"}


# ── 床上有几台设备、跑在哪、没过的案带会话转储 ──────────────────────────
def test_a_workbook_that_names_a_device_the_bed_lacks_is_refused(fake_env, tmp_path):
    """框架按 conf [comm] ssh_ips 的第 k 个地址连 APV_k：conf 里没有第 k 台，整卷一个案都不跑。"""
    gw, apv = fake_env["gateway"], fake_env["apv"]
    lease = _lease(gw)
    for obj in ("APV_2", "Seg2_tmp"):
        data = make_workbook(tmp_path / f"{obj}.xlsx", [
            ("202610080000000001", "APV_0", "cmd", "show slb real"),
            ("", obj, "cmd", "show slb real")])
        out = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
        assert out["ok"] is False and any(obj in p and "2 device(s)" in p
                                          for p in out["problems"]), out
    conf = apv / "conf" / "bed.conf"
    conf.write_text(conf.read_text(encoding="utf-8").replace("127.0.0.1, 127.0.0.2", "127.0.0.1"),
                    encoding="utf-8")
    data = make_workbook(tmp_path / "apv1.xlsx", [("202610080000000002", "APV_1", "cmd", "show x")])
    out = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert out["ok"] is False and "APV_1 needs device 1" in out["error"], out


def test_env_prepare_says_how_many_devices_the_bed_has(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw)
    monkeypatch.setattr(framework, "device_reachable", lambda ip, **_: True)
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "output": f"Software Version : {BUILD}\n"})
    out = gw.call(ALICE, "env_prepare", lease)
    assert out["device_count"] == 2
    conf = next(c for c in out["checks"] if c["check"] == "framework_conf")
    assert "APV_0, APV_1" in conf["detail"]


def test_results_name_the_run_and_carry_sessions_of_cases_that_did_not_pass(fake_env, tmp_path):
    gw, apv = fake_env["gateway"], fake_env["apv"]
    a, b = "202610080000000011", "202610080000000012"
    (apv / "fake_verdicts.json").write_text(json.dumps({b: "FAIL"}), encoding="utf-8")
    data = make_workbook(tmp_path / "s.xlsx", [(a, "APV_0", "cmd", "show slb real"),
                                              (b, "APV_0", "cmd", "show slb real")])
    lease = _lease(gw)
    submitted = gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})
    assert submitted["ok"] and submitted["submit_autoid"] == a and submitted["module"] == "sdns"
    _wait_done(gw, ALICE, submitted["task_id"])
    out = gw.call(ALICE, "case_results", {"task_id": submitted["task_id"]})
    assert out["submit_autoid"] == a and out["module"] == "sdns"
    assert out["report_dir"].startswith(f"report/{out['run_dir']}/")
    assert out["report_dir"].endswith(f"ist_staging_sdns/{a}/test_xlsx/case.xlsx")
    cases = {c["case_id"]: c for c in out["cases"]}
    assert "sessions" not in cases[a], "a pass carries no session dumps"
    assert cases[b]["sessions"] == {"apv_192.0.2.10.txt": f"APV(config)#show sdns node\nnode1 {b}\n"}
    assert "######################      FAIL      ####################" in cases[b]["log"]
