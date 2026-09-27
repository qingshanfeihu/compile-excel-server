"""上机的生命周期：runner 半路死掉报 lost 而不是永远 running；准备期间租约被接管就不再上机。"""

from __future__ import annotations

import base64
import json
import os
import signal
import time

from conftest import CRED_LITERAL, make_workbook

from gateway import framework

from test_gateway import ALICE, _lease, _wait_done


def _submit(gw, lease, tmp_path, autoid="202609260000000091"):
    data = make_workbook(tmp_path / "c.xlsx", [(autoid, "APV_1", "cmd", "show version")])
    return gw.call(ALICE, "case_submit", {**lease, "xlsx_b64": base64.b64encode(data).decode()})


def test_runner_killed_mid_run_is_reported_lost(fake_env, tmp_path):
    gw = fake_env["gateway"]
    (fake_env["apv"] / "slow_run").write_text("30", encoding="utf-8")
    submitted = _submit(gw, _lease(gw), tmp_path)
    assert submitted["ok"], submitted
    task_id = submitted["task_id"]
    process = json.loads((gw.cfg.state_dir / "tasks" / f"{task_id}.runner.json")
                         .read_text(encoding="utf-8"))
    assert process["pgid"] == process["pid"] and process["started_at"] > 0
    assert gw.call(ALICE, "case_status", {"task_id": task_id})["state"] == "running"

    # systemd 按 cgroup 停网关时就是这样连带杀掉：整组 TERM，没走的再补
    # （刚 fork 出来的子进程会漏掉一轮）
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            os.killpg(process["pgid"], signal.SIGTERM)
        except (ProcessLookupError, PermissionError):   # macOS：只剩僵尸时回 EPERM
            break
        time.sleep(0.2)
    while gw.state.bed_busy() and time.time() < deadline:
        time.sleep(0.2)
    assert not gw.state.bed_busy(), "runner 进程组没退干净"

    status = gw.call(ALICE, "case_status", {"task_id": task_id})
    assert status["ok"] and status["state"] == "lost" and status["rc"] is None, status
    assert "no verdicts" in status["note"]
    results = gw.call(ALICE, "case_results", {"task_id": task_id})
    assert results["ok"] and results["channel"] == "runner_lost", results
    assert results["rc"] is None and "resubmit" in results["explanation"]


def test_finished_run_is_done_not_lost_and_old_tasks_stay_running(fake_env, tmp_path):
    gw = fake_env["gateway"]
    submitted = _submit(gw, _lease(gw), tmp_path, "202609260000000092")
    assert submitted["ok"], submitted
    done = _wait_done(gw, ALICE, submitted["task_id"])
    assert done["state"] == "done" and done["rc"] == 0
    assert framework.runner_gone(gw.cfg, submitted["task_id"])
    # 升级前起的任务没有 .alive：判断不了死活，照旧报 running
    legacy = gw.cfg.state_dir / "tasks" / "cex_sdns_1_1.status.json"
    legacy.write_text(json.dumps({"task_id": "cex_sdns_1_1", "state": "running"}),
                      encoding="utf-8")
    assert framework.read_status(gw.cfg, "cex_sdns_1_1")["state"] == "running"


def test_submit_rechecks_the_lease_after_taking_the_bed_lock(fake_env, tmp_path, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw)

    def slow_literals():
        # 抽凭据字面量那几十秒里租约过期、被 bob 接管
        gw.state.expire_now_for_tests()
        gw.state.acquire("bob")
        return frozenset({CRED_LITERAL})

    monkeypatch.setattr(gw, "credential_literals", slow_literals)
    refused = _submit(gw, lease, tmp_path, "202609260000000093")
    assert refused["ok"] is False and "lease" in refused["error"], refused
    assert not list((fake_env["apv"] / "smoke_test" / "sdns").rglob("case.xlsx")), "不落位"
    assert not gw.state.bed_busy(), "拒绝后床锁放回"
