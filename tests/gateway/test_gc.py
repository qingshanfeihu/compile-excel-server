"""cexg gc：只清 N 天前已结束任务的记录、落位目录与网关落位跑出来的报告；默认只列出，--apply 才删；
runner 还活着的任务、别的报告、符号链接指到外面的目录一概不碰。"""

from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from gateway import cexg

OLD = time.time() - 40 * 86400


def _age(path: Path, when: float = OLD) -> None:
    for sub in [path, *path.rglob("*")] if path.is_dir() else [path]:
        os.utime(sub, (when, when), follow_symlinks=False)


def _task(tasks: Path, task_id: str, state: str, *, alive: bool, when: float = OLD) -> None:
    tasks.mkdir(parents=True, exist_ok=True)
    (tasks / f"{task_id}.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (tasks / f"{task_id}.log").write_text("log\n", encoding="utf-8")
    (tasks / f"{task_id}.status.json").write_text(json.dumps({"state": state}), encoding="utf-8")
    if alive:
        (tasks / f"{task_id}.alive").write_text("", encoding="utf-8")
    for path in tasks.glob(f"{task_id}.*"):
        _age(path, when)


def _tree(root: Path, rel: str, when: float = OLD) -> Path:
    leaf = root / rel
    leaf.mkdir(parents=True)
    (leaf / "x.txt").write_text("x" * 100, encoding="utf-8")
    top = root / Path(rel).parts[0]
    _age(top, when)
    return leaf


def _gc(config: Path, capsys, *extra: str) -> tuple[int, dict]:
    rc = cexg.main(["gc", "--config", str(config), *extra])
    return rc, json.loads(capsys.readouterr().out)


def test_gc_lists_by_default_and_deletes_only_what_it_owns(fake_env, capsys):
    gw, apv, config = fake_env["gateway"], fake_env["apv"], fake_env["config"]
    tasks = gw.cfg.state_dir / "tasks"
    _task(tasks, "cex_sdns_1_1", "done", alive=True)
    _task(tasks, "cex_sdns_2_2", "running", alive=True)          # runner 死了：lost
    _task(tasks, "cex_sdns_3_3", "running", alive=False)         # 升级前起的，早该结束
    _task(tasks, "cex_sdns_4_4", "done", alive=True, when=time.time())   # 最近的
    _task(tasks, "cex_sdns_5_5", "running", alive=True)          # runner 还拿着存活锁
    holder = os.open(tasks / "cex_sdns_5_5.alive", os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for task_id, created in (("cex_sdns_1_1", OLD), ("cex_sdns_6_6", OLD),
                             ("cex_sdns_4_4", time.time())):
        gw.state.record_task(task_id=task_id, lease_id="l", token=1, holder="alice",
                             module="sdns", autoid="1", build="b", case_ids=["1"],
                             xlsx_sha256="0" * 64, staging_dir="s", deliver_epoch=created,
                             created_at=created)
    staging = gw.cfg.staging_parent
    old_stage = _tree(staging, "ist_staging_sdns/202601010000000001")
    new_stage = _tree(staging / "ist_staging_sdns", "202609260000000001", when=time.time())
    report = apv / "report"
    gone_run = _tree(report, "run-old/sdns/ist_staging_sdns/202601010000000001/test_xlsx")
    mixed = _tree(report, "run-mixed/sdns/ist_staging_sdns/202601010000000002")
    manual = _tree(report / "run-mixed" / "sdns", "test_manual")
    _age(report / "run-mixed")
    human = _tree(report, "run-human/slb/test_x")
    recent = _tree(report, "run-new/sdns/ist_staging_sdns/202609260000000001", when=time.time())
    outside = _tree(fake_env["tmp"], "elsewhere/sdns/ist_staging_sdns/202601010000000003")
    (report / "run-link").symlink_to(fake_env["tmp"] / "elsewhere")
    try:
        rc, listed = _gc(config, capsys)
        assert rc == 0 and listed["applied"] is False
        assert listed["tasks"] == ["cex_sdns_1_1", "cex_sdns_2_2", "cex_sdns_3_3",
                                   "cex_sdns_6_6"]
        assert listed["staging"] == [str(old_stage)]
        assert listed["reports"] == [str(report / "run-mixed/sdns/ist_staging_sdns"),
                                     str(report / "run-old/sdns/ist_staging_sdns")]
        assert listed["bytes"] > 0
        assert old_stage.exists() and gone_run.exists() and (tasks / "cex_sdns_1_1.log").exists()

        rc, applied = _gc(config, capsys, "--apply")
        assert rc == 0 and applied["applied"] is True and applied["tasks"] == listed["tasks"]
    finally:
        os.close(holder)
    left = sorted(p.name for p in tasks.iterdir())
    assert not any(name.startswith(("cex_sdns_1_1.", "cex_sdns_2_2.", "cex_sdns_3_3."))
                   for name in left)
    assert "cex_sdns_4_4.log" in left and "cex_sdns_5_5.log" in left
    assert gw.state.task("cex_sdns_1_1") is None and gw.state.task("cex_sdns_6_6") is None
    assert gw.state.task("cex_sdns_4_4") is not None
    assert not old_stage.exists() and new_stage.exists()
    assert not (report / "run-old").exists(), "只剩空壳的报告目录一并删"
    assert not mixed.exists() and manual.exists(), "同一轮里别的用例的报告不碰"
    assert human.exists() and recent.exists() and outside.exists()


def test_gc_refuses_a_short_window_and_a_busy_bed(fake_env, capsys):
    rc, out = _gc(fake_env["config"], capsys, "--days", "0.01")
    assert rc == 2 and out["ok"] is False and "--days" in out["error"]
    fd = fake_env["gateway"].state.try_bed_lock()
    try:
        rc, out = _gc(fake_env["config"], capsys, "--apply")
        assert rc == 2 and "bed busy" in out["error"]
        assert _gc(fake_env["config"], capsys)[0] == 0, "只列出不用床锁"
    finally:
        os.close(fd)
