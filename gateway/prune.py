"""cexg gc：清掉 N 天前已结束任务的记录与网关落位留下的目录；默认只列出，--apply 才删。

清理范围（别的一概不碰）：
- 任务：<state>/tasks/<task_id>.*（runner 脚本、日志、状态、junit、存活锁、进程记录）
  与 state.db 里那一行，只清最近一次写入在 N 天前、且 runner 不再拿着存活锁的；
- 落位目录：<staging_parent>/ist_staging_*/<autoid>/，最近一次写入在 N 天前的；
- 框架报告里网关落位跑出来的那一截：<apv_src>/report/<run>/<模块>/ist_staging_*/，
  最近一次写入在 N 天前的；删完 report/<run>/<模块> 与 report/<run> 若空了一并删；
  不在 ist_staging_* 下的报告不碰。
N 天必须长过一轮上机的最长时长（run_max_s）再加一小时：进行中的任务不可能留下那么旧的文件。
真删时先拿床锁再清点、再删，免得清点之后刚好有人往同一个落位目录里投递。
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any

from . import framework
from .config import GatewayConfig
from .state import StateStore

DAY_S = 86400


class PruneError(RuntimeError):
    pass


def _scan(path: Path) -> tuple[float, int]:
    """目录树（或单个文件）最近一次写入的时刻与总字节数；不跟符号链接。"""
    info = path.lstat()
    newest, size = info.st_mtime, info.st_size
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path):
            for name in dirs + files:
                try:
                    info = os.lstat(os.path.join(root, name))
                except OSError:
                    continue
                newest, size = max(newest, info.st_mtime), size + info.st_size
    return newest, size


def _inside(path: Path, root: Path) -> bool:
    """真实目录，且解析后仍在 root 之下（中间有符号链接指到别处的不算）。"""
    return path.is_dir() and not path.is_symlink() and \
        path.resolve().is_relative_to(root.resolve())


def _task_id(name: str) -> str | None:
    for _, suffix in framework.TASK_FILES:
        for tail in (suffix, suffix + ".tmp"):
            if name.endswith(tail) and len(name) > len(tail):
                return name[:-len(tail)]
    return None


def collect(cfg: GatewayConfig, days: float, now: float | None = None) -> dict[str, Any]:
    if days < 1 or days * DAY_S <= cfg.run_max_s + 3600:
        raise PruneError(f"--days must be at least 1 and longer than run_max_s + 1h "
                         f"({cfg.run_max_s}s)")
    cutoff = (time.time() if now is None else now) - days * DAY_S
    store = StateStore(cfg.state_dir, cfg.lease_ttl_s)
    groups: dict[str, list[Path]] = {}
    tasks_dir = cfg.state_dir / "tasks"
    if tasks_dir.is_dir():
        for path in sorted(tasks_dir.iterdir()):
            task_id = _task_id(path.name)
            if task_id is not None and not path.is_dir():
                groups.setdefault(task_id, []).append(path)
    tasks: list[str] = []
    files: list[Path] = []
    size = 0
    for task_id in sorted(set(groups) | set(store.tasks_created_before(cutoff))):
        paths = groups.get(task_id, [])
        scans = [_scan(path) for path in paths]
        if any(newest >= cutoff for newest, _ in scans):
            continue
        # runner 还拿着存活锁（进程组里还有活的）：不管多旧都不动
        if paths and framework.task_paths(cfg, task_id)["alive"].exists() \
                and not framework.runner_gone(cfg, task_id):
            continue
        tasks.append(task_id)
        files.extend(paths)
        size += sum(bytes_ for _, bytes_ in scans)
    trees: dict[str, list[Path]] = {"staging": [], "reports": []}
    for key, root, pattern in (("staging", cfg.staging_parent, "ist_staging_*/*"),
                               ("reports", cfg.apv_src / "report", "*/*/ist_staging_*")):
        for path in sorted(root.glob(pattern)) if root.is_dir() else []:
            if not _inside(path, root):
                continue
            newest, bytes_ = _scan(path)
            if newest < cutoff:
                trees[key].append(path)
                size += bytes_
    return {"days": days, "cutoff": int(cutoff), "tasks": tasks, "task_files": files,
            **trees, "bytes": size}


def run(cfg: GatewayConfig, days: float, *, apply: bool) -> dict[str, Any]:
    """清点；apply 时在床锁里清点并删除。返回清点结果。"""
    if not apply:
        return collect(cfg, days)
    store = StateStore(cfg.state_dir, cfg.lease_ttl_s)
    fd = store.try_bed_lock()
    if fd is None:
        raise PruneError("bed busy: a run or device operation is in progress; run gc later")
    try:
        plan = collect(cfg, days)
        _delete(store, plan)
    finally:
        os.close(fd)
    return plan


def _delete(store: StateStore, plan: dict[str, Any]) -> None:
    for path in plan["task_files"]:
        path.unlink(missing_ok=True)
    store.delete_tasks(plan["tasks"])
    for path in plan["staging"] + plan["reports"]:
        shutil.rmtree(path)
    # 空了的上层一并删：落位的 ist_staging_<模块>；报告的 <模块> 与 <run>
    for path in plan["staging"]:
        _rmdir_if_empty(path.parent)
    for path in plan["reports"]:
        if _rmdir_if_empty(path.parent):
            _rmdir_if_empty(path.parent.parent)


def _rmdir_if_empty(path: Path) -> bool:
    try:
        path.rmdir()
    except OSError:
        return False
    return True


def report(plan: dict[str, Any], applied: bool) -> dict[str, Any]:
    return {"ok": True, "applied": applied, "days": plan["days"],
            "cutoff": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(plan["cutoff"])),
            "tasks": plan["tasks"], "staging": [str(p) for p in plan["staging"]],
            "reports": [str(p) for p in plan["reports"]], "bytes": plan["bytes"]}
