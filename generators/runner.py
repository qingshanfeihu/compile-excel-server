"""生成链运行器：输入目录 → 工作数据根 → 逐步子进程 → 产物目录 + 报告。

  run(inputs, out, steps=None, params=...) -> dict

- inputs：InfoTest 仓根布局的输入目录（knowledge/framework/mirror、knowledge/data/manual、
  runtime/command_tree、scripts/data、knowledge/data/compile_ref 里入库的那几份……）。不改它：
  整份复制成工作副本再跑（生成器会就地改写 compile_ref，例如清场 atlas 改写 domain_grammar）。
- out：compile_ref 里本次新写或改动的文件复制到这里（只放投影，可直接交给
  `ces registry import-dir <build> projections <out>`）；报告由调用方另存。
- 每一步：先核对 `needs` 与 `params`，缺了记 missing_inputs / missing_params；排在它前面、同一次
  请求里失败了的步骤（`after`）让它记 skipped；否则起子进程跑，失败记 failed 并带原因码。
- cex_core 从 gateway/vendor 取（tools/sync_gateway_vendor.py 从 compile-excel-skills 生成）；
  子进程的 CEX_ENGINE_DATA_ROOT 指向工作副本，工作目录也设成它。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .chain import COMPILE_REF, DEFAULT_STEPS, STEPS

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VENDOR = REPO_ROOT / "gateway" / "vendor"
REPORT_SCHEMA = "ces.generate-report/v1"


class GenerateError(Exception):
    pass


def _digests(root: Path) -> dict[str, str]:
    base = root / COMPILE_REF
    if not base.is_dir():
        return {}
    return {p.relative_to(base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(base.rglob("*")) if p.is_file() and not p.is_symlink()}


def _run_step(name: str, work: Path, params: dict[str, Any], vendor: Path, python: str,
              timeout: int) -> dict[str, Any]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("IST_", "CEX_ENGINE_"))}
    env["CEX_ENGINE_DATA_ROOT"] = str(work)
    env["PYTHONPATH"] = os.pathsep.join([str(vendor), str(REPO_ROOT)])
    payload = json.dumps({**params, "root": str(work)}, ensure_ascii=False)
    try:
        proc = subprocess.run([python, "-m", "generators._step", name, payload], cwd=work,
                              env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": "timeout", "timeout_s": timeout}
    last = (proc.stdout.strip().splitlines() or [""])[-1]
    try:
        result = json.loads(last)
    except ValueError:
        result = {"ok": False, "error": "no_result", "detail": proc.stderr.strip()[-400:]}
    if proc.returncode == 0 and result.get("ok"):
        return {"status": "ok", "value": result.get("value")}
    return {"status": "failed", **{k: result.get(k) for k in ("error", "code", "detail")}}


def run(inputs: Path, out: Path, *, steps: list[str] | None = None,
        params: dict[str, Any] | None = None, vendor: Path | None = None,
        python: str | None = None, timeout: int = 1800, keep_work: bool = False) -> dict[str, Any]:
    inputs, out = Path(inputs).resolve(), Path(out).resolve()
    vendor = Path(vendor or DEFAULT_VENDOR).resolve()
    if not inputs.is_dir():
        raise GenerateError(f"inputs directory not found: {inputs}")
    if not (vendor / "cex_core" / "engine" / "__init__.py").is_file():
        raise GenerateError(f"no cex_core engine under {vendor}; run tools/sync_gateway_vendor.py "
                            "--only cex_core --skills-root <compile-excel-skills checkout>")
    names = list(steps or DEFAULT_STEPS)
    unknown = [name for name in names if name not in STEPS]
    if unknown:
        raise GenerateError(f"unknown steps: {unknown}; known: {sorted(STEPS)}")
    params = dict(params or {})
    work_parent = Path(tempfile.mkdtemp(prefix="ces-generate-"))
    work = work_parent / "root"
    shutil.copytree(inputs, work, symlinks=True)
    # InfoTest 仓里这个目录恒在（有入库投影），有的生成器按相对路径直接写进去
    (work / COMPILE_REF).mkdir(parents=True, exist_ok=True)
    before = _digests(work)
    report: dict[str, Any] = {"schema": REPORT_SCHEMA, "inputs": str(inputs), "steps": {}}
    failed: set[str] = set()
    for name in names:
        step = STEPS[name]
        missing = [need for need in step.needs if not (work / need).exists()]
        missing_params = [key for key in step.params if not params.get(key)]
        blocked = [dep for dep in step.after if dep in failed]
        if blocked:
            entry: dict[str, Any] = {"status": "skipped", "because": blocked}
        elif missing:
            entry = {"status": "missing_inputs", "missing": missing}
        elif missing_params:
            entry = {"status": "missing_params", "missing": missing_params}
        else:
            entry = _run_step(name, work, params, vendor, python or sys.executable, timeout)
        if entry["status"] != "ok":
            failed.add(name)
        report["steps"][name] = entry
    after = _digests(work)
    produced = sorted(rel for rel, digest in after.items() if before.get(rel) != digest)
    out.mkdir(parents=True, exist_ok=True)
    for rel in produced:
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(work / COMPILE_REF / rel, target)
    report["produced"] = {rel: after[rel] for rel in produced}
    report["ok"] = not failed
    if keep_work:
        report["work"] = str(work)
    else:
        shutil.rmtree(work_parent)
    return report
