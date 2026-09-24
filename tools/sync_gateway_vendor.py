#!/usr/bin/env python3
"""把网关依赖的判据代码同步进 gateway/vendor/（改判据先改源头，再跑本脚本）。

  python3 tools/sync_gateway_vendor.py --skills-root ../compile-excel-skills \\
      --infotest-root ../InfoTest_Engine [--check]

- gateway/vendor/cex_core/            ← compile-excel-skills 的 cex_core/（整包原样复制）
- gateway/vendor/credential_literals.py ← InfoTest main/case_compiler/credential_literals.py
  （从框架源码 AST 提取凭据字面量；只把默认镜像路径的导入换成“调用方必须显式给根目录”）
--check 只比对不写，有差异退出码 1（tests/gateway/test_vendor_drift.py 用它）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR = REPO_ROOT / "gateway" / "vendor"
_MIRROR_IMPORT = "from main.knowledge_paths import KNOWLEDGE_FRAMEWORK_MIRROR\n"
_MIRROR_STUB = ("# 网关总是显式传框架根目录；InfoTest 的默认镜像路径在跳板机上不存在\n"
                "KNOWLEDGE_FRAMEWORK_MIRROR = None\n")
_HEADER = ("# 同步自 InfoTest main/case_compiler/credential_literals.py（tools/sync_gateway_vendor.py），"
           "不在这里手改。\n")


def build(skills_root: Path, infotest_root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    core = skills_root / "cex_core"
    if not (core / "__init__.py").is_file():
        raise SystemExit(f"找不到 {core}")
    for path in sorted(core.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            files["cex_core/" + path.relative_to(core).as_posix()] = path.read_bytes()
    source = (infotest_root / "main" / "case_compiler" / "credential_literals.py").read_text(
        encoding="utf-8")
    if source.count(_MIRROR_IMPORT) != 1:
        raise SystemExit("InfoTest credential_literals 的导入变了，先更新本脚本")
    source = source.replace(_MIRROR_IMPORT, _MIRROR_STUB)
    if "from main" in source or "import main" in source:
        raise SystemExit("InfoTest credential_literals 引用了其他 InfoTest 模块，先更新本脚本")
    files["credential_literals.py"] = (_HEADER + source).encode("utf-8")
    files["__init__.py"] = "\"\"\"网关引用的外部判据代码（同步而来，不手改）。\"\"\"\n".encode()
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="同步网关 vendor 代码")
    parser.add_argument("--skills-root", default=str(REPO_ROOT.parent / "compile-excel-skills"))
    parser.add_argument("--infotest-root", default=str(REPO_ROOT.parent / "InfoTest_Engine"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    wanted = build(Path(args.skills_root).resolve(), Path(args.infotest_root).resolve())
    drift = []
    for rel, content in wanted.items():
        target = VENDOR / rel
        if target.is_file() and target.read_bytes() == content:
            continue
        drift.append(rel)
        if not args.check:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    existing = {p.relative_to(VENDOR).as_posix() for p in VENDOR.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts} if VENDOR.is_dir() else set()
    stale = sorted(existing - set(wanted))
    for rel in stale:
        drift.append(rel + "（源头已没有）")
        if not args.check:
            (VENDOR / rel).unlink()
    for rel in drift:
        print(("不一致: " if args.check else "已更新: ") + rel)
    return 1 if (args.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
