#!/usr/bin/env python3
"""把网关依赖的判据代码同步进 gateway/vendor/（改判据先改源头，再跑本脚本）。

  python3 tools/sync_gateway_vendor.py --skills-root ../compile-excel-skills \\
      --infotest-root ../InfoTest_Engine [--only cex_core|credential_literals] [--check]

- gateway/vendor/cex_core/            ← compile-excel-skills 的 cex_core/（整包原样复制）。
  **不入库**（.gitignore）：cex_core 带着真实模板/契约身份与内部构建名，本仓守着“零内部资产”
  （tests/test_e2e.py::test_no_internal_assets_in_repo）。测试前由 tests/gateway/conftest.py、
  发版时由 release 流程从 skills 仓现同步。
- gateway/vendor/credential_literals.py ← InfoTest main/case_compiler/credential_literals.py
  （从框架源码 AST 提取凭据字面量；只把默认镜像路径的导入换成“调用方必须显式给根目录”）。入库。
--check 只比对不写，有差异退出码 1（tests/gateway/test_gateway.py::test_vendor_matches_sources 用它）。
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


PARTS = ("cex_core", "credential_literals")
_VENDOR_INIT = "\n".join([
    '"""网关引用的外部判据代码（同步而来，不手改）。',
    "",
    "cex_core/ 不入库，由 tools/sync_gateway_vendor.py --only cex_core 从 compile-excel-skills 生成。",
    '"""',
    "",
    "from importlib.util import find_spec as _find_spec",
    "",
    "# 按模块查找而不是看文件：PyInstaller 打包后 cex_core 在归档里，磁盘上没有 .py",
    'if _find_spec(__name__ + ".cex_core") is None:',
    '    raise ImportError("gateway/vendor/cex_core is generated and not in git; run "',
    '                      "python3 tools/sync_gateway_vendor.py --only cex_core "',
    '                      "--skills-root <compile-excel-skills checkout>")',
    "",
])


def build(skills_root: Path, infotest_root: Path, parts: tuple[str, ...] = PARTS
          ) -> dict[str, bytes]:
    files: dict[str, bytes] = {"__init__.py": _VENDOR_INIT.encode("utf-8")}
    if "cex_core" in parts:
        core = skills_root / "cex_core"
        if not (core / "__init__.py").is_file():
            raise SystemExit(f"找不到 {core}")
        for path in sorted(core.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                files["cex_core/" + path.relative_to(core).as_posix()] = path.read_bytes()
    if "credential_literals" in parts:
        files["credential_literals.py"] = _credential_literals(infotest_root)
    return files


def _credential_literals(infotest_root: Path) -> bytes:
    source = (infotest_root / "main" / "case_compiler" / "credential_literals.py").read_text(
        encoding="utf-8")
    if source.count(_MIRROR_IMPORT) != 1:
        raise SystemExit("InfoTest credential_literals 的导入变了，先更新本脚本")
    source = source.replace(_MIRROR_IMPORT, _MIRROR_STUB)
    if "from main" in source or "import main" in source:
        raise SystemExit("InfoTest credential_literals 引用了其他 InfoTest 模块，先更新本脚本")
    return (_HEADER + source).encode("utf-8")


def _owned(rel: str, parts: tuple[str, ...]) -> bool:
    if rel == "__init__.py":
        return True
    if rel.startswith("cex_core/"):
        return "cex_core" in parts
    return rel == "credential_literals.py" and "credential_literals" in parts


def main() -> int:
    parser = argparse.ArgumentParser(description="同步网关 vendor 代码")
    parser.add_argument("--skills-root", default=str(REPO_ROOT.parent / "compile-excel-skills"))
    parser.add_argument("--infotest-root", default=str(REPO_ROOT.parent / "InfoTest_Engine"))
    parser.add_argument("--only", choices=PARTS, action="append",
                        help="只同步这一部分（可重复）；缺省两部分都同步")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    parts = tuple(args.only or PARTS)
    wanted = build(Path(args.skills_root).resolve(), Path(args.infotest_root).resolve(), parts)
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
    stale = sorted(rel for rel in existing - set(wanted) if _owned(rel, parts))
    for rel in stale:
        drift.append(rel + "（源头已没有）")
        if not args.check:
            (VENDOR / rel).unlink()
    for rel in drift:
        print(("不一致: " if args.check else "已更新: ") + rel)
    return 1 if (args.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
