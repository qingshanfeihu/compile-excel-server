#!/usr/bin/env python3
"""把网关依赖的判据代码同步进 gateway/vendor/（改判据先改源头，再跑本脚本）。

  python3 tools/sync_gateway_vendor.py --skills-root ../compile-excel-skills \\
      --infotest-root ../InfoTest_Engine [--only cex_core|credential_literals] [--rev <提交>] \\
      [--allow-dirty] [--check]

- gateway/vendor/cex_core/            ← compile-excel-skills 某个**提交**里的 cex_core/
  （`git archive <rev>`，缺省 HEAD）。不取工作区：没提交的改动、被 .gitignore 挡在库外的文件
  （cex_core/engine/_identities.json 是抽取时外置的真实用例号）都不会进来；_identities.json 即使
  被强行提交了也显式排除（网关与发布工具的代码路径都不读它）。skills 仓 cex_core 有未提交的
  改动时拒绝同步（它们不会进 vendor，多半不是你想要的），确认只要提交内容时加 --allow-dirty。
  同步写一份来源戳 cex_core/.vendor_stamp.json（skills 提交、提交时间、排除了哪些文件）。
  **不入库**（.gitignore）：cex_core 带着真实模板/契约身份与内部构建名，本仓守着“零内部资产”
  （tests/test_e2e.py::test_no_internal_assets_in_repo）。发版时由 release 流程从 skills 仓现同步。
- gateway/vendor/credential_literals.py ← InfoTest main/case_compiler/credential_literals.py
  （从框架源码 AST 提取凭据字面量；只把默认镜像路径的导入换成“调用方必须显式给根目录”）。入库。
--check 只比对不写（与同步用同一个提交比），有差异退出码 1
（tests/gateway/test_vendor_readonly.py 用它）。
"""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR = REPO_ROOT / "gateway" / "vendor"
_MIRROR_IMPORT = "from main.knowledge_paths import KNOWLEDGE_FRAMEWORK_MIRROR\n"
_MIRROR_STUB = ("# 网关总是显式传框架根目录；InfoTest 的默认镜像路径在跳板机上不存在\n"
                "KNOWLEDGE_FRAMEWORK_MIRROR = None\n")
_HEADER = ("# 同步自 InfoTest main/case_compiler/credential_literals.py（tools/sync_gateway_vendor.py），"
           "不在这里手改。\n")
STAMP = "cex_core/.vendor_stamp.json"
# 即使在提交里也不进 vendor：抽取时外置的生产身份表（真实用例号），网关与发布工具都用不到
EXCLUDED = ("cex_core/engine/_identities.json",)


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


def _git(skills_root: Path, *args: str) -> bytes:
    try:
        proc = subprocess.run(["git", "-C", str(skills_root), *args], capture_output=True,
                              timeout=120, check=False)
    except OSError as exc:
        raise SystemExit(f"git 不可用：{exc}") from exc
    if proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args[:2])} 失败（{skills_root}）："
                         f"{proc.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return proc.stdout


def resolve_commit(skills_root: Path, rev: str) -> tuple[str, str]:
    """(提交 sha, 提交时间 ISO 8601)。"""
    commit = _git(skills_root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").decode().strip()
    date = _git(skills_root, "show", "-s", "--format=%cI", commit).decode().strip()
    return commit, date


def dirty_paths(skills_root: Path) -> list[str]:
    """skills 仓 cex_core 下没提交的改动（含未跟踪文件；.gitignore 挡住的不算）。"""
    out = _git(skills_root, "status", "--porcelain", "--untracked-files=all", "--", "cex_core")
    return [line[3:] for line in out.decode("utf-8", "replace").splitlines() if line.strip()]


def _core_files(skills_root: Path, rev: str) -> dict[str, bytes]:
    if not (skills_root / ".git").exists():
        raise SystemExit(f"{skills_root} 不是 git 检出：vendor 只从提交同步（git archive）")
    commit, date = resolve_commit(skills_root, rev)
    archive = _git(skills_root, "archive", "--format=tar", commit, "cex_core")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar.getmembers():
            name = member.name
            if (not member.isfile() or name in EXCLUDED or "__pycache__" in name.split("/")
                    or name.endswith(".pyc")):
                continue
            stream = tar.extractfile(member)
            files[name] = stream.read() if stream is not None else b""
    if "cex_core/__init__.py" not in files:
        raise SystemExit(f"skills 提交 {commit[:12]} 里没有 cex_core/__init__.py")
    stamp = {"schema": "cex.vendor-stamp/v1", "source": "compile-excel-skills", "path": "cex_core",
             "commit": commit, "commit_date": date, "excluded": list(EXCLUDED)}
    files[STAMP] = (json.dumps(stamp, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    return files


def build(skills_root: Path, infotest_root: Path, parts: tuple[str, ...] = PARTS,
          rev: str = "HEAD") -> dict[str, bytes]:
    files: dict[str, bytes] = {"__init__.py": _VENDOR_INIT.encode("utf-8")}
    if "cex_core" in parts:
        files.update(_core_files(skills_root, rev))
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="同步网关 vendor 代码")
    parser.add_argument("--skills-root", default=str(REPO_ROOT.parent / "compile-excel-skills"))
    parser.add_argument("--infotest-root", default=str(REPO_ROOT.parent / "InfoTest_Engine"))
    parser.add_argument("--only", choices=PARTS, action="append",
                        help="只同步这一部分（可重复）；缺省两部分都同步")
    parser.add_argument("--rev", default="HEAD", help="从 skills 仓的这个提交取 cex_core（缺省 HEAD）")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="skills 仓 cex_core 有未提交改动也照样按 --rev 的提交同步")
    parser.add_argument("--vendor-dir", default=str(VENDOR), help=argparse.SUPPRESS)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    parts = tuple(args.only or PARTS)
    vendor = Path(args.vendor_dir)
    skills_root = Path(args.skills_root).resolve()
    if "cex_core" in parts and not args.check:
        if not (skills_root / ".git").exists():
            print(f"{skills_root} 不是 git 检出：vendor 只从提交同步（git archive）", file=sys.stderr)
            return 2
        dirty = dirty_paths(skills_root)
        if dirty and not args.allow_dirty:
            print(f"skills 仓 cex_core 有 {len(dirty)} 处未提交的改动（如 {dirty[0]}）：vendor 只取 "
                  f"{args.rev} 的提交内容，这些改动不会进来。先提交再同步；确认只要提交内容就加 "
                  "--allow-dirty", file=sys.stderr)
            return 2
    wanted = build(skills_root, Path(args.infotest_root).resolve(), parts, args.rev)
    drift = []
    for rel, content in wanted.items():
        target = vendor / rel
        if target.is_file() and target.read_bytes() == content:
            continue
        drift.append(rel)
        if not args.check:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    existing = {p.relative_to(vendor).as_posix() for p in vendor.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts} if vendor.is_dir() else set()
    stale = sorted(rel for rel in existing - set(wanted) if _owned(rel, parts))
    for rel in stale:
        drift.append(rel + "（源头已没有）")
        if not args.check:
            (vendor / rel).unlink()
    for rel in drift:
        print(("不一致: " if args.check else "已更新: ") + rel)
    if "cex_core" in parts:
        stamp = json.loads(wanted[STAMP])
        print(f"cex_core ← compile-excel-skills {stamp['commit'][:12]}（{stamp['commit_date']}）")
    return 1 if (args.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
