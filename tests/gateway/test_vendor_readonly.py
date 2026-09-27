"""测试对仓库只读：夹具从不改写 gateway/vendor；与 skills 仓 cex_core 的差异只用 --check 报出来。"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, SKILLS_ROOT, SYNC_COMMAND


def test_conftest_never_writes_the_vendor_tree(tmp_path, monkeypatch):
    """即使找得到 skills 仓（而且与 vendor 副本不同），载入夹具也不跑会写文件的同步。"""
    (tmp_path / "cex_core").mkdir()
    (tmp_path / "cex_core" / "__init__.py").write_text("# drifted\n", encoding="utf-8")
    monkeypatch.setenv("CEX_SKILLS_ROOT", str(tmp_path))
    calls: list[list[str]] = []

    def record(argv, *args, **kwargs):
        calls.append([str(a) for a in argv])
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr(subprocess, "check_call", record)
    spec = importlib.util.spec_from_file_location("gateway_conftest_probe",
                                                  REPO_ROOT / "tests" / "gateway" / "conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    writes = [argv for argv in calls
              if any("sync_gateway_vendor" in a for a in argv) and "--check" not in argv]
    assert not writes, writes


def test_no_test_runs_the_vendor_sync_without_check():
    """整个 tests/ 里拼给同步脚本的参数列表都得带 --check（不带就会改写 gateway/vendor）。"""
    offenders = []
    for path in sorted((REPO_ROOT / "tests").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.List)
                    and "sync_gateway_vendor.py" in (ast.get_source_segment(source, node) or "")
                    and not any(isinstance(e, ast.Constant) and e.value == "--check"
                                for e in node.elts)):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, offenders


def test_vendor_cex_core_matches_skills():
    if not (SKILLS_ROOT / "cex_core" / "__init__.py").is_file():
        pytest.skip(f"no compile-excel-skills checkout at {SKILLS_ROOT} (set CEX_SKILLS_ROOT)")
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "sync_gateway_vendor.py"),
                           "--only", "cex_core", "--skills-root", str(SKILLS_ROOT), "--check"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"gateway/vendor/cex_core is stale; run {SYNC_COMMAND}\n" \
        + proc.stdout
