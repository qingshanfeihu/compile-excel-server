"""服务端生成链（generators/）：

- 缺输入就明确失败、下游步骤跳过，不静默产出；
- 能只靠 InfoTest 库内输入跑的两个生成器（rule_registry、device_behavior_examples 的密封语料
  构建），服务端跑出的投影与 InfoTest 原生成器在同一份输入上逐字节一致。

需要同级 compile-excel-skills 检出（生成器来自它的 cex_core/engine）以及 InfoTest 检出和 venv
（生成器依赖在那个 venv 里，也用它跑 InfoTest 那一侧）；缺哪样就跳过。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

SKILLS_ROOT = Path(os.environ.get("CEX_SKILLS_ROOT") or REPO_ROOT.parent / "compile-excel-skills")
INFOTEST_ROOT = Path(os.environ.get("INFOTEST_ROOT") or REPO_ROOT.parent / "InfoTest_Engine")
INFOTEST_PYTHON = Path(os.environ.get("INFOTEST_PYTHON")
                       or Path.home() / ".venvs" / "infotest-engine" / "bin" / "python")
CORPUS = "knowledge/data/device_behavior_corpus"

pytestmark = pytest.mark.skipif(
    not (SKILLS_ROOT / "cex_core" / "engine" / "scripts" / "gen_rule_registry.py").is_file()
    or not (INFOTEST_ROOT / CORPUS).is_dir() or not INFOTEST_PYTHON.is_file(),
    reason="需要同级 compile-excel-skills（含生成器）、InfoTest 检出与它的 venv")


@pytest.fixture(scope="module")
def vendor(tmp_path_factory):
    """skills 仓 cex_core 的临时副本：测的是它当前的生成器，又不改写仓库里的 gateway/vendor
    （测试对仓库只读；gateway/vendor 由人手跑 tools/sync_gateway_vendor.py 更新）。"""
    root = tmp_path_factory.mktemp("vendor")
    shutil.copytree(SKILLS_ROOT / "cex_core", root / "cex_core",
                    ignore=shutil.ignore_patterns("__pycache__"))
    return root


def _run(inputs: Path, out: Path, vendor: Path, steps=None, params=None) -> dict:
    from generators.runner import run

    return run(inputs, out, steps=steps, params=params, vendor=vendor,
               python=str(INFOTEST_PYTHON), timeout=600)


def test_missing_inputs_fail_closed_and_skip_what_depends_on_them(tmp_path, vendor):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    report = _run(inputs, tmp_path / "out", vendor)
    assert report["ok"] is False and report["produced"] == {}
    steps = report["steps"]
    assert steps["framework_projections"] == {"status": "missing_inputs",
                                              "missing": ["knowledge/framework/mirror/lib"]}
    assert steps["compile_projections"] == {"status": "skipped",
                                            "because": ["framework_projections"]}


def test_missing_params_are_named(tmp_path, vendor):
    inputs = tmp_path / "inputs"
    for need in ("runtime/command_tree", "knowledge/data/manual"):
        (inputs / need).mkdir(parents=True)
    for need in ("knowledge/framework/mirror/lib/apv/clear.py",
                 "scripts/data/criterion_rule_sources.json",
                 "knowledge/data/compile_ref/domain_grammar.json",
                 "knowledge/data/compile_ref/blocks_schema.json"):
        (inputs / need).parent.mkdir(parents=True, exist_ok=True)
        (inputs / need).write_text("{}", encoding="utf-8")
    report = _run(inputs, tmp_path / "out", vendor, steps=["compile_projections"])
    assert report["steps"]["compile_projections"] == {"status": "missing_params",
                                                      "missing": ["raw_build", "version"]}


def test_tracked_generators_match_infotest_byte_for_byte(tmp_path, vendor):
    inputs = tmp_path / "inputs"
    shutil.copytree(INFOTEST_ROOT / CORPUS, inputs / CORPUS)
    report = _run(inputs, tmp_path / "out", vendor,
                  steps=["rule_registry", "device_behavior_examples"])
    assert report["ok"], report["steps"]
    assert set(report["produced"]) == {"rule_registry.json", "device_behavior_examples.json"}

    reference = tmp_path / "infotest"
    shutil.copytree(INFOTEST_ROOT / CORPUS, reference / CORPUS)
    (reference / "knowledge" / "data" / "compile_ref").mkdir(parents=True)
    script = f'''
import os, sys
from pathlib import Path
sys.path.insert(0, {str(INFOTEST_ROOT)!r})
from scripts import gen_device_behavior_examples, gen_rule_registry
root = Path({str(reference)!r})
out = root / "knowledge" / "data" / "compile_ref"
assert gen_device_behavior_examples.main(["--output", str(out / "device_behavior_examples.json")],
                                         root=root) == 0
os.chdir(root)
gen_rule_registry.main()
'''
    proc = subprocess.run([str(INFOTEST_PYTHON), "-c", script], capture_output=True, text=True,
                          timeout=600)
    assert proc.returncode == 0, proc.stderr[-2000:]
    ref = reference / "knowledge" / "data" / "compile_ref"
    name = "device_behavior_examples.json"
    assert (tmp_path / "out" / name).read_bytes() == (ref / name).read_bytes()
    # rule_registry 把生成时刻写进 _meta.generated_at：两次运行本来就不同，其余逐字节比
    ours, theirs = [json.loads(path.read_text(encoding="utf-8"))
                    for path in (tmp_path / "out" / "rule_registry.json", ref / "rule_registry.json")]
    assert ours["_meta"].pop("generated_at") and theirs["_meta"].pop("generated_at")
    assert ours == theirs
    assert [p.read_text(encoding="utf-8").count("\n") for p in
            (tmp_path / "out" / "rule_registry.json", ref / "rule_registry.json")] == [
        (ref / "rule_registry.json").read_text(encoding="utf-8").count("\n")] * 2


def test_cli_reports_and_exits_nonzero_on_failure(tmp_path, vendor):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    proc = subprocess.run(
        [str(INFOTEST_PYTHON), str(REPO_ROOT / "ces_main.py"), "generate", "--inputs", str(inputs),
         "--out", str(tmp_path / "out"), "--vendor", str(vendor),
         "--report", str(tmp_path / "report.json")],
        capture_output=True, text=True, timeout=600)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["steps"]["framework_projections"]["status"] == "missing_inputs"
