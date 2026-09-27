"""tools/sync_gateway_vendor.py：cex_core 从 skills 仓的**提交**同步（git archive），不取工作区。

用 tmp 里现建的 git 仓当 skills 仓、tmp 里的目录当 vendor（--vendor-dir），不碰真实的 gateway/vendor。
- 被 .gitignore 挡住的 _identities.json（真实用例号）不进 vendor；即使被强行提交也显式排除；
  以前同步进来的会当作“源头已没有”删掉；
- cex_core 有未提交改动时拒绝同步；--allow-dirty 照样只取提交内容；
- 写来源戳 cex_core/.vendor_stamp.json（skills 提交、提交时间）；--check 与同步比同一个提交。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "sync_gateway_vendor.py"
IDENTITIES = "cex_core/engine/_identities.json"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), "-c", "user.name=Example",
                           "-c", "user.email=publisher@example.com", "-c", "commit.gpgsign=false",
                           *args], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@pytest.fixture
def skills(tmp_path):
    repo = tmp_path / "skills"
    (repo / "cex_core" / "engine").mkdir(parents=True)
    (repo / "cex_core" / "__init__.py").write_text('"""core"""\n', encoding="utf-8")
    (repo / "cex_core" / "engine" / "_root.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / ".gitignore").write_text(f"{IDENTITIES}\n__pycache__/\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    (repo / IDENTITIES).write_text('{"k": ["000000000000000001"]}\n', encoding="utf-8")
    return repo


def _sync(skills: Path, vendor: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), "--only", "cex_core", "--skills-root",
                           str(skills), "--vendor-dir", str(vendor), *extra],
                          capture_output=True, text=True, timeout=120)


def test_vendors_the_commit_without_ignored_identities(skills, tmp_path):
    vendor = tmp_path / "vendor"
    proc = _sync(skills, vendor)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (vendor / "cex_core/engine/_root.py").read_text() == "VALUE = 1\n"
    assert not (vendor / IDENTITIES).exists()
    stamp = json.loads((vendor / "cex_core/.vendor_stamp.json").read_text())
    assert stamp["commit"] == _git(skills, "rev-parse", "HEAD")
    assert stamp["commit_date"] == _git(skills, "show", "-s", "--format=%cI", "HEAD")
    assert IDENTITIES in stamp["excluded"]
    assert _sync(skills, vendor, "--check").returncode == 0


def test_uncommitted_changes_are_refused_and_never_vendored(skills, tmp_path):
    vendor = tmp_path / "vendor"
    (skills / "cex_core" / "engine" / "_root.py").write_text("VALUE = 2  # wip\n", encoding="utf-8")
    proc = _sync(skills, vendor)
    assert proc.returncode == 2 and "--allow-dirty" in proc.stderr
    assert not vendor.exists(), "nothing is written when refusing"
    proc = _sync(skills, vendor, "--allow-dirty")
    assert proc.returncode == 0, proc.stderr
    assert (vendor / "cex_core/engine/_root.py").read_text() == "VALUE = 1\n", "the commit, not the edit"


def test_identities_stay_out_even_when_committed(skills, tmp_path):
    vendor = tmp_path / "vendor"
    (vendor / "cex_core" / "engine").mkdir(parents=True)
    (vendor / IDENTITIES).write_text("{}", encoding="utf-8")  # 旧版同步从工作区带进来的
    _git(skills, "add", "-f", IDENTITIES)
    _git(skills, "commit", "-qm", "oops")
    assert _sync(skills, vendor, "--check").returncode == 1
    proc = _sync(skills, vendor)
    assert proc.returncode == 0, proc.stderr
    assert not (vendor / IDENTITIES).exists()


def test_check_compares_against_the_same_commit(skills, tmp_path):
    vendor = tmp_path / "vendor"
    assert _sync(skills, vendor).returncode == 0
    (skills / "cex_core" / "engine" / "_root.py").write_text("VALUE = 3\n", encoding="utf-8")
    _git(skills, "commit", "-qam", "next")
    check = _sync(skills, vendor, "--check")
    assert check.returncode == 1 and "cex_core/engine/_root.py" in check.stdout
    assert _sync(skills, vendor, "--check", "--rev", "HEAD~1").returncode == 0
    assert _sync(skills, vendor).returncode == 0
    assert _sync(skills, vendor, "--check").returncode == 0


def test_a_skills_tree_that_is_not_a_git_checkout_is_refused(tmp_path):
    plain = tmp_path / "plain"
    (plain / "cex_core").mkdir(parents=True)
    (plain / "cex_core" / "__init__.py").write_text("", encoding="utf-8")
    proc = _sync(plain, tmp_path / "vendor")
    assert proc.returncode == 2 and "git" in proc.stderr
