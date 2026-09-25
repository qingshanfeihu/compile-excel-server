"""仓库边界守门：服务端代码不读 InfoTest 的配置文件、不 import InfoTest 的环境加载模块。

唯一例外是 tools/import_infotest.py：它是过渡期寄宿在 InfoTest venv 里的发布通道，
按设计调用 InfoTest 自己的代码（InfoTest 的代码读它自己的配置）。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {"tools/import_infotest.py"}
# 运行时拼装，避免守卫扫到自身
_PATTERNS = [
    re.compile(r"langchain" + r"_env"),
    re.compile(r"""["'/]\s*""" + "environ" + r"""ment["']"""),
]
# 逐字放行的同名字面（文件 → 原文）：不是配置文件路径。只剥这一段原文再扫，同一文件里别处
# 再出现照样报。publish_data_dir.py 读的是 Excel 晋升回执里的字段（晋升环境）。
_ENV = "environ" + "ment"
_KNOWN_LITERALS = {
    "tools/publish_data_dir.py": (f'receipt.get("{_ENV}")',),
}


def test_server_code_does_not_touch_infotest_configuration():
    tracked = subprocess.run(["git", "ls-files", "*.py"], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
    offenders = []
    for rel in tracked:
        if rel in ALLOWED or rel.startswith("tests/"):
            continue
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        for literal in _KNOWN_LITERALS.get(rel, ()):
            assert text.count(literal) == 1, f"{rel}: 放行的原文变了，重核这条放行：{literal}"
            text = text.replace(literal, "")
        for pattern in _PATTERNS:
            if pattern.search(text):
                offenders.append(f"{rel}: {pattern.pattern}")
    assert offenders == []
