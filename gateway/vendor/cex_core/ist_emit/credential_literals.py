"""凭据字面量 redact 源（skill 改造版）。

上游来源：InfoTest_Engine main/case_compiler/credential_literals.py。
上游从完整框架镜像源码（AST）提取凭据字面量；skill 分发不带框架镜像，
字面量改为读本地可选文件 `$COMPILE_EXCEL_CREDENTIALS_DENY`（缺省
~/.config/compile-excel/credentials.deny），一行一个字面量，`#` 注释与
空行跳过。缺省（文件不存在）= 空集——deny 清单是可选加固项，不是出件
门槛；redact 语义不变：模板里命中字面量的单元格在出盘前替换为
"<已移除凭据>"。
"""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

__all__ = [
    "deny_file_path",
    "clear_credential_literal_cache",
    "mirror_credential_literals",
]

DEFAULT_DENY_DIR = Path.home() / ".config" / "compile-excel"
ENV_OVERRIDE = "COMPILE_EXCEL_CREDENTIALS_DENY"

_CACHE_LOCK = threading.Lock()
_CACHE: tuple[tuple[int, int], frozenset[str]] | None = None


def deny_file_path() -> Path:
    override = (os.environ.get(ENV_OVERRIDE) or "").strip()
    if override:
        return Path(override)
    return DEFAULT_DENY_DIR / "credentials.deny"


def clear_credential_literal_cache() -> None:
    global _CACHE
    with _CACHE_LOCK:
        _CACHE = None


def _read_deny_file(path: Path) -> frozenset[str]:
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return frozenset()
    except OSError:
        return frozenset()
    if not stat.S_ISREG(info.st_mode):
        return frozenset()
    try:
        with open(path, "rb") as stream:
            payload = stream.read(1 * 1024 * 1024)
        text = payload.decode("utf-8")
    except (OSError, UnicodeError):
        return frozenset()
    values = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    return frozenset(value for value in values if value)


def mirror_credential_literals() -> frozenset[str]:
    """读 deny 文件返回字面量闭集；按 (mtime_ns, size) 缓存。

    函数名沿用上游（xlsx_emit 的 redact 调用点不变）。读不到返回空集，
    绝不因 deny 文件问题阻塞出件。
    """
    global _CACHE
    path = deny_file_path()
    try:
        info = os.stat(path, follow_symlinks=False)
        key = (int(info.st_mtime_ns), int(info.st_size))
    except OSError:
        with _CACHE_LOCK:
            _CACHE = None
        return frozenset()
    with _CACHE_LOCK:
        if _CACHE is not None and _CACHE[0] == key:
            return _CACHE[1]
    values = _read_deny_file(path)
    with _CACHE_LOCK:
        _CACHE = (key, values)
    return values
