"""审计日志哈希链：服务端与网关共用（只用标准库）。

每行是一条 JSON 记录，带 `prev` 字段 = 上一行原始字节（含换行前的全部内容，含 hmac 后缀）的
SHA-256；第一行的 prev 是 64 个 0。改动或删除中间任意一行，下一行的 prev 就对不上。
服务端有实例密钥时，行尾另附 `\\thmac=<hex>`（HMAC-SHA256，覆盖 `\\t` 之前的 JSON），
防的是没有密钥的人重算整条链。

哈希链只能证明"链上的行没被改过"，证明不了"末尾没被截掉"：截尾需要把最新一行的哈希
另存到别处（例如定期记进外部系统），这里不做。

升级前写下的旧行没有 prev：校验时允许它们出现在链开始之前，链一旦开始，之后每行都必须接上。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable

GENESIS = "0" * 64
_HMAC_SEP = "\thmac="


def line_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _last_line(path: Path) -> str | None:
    try:
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            if size == 0:
                return None
            block = 4096
            data = b""
            pos = size
            while pos > 0:
                step = min(block, pos)
                pos -= step
                stream.seek(pos)
                data = stream.read(step) + data
                stripped = data.rstrip(b"\n")
                if b"\n" in stripped:
                    return stripped.rsplit(b"\n", 1)[1].decode("utf-8")
            return data.rstrip(b"\n").decode("utf-8") or None
    except FileNotFoundError:
        return None


class AuditChain:
    """追加式审计写入器。线程安全；同一文件只应有一个进程在写。"""

    def __init__(self, path: Path, key: Callable[[], bytes | None] | bytes | None = None):
        self.path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        last = _last_line(self.path)
        self._prev = line_hash(last) if last is not None else GENESIS

    def _current_key(self) -> bytes | None:
        return self._key() if callable(self._key) else self._key

    def append(self, record: dict[str, Any]) -> None:
        with self._lock:
            body = json.dumps({**record, "prev": self._prev}, ensure_ascii=False)
            key = self._current_key()
            raw = body + (_HMAC_SEP + hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
                          if key else "")
            try:
                with open(self.path, "a", encoding="utf-8") as stream:
                    stream.write(raw + "\n")
            except OSError:
                return
            self._prev = line_hash(raw)


def verify(path: Path, key: bytes | None = None) -> dict[str, Any]:
    """逐行复核：prev 链、（给了密钥时）hmac。返回第一处问题的行号（从 1 起）。"""
    path = Path(path)
    if not path.is_file():
        return {"ok": True, "lines": 0, "chained": 0, "legacy": 0}
    prev: str | None = None
    chained = legacy = 0
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, raw in enumerate(lines, start=1):
        body, sep, mac = raw.partition(_HMAC_SEP)
        if key is not None:
            if not sep:
                return {"ok": False, "line": number, "reason": "missing hmac"}
            expected = hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, mac):
                return {"ok": False, "line": number, "reason": "hmac mismatch"}
        try:
            record = json.loads(body)
        except ValueError:
            return {"ok": False, "line": number, "reason": "not JSON"}
        link = record.get("prev") if isinstance(record, dict) else None
        if link is None:
            if chained:
                return {"ok": False, "line": number, "reason": "line without prev after the chain began"}
            legacy += 1
        else:
            want = GENESIS if prev is None else prev
            if link != want:
                return {"ok": False, "line": number, "reason": "prev does not match the previous line"}
            chained += 1
        prev = line_hash(raw)
    return {"ok": True, "lines": len(lines), "chained": chained, "legacy": legacy}
