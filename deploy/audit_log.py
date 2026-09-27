"""服务端审计日志 <data>/audit.log：server.py 与 ces 管理命令共用的写入、轮换与复核。

- 写：每次追加都先拿 <data>/audit.log.lock 上的文件锁，锁内重读文件最后一行再接哈希链
  （gateway/audit_chain.py），所以服务进程与 ces 管理命令能往同一条链里写，prev 不会接错；
  实例密钥（audit_hmac_key）每次现读，换钥之后的下一行就用新钥签。
- 轮换（`ces audit rotate [--new-key]`）：旧文件末尾写一行 audit_sealed（旧钥签）封口，整份移到
  audit_archive/audit-NNNN.log，当时的密钥另存 audit-NNNN.key（0600）；要换钥就生成新钥；
  新 audit.log 的第一行 audit_rotated 记下被封段的名字与最后一行的哈希，从创世值重新起链。
- 复核（`ces audit verify`）：每段用它自己的密钥逐行复核，再核段与段之间首尾相接
  （封口行在、起链行指向的正是上一段最后一行）；没轮换过时结果与单文件复核相同。

root 跑管理命令时新建的文件交给数据目录的属主（服务账号），免得服务进程之后写不进去。
"""

from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from gateway.audit_chain import AuditChain, line_hash, verify

try:
    import fcntl
except ImportError:  # Windows：只有进程内的锁
    fcntl = None  # type: ignore[assignment]

LOG_NAME = "audit.log"
KEY_NAME = "audit_hmac_key"
LOCK_NAME = "audit.log.lock"
ARCHIVE_DIR = "audit_archive"
SEALED = "audit_sealed"
ROTATED = "audit_rotated"
_SEGMENT_RE = re.compile(r"^audit-(\d{4,})\.log$")
_HMAC_SEP = "\thmac="
_THREAD_LOCK = threading.Lock()
LOCK_WAIT_S = 2.0


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_key(path: Path, *, strict: bool = False) -> bytes | None:
    """读 hex 密钥。文件不存在返回 None；读不了或格式坏了：strict 时抛错，否则当没有。"""
    try:
        return bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        if strict:
            raise
        return None


def _match_owner(path: Path, data_dir: Path) -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        info = Path(data_dir).stat()
        os.chown(path, info.st_uid, info.st_gid)
    except OSError:
        pass


def _open_lock(data_dir: Path) -> int | None:
    lock_path = Path(data_dir) / LOCK_NAME
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        _match_owner(lock_path, data_dir)
        return fd
    except PermissionError:  # 别的账号建的锁文件：只读打开也能 flock
        try:
            return os.open(lock_path, os.O_RDONLY)
        except OSError:
            return None
    except OSError:
        return None


def _flock(fd: int) -> None:
    """最多等 LOCK_WAIT_S 秒：持锁的只会是几毫秒的追加/轮换，等不到（持锁进程被挂起）就不等了，
    照写——服务进程在事件循环线程里写审计，不能被一个卡住的管理命令拖死；真接错了 verify 会报出来。"""
    deadline = time.monotonic() + LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return
            time.sleep(0.005)
        except OSError:
            return


@contextmanager
def _locked(data_dir: Path) -> Iterator[None]:
    """进程内用线程锁，进程间用 flock（锁文件单独一个，轮换改名不影响它）。
    锁文件打不开时退回只有进程内的锁：审计照写，不让请求因此失败。"""
    with _THREAD_LOCK:
        fd = _open_lock(data_dir) if fcntl is not None else None
        try:
            if fd is not None:
                _flock(fd)
            yield
        finally:
            if fd is not None:
                os.close(fd)  # 关掉即释放 flock


class AuditLog:
    """追加式审计写入器；服务进程与管理命令共写同一条链。调用方保证记录里没有任何凭据。"""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / LOG_NAME
        self.key_path = self.data_dir / KEY_NAME

    def append(self, record: dict[str, Any]) -> bool:
        """追加一行；数据目录写不进去时返回 False（与 AuditChain 一样不抛错，不拖垮请求）。"""
        if "ts" not in record:
            record = {"ts": _now(), **record}
        try:
            with _locked(self.data_dir):
                created = not self.path.exists()
                before = self.path.stat().st_size if not created else 0
                AuditChain(self.path, key=lambda: load_key(self.key_path)).append(record)
                if created:
                    _match_owner(self.path, self.data_dir)
                return self.path.stat().st_size > before
        except OSError:
            return False


def _raw_lines(path: Path) -> list[str]:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []


def _record(raw: str) -> dict[str, Any]:
    try:
        record = json.loads(raw.partition(_HMAC_SEP)[0])
    except ValueError:
        return {}
    return record if isinstance(record, dict) else {}


def _write_private(path: Path, text: str, data_dir: Path) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    _match_owner(path, data_dir)


def _segments(data_dir: Path) -> list[Path]:
    archive = Path(data_dir) / ARCHIVE_DIR
    if not archive.is_dir():
        return []
    found = [(int(m.group(1)), p) for p in archive.iterdir() if (m := _SEGMENT_RE.match(p.name))]
    return [path for _, path in sorted(found)]


def rotate(data_dir: Path, *, new_key: bool = False,
           fields: dict[str, Any] | None = None) -> dict[str, Any]:
    """封存当前段、（可选）换钥、起新链。全程持写锁，服务进程在此期间的审计写入排队等候。"""
    data_dir = Path(data_dir)
    log, key_path = data_dir / LOG_NAME, data_dir / KEY_NAME
    archive = data_dir / ARCHIVE_DIR
    extra = dict(fields or {})
    with _locked(data_dir):
        archive.mkdir(mode=0o700, exist_ok=True)
        _match_owner(archive, data_dir)
        existing = _segments(data_dir)
        number = int(_SEGMENT_RE.match(existing[-1].name).group(1)) + 1 if existing else 1
        name = f"audit-{number:04d}.log"
        old_key = load_key(key_path, strict=True)
        before = _raw_lines(log)
        AuditChain(log, key=old_key).append(
            {"ts": _now(), "event": SEALED, "segment": name, **extra})
        lines = _raw_lines(log)
        if len(lines) != len(before) + 1:
            raise OSError(f"封口行没能写进 {log}")
        last = lines[-1]
        if old_key is not None:
            _write_private(archive / f"audit-{number:04d}.key", old_key.hex() + "\n", data_dir)
        os.replace(log, archive / name)
        if new_key:
            _write_private(key_path, secrets.token_hex(32) + "\n", data_dir)
        AuditChain(log, key=load_key(key_path, strict=True)).append({
            "ts": _now(), "event": ROTATED, "sealed_segment": name,
            "sealed_last_hash": line_hash(last), "sealed_keyed": old_key is not None,
            "key_rotated": bool(new_key), **extra})
        _match_owner(log, data_dir)
    return {"sealed_segment": str(archive / name), "key_rotated": bool(new_key),
            "sealed_keyed": old_key is not None}


def verify_all(data_dir: Path) -> dict[str, Any]:
    """复核全部段。没有轮换过：与 gateway.audit_chain.verify(audit.log) 的结果一致。"""
    data_dir = Path(data_dir)
    current_key = load_key(data_dir / KEY_NAME, strict=True)
    segments = _segments(data_dir)
    if not segments:
        result = verify(data_dir / LOG_NAME, current_key)
        lines = _raw_lines(data_dir / LOG_NAME) if result["ok"] else []
        if lines and _record(lines[0]).get("event") == ROTATED:
            return {"ok": False, "line": 1,
                    "reason": f"continues sealed segment {_record(lines[0]).get('sealed_segment')}"
                              f", which is missing from {ARCHIVE_DIR}/"}
        return result
    results: list[dict[str, Any]] = []
    sealed: tuple[str, str, bool] | None = None  # (段名, 最后一行哈希, 该段有没有密钥文件)

    def fail(segment: str, line: int, reason: str) -> dict[str, Any]:
        return {"ok": False, "segment": segment, "line": line, "reason": reason,
                "segments": results}

    for path in [*segments, data_dir / LOG_NAME]:
        archived = path.parent.name == ARCHIVE_DIR
        key = load_key(path.with_suffix(".key"), strict=True) if archived else current_key
        result = {"segment": path.name, **verify(path, key)}
        results.append(result)
        if not result["ok"]:
            return fail(path.name, result.get("line", 0), result.get("reason", ""))
        lines = _raw_lines(path)
        first = _record(lines[0]) if lines else {}
        if sealed is None:
            if first.get("event") == ROTATED:
                return fail(path.name, 1, f"continues sealed segment {first.get('sealed_segment')}"
                                          ", which is missing")
        else:
            if (first.get("event") != ROTATED or first.get("sealed_segment") != sealed[0]
                    or first.get("sealed_last_hash") != sealed[1]):
                return fail(path.name, 1, f"does not continue the sealed segment {sealed[0]}")
            if first.get("sealed_keyed") and not sealed[2]:
                return fail(sealed[0], 0, "the key file of this sealed segment is missing")
        if archived:
            if not lines or _record(lines[-1]).get("event") != SEALED:
                return fail(path.name, len(lines), "sealed segment does not end with audit_sealed")
            sealed = (path.name, line_hash(lines[-1]), key is not None)
    return {"ok": True, "lines": sum(r["lines"] for r in results),
            "chained": sum(r["chained"] for r in results),
            "legacy": sum(r["legacy"] for r in results), "segments": results}
