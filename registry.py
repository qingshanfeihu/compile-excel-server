"""数据包注册表：按构建发布编译数据，blob 按内容寻址。

- blob：`<root>/blobs/sha256/<前2位>/<sha>`，写入时边写边算哈希，一致才改名落位；落位后不再改动。
  没有任何包引用、且最近一次登记（上传）早于宽限期的 blob 才会被 gc 回收。
- 包（bundle）：一个构建的一组条目（kind + 相对路径 + blob sha + meta）。bundle_id 是规范化
  条目清单的 SHA-256，内容不变就是同一个包，重复发布是空操作：不新建包，也不动任何通道指针。
- 通道：每个构建有 candidate / stable 两个指针。新包进 candidate；进 stable 要自检通过、并含服务端
  下限要求的 kind（STABLE_REQUIRED_KINDS，`$CES_STABLE_REQUIRED_KINDS` 可改），与发布方声明的
  required_kinds 无关。切通道可带 expect（调用方以为的当前指针），对不上就拒绝，不静默覆盖。

只依赖标准库；服务进程和 `ces registry` 命令行各自打开同一个库文件。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

BUNDLE_SCHEMA = "cex.bundle/v1"
KINDS = ("cmdtree", "manual", "spec", "projections", "template", "framework", "footprints")
CHANNELS = ("candidate", "stable")
# 没有这两类就编不出用例：命令存在性判定靠 cmdtree，产物落盘靠 template
REQUIRED_KINDS = ("cmdtree", "template")
# 进 stable 的服务端下限（发布方声明的 required_kinds 放不宽它）：客户端判命令存在性读
# cmdtree/vendor_stdlib_*，自毁扫描与网关上机前闸读 projections/domain_grammar.json。
# 旧 artifacts 目录的导入（服务端自己登记运维放在数据目录里的文件）按它实际有的类走，不受此限。
STABLE_REQUIRED_KINDS = ("cmdtree", "projections")
STABLE_KINDS_ENV = "CES_STABLE_REQUIRED_KINDS"
LEGACY_PUBLISHER = "legacy-import"
GC_GRACE_SECONDS = 24 * 3600

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_BUILD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEDIA_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_BAD_COMPONENT_CHARS = set('\\:*?"<>|')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS blobs (
    sha256     TEXT PRIMARY KEY,
    bytes      INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS builds (
    build      TEXT PRIMARY KEY,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bundles (
    bundle_id   TEXT PRIMARY KEY,
    build       TEXT NOT NULL REFERENCES builds(build),
    created_at  REAL NOT NULL,
    publisher   TEXT NOT NULL,
    source_json TEXT NOT NULL,
    checks_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    bundle_id  TEXT NOT NULL REFERENCES bundles(bundle_id),
    kind       TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL REFERENCES blobs(sha256),
    bytes      INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    meta_json  TEXT NOT NULL,
    PRIMARY KEY (bundle_id, path)
);
CREATE TABLE IF NOT EXISTS channels (
    build      TEXT NOT NULL REFERENCES builds(build),
    channel    TEXT NOT NULL CHECK (channel IN ('candidate', 'stable')),
    bundle_id  TEXT NOT NULL REFERENCES bundles(bundle_id),
    updated_at REAL NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (build, channel)
);
"""


class RegistryError(ValueError):
    """调用方可见的拒绝原因（参数非法、引用缺失、自检不过）。"""


class BlobTooLarge(RegistryError):
    """blob 超过上传上限。"""


class ChannelConflict(RegistryError):
    """通道当前指针与调用方给的 expect 不一致。"""

    def __init__(self, message: str, current: str | None):
        super().__init__(message)
        self.current = current


def stable_required_kinds(value: str | None = None) -> tuple[str, ...]:
    """stable 下限：取 $CES_STABLE_REQUIRED_KINDS（空格或逗号分隔；`none` 表示不设下限），没设用缺省。"""
    raw = os.environ.get(STABLE_KINDS_ENV, "") if value is None else value
    items = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    if not items:
        return STABLE_REQUIRED_KINDS
    if items == ["none"]:
        return ()
    unknown = [item for item in items if item not in KINDS]
    if unknown:
        raise RegistryError(f"{STABLE_KINDS_ENV} 含未知 kind：{', '.join(unknown)}"
                            f"（可用：{', '.join(KINDS)}，或 none）")
    return tuple(dict.fromkeys(items))


def valid_sha(value: str) -> bool:
    return bool(_SHA_RE.match(value or ""))


def valid_build(value: str) -> bool:
    return bool(_BUILD_RE.match(value or ""))


def check_entry_path(kind: str, path: str) -> str:
    """条目路径：以 `<kind>/` 开头的相对 posix 路径；每段不能是 . / ..、不能以点开头、
    不含控制字符和 Windows 保留字符。允许中文文件名（spec 文档常见）。"""
    if kind not in KINDS:
        raise RegistryError(f"未知 kind：{kind!r}（可用：{', '.join(KINDS)}）")
    if not isinstance(path, str) or not path or len(path.encode("utf-8")) > 1024:
        raise RegistryError(f"路径非法：{path!r}")
    normalized = unicodedata.normalize("NFC", path)
    parts = normalized.split("/")
    if parts[0] != kind or len(parts) < 2:
        raise RegistryError(f"路径必须以 {kind}/ 开头：{path!r}")
    for part in parts[1:]:
        if (not part or part in (".", "..") or part.startswith(".")
                or len(part.encode("utf-8")) > 255
                or any(ord(ch) < 32 or ch in _BAD_COMPONENT_CHARS for ch in part)):
            raise RegistryError(f"路径段非法：{path!r}")
    return normalized


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def _json_text(obj: Any, what: str) -> str:
    """落库的 JSON：NaN/Infinity 这类非有限数拒收（存进去之后清单就发不出去了）。"""
    try:
        return json.dumps(obj, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RegistryError(f"{what} 必须是 JSON，数值必须有限：{exc}") from None


def compute_bundle_id(build: str, entries: Iterable[dict[str, Any]]) -> str:
    rows = sorted(
        ({"kind": e["kind"], "path": e["path"], "sha256": e["sha256"],
          "media_type": e["media_type"], "meta": e.get("meta") or {}} for e in entries),
        key=lambda row: row["path"])
    return hashlib.sha256(_canonical({"build": build, "entries": rows})).hexdigest()


class Registry:
    def __init__(self, root: Path, stable_kinds: Iterable[str] | None = None):
        self.root = Path(root)
        self.blob_root = self.root / "blobs" / "sha256"
        self.blob_root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "registry.db"
        self.stable_kinds = (stable_required_kinds() if stable_kinds is None
                             else tuple(stable_kinds))
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    # ── blob ─────────────────────────────────────────────
    def blob_path(self, sha: str) -> Path:
        if not valid_sha(sha):
            raise RegistryError(f"sha256 非法：{sha!r}")
        return self.blob_root / sha[:2] / sha

    def blob_info(self, sha: str) -> dict[str, Any] | None:
        if not valid_sha(sha):
            return None
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM blobs WHERE sha256=?", (sha,)).fetchone()
        if row is None or not self.blob_path(sha).is_file():
            return None
        return dict(row)

    def begin_blob(self, media_type: str = "application/octet-stream",
                   max_bytes: int | None = None) -> "BlobWriter":
        """逐块写入 blob（给异步请求体用）；最后 finish() 校验并落位，出错 abort()。"""
        return BlobWriter(self, media_type, max_bytes)

    def put_blob_stream(self, expected_sha: str | None, chunks: Iterable[bytes],
                        media_type: str = "application/octet-stream",
                        max_bytes: int | None = None) -> dict[str, Any]:
        """流式写入 blob。给了 expected_sha 时哈希必须一致；已存在则不重写。"""
        writer = self.begin_blob(media_type, max_bytes)
        try:
            for chunk in chunks:
                writer.write(chunk)
            return writer.finish(expected_sha)
        except BaseException:
            writer.abort()
            raise

    def _register_blob(self, sha: str, size: int, media_type: str) -> None:
        # created_at 记的是最近一次登记（上传）时间：gc 的宽限期从这里算
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO blobs(sha256, bytes, media_type, created_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(sha256) DO UPDATE SET created_at=excluded.created_at",
                (sha, size, media_type, time.time()))

    def touch_blob(self, sha: str) -> None:
        """已有的 blob 又被上传了一次（发布进行中）：刷新登记时间，宽限期内 gc 不回收它。"""
        with self._conn() as conn:
            conn.execute("UPDATE blobs SET created_at=? WHERE sha256=?", (time.time(), sha))

    def put_blob_file(self, path: Path, media_type: str = "application/octet-stream"
                      ) -> dict[str, Any]:
        with open(path, "rb") as stream:
            return self.put_blob_stream(
                None, iter(lambda: stream.read(1 << 20), b""), media_type)

    def open_blob(self, sha: str) -> BinaryIO:
        return open(self.blob_path(sha), "rb")

    # ── 包 ───────────────────────────────────────────────
    def _normalize_entries(self, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(entries, list) or not entries:
            raise RegistryError("entries 不能为空")
        seen: set[str] = set()
        normalized = []
        for raw in entries:
            if not isinstance(raw, dict):
                raise RegistryError("entries 的每一项必须是对象")
            kind = str(raw.get("kind") or "")
            path = check_entry_path(kind, str(raw.get("path") or ""))
            if path.casefold() in seen:
                raise RegistryError(f"路径重复（忽略大小写后）：{path}")
            seen.add(path.casefold())
            sha = str(raw.get("sha256") or "")
            if not valid_sha(sha):
                raise RegistryError(f"{path}: sha256 非法")
            media_type = str(raw.get("media_type") or "application/octet-stream")
            if not _MEDIA_RE.match(media_type):
                raise RegistryError(f"{path}: media_type 非法")
            meta = raw.get("meta") or {}
            if not isinstance(meta, dict):
                raise RegistryError(f"{path}: meta 必须是对象")
            normalized.append({"kind": kind, "path": path, "sha256": sha,
                               "media_type": media_type, "meta": meta})
        return normalized

    def self_check(self, entries: list[dict[str, Any]],
                   required_kinds: Iterable[str] = REQUIRED_KINDS) -> dict[str, Any]:
        """blob 齐全、落盘内容哈希复核、必备 kind 齐全。"""
        problems: list[str] = []
        for entry in entries:
            path = self.blob_path(entry["sha256"])
            if not path.is_file():
                problems.append(f"{entry['path']}: blob 缺失")
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            if digest.hexdigest() != entry["sha256"]:
                problems.append(f"{entry['path']}: blob 内容与哈希不符")
        present = {entry["kind"] for entry in entries}
        missing = [kind for kind in required_kinds if kind not in present]
        if missing:
            problems.append(f"缺少必备 kind：{', '.join(missing)}")
        return {"ok": not problems, "problems": problems, "checked_at": time.time(),
                "required_kinds": list(required_kinds)}

    def submit_bundle(self, build: str, entries: list[dict[str, Any]], *, publisher: str,
                      source: dict[str, Any] | None = None,
                      required_kinds: Iterable[str] | None = None,
                      set_candidate: bool = True) -> dict[str, Any]:
        """登记一个包。返回 {bundle_id, created, checks, channels}。

        新包（created）让 candidate 指向它；内容与已有包相同（created 为 False）时不动任何通道
        指针——同内容重发是空操作，不会把别人刚切过、运维刚回滚过的指针拨回来。
        channels 是登记后该构建两个通道的当前指针，供发布方切 stable 时带 expect。"""
        if not valid_build(build):
            raise RegistryError(f"build 非法：{build!r}")
        normalized = self._normalize_entries(entries)
        required = tuple(REQUIRED_KINDS if required_kinds is None else required_kinds)
        for kind in required:
            if kind not in KINDS:
                raise RegistryError(f"required_kinds 含未知 kind：{kind!r}")
        source_json = _json_text(source or {}, "source")
        meta_json = [_json_text(e["meta"], f"{e['path']}: meta") for e in normalized]
        with self._conn() as conn:
            known = {row["sha256"]: row for row in conn.execute(
                "SELECT sha256, bytes FROM blobs WHERE sha256 IN (%s)"
                % ",".join("?" * len(normalized)), [e["sha256"] for e in normalized])}
        missing = sorted({e["sha256"] for e in normalized if e["sha256"] not in known})
        if missing:
            raise RegistryError("这些 blob 还没上传：" + ", ".join(missing))
        bundle_id = compute_bundle_id(build, normalized)
        checks = self.self_check(normalized, required)
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("INSERT OR IGNORE INTO builds(build, created_at) VALUES (?, ?)",
                             (build, now))
                exists = conn.execute("SELECT 1 FROM bundles WHERE bundle_id=?",
                                      (bundle_id,)).fetchone() is not None
                if not exists:
                    conn.execute(
                        "INSERT INTO bundles(bundle_id, build, created_at, publisher,"
                        " source_json, checks_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (bundle_id, build, now, publisher, source_json,
                         json.dumps(checks, ensure_ascii=False)))
                    conn.executemany(
                        "INSERT INTO entries(bundle_id, kind, path, sha256, bytes, media_type,"
                        " meta_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [(bundle_id, e["kind"], e["path"], e["sha256"],
                          known[e["sha256"]]["bytes"], e["media_type"], meta)
                         for e, meta in zip(normalized, meta_json)])
                    if set_candidate:
                        self._set_channel(conn, build, "candidate", bundle_id, publisher, now)
                else:
                    conn.execute("UPDATE bundles SET checks_json=? WHERE bundle_id=?",
                                 (json.dumps(checks, ensure_ascii=False), bundle_id))
                channels = {channel: self._pointer(conn, build, channel) for channel in CHANNELS}
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {"bundle_id": bundle_id, "created": not exists, "checks": checks,
                "channels": channels}

    @staticmethod
    def _pointer(conn: sqlite3.Connection, build: str, channel: str) -> str | None:
        row = conn.execute("SELECT bundle_id FROM channels WHERE build=? AND channel=?",
                           (build, channel)).fetchone()
        return row["bundle_id"] if row else None

    @staticmethod
    def _set_channel(conn: sqlite3.Connection, build: str, channel: str, bundle_id: str,
                     actor: str, now: float) -> None:
        conn.execute(
            "INSERT INTO channels(build, channel, bundle_id, updated_at, updated_by)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT(build, channel) DO UPDATE SET"
            " bundle_id=excluded.bundle_id, updated_at=excluded.updated_at,"
            " updated_by=excluded.updated_by", (build, channel, bundle_id, now, actor))

    def set_channel(self, build: str, channel: str, bundle_id: str, actor: str, *,
                    expect: str | None = None) -> bool:
        """把通道指向 bundle_id；返回指针是否真的变了（本来就指着它是空操作）。

        expect：调用方以为通道当前指向的包（`none` 表示当前应为空）。给了就在同一事务里核对，
        对不上抛 ChannelConflict：并发的发布、运维刚做的回滚，都不会被后来者静默覆盖。
        进 stable 要自检通过，并含服务端下限要求的 kind（self.stable_kinds）；旧目录导入的包
        （legacy-import）不受下限约束——导入时如此，之后手工切回它（回滚）也如此。"""
        if channel not in CHANNELS:
            raise RegistryError(f"未知通道：{channel!r}（可用：{', '.join(CHANNELS)}）")
        if expect is not None and expect != "none" and not valid_sha(expect):
            raise RegistryError(f"expect 必须是 bundle_id 或 none：{expect!r}")
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT build, checks_json, publisher FROM bundles WHERE bundle_id=?",
                    (bundle_id,)).fetchone()
                if row is None or row["build"] != build:
                    raise RegistryError(f"构建 {build} 下没有包 {bundle_id}")
                if channel == "stable":
                    if not json.loads(row["checks_json"]).get("ok"):
                        raise RegistryError("这个包的服务端自检没通过，不能进 stable")
                    kinds = {r["kind"] for r in conn.execute(
                        "SELECT DISTINCT kind FROM entries WHERE bundle_id=?", (bundle_id,))}
                    floor = () if row["publisher"] == LEGACY_PUBLISHER else self.stable_kinds
                    lacking = [kind for kind in floor if kind not in kinds]
                    if lacking:
                        raise RegistryError(
                            f"这个包缺少进 stable 的必备 kind：{', '.join(lacking)}"
                            f"（服务端下限 {' '.join(self.stable_kinds)}，见 {STABLE_KINDS_ENV}）")
                current = self._pointer(conn, build, channel)
                if expect is not None and current != (None if expect == "none" else expect):
                    raise ChannelConflict(
                        f"{build} 的 {channel} 当前指向 {current or '（空）'}，不是 expect 给的 "
                        f"{expect}；先看 ces registry list / GET /v1/builds 再决定", current)
                changed = current != bundle_id
                if changed:
                    self._set_channel(conn, build, channel, bundle_id, actor, time.time())
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return changed

    def channel_bundle(self, build: str, channel: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT bundle_id FROM channels WHERE build=? AND channel=?",
                               (build, channel)).fetchone()
        return row["bundle_id"] if row else None

    def bundle_manifest(self, bundle_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            head = conn.execute("SELECT * FROM bundles WHERE bundle_id=?",
                                (bundle_id,)).fetchone()
            if head is None:
                return None
            rows = conn.execute(
                "SELECT kind, path, sha256, bytes, media_type, meta_json FROM entries"
                " WHERE bundle_id=? ORDER BY path", (bundle_id,)).fetchall()
        return {
            "schema": BUNDLE_SCHEMA,
            "bundle_id": head["bundle_id"],
            "build": head["build"],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(head["created_at"])),
            "publisher": head["publisher"],
            "source": json.loads(head["source_json"]),
            "checks": json.loads(head["checks_json"]),
            "entries": [{"kind": r["kind"], "path": r["path"], "sha256": r["sha256"],
                         "bytes": r["bytes"], "media_type": r["media_type"],
                         "meta": json.loads(r["meta_json"])} for r in rows],
        }

    def list_builds(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            builds = conn.execute("SELECT build, created_at FROM builds ORDER BY build").fetchall()
            channels = conn.execute("SELECT * FROM channels").fetchall()
            counts = conn.execute(
                "SELECT build, COUNT(*) AS n FROM bundles GROUP BY build").fetchall()
        by_build: dict[str, dict[str, Any]] = {
            row["build"]: {"build": row["build"], "channels": {}, "bundles": 0}
            for row in builds}
        for row in counts:
            by_build[row["build"]]["bundles"] = row["n"]
        for row in channels:
            by_build[row["build"]]["channels"][row["channel"]] = {
                "bundle_id": row["bundle_id"], "updated_by": row["updated_by"],
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                            time.gmtime(row["updated_at"]))}
        return list(by_build.values())

    def verify_all(self) -> list[str]:
        """全量复核：每个登记的 blob 都在、内容与哈希一致。"""
        problems = []
        with self._conn() as conn:
            shas = [row["sha256"] for row in conn.execute("SELECT sha256 FROM blobs")]
        for sha in shas:
            path = self.blob_path(sha)
            if not path.is_file():
                problems.append(f"{sha}: 缺失")
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            if digest.hexdigest() != sha:
                problems.append(f"{sha}: 内容被改动")
        return problems

    def gc(self, grace_s: float = GC_GRACE_SECONDS) -> int:
        """删除没有任何包引用、且最近一次登记早于 grace_s 秒之前的 blob。

        宽限期护住进行中的发布：blob 已 PUT、清单还没 POST 时它暂时没有引用。"""
        cutoff = time.time() - max(0.0, grace_s)
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                orphans = [row["sha256"] for row in conn.execute(
                    "SELECT sha256 FROM blobs WHERE created_at < ?"
                    " AND sha256 NOT IN (SELECT sha256 FROM entries)", (cutoff,))]
                for sha in orphans:
                    conn.execute("DELETE FROM blobs WHERE sha256=?", (sha,))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        for sha in orphans:
            try:
                self.blob_path(sha).unlink()
            except FileNotFoundError:
                pass
        return len(orphans)

    # ── 旧版工件目录 → 包 ─────────────────────────────────
    def import_legacy_dir(self, build: str, artifacts_dir: Path,
                          artifact_meta: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
        """把旧 artifacts 目录登记成一个包，candidate 和 stable 指向它（每次启动都跑）。

        每个通道只在它为空、或它本身指着一个旧目录导入的包时才动：导入器发布过的 stable 不会
        被旧目录覆盖（这时整个导入跳过），导入器刚登记的 candidate 也不会被重启拨回旧目录。
        stable 还要自检通过；旧目录的包只按它实际有的必备类自检，不受 stable 下限约束——
        那是运维自己放进数据目录的文件，不是经接口发布的包。目录里没有任何登记过的文件时返回 None。
        """
        if not valid_build(build):
            return None
        entries = []
        for name in sorted(artifact_meta):
            path = Path(artifacts_dir) / name
            if not path.is_file() or path.is_symlink():
                continue
            kind = legacy_kind(name)
            meta = artifact_meta[name] or {}
            media_type = str(meta.get("media_type") or "application/octet-stream")
            blob = self.put_blob_file(path, media_type)
            entries.append({
                "kind": kind, "path": f"{kind}/{name}", "sha256": blob["sha256"],
                "media_type": media_type,
                "meta": {"legacy_name": name, "version": str(meta.get("version") or ""),
                         "receipt": meta.get("receipt") or {}},
            })
        if not entries:
            return None
        current = self.channel_bundle(build, "stable")
        if current is not None:
            head = self.bundle_manifest(current)
            if head and head["publisher"] != LEGACY_PUBLISHER:
                return {"bundle_id": current, "skipped": "stable 由导入器发布，不用旧目录覆盖"}
        kinds = sorted({e["kind"] for e in entries})
        result = self.submit_bundle(build, entries, publisher=LEGACY_PUBLISHER,
                                    source={"importer": LEGACY_PUBLISHER},
                                    required_kinds=[k for k in REQUIRED_KINDS if k in kinds],
                                    set_candidate=False)
        bundle_id = result["bundle_id"]
        moved = []
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                for channel in CHANNELS:
                    if channel == "stable" and not result["checks"]["ok"]:
                        continue
                    current = self._pointer(conn, build, channel)
                    if current == bundle_id:
                        continue
                    owner = conn.execute("SELECT publisher FROM bundles WHERE bundle_id=?",
                                         (current,)).fetchone() if current else None
                    if current is None or (owner and owner["publisher"] == LEGACY_PUBLISHER):
                        self._set_channel(conn, build, channel, bundle_id, LEGACY_PUBLISHER,
                                          time.time())
                        moved.append(channel)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {**result, "moved": moved}


class BlobWriter:
    def __init__(self, registry: Registry, media_type: str, max_bytes: int | None):
        self.registry = registry
        self.media_type = media_type if _MEDIA_RE.match(media_type or "") \
            else "application/octet-stream"
        self.max_bytes = max_bytes
        self.digest = hashlib.sha256()
        self.size = 0
        tmp_dir = registry.root / "tmp"
        tmp_dir.mkdir(exist_ok=True)
        fd, self.tmp_name = tempfile.mkstemp(dir=tmp_dir, prefix="blob-")
        self.stream = os.fdopen(fd, "wb")

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.size += len(chunk)
        if self.max_bytes is not None and self.size > self.max_bytes:
            raise BlobTooLarge(f"blob 超过上限 {self.max_bytes} 字节")
        self.digest.update(chunk)
        self.stream.write(chunk)

    def finish(self, expected_sha: str | None = None) -> dict[str, Any]:
        if expected_sha is not None and not valid_sha(expected_sha):
            self.abort()
            raise RegistryError(f"sha256 非法：{expected_sha!r}")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        sha = self.digest.hexdigest()
        if expected_sha is not None and sha != expected_sha:
            self.abort()
            raise RegistryError(f"内容哈希 {sha} 与声明的 {expected_sha} 不符，拒收")
        target = self.registry.blob_path(sha)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            self.abort()
        else:
            os.chmod(self.tmp_name, 0o444)
            os.replace(self.tmp_name, target)
        self.registry._register_blob(sha, self.size, self.media_type)
        return {"sha256": sha, "bytes": self.size, "media_type": self.media_type}

    def abort(self) -> None:
        if not self.stream.closed:
            self.stream.close()
        try:
            os.unlink(self.tmp_name)
        except FileNotFoundError:
            pass


def legacy_kind(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".xml") or "cmdtree" in lower or "vendor_stdlib" in lower:
        return "cmdtree"
    if lower.endswith((".xlsx", ".xlsm")):
        return "template"
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        return "framework"
    return "projections"
