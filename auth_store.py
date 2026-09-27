"""身份与令牌存储（SQLite，只存哈希）。

- 用户：`ces users add` 生成访问码，库里只存加盐哈希；访问码只在生成时显示一次。
- 服务客户端（网关、发布导入器）：`ces clients add` 生成 client secret，同样只存哈希；
  `ces clients rotate-secret` 换 secret，已签发的令牌照常用到过期。
- 访问码与 secret 都是服务端生成的高熵随机串（144 / 256 位），不怕离线穷举，存加盐 HMAC-SHA256：
  每次校验是微秒级，不给未认证请求烧 CPU 的机会。早期写入的 PBKDF2 哈希照认，
  校验通过时顺手换成新格式（盐不变）。
- 令牌：access / refresh 都是高熵随机串，库里只存 SHA-256；可按令牌、按用户撤销。
  refresh 每用一次就轮换；已轮换掉的 refresh 被再次出示时，视为泄漏，整族撤销。
  令牌能用的 scope 始终是签发时的 scope 与主体**当前** scope 的交集。

只依赖标准库；服务进程和 `ces` 命令行各自打开同一个库文件。
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# 权限面：服务端各路由与网关按这张表校验（网关经 introspect 拿到 scope）
SCOPES: dict[str, str] = {
    "artifacts:read": "旧版工件清单与下载",
    "docs:query": "知识库检索",
    "bundles:read": "读取数据包与 blob",
    "bundles:publish": "发布数据包、切换通道（导入器/生成器用）",
    "config:read": "读取组织下发的客户端常量",
    "jumphost:run": "经网关租床、部署环境、提交用例",
    "jumphost:admin": "经网关初始化设备（两步确认）",
    "introspect": "令牌内省（网关用）",
}
DEFAULT_USER_SCOPES = ("artifacts:read", "docs:query", "bundles:read", "config:read",
                       "jumphost:run")

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# 注册表拿来标记服务端自己登记的包（旧目录导入、ces 命令行），不能再发给账号或客户端：
# 否则经接口发布的包会被当成旧目录导入的包（后者不受 stable 的 kind 下限约束）
RESERVED_NAMES = frozenset({"legacy-import", "ces-cli"})
_PBKDF2_ROUNDS = 200_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    code_salt  BLOB NOT NULL,
    code_hash  BLOB NOT NULL,
    scopes     TEXT NOT NULL,
    disabled   INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    client_id   TEXT PRIMARY KEY,
    secret_salt BLOB NOT NULL,
    secret_hash BLOB NOT NULL,
    scopes      TEXT NOT NULL,
    disabled    INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    subject    TEXT NOT NULL,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('user', 'client')),
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    family     TEXT NOT NULL,
    issued_at  REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL,
    rotated_at REAL
);
CREATE INDEX IF NOT EXISTS tokens_subject ON tokens(subject_kind, subject);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family);
"""


class AuthError(ValueError):
    """用户可见的参数错误（名字非法、重复、scope 未知）。"""


def valid_name(value: str) -> bool:
    return bool(_NAME_RE.match(value or ""))


def normalize_scopes(value: str | list[str] | tuple[str, ...]) -> list[str]:
    items = value.split() if isinstance(value, str) else list(value)
    unknown = sorted({item for item in items if item not in SCOPES})
    if unknown:
        raise AuthError(f"未知 scope：{' '.join(unknown)}（可用：{' '.join(SCOPES)}）")
    return sorted(set(items))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_access_code() -> str:
    return secrets.token_urlsafe(18)


def new_client_secret() -> str:
    return secrets.token_urlsafe(32)


def _legacy_hash(secret: str, salt: bytes) -> bytes:
    """早期格式（PBKDF2，20 万轮）：只用来认库里还没换格式的旧哈希。"""
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _PBKDF2_ROUNDS)


_HASH_PREFIX = b"hs256$"


def _secret_hash(secret: str, salt: bytes) -> bytes:
    return _HASH_PREFIX + hmac.new(salt, secret.encode("utf-8"), hashlib.sha256).digest()


def _check_secret(secret: str, salt: bytes, stored: bytes) -> tuple[bool, bool]:
    """(是否匹配, 是否旧格式)。"""
    stored = bytes(stored)
    if stored.startswith(_HASH_PREFIX):
        return hmac.compare_digest(_secret_hash(secret, salt), stored), False
    return hmac.compare_digest(_legacy_hash(secret, salt), stored), True


def _credential_tag(salt: bytes) -> str:
    """凭据指纹：重置访问码 / 换 secret 都换新盐，指纹就变（换哈希格式不换盐，指纹不变）。"""
    return hashlib.sha256(b"ces-credential\0" + bytes(salt)).hexdigest()[:32]


def _fresh_secret(value: str | None, generate) -> str:
    secret = value or generate()
    if len(secret) < 20:
        raise AuthError("凭据太短（至少 20 个字符，用 new_access_code / new_client_secret 生成）")
    return secret


# 用户不存在时也算一次同样的哈希，避免按耗时区分“无此用户”和“访问码错”
_DUMMY_SALT = secrets.token_bytes(16)
_DUMMY_HASH = _secret_hash(secrets.token_urlsafe(24), _DUMMY_SALT)


class AuthStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=10000")
            yield conn
        finally:
            conn.close()

    # ── 用户 ─────────────────────────────────────────────
    def add_user(self, username: str, scopes: list[str] | None = None, *,
                 code: str | None = None) -> str:
        """建账号并返回访问码。code 可由调用方预先生成（ces 先把它写进 --out 文件再落库）。"""
        if not valid_name(username):
            raise AuthError(f"用户名非法：{username!r}（字母数字开头，只含 . _ -，最长 64）")
        if username in RESERVED_NAMES:
            raise AuthError(f"{username} 是保留名（注册表用它标记服务端自己登记的包），换一个")
        granted = normalize_scopes(scopes if scopes is not None else list(DEFAULT_USER_SCOPES))
        code = _fresh_secret(code, new_access_code)
        salt = secrets.token_bytes(16)
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO users(username, code_salt, code_hash, scopes, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (username, salt, _secret_hash(code, salt), " ".join(granted), time.time()))
            except sqlite3.IntegrityError:
                raise AuthError(f"用户已存在：{username}（换访问码用 reset-code）") from None
        return code

    def reset_code(self, username: str, *, code: str | None = None) -> str:
        code = _fresh_secret(code, new_access_code)
        salt = secrets.token_bytes(16)
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET code_salt=?, code_hash=? WHERE username=?",
                (salt, _secret_hash(code, salt), username))
            if cur.rowcount == 0:
                raise AuthError(f"无此用户：{username}")
        self.revoke_subject("user", username)
        return code

    def set_user_scopes(self, username: str, scopes: list[str]) -> list[str]:
        granted = normalize_scopes(scopes)
        with self._conn() as conn:
            cur = conn.execute("UPDATE users SET scopes=? WHERE username=?",
                               (" ".join(granted), username))
            if cur.rowcount == 0:
                raise AuthError(f"无此用户：{username}")
        # 已签发令牌的 scope 可能超出新授权，一并撤销，下次登录按新授权签发
        self.revoke_subject("user", username)
        return granted

    def set_user_disabled(self, username: str, disabled: bool) -> None:
        with self._conn() as conn:
            cur = conn.execute("UPDATE users SET disabled=? WHERE username=?",
                               (1 if disabled else 0, username))
            if cur.rowcount == 0:
                raise AuthError(f"无此用户：{username}")
        if disabled:
            self.revoke_subject("user", username)

    def list_users(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT username, scopes, disabled, created_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    def user_exists(self, username: str) -> bool:
        if not valid_name(username):
            return False
        with self._conn() as conn:
            return conn.execute("SELECT 1 FROM users WHERE username=?",
                                (username,)).fetchone() is not None

    def _upgrade_hash(self, table: str, column: str, name: str, salt: bytes, old: bytes,
                      secret: str) -> None:
        """旧格式哈希校验通过后换成新格式；只在这期间没人改过这一行时才写（不覆盖并发的重置）。"""
        prefix = "code" if table == "users" else "secret"
        with self._conn() as conn:
            conn.execute(
                f"UPDATE {table} SET {prefix}_hash=? WHERE {column}=? AND {prefix}_salt=?"
                f" AND {prefix}_hash=?", (_secret_hash(secret, salt), name, salt, old))

    def verify_user(self, username: str, code: str) -> dict[str, Any] | None:
        """访问码正确且账号未停用时返回 {username, scopes, credential}。

        credential 是凭据指纹：授权后、兑换令牌前访问码被重置，兑换时指纹就对不上。"""
        row = None
        if valid_name(username):
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT username, code_salt, code_hash, scopes, disabled"
                    " FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            hmac.compare_digest(_secret_hash(code or "", _DUMMY_SALT), _DUMMY_HASH)
            return None
        matched, legacy = _check_secret(code or "", row["code_salt"], row["code_hash"])
        if not matched:
            return None
        if legacy:
            self._upgrade_hash("users", "username", row["username"], row["code_salt"],
                               row["code_hash"], code)
        if row["disabled"]:
            return None
        return {"username": row["username"], "scopes": row["scopes"].split(),
                "credential": _credential_tag(row["code_salt"])}

    # ── 服务客户端 ───────────────────────────────────────
    def add_client(self, client_id: str, scopes: list[str], *, secret: str | None = None) -> str:
        if not valid_name(client_id):
            raise AuthError(f"client_id 非法：{client_id!r}")
        if client_id in RESERVED_NAMES:
            raise AuthError(f"{client_id} 是保留名（注册表用它标记服务端自己登记的包），换一个")
        granted = normalize_scopes(scopes)
        secret = _fresh_secret(secret, new_client_secret)
        salt = secrets.token_bytes(16)
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO clients(client_id, secret_salt, secret_hash, scopes, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (client_id, salt, _secret_hash(secret, salt), " ".join(granted), time.time()))
            except sqlite3.IntegrityError:
                raise AuthError(f"客户端已存在：{client_id}（换 secret 用 rotate-secret）") from None
        return secret

    def rotate_client_secret(self, client_id: str, *, secret: str | None = None) -> str:
        """换 client secret：旧 secret 立即失效；已签发的令牌不撤销，照常用到过期。"""
        secret = _fresh_secret(secret, new_client_secret)
        salt = secrets.token_bytes(16)
        with self._conn() as conn:
            cur = conn.execute("UPDATE clients SET secret_salt=?, secret_hash=? WHERE client_id=?",
                               (salt, _secret_hash(secret, salt), client_id))
            if cur.rowcount == 0:
                raise AuthError(f"无此客户端：{client_id}")
        return secret

    def remove_client(self, client_id: str) -> None:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM clients WHERE client_id=?", (client_id,))
            if cur.rowcount == 0:
                raise AuthError(f"无此客户端：{client_id}")
        self.revoke_subject("client", client_id)

    def list_clients(self) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT client_id, scopes, disabled, created_at FROM clients ORDER BY client_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_client(self, client_id: str, secret: str) -> dict[str, Any] | None:
        row = None
        if valid_name(client_id):
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT client_id, secret_salt, secret_hash, scopes, disabled"
                    " FROM clients WHERE client_id=?", (client_id,)).fetchone()
        if row is None:
            hmac.compare_digest(_secret_hash(secret or "", _DUMMY_SALT), _DUMMY_HASH)
            return None
        matched, legacy = _check_secret(secret or "", row["secret_salt"], row["secret_hash"])
        if not matched:
            return None
        if legacy:
            self._upgrade_hash("clients", "client_id", row["client_id"], row["secret_salt"],
                               row["secret_hash"], secret)
        if row["disabled"]:
            return None
        return {"client_id": row["client_id"], "scopes": row["scopes"].split()}

    # ── 令牌 ─────────────────────────────────────────────
    def issue(self, *, subject: str, subject_kind: str, client_id: str, scope: list[str],
              access_ttl: int, refresh_ttl: int | None, family: str | None = None
              ) -> dict[str, Any]:
        now = time.time()
        family = family or secrets.token_hex(16)
        access = secrets.token_urlsafe(32)
        rows = [(_token_hash(access), "access", subject, subject_kind, client_id,
                 " ".join(scope), family, now, now + access_ttl)]
        refresh = None
        if refresh_ttl:
            refresh = secrets.token_urlsafe(32)
            rows.append((_token_hash(refresh), "refresh", subject, subject_kind, client_id,
                         " ".join(scope), family, now, now + refresh_ttl))
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO tokens(token_hash, kind, subject, subject_kind, client_id, scope,"
                " family, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        issued = {"access_token": access, "token_type": "Bearer", "expires_in": access_ttl,
                  "scope": " ".join(scope)}
        if refresh:
            issued["refresh_token"] = refresh
        return issued

    @staticmethod
    def _subject_row(conn: sqlite3.Connection, subject_kind: str,
                     subject: str) -> sqlite3.Row | None:
        """主体在且未停用时返回 (scopes, salt) 行，否则 None。"""
        if subject_kind == "user":
            sql = "SELECT scopes, disabled, code_salt AS salt FROM users WHERE username=?"
        else:
            sql = "SELECT scopes, disabled, secret_salt AS salt FROM clients WHERE client_id=?"
        row = conn.execute(sql, (subject,)).fetchone()
        return None if row is None or row["disabled"] else row

    def subject_state(self, subject_kind: str, subject: str) -> dict[str, Any] | None:
        """主体当前状态 {scopes, credential}；不存在或已停用返回 None。"""
        with self._conn() as conn:
            row = self._subject_row(conn, subject_kind, subject)
        if row is None:
            return None
        return {"scopes": row["scopes"].split(), "credential": _credential_tag(row["salt"])}

    def lookup_access(self, token: str) -> dict[str, Any] | None:
        """有效 access token 的元数据；过期、撤销、主体停用或删除都返回 None。

        scope 是签发时的 scope 与主体当前 scope 的交集：管理员收回的权限立即不再生效。"""
        if not token:
            return None
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE token_hash=? AND kind='access'",
                (_token_hash(token),)).fetchone()
            if row is None or row["revoked_at"] is not None or row["expires_at"] < time.time():
                return None
            subject = self._subject_row(conn, row["subject_kind"], row["subject"])
            if subject is None:
                return None
        current = set(subject["scopes"].split())
        return {
            "subject": row["subject"], "subject_kind": row["subject_kind"],
            "client_id": row["client_id"],
            "scope": [item for item in row["scope"].split() if item in current],
            "issued_at": row["issued_at"], "expires_at": row["expires_at"],
        }

    def rotate_refresh(self, token: str) -> tuple[str, dict[str, Any] | None]:
        """消费一个 refresh token。返回 (状态, 记录)：ok / reused / invalid。

        reused：该 refresh 已经换过新令牌又被出示，说明可能被复制，整族撤销。
        ok 时记录里的 scope 已与主体当前 scope 取交集（收回的权限不随 refresh 续上）；
        主体停用、删除，或交集为空，都算 invalid。
        """
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM tokens WHERE token_hash=? AND kind='refresh'",
                    (_token_hash(token or ""),)).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return "invalid", None
                if row["rotated_at"] is not None:
                    conn.execute(
                        "UPDATE tokens SET revoked_at=? WHERE family=? AND revoked_at IS NULL",
                        (now, row["family"]))
                    conn.execute("COMMIT")
                    return "reused", dict(row)
                subject = self._subject_row(conn, row["subject_kind"], row["subject"])
                current = set(subject["scopes"].split()) if subject is not None else set()
                granted = [item for item in row["scope"].split() if item in current]
                if row["revoked_at"] is not None or row["expires_at"] < now or not granted:
                    conn.execute("COMMIT")
                    return "invalid", None
                conn.execute("UPDATE tokens SET rotated_at=? WHERE token_hash=?",
                             (now, row["token_hash"]))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return "ok", {**dict(row), "scope": " ".join(granted)}

    def revoke_token(self, token: str) -> bool:
        """撤销单个令牌；撤销 refresh 时同族的 access 一并失效。"""
        now = time.time()
        with self._conn() as conn:
            row = conn.execute("SELECT kind, family FROM tokens WHERE token_hash=?",
                               (_token_hash(token or ""),)).fetchone()
            if row is None:
                return False
            if row["kind"] == "refresh":
                conn.execute(
                    "UPDATE tokens SET revoked_at=? WHERE family=? AND revoked_at IS NULL",
                    (now, row["family"]))
            else:
                conn.execute("UPDATE tokens SET revoked_at=? WHERE token_hash=?",
                             (now, _token_hash(token)))
        return True

    def revoke_subject(self, subject_kind: str, subject: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE tokens SET revoked_at=? WHERE subject_kind=? AND subject=?"
                " AND revoked_at IS NULL", (time.time(), subject_kind, subject))
            return cur.rowcount

    def purge_expired(self, grace_s: float = 86400) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM tokens WHERE expires_at < ?",
                               (time.time() - grace_s,))
            return cur.rowcount

    def active_token_count(self, subject_kind: str, subject: str) -> int:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM tokens WHERE subject_kind=? AND subject=?"
                " AND revoked_at IS NULL AND expires_at > ?",
                (subject_kind, subject, time.time())).fetchone()
        return int(row["n"])
