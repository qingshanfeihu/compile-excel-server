"""网关的调用方只有一个：circle-hub 的 worker。它用静态密钥（Authorization: Bearer）证明自己，网关在本地
比对密钥的 SHA-256，不回调任何服务端。

- 密钥摘要文件只放密钥的 SHA-256（64 位十六进制一行），权限 0600；换密钥就是换文件内容，按 mtime 重读，
  不用重启网关。
- 可选的管理密钥另外带 jumphost:admin（init_device 用）；hub 只在设备初始化时拿它来调用。
- 调用方可以带 X-Circle-Hub-Actor 头说明替谁执行：它只进审计和租约持有人，不参与授权——授权是 hub 的事。
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import GatewayConfig

ACTOR_HEADER = "X-Circle-Hub-Actor"
RUN_SCOPES = frozenset({"jumphost:run"})
ADMIN_SCOPES = frozenset({"jumphost:run", "jumphost:admin"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@/-]{0,127}$")


class AuthError(RuntimeError):
    """密钥摘要文件缺失、权限不对或内容不是 SHA-256：网关自己的配置问题，回 503，不回 401。"""


class ActorError(ValueError):
    """X-Circle-Hub-Actor 不是合法的主体名。"""


@dataclass
class Caller:
    subject: str
    scopes: frozenset[str]


def secret_digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


class SecretFile:
    """按 mtime 缓存的密钥摘要文件。"""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._cached: tuple[tuple[int, int], str] | None = None
        self._lock = threading.Lock()

    def digest(self) -> str:
        try:
            info = self.path.stat()
        except OSError:
            raise AuthError(f"密钥摘要文件不存在：{self.path}") from None
        if info.st_mode & 0o077:
            raise AuthError(f"密钥摘要文件权限必须是 0600：{self.path}")
        key = (info.st_mtime_ns, info.st_size)
        with self._lock:
            if self._cached and self._cached[0] == key:
                return self._cached[1]
            text = self.path.read_text(encoding="utf-8").strip().lower()
            if not _HEX64.match(text):
                raise AuthError(f"密钥摘要文件内容必须是 64 位十六进制的 SHA-256：{self.path}")
            self._cached = (key, text)
            return text


def check_secret_file(path: Path) -> dict[str, Any]:
    """cexg check 用：文件在、0600、内容是 SHA-256。不打印任何内容。"""
    try:
        SecretFile(path).digest()
    except AuthError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "path": str(path)}


class StaticSecretAuth:
    def __init__(self, subject: str, secret_file: Path, admin_secret_file: Path | None = None):
        self.subject = subject
        self._run = SecretFile(secret_file)
        self._admin = SecretFile(admin_secret_file) if admin_secret_file else None

    @classmethod
    def from_config(cls, cfg: GatewayConfig) -> StaticSecretAuth:
        return cls(cfg.hub_subject, cfg.hub_secret_file, cfg.hub_admin_secret_file)

    def caller(self, bearer: str | None, actor: str | None = None) -> Caller | None:
        """Bearer 对得上就是 hub；对不上回 None（401）。两把密钥都比，不因第一把对上就省掉第二把。"""
        if not bearer:
            return None
        presented = secret_digest(bearer)
        scopes = None
        if hmac.compare_digest(presented, self._run.digest()):
            scopes = RUN_SCOPES
        if self._admin is not None and hmac.compare_digest(presented, self._admin.digest()):
            scopes = ADMIN_SCOPES
        if scopes is None:
            return None
        subject = self.subject
        if actor:
            if not _ACTOR.match(actor):
                raise ActorError(actor)
            subject = f"{self.subject}/{actor}"
        return Caller(subject=subject, scopes=scopes)
