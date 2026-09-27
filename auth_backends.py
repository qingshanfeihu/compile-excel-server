"""设备授权流里“谁在授权”的认证后端（可插拔）。

设备流对外协议（/device_authorize、/token）不随后端变化；后端只决定授权页收哪些字段、
怎么判定这个人是谁、他最多能拿哪些 scope。

现有后端：
- private-mock：内置的“管理员发放访问码”后端（名字沿用早期的“私有模拟”）。管理员用
  `ces users add <名>` 建账号并拿到一次性显示的访问码，用户在授权页填用户名 + 访问码。
  库里只存访问码哈希。
企业身份（LDAP / OIDC 上游）以后按同一接口加一个类，登记进 BACKENDS。

authenticate 在线程池里调用（服务端不让哈希校验占住事件循环），实现要线程安全。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol

from auth_store import AuthStore, valid_name


@dataclass(frozen=True)
class FormField:
    name: str
    label: str
    input_type: str = "text"


@dataclass(frozen=True)
class Principal:
    username: str
    scopes: tuple[str, ...]
    # 凭据指纹：授权与兑换令牌之间凭据被重置，兑换时就对不上（后端给不出时留空）
    credential: str = ""


class AuthBackend(Protocol):
    name: str
    fields: tuple[FormField, ...]

    def authenticate(self, form: dict[str, str]) -> Principal | None: ...


class PrivateMockBackend:
    name = "private-mock"
    fields = (
        FormField("username", "用户名"),
        FormField("access_code", "访问码", "password"),
    )

    # 同一账号在 LOCK_SECONDS 内连续失败这么多次后锁定 LOCK_SECONDS（进程内计数，重启清零）。
    # 只给真实存在的账号计数：随手填的用户名不进表，表的大小以账号数为界，另有 MAX_TRACKED 兜底。
    MAX_FAILURES = 5
    LOCK_SECONDS = 900
    MAX_TRACKED = 10_000

    def __init__(self, store: AuthStore):
        self.store = store
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def locked(self, username: str) -> bool:
        with self._lock:
            count, since = self._failures.get(username, (0, 0.0))
            if count < self.MAX_FAILURES:
                return False
            if time.time() - since > self.LOCK_SECONDS:
                self._failures.pop(username, None)
                return False
            return True

    def _evict(self, now: float) -> None:
        """表满了：先丢窗口外的旧记录，还满就丢最早的一半。调用方持锁。"""
        for name in [n for n, (_, since) in self._failures.items()
                     if now - since > self.LOCK_SECONDS]:
            del self._failures[name]
        if len(self._failures) >= self.MAX_TRACKED:
            oldest = sorted(self._failures, key=lambda n: self._failures[n][1])
            for name in oldest[:len(oldest) // 2]:
                del self._failures[name]

    def _record_failure(self, username: str) -> None:
        now = time.time()
        with self._lock:
            if username not in self._failures and len(self._failures) >= self.MAX_TRACKED:
                self._evict(now)
            count, since = self._failures.get(username, (0, 0.0))
            if now - since > self.LOCK_SECONDS:
                count = 0  # 上一次失败已在窗口之外：重新计数
            self._failures[username] = (count + 1, now)

    def authenticate(self, form: dict[str, str]) -> Principal | None:
        username = (form.get("username") or "").strip()
        code = (form.get("access_code") or "").strip()
        if not valid_name(username) or not code:
            return None
        if self.locked(username):
            # 锁定期内也照常走一遍哈希与查库：耗时不暴露“这个账号存在且被锁”
            self.store.verify_user("", code)
            self.store.user_exists(username)
            return None
        record = self.store.verify_user(username, code)
        if record is None:
            if self.store.user_exists(username):
                self._record_failure(username)
            return None
        with self._lock:
            self._failures.pop(username, None)
        return Principal(record["username"], tuple(record["scopes"]),
                         str(record.get("credential") or ""))


BACKENDS = {PrivateMockBackend.name: PrivateMockBackend}
DEFAULT_BACKEND = PrivateMockBackend.name


def make_backend(name: str, store: AuthStore) -> AuthBackend:
    try:
        factory = BACKENDS[name or DEFAULT_BACKEND]
    except KeyError:
        raise ValueError(f"未知认证后端 {name!r}（可用：{', '.join(BACKENDS)}）") from None
    return factory(store)
