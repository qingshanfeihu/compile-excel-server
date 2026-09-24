"""设备授权流里“谁在授权”的认证后端（可插拔）。

设备流对外协议（/device_authorize、/token）不随后端变化；后端只决定授权页收哪些字段、
怎么判定这个人是谁、他最多能拿哪些 scope。

现有后端：
- private-mock：私有模拟。管理员用 `ces users add <名>` 建账号并拿到一次性显示的访问码，
  用户在授权页填用户名 + 访问码。库里只存访问码哈希。
企业身份（LDAP / OIDC 上游）以后按同一接口加一个类，登记进 BACKENDS。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from auth_store import AuthStore


@dataclass(frozen=True)
class FormField:
    name: str
    label: str
    input_type: str = "text"


@dataclass(frozen=True)
class Principal:
    username: str
    scopes: tuple[str, ...]


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

    # 同一用户名连续失败这么多次后锁定一段时间（进程内计数，重启清零）
    MAX_FAILURES = 5
    LOCK_SECONDS = 900

    def __init__(self, store: AuthStore):
        self.store = store
        self._failures: dict[str, tuple[int, float]] = {}

    def locked(self, username: str) -> bool:
        count, since = self._failures.get(username, (0, 0.0))
        if count < self.MAX_FAILURES:
            return False
        if time.time() - since > self.LOCK_SECONDS:
            self._failures.pop(username, None)
            return False
        return True

    def authenticate(self, form: dict[str, str]) -> Principal | None:
        username = (form.get("username") or "").strip()
        code = (form.get("access_code") or "").strip()
        if not username or not code or self.locked(username):
            return None
        record = self.store.verify_user(username, code)
        if record is None:
            count, _ = self._failures.get(username, (0, 0.0))
            self._failures[username] = (count + 1, time.time())
            return None
        self._failures.pop(username, None)
        return Principal(record["username"], tuple(record["scopes"]))


BACKENDS = {PrivateMockBackend.name: PrivateMockBackend}
DEFAULT_BACKEND = PrivateMockBackend.name


def make_backend(name: str, store: AuthStore) -> AuthBackend:
    try:
        factory = BACKENDS[name or DEFAULT_BACKEND]
    except KeyError:
        raise ValueError(f"未知认证后端 {name!r}（可用：{', '.join(BACKENDS)}）") from None
    return factory(store)
