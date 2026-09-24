"""组织下发给客户端的常量（`GET /v1/config/client`）。

放的是每台客户端都一样、又不该写死在 skill 里的东西：门户地址、缺陷系统地址、网关地址。
这里只放非机密的网络地址；任何像凭据的键名或带账号口令的 URL 都拒收——
个人门户账号一律不保存，走客户端扫码登录。

存储：<数据目录>/client_config.json。管理：`ces config show|set|unset|import-env`。
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA = "cex.client-config/v1"

# 可配置键（点分路径）与说明；只收这些，拼错的键直接报错
KEYS: dict[str, str] = {
    "portal.login_url": "零信任门户登录地址",
    "portal.login_url_alt": "备用门户登录地址",
    "defects.bugzilla.base_url": "Bugzilla 直连地址",
    "defects.bugzilla.proxy_url": "经门户代理的 Bugzilla 地址",
    "defects.zentao.base_url": "禅道地址",
    "defects.plm.proxy_url": "经门户代理的 PLM 地址",
    "gateway.url": "跳板机网关 MCP 地址",
}

# InfoTest environment 里可迁移过来的键（只迁地址；账号口令一律不迁）
IMPORT_ENV_MAP: dict[str, str] = {
    "PORTAL_LOGIN_URL": "portal.login_url",
    "PORTAL_LOGIN_URL_ALT": "portal.login_url_alt",
    "BUGZILLA_BASE_URL": "defects.bugzilla.base_url",
    "BUGZILLA_PROXY_URL": "defects.bugzilla.proxy_url",
    "ZENTAO_BASE_URL": "defects.zentao.base_url",
    "PLM_PROXY_URL": "defects.plm.proxy_url",
}

_SECRETISH = re.compile(r"pass|secret|token|cookie|credential|api_?key|private|session",
                        re.IGNORECASE)


class ConfigError(ValueError):
    pass


def config_path(data_dir: Path) -> Path:
    return Path(data_dir) / "client_config.json"


def _check_url(key: str, value: str) -> str:
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{key} 需要 http(s) 地址")
    if parts.username or parts.password:
        raise ConfigError(f"{key} 不能带账号口令（门户账号不保存，客户端扫码登录）")
    return value


def _flatten(tree: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in tree.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def validate(tree: dict[str, Any]) -> dict[str, str]:
    """返回扁平化的已校验键值；任何越界都抛 ConfigError。"""
    if not isinstance(tree, dict):
        raise ConfigError("client_config.json 顶层必须是对象")
    flat = _flatten({k: v for k, v in tree.items() if k != "schema"})
    checked: dict[str, str] = {}
    for key, value in flat.items():
        if _SECRETISH.search(key):
            raise ConfigError(f"拒收疑似凭据的键：{key}")
        if key not in KEYS:
            raise ConfigError(f"未知键：{key}（可用：{', '.join(KEYS)}）")
        if value in ("", None):
            continue
        if not isinstance(value, str):
            raise ConfigError(f"{key} 必须是字符串")
        checked[key] = _check_url(key, value)
    return checked


def _nest(flat: dict[str, str]) -> dict[str, Any]:
    tree: dict[str, Any] = {}
    for key, value in sorted(flat.items()):
        node = tree
        *parents, leaf = key.split(".")
        for part in parents:
            node = node.setdefault(part, {})
        node[leaf] = value
    return tree


def load(data_dir: Path) -> dict[str, str]:
    path = config_path(data_dir)
    if not path.is_file():
        return {}
    try:
        tree = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} 不是合法 JSON：{exc}") from None
    return validate(tree)


def document(data_dir: Path) -> dict[str, Any]:
    """下发给客户端的完整文档。"""
    return {"schema": SCHEMA, **_nest(load(data_dir))}


def save(data_dir: Path, flat: dict[str, str]) -> None:
    validate(_nest(flat))
    path = config_path(data_dir)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"schema": SCHEMA, **_nest(flat)}, ensure_ascii=False, indent=1)
                   + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def set_key(data_dir: Path, key: str, value: str) -> None:
    if key not in KEYS:
        raise ConfigError(f"未知键：{key}（可用：{', '.join(KEYS)}）")
    flat = load(data_dir)
    flat[key] = _check_url(key, value)
    save(data_dir, flat)


def unset_key(data_dir: Path, key: str) -> bool:
    flat = load(data_dir)
    removed = flat.pop(key, None) is not None
    save(data_dir, flat)
    return removed


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        name, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name.strip()] = value
    return values


def import_env(data_dir: Path, env_file: Path) -> tuple[list[str], list[str]]:
    """按白名单从 InfoTest 的 environment 导入地址。返回 (已导入的键, 跳过的原因)。

    不回显任何值；账号口令类变量根本不在白名单里。
    """
    source = _parse_env_file(env_file)
    flat = load(data_dir)
    imported: list[str] = []
    skipped: list[str] = []
    for env_name, key in IMPORT_ENV_MAP.items():
        value = source.get(env_name, "").strip()
        if not value:
            continue
        try:
            flat[key] = _check_url(key, value)
        except ConfigError as exc:
            skipped.append(f"{env_name}: {exc}")
            continue
        imported.append(f"{env_name} → {key}")
    save(data_dir, flat)
    return imported, skipped
