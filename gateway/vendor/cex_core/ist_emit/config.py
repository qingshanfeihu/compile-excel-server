
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).resolve().parents[2]
# 路径参数化（skill 剪切）：上游固定读 InfoTest 根的 runtime/compiler_config.json；
# 这里优先 $COMPILE_EXCEL_COMPILER_CONFIG，缺省落到 skill 目录下的 runtime/（通常不存在，
# 即纯默认值运行）。env > 配置文件 > 默认 的取值顺序不变。
_CONFIG_PATH = Path(
    os.environ.get("COMPILE_EXCEL_COMPILER_CONFIG")
    or (_ROOT / "runtime" / "compiler_config.json")
)


def _load_file_config() -> dict:
    try:
        if _CONFIG_PATH.is_file():
            return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        logger.warning("配置文件读取/解析失败: %s", _CONFIG_PATH, exc_info=True)
    return {}


def _pick(env_key: str, file_cfg: dict, file_key: str, default: Any) -> Any:
    v = os.environ.get(env_key)
    if v is not None and str(v).strip() != "":
        return v
    if file_key in file_cfg and file_cfg[file_key] not in (None, ""):
        return file_cfg[file_key]
    return default


def _pick_port(env_key: str, file_cfg: dict, file_key: str, default: int) -> int:
    """端口取值：env > 配置文件 > 默认。

    与 `env_preflight._jumphost_port` / `env_identity._resolve_jumphost` /
    `device_mcp_server.deploy._jumphost_port` 是同一套顺序。取不成整数按默认值、
    不抛——那三处都这么兜；在这里抛会让预检按 `[host]:2222` 给绿灯而实连另一个口。
    """
    env_raw = os.environ.get(env_key)
    from_env = env_raw is not None and str(env_raw).strip() != ""
    source = env_key if from_env else f"配置文件 {file_key}"
    raw = _pick(env_key, file_cfg, file_key, default)
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning("%s 不是整数端口，按 %d 处理", source, default)
        return default
    if not 0 < port < 65536:
        # 配置文件写 `port: 0` 这类假值，那三处用 `or 22` 折成默认；这里同样折，
        # 否则预检说 22、现探拨 0——又是绿灯给错对象。
        logger.warning("%s 的端口 %d 不在 1–65535，按 %d 处理", source, port, default)
        return default
    return port


@dataclass
class JumphostConfig:

    host: str = ""
    user: str = ""
    port: int = 22
    apv_src: str = "/home/test/apv_src"
    server_path: str = "/home/test/mcp_server/server.py"
    py38: str = "/home/test/apv_src/.python3.8/bin/python"
    password_env: str = "IST_JUMPHOST_PASS"

    @property
    def server_cmd(self) -> str:
        return f"cd {self.apv_src} && {self.py38} {self.server_path}"


@dataclass
class XlsxLayout:

    header_row: int = 28
    data_start: int = 29
    header_anchor: str = "自动化ID"
    n_cols: int = 9


@dataclass
class CompilerConfig:

    build: str = "InfosecOS_Beta_APV_HG_K_10_5_0_585"
    target_version: str = "10.5.0.585"

    staging_module: str = "sdns"

    mysql_host: str = ""
    mysql_db: str = "smoke_test"
    mysql_user: str = "root"
    mysql_password_env: str = "IST_MYSQL_PASS"

    jumphost: JumphostConfig = field(default_factory=JumphostConfig)
    xlsx: XlsxLayout = field(default_factory=XlsxLayout)

    default_init_lines: list[str] = field(default_factory=list)

    @classmethod
    def load(cls) -> "CompilerConfig":
        fc = _load_file_config()
        jh_fc = fc.get("jumphost", {}) or {}
        xl_fc = fc.get("xlsx", {}) or {}

        jh = JumphostConfig(
            host=_pick("IST_JUMPHOST_HOST", jh_fc, "host", JumphostConfig.host),
            user=_pick("IST_JUMPHOST_USER", jh_fc, "user", JumphostConfig.user),
            port=_pick_port("IST_JUMPHOST_PORT", jh_fc, "port", JumphostConfig.port),
            apv_src=_pick("IST_APV_SRC", jh_fc, "apv_src", JumphostConfig.apv_src),
            server_path=_pick("IST_MCP_SERVER_PATH", jh_fc, "server_path", JumphostConfig.server_path),
            py38=_pick("IST_JUMPHOST_PY38", jh_fc, "py38", JumphostConfig.py38),
        )
        xl = XlsxLayout(
            header_row=int(_pick("IST_XLSX_HEADER_ROW", xl_fc, "header_row", XlsxLayout.header_row)),
            data_start=int(_pick("IST_XLSX_DATA_START", xl_fc, "data_start", XlsxLayout.data_start)),
            header_anchor=_pick("IST_XLSX_HEADER_ANCHOR", xl_fc, "header_anchor", XlsxLayout.header_anchor),
        )
        init = fc.get("default_init")
        if not isinstance(init, list) or not init:
            init = None
        return cls(
            build=_pick("IST_DEVICE_BUILD", fc, "build", cls.build),
            target_version=_pick("IST_TARGET_VERSION", fc, "target_version", cls.target_version),
            staging_module=_pick("IST_STAGING_MODULE", fc, "staging_module", cls.staging_module),
            mysql_host=_pick("IST_MYSQL_HOST", fc, "mysql_host", cls.mysql_host),
            mysql_db=_pick("IST_MYSQL_DB", fc, "mysql_db", cls.mysql_db),
            mysql_user=_pick("IST_MYSQL_USER", fc, "mysql_user", cls.mysql_user),
            jumphost=jh,
            xlsx=xl,
            default_init_lines=(init or list(cls().default_init_lines)),
        )

    def default_init_g(self) -> str:
        return "\n".join("    " + line for line in self.default_init_lines)

    def to_dict(self) -> dict:
        return asdict(self)


_CACHED: Optional[CompilerConfig] = None


def get_config(reload: bool = False) -> CompilerConfig:
    global _CACHED
    if _CACHED is None or reload:
        _CACHED = CompilerConfig.load()
    return _CACHED


@dataclass
class Environment:

    id: str
    jumphost: str
    ssh_user: str = ""
    ssh_port: int = 22
    pass_env: str = "IST_JUMPHOST_PASS"
    apv_src: str = "/home/test/apv_src"
    server_path: str = "/home/test/mcp_server/server.py"
    py38: str = "/home/test/apv_src/.python3.8/bin/python"
    mcp_url: str = ""
    topology: str = "network_topology.json"

    @property
    def server_cmd(self) -> str:
        return f"cd {self.apv_src} && {self.py38} {self.server_path}"


def _pool_enabled() -> bool:
    return (os.environ.get("IST_ENV_POOL_ENABLED") or "0").strip().lower() in (
        "1", "true", "on", "yes",
    )


def load_environments() -> list["Environment"]:
    cfg = get_config()
    jh = cfg.jumphost

    def _mk(host: str) -> Environment:
        host = host.strip()
        return Environment(
            id=f"env-{host.rsplit('.', 1)[-1]}",
            # 端口跟配置走，不落回 22：池关时这一份就是现役单环境，写死 22 会与
            # 预检 / deploy 认的 `IST_JUMPHOST_PORT` 分叉。
            jumphost=host, ssh_user=jh.user, ssh_port=jh.port,
            pass_env=jh.password_env,
            apv_src=jh.apv_src, server_path=jh.server_path, py38=jh.py38,
            mcp_url=f"http://{host}:8000/mcp",
        )

    if not _pool_enabled():
        return [_mk(jh.host)]

    fc = _load_file_config()
    raw = fc.get("environments")
    if isinstance(raw, list) and raw:
        out: list[Environment] = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("jumphost"):
                continue
            host = str(item["jumphost"]).strip()
            out.append(Environment(
                id=str(item.get("id") or f"env-{host.rsplit('.', 1)[-1]}"),
                jumphost=host,
                ssh_user=str(item.get("ssh_user") or jh.user),
                # 条目没声明端口就继承配置里的那个，不落回 22（同上）。
                ssh_port=int(item.get("ssh_port") or jh.port),
                pass_env=str(item.get("pass_env") or jh.password_env),
                apv_src=str(item.get("apv_src") or jh.apv_src),
                server_path=str(item.get("server_path") or jh.server_path),
                py38=str(item.get("py38") or jh.py38),
                mcp_url=str(item.get("mcp_url") or f"http://{host}:8000/mcp"),
                topology=str(item.get("topology") or "network_topology.json"),
            ))
        if out:
            return out

    env_hosts = (os.environ.get("IST_ENV_POOL_HOSTS") or "").strip()
    hosts = [h.strip() for h in env_hosts.split(",") if h.strip()]
    seen: set[str] = set()
    hosts = [h for h in hosts if not (h in seen or seen.add(h))]
    return [_mk(h) for h in hosts]


def detect_xlsx_layout(grid: list[list[Any]], cfg: Optional[CompilerConfig] = None) -> XlsxLayout:
    cfg = cfg or get_config()
    anchor = cfg.xlsx.header_anchor
    for idx, row in enumerate(grid):
        a = row[0] if row else None
        if a is not None and str(a).strip() == anchor:
            header_1based = idx + 1
            return XlsxLayout(
                header_row=header_1based,
                data_start=header_1based + 1,
                header_anchor=anchor,
                n_cols=cfg.xlsx.n_cols,
            )
    return cfg.xlsx
