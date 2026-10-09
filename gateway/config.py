"""网关配置（gateway.toml）。迁移表里“跳板机本机路径”那一组都在这里，不读任何 environment 文件。

必填项缺了就拒绝启动，不猜：conf 名不再按网卡地址推，框架路径不给默认。
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SERVICE_PROTOS = ("http", "https", "tcp", "udp", "dns")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class GatewayConfig:
    # 身份：向 compile-excel-server 内省令牌、取数据包
    server_url: str
    client_id: str
    client_secret_file: Path
    build: str
    # 服务端证书由内置 CA 签发时填那张 CA 证书（ces tls gateway 给出的 ca.pem）；空＝只用系统证书库
    ca_file: Path | None = None
    # 监听
    host: str = "127.0.0.1"
    port: int = 8910
    tls_cert: Path | None = None
    tls_key: Path | None = None
    insecure_lan: bool = False
    # 框架
    apv_src: Path = Path()
    py38: Path = Path()
    conf_name: str = ""
    staging_parent: Path = Path()
    default_module: str = ""
    run_max_s: int = 2400
    # 状态
    state_dir: Path = Path()
    lease_ttl_s: int = 1800
    # 结果库：给了口令文件就直连 MySQL，否则借框架自己的 Result_DB
    mysql_password_file: Path | None = None
    mysql_user: str = "root"
    mysql_db: str = "smoke_test"
    # 设备初始化（串口）；命令全在配置里，代码不写任何设备命令
    console_command: tuple[str, ...] = ("cu", "-s", "9600", "-l", "{tty}")
    tty_name: str = "ttyS{idx}"
    max_devices: int = 3
    init_commands: tuple[str, ...] = ()
    init_long_commands: dict[str, int] = field(default_factory=dict)
    init_step_timeout_s: int = 5
    login_timeout_s: int = 10
    # 本床常驻服务（运维维护的清单，bed_topology 原样带给客户端）：{host, ip, proto, port, note}
    bed_services: tuple[dict[str, Any], ...] = ()

    @property
    def conf_path(self) -> Path:
        return self.apv_src / "conf" / self.conf_name

    @property
    def is_loopback(self) -> bool:
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False


def _path(value: Any, what: str, *, required: bool = True) -> Path | None:
    if value in (None, ""):
        if required:
            raise ConfigError(f"缺少 {what}")
        return None
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        raise ConfigError(f"{what} 必须是绝对路径：{value}")
    return path


def _safe(value: Any, what: str) -> str:
    text = str(value or "")
    if not _SAFE.match(text) or ".." in text:
        raise ConfigError(f"{what} 只能含字母数字与 . _ -：{text!r}")
    return text


def _services(raw: Any) -> tuple[dict[str, Any], ...]:
    """[[bed.services]]：host 名、ip 地址、proto（http/https/tcp/udp/dns）、port、note（可省）。"""
    if raw in (None, []):
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise ConfigError("bed.services 必须是 [[bed.services]] 表数组")
    out = []
    for index, item in enumerate(raw):
        where = f"bed.services[{index}]"
        unknown = set(item) - {"host", "ip", "proto", "port", "note"}
        if unknown:
            raise ConfigError(f"{where} 有未知字段：{', '.join(sorted(unknown))}")
        host = _safe(item.get("host"), f"{where}.host")
        try:
            ip = str(ipaddress.ip_address(str(item.get("ip") or "")))
        except ValueError:
            raise ConfigError(f"{where}.ip 不是 IP 地址：{item.get('ip')!r}") from None
        proto = str(item.get("proto") or "").lower()
        if proto not in SERVICE_PROTOS:
            raise ConfigError(f"{where}.proto 只能是 {'/'.join(SERVICE_PROTOS)}：{proto!r}")
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ConfigError(f"{where}.port 必须是 1–65535 的整数：{port!r}")
        note = item.get("note", "")
        if not isinstance(note, str):
            raise ConfigError(f"{where}.note 必须是字符串")
        out.append({"host": host, "ip": ip, "proto": proto, "port": port, "note": note})
    return tuple(out)


def load(path: Path) -> GatewayConfig:
    try:
        raw = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"读不了配置 {path}：{exc}") from None
    server = raw.get("server") or {}
    listen = raw.get("listen") or {}
    fw = raw.get("framework") or {}
    state = raw.get("state") or {}
    results = raw.get("results") or {}
    device = raw.get("device") or {}
    init = raw.get("init_device") or {}
    bed = raw.get("bed") or {}

    url = str(server.get("url") or "").rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise ConfigError("server.url 必须是 http(s) 地址")
    if "#" in url or "?" in url:
        raise ConfigError("server.url 只填地址（例如 https://192.168.1.20:8900），不要带连接串里 # 后面的"
                          "部分；CA 证书另填 server.ca_file")
    conf_name = str(fw.get("conf_name") or "")
    if not conf_name:
        raise ConfigError("framework.conf_name 必填（不再按网卡地址推导）")
    if not conf_name.endswith(".conf"):
        conf_name += ".conf"
    tls_cert = _path(listen.get("tls_cert"), "listen.tls_cert", required=False)
    tls_key = _path(listen.get("tls_key"), "listen.tls_key", required=False)
    if bool(tls_cert) != bool(tls_key):
        raise ConfigError("listen.tls_cert 与 listen.tls_key 要么都给，要么都不给")
    ca_file = _path(server.get("ca_file"), "server.ca_file", required=False)
    if ca_file is not None and not ca_file.is_file():
        raise ConfigError(f"server.ca_file 不存在：{ca_file}")
    commands = init.get("commands") or []
    if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
        raise ConfigError("init_device.commands 必须是字符串列表")
    long_commands = init.get("long_commands") or {}
    if not isinstance(long_commands, dict):
        raise ConfigError("init_device.long_commands 必须是 {命令: 秒数}")
    console = device.get("console_command") or ["cu", "-s", "9600", "-l", "{tty}"]
    cfg = GatewayConfig(
        server_url=url,
        client_id=_safe(server.get("client_id"), "server.client_id"),
        client_secret_file=_path(server.get("client_secret_file"), "server.client_secret_file"),
        build=_safe(server.get("build"), "server.build"),
        ca_file=ca_file,
        host=str(listen.get("host") or "127.0.0.1"),
        port=int(listen.get("port") or 8910),
        tls_cert=tls_cert,
        tls_key=tls_key,
        insecure_lan=bool(listen.get("insecure_lan")),
        apv_src=_path(fw.get("apv_src"), "framework.apv_src"),
        py38=_path(fw.get("py38"), "framework.py38"),
        conf_name=_safe(conf_name, "framework.conf_name"),
        staging_parent=_path(fw.get("staging_parent"), "framework.staging_parent"),
        default_module=_safe(fw.get("default_module"), "framework.default_module"),
        run_max_s=int(fw.get("run_max_s") or 2400),
        state_dir=_path(state.get("dir"), "state.dir"),
        lease_ttl_s=int(state.get("lease_ttl_s") or 1800),
        mysql_password_file=_path(results.get("mysql_password_file"),
                                  "results.mysql_password_file", required=False),
        mysql_user=str(results.get("mysql_user") or "root"),
        mysql_db=str(results.get("mysql_db") or "smoke_test"),
        console_command=tuple(str(part) for part in console),
        tty_name=str(device.get("tty_name") or "ttyS{idx}"),
        max_devices=int(device.get("max_devices") or 3),
        init_commands=tuple(commands),
        init_long_commands={str(k): int(v) for k, v in long_commands.items()},
        init_step_timeout_s=int(init.get("step_timeout_s") or 5),
        login_timeout_s=int(init.get("login_timeout_s") or 10),
        bed_services=_services(bed.get("services")),
    )
    if not cfg.is_loopback and not cfg.tls_cert and not cfg.insecure_lan:
        raise ConfigError("监听非回环地址必须配 TLS（listen.tls_cert/tls_key），"
                          "或在受信任的实验网里显式设 listen.insecure_lan = true")
    return cfg
