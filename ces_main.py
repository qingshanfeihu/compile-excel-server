#!/usr/bin/env python3
"""compile-excel-server 统一入口（ces）。

用法：ces（不带参数）进入管理菜单；下面的子命令供脚本使用，菜单里每做完一步也会显示对应的命令。

  setup [...]                配置向导；带参数时不提问，直接安装
  status / link / version    运行状态 / 发给用户的连接串 / 版本号
  start | stop | restart | log   启动、停止、重启、看日志
  service install|remove|print [--user 账号]   开机自启（systemd / launchd）
  update [--version 版本]    更新到最新版（或指定版本），数据目录不动
  uninstall [--purge]        卸载（--purge 连数据目录一起删）
  users add|list|disable|enable|reset-code|scopes   账号与访问码
  clients add|list|remove|rotate-secret              服务客户端（网关、发布器）
  tokens revoke|purge        撤销令牌、清理过期记录
  tls show|renew|gateway     证书：查看、重新签发服务器证书、为网关签发证书
  config show|set|unset|import-env   下发给客户端的地址（网关、门户、缺陷系统）
  docs list|add              知识库手册（markdown）
  artifacts list|add|build|kms        旧版工件、构建号、KMS 地址
  registry list|bundles|show|import-dir|promote|verify|gc   数据包
  audit verify|rotate        复核审计日志、封存当前段并起新链
  generate --inputs D --out D [...]   服务端生成链（只在源码安装里可用）
  serve                      前台运行服务（给服务管理器用）

管理命令默认作用于安装时登记的数据目录，也可以加 --data <目录>。
改动账号、客户端、令牌、证书、配置、数据包的命令都写进服务端审计日志（<数据目录>/audit.log）。
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

if getattr(sys, "frozen", False):  # PyInstaller onedir
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    ROOT = Path(__file__).resolve().parent


from deploy.paths import config_root, system_env  # noqa: E402

CONFIG_ROOT = config_root()
INSTALL_JSON = CONFIG_ROOT / "install.json"
REPO = os.environ.get("CES_REPO") or "qingshanfeihu/compile-excel-server"
# 最近一次 registry import-dir 的结果（菜单"导入后马上发布"要发布的正是这次导入的包）
LAST_IMPORT: dict = {}
DEFAULT_PORT = 8900


# ── 安装登记 ──────────────────────────────────────────────
def load_install() -> dict:
    try:
        data = json.loads(INSTALL_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"还没有配置过（找不到 {INSTALL_JSON}）：先运行 ces setup")
        raise SystemExit(2)
    if not isinstance(data, dict) or "data" not in data:
        print(f"安装登记损坏（{INSTALL_JSON}）：重新运行 ces setup")
        raise SystemExit(2)
    return data


def installed() -> dict | None:
    """安装登记；还没配置过时返回 None（菜单首页用，不退出）。"""
    try:
        data = json.loads(INSTALL_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and "data" in data else None


# ── 进程/健康 ────────────────────────────────────────────
def _pid_file(install: dict) -> Path:
    return Path(install["data"]) / "server.pid"


def _read_pid(install: dict) -> int | None:
    try:
        return int(_pid_file(install).read_text().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _host(install: dict) -> str:
    return str(install.get("host") or "127.0.0.1").strip()


def healthz(port: int, timeout: float = 2.0, host: str = "127.0.0.1",
            tls_cert: str = "") -> dict | None:
    from deploy.tls_policy import healthz as probe

    return probe(port, host=host, tls_cert=tls_cert, timeout=timeout)


def _health(install: dict, timeout: float = 2.0) -> dict | None:
    return healthz(install["port"], timeout=timeout, host=_host(install),
                   tls_cert=str(install.get("tls_cert") or ""))


def _legacy_plaintext(install: dict) -> bool:
    """TLS 规则之前装的非回环明文实例：install.json 里没有任何 TLS 相关键。"""
    from deploy.tls_policy import is_loopback_host

    return (not install.get("tls_cert") and "insecure_lan" not in install
            and not is_loopback_host(_host(install)))


def _tls_argv(install: dict) -> list[str]:
    argv: list[str] = []
    if install.get("tls_cert") and install.get("tls_key"):
        argv += ["--tls-cert", str(install["tls_cert"]), "--tls-key", str(install["tls_key"])]
    if install.get("insecure_lan"):
        argv.append("--insecure-lan")
    elif _legacy_plaintext(install):
        # 旧安装照旧起（升级不能把在用的服务停掉），但每次都提示
        print(f"警告：监听 {_host(install)} 却没有证书，登录令牌会明文经过网络。运行 ces setup 重新配置"
              "（选“自动生成证书”）；确认是可信实验网的话，在 install.json 里写 \"insecure_lan\": true "
              "就不再提示。", file=sys.stderr)
        argv.append("--insecure-lan")
    return argv


def program_prefix() -> Path:
    """安装包形态的程序根目录（~/.local/share/compile-excel-server 之类）。
    程序实际在 <根>/versions/<版本>/compile-excel-server/，<根>/current 是指向当前版本的链接。"""
    exe = Path(sys.executable).resolve()
    for parent in exe.parents:
        if parent.name == "versions":
            return parent.parent
    if exe.parent.parent.name == "current":  # 旧布局：current 本身就是目录
        return exe.parent.parent.parent
    return Path(os.environ.get("CES_PREFIX") or Path.home() / ".local/share/compile-excel-server")


def stable_executable() -> str:
    """写进服务单元、更新后重启用的程序路径：走 current 链接，更新后自动指向新版本。"""
    exe = Path(sys.executable)
    if not getattr(sys, "frozen", False):
        return str(exe)
    stable = program_prefix() / "current" / exe.name / exe.name
    try:
        if stable.resolve() == exe.resolve():
            return str(stable)
    except OSError:
        pass
    return str(exe)


def self_command(*args: str) -> str:
    """提示用户手动运行时给出的完整命令（用绝对路径：sudo 的 PATH 里没有 ~/.local/bin）。"""
    import shlex

    base = ([stable_executable()] if getattr(sys, "frozen", False)
            else [sys.executable, str(ROOT / "ces_main.py")])
    return shlex.join([*base, *args])


def _serve_argv(install: dict) -> list[str]:
    if getattr(sys, "frozen", False):
        return [stable_executable(), "serve",
                "--data", install["data"], "--port", str(install["port"]),
                "--host", _host(install), *_tls_argv(install)]
    return [sys.executable, str(ROOT / "ces_main.py"), "serve",
            "--data", install["data"], "--port", str(install["port"]),
            "--host", _host(install), *_tls_argv(install)]


def _detached_popen(argv: list[str], log_path: Path) -> int:
    log = open(log_path, "ab")
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0))
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(argv, stdout=log, stderr=log, **kwargs)
    return proc.pid


# ── 连接串与证书 ─────────────────────────────────────────
def _lan_ip() -> str:
    """监听全部网卡时连接串里写哪个地址：有默认路由走默认路由那块网卡，否则取第一块网卡；
    都没有返回空串（调用方提示用 ces link --host 指定）。"""
    from deploy import certs

    return certs.default_route_ip() or next(iter(certs.interface_addresses()), "")


def connection_info(install: dict) -> dict:
    """发给用户的连接串。内置 CA 签的证书带 #ca=<CA 指纹>，客户端凭它核对证书。
    install.json 的 advertise_host（ces link --host 设置）优先：多网卡、经映射访问时用。"""
    from deploy import certs
    from deploy.tls_policy import is_loopback_host

    host = _host(install)
    data = Path(install["data"])
    tls_cert = str(install.get("tls_cert") or "")
    shown = str(install.get("advertise_host") or "")
    guessed = False
    if not shown:
        shown = host
        if host in ("0.0.0.0", "::", ""):
            shown = _lan_ip()
            guessed = True
    no_address = not shown
    shown = shown or "127.0.0.1"
    if ":" in shown and not shown.startswith("["):
        shown = f"[{shown}]"
    url = f"{'https' if tls_cert else 'http'}://{shown}:{install['port']}"
    info = {"url": url, "link": url, "fingerprint": "", "local_only": is_loopback_host(host),
            "guessed": guessed, "no_address": no_address}
    if certs.is_builtin(data, tls_cert):
        fp = certs.fingerprint(certs.ca_paths(data)[0])
        label = "https，内置 CA 签发"
        try:
            days = certs.cert_info(Path(tls_cert))["days_left"]
            if days <= certs.RENEW_BEFORE_DAYS:
                label += f"（证书还剩 {days} 天到期，运行 ces tls renew 后重启）"
        except (OSError, ValueError, certs.CertError):
            label += "（读不出证书，运行 ces tls show 查看）"
        info.update(link=f"{url}#ca={fp}", fingerprint=fp, tls="builtin", tls_label=label)
    elif tls_cert:
        info.update(tls="custom", tls_label="https，自备证书")
    elif info["local_only"]:
        info.update(tls="plain", tls_label="http（只本机访问）")
    else:
        info.update(tls="plain", tls_label="http 明文（已确认是可信实验网）")
    return info


def _write_install(install: dict) -> None:
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    INSTALL_JSON.write_text(json.dumps(install, ensure_ascii=False, indent=1), encoding="utf-8")


def cmd_link(rest: list[str] | None = None) -> int:
    from deploy import certs

    args = list(rest or [])
    host = _pop_option(args, "--host")
    install = load_install()
    if host is not None:
        host = host.strip().strip("[]")
        if host in ("", "auto"):
            install.pop("advertise_host", None)
            print("连接串里的地址改回自动选择。")
        else:
            try:
                certs._split_names([host])
            except certs.CertError as exc:
                print(str(exc))
                return 64
            install["advertise_host"] = host
            print(f"连接串里的地址改为 {host}。")
        _write_install(install)
        tls_cert = str(install.get("tls_cert") or "")
        data = Path(install["data"])
        missing = (host not in ("", "auto") and certs.is_builtin(data, tls_cert)
                   and host.lower() not in {n.lower()
                                            for n in certs.cert_info(Path(tls_cert))["names"]})
        if missing:
            try:
                certs.ensure_server_cert(data, [host])
            except certs.CertError as exc:
                print(str(exc))
                return 1
            _admin_audit(data, "admin_tls_renewed", names=certs.cert_info(Path(tls_cert))["names"])
            print(f"服务器证书里原来没有 {host}，已重新签发并加上；{RESTART_HINT}")
        print()
    info = connection_info(install)
    print("连接串（原样发给用户）：")
    print(f"  {info['link']}")
    print()
    print("用户在编译助手里说：“初始化编译工作区，连接串是 <上面这一行>”，再按提示在浏览器里登录。")
    if info["fingerprint"]:
        print(f"CA 证书指纹（电话里核对用）：{certs.pretty_fingerprint(info['fingerprint'])}")
    if info["local_only"]:
        print("注意：服务只监听本机，别的电脑连不上。要给局域网用，运行 ces setup 重新配置，"
              "选“给局域网里的其他电脑用”。")
    elif info["tls"] == "plain":
        print("注意：这是明文连接，用户初始化时要同时说明“这是可信实验网，允许明文”。")
    elif info["tls"] == "custom":
        print("注意：用的是自备证书，用户电脑要信任签发它的 CA；地址要用证书里写的域名或 IP。")
    if info["no_address"]:
        print("注意：没找到本机的局域网地址，上面只能先写 127.0.0.1。用 ces link --host <本机地址> 指定。")
    elif info["guessed"]:
        others = [a for a in certs.interface_addresses() if a not in info["url"]]
        if others:
            print(f"本机还有这些地址：{'、'.join(others)}。用户在别的网段时，"
                  "用 ces link --host <地址> 改连接串里的地址。")
    return 0


def cmd_tls(rest: list[str]) -> int:
    from deploy import certs

    data, args = _admin_args(rest)
    install = installed() or {}
    action = args[0] if args else ""
    tls_cert = str(install.get("tls_cert") or "")
    builtin = certs.is_builtin(data, tls_cert)
    try:
        if action == "show":
            if not tls_cert:
                print("服务没有配证书（http）。要改成 https，运行 ces setup 重新配置。")
                return 0
            info = certs.cert_info(Path(tls_cert))
            print(f"方式    ：{'内置 CA 签发' if builtin else '自备证书'}")
            print(f"证书文件：{tls_cert}")
            print(f"包含地址：{', '.join(info['names']) or '（没有）'}")
            print(f"到期    ：{info['expires']}（还剩 {info['days_left']} 天）")
            if builtin:
                fp = certs.fingerprint(certs.ca_paths(data)[0])
                print(f"CA 指纹 ：{certs.pretty_fingerprint(fp)}")
            return 0
        if action == "renew":
            names, removed = [], []
            while "--name" in args:
                names.append(_pop_option(args, "--name") or "")
            while "--remove" in args:
                removed.append(_pop_option(args, "--remove") or "")
            if not builtin:
                print("服务没有使用内置 CA，不能在这里重新签发。要改用内置 CA，运行 ces setup 重新配置。")
                return 1
            advertise = [str(install["advertise_host"])] if install.get("advertise_host") else []
            wanted = certs.local_names(_host(install)) + advertise + names
            cert, _ = certs.ensure_server_cert(data, wanted, force=True, remove=removed)
            info = certs.cert_info(cert)
            _admin_audit(data, "admin_tls_renewed", names=info["names"])
            print(f"已重新签发服务器证书（以前加过的地址都保留），包含：{', '.join(info['names'])}")
            print("重启服务后生效（ces restart）。CA 没变，用户不用重新初始化。")
            return 0
        if action == "gateway":
            out = _pop_option(args, "--out")
            names = args[1:]
            if not names or not out:
                print("用法：ces tls gateway <跳板机的 IP 或主机名>... --out <目录>")
                return 64
            if not builtin:
                print("服务没有使用内置 CA：客户端只认服务端的 CA，网关证书请用签发服务端证书的同一个 CA 签。")
                return 1
            target = Path(out).expanduser()
            cert = certs.issue(data, names, target / "gateway.pem", target / "gateway.key")
            ca_copy = target / "ca.pem"
            ca_copy.write_bytes(certs.ca_paths(data)[0].read_bytes())
            info = certs.cert_info(cert)
            _admin_audit(data, "admin_tls_gateway_issued", names=info["names"])
            print(f"已签发网关证书（包含：{', '.join(info['names'])}）：")
            print(f"  {target / 'gateway.pem'}   证书")
            print(f"  {target / 'gateway.key'}   私钥（0600）")
            print(f"  {ca_copy}         服务端的 CA 证书（网关用它校验服务端）")
            print("把这三个文件拷到跳板机，gateway.toml 里：[listen] tls_cert / tls_key 指向前两个，"
                  "[server] ca_file 指向 ca.pem。")
            return 0
    except certs.CertError as exc:
        print(str(exc))
        return 1
    print("用法：ces tls show | renew [--name 加上的地址]... [--remove 去掉的地址]... | "
          "gateway <地址>... --out <目录>")
    return 64


# ── 子命令 ───────────────────────────────────────────────
def _build_and_kms(data: Path) -> tuple[str, str]:
    try:
        meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
        build = str(meta.get("device_build") or "")
        if build in ("", "DEVICE_BUILD_PLACEHOLDER"):  # provision 写的占位值
            build = "-"
        return build, str(meta.get("kms_addr") or "")
    except (OSError, ValueError, AttributeError):
        return "-", ""


def autostart_registered(install: dict) -> bool:
    unit = _service_unit_path(install)
    return bool(unit and unit.exists())


def cmd_status() -> None:
    from ces_version import __version__

    install = load_install()
    pid = _read_pid(install)
    alive = _pid_alive(pid)
    health = _health(install)
    build, _ = _build_and_kms(Path(install["data"]))
    info = connection_info(install)
    if health:
        running = f"运行中（pid {pid}）" if alive else "运行中（由系统服务管理）"
    else:
        running = "进程在，但没有响应（看日志：ces log）" if alive else "未运行"
    print(f"compile-excel-server {__version__}")
    print(f"  服务    ：{running}")
    print(f"  连接串  ：{info['link']}")
    print(f"  证书    ：{info['tls_label']}")
    print(f"  开机自启：{'是' if autostart_registered(install) else '否'}")
    if build != "-":
        print(f"  旧版构建号：{build}")
    print(f"  数据目录：{install['data']}")


SERVICE_NAME = "compile-excel-server"
VERB_LABELS = {"start": "启动", "stop": "停止", "restart": "重启"}
LAUNCHD_LABEL = "io.github.qingshanfeihu.compile-excel-server"


def _system(argv: list[str], *, quiet: bool = False) -> int:
    """调系统程序（systemctl、launchctl）：用还原过的环境变量，不让它加载到包里自带的库。"""
    out = subprocess.DEVNULL if quiet else None
    return subprocess.run(argv, check=False, env=system_env(), stdout=out, stderr=out).returncode


def _managed(install: dict, verb: str) -> bool:
    """注册了开机自启时，启停交给系统服务管理器（否则 pid 文件管不到它起的进程）。
    返回 True 表示已处理。"""
    if not autostart_registered(install):
        return False
    if sys.platform.startswith("linux"):
        if _system(["systemctl", verb, SERVICE_NAME]) != 0:
            print(f"需要管理员权限：sudo systemctl {verb} {SERVICE_NAME}")
            raise SystemExit(1)
        print(f"已{VERB_LABELS[verb]}（systemd）")
        return True
    if sys.platform == "darwin":
        unit = str(_service_unit_path(install))
        if verb == "stop":
            _system(["launchctl", "unload", unit], quiet=True)
            print("已停止（launchd；ces start 或下次登录时再起）")
            return True
        # restart：服务在就 kickstart；被 stop 卸载过（kickstart 找不到它）就重新 load
        if verb == "restart" and _system(["launchctl", "kickstart", "-k",
                                          f"gui/{os.getuid()}/{LAUNCHD_LABEL}"], quiet=True) == 0:
            print("已重启（launchd）")
            return True
        _system(["launchctl", "load", unit], quiet=True)
        print(f"已{VERB_LABELS[verb]}（launchd）")
        return True
    return False


def _wait_healthy(install: dict) -> None:
    for _ in range(40):
        if _health(install, timeout=1):
            print(f"服务已就绪：{connection_info(install)['url']}")
            return
        time.sleep(0.5)
    print(f"服务没有响应，看日志：ces log（{Path(install['data']) / 'server.log'}）",
          file=sys.stderr)
    raise SystemExit(1)


def cmd_start() -> None:
    install = load_install()
    if _managed(install, "start"):
        _wait_healthy(install)
        return
    if _pid_alive(_read_pid(install)):
        print(f"已在运行（pid {_read_pid(install)}）")
        return
    if _health(install):
        print(f"端口 {install['port']} 上已经有一个实例在运行")
        return
    pid = _detached_popen(_serve_argv(install), Path(install["data"]) / "server.log")
    _pid_file(install).write_text(str(pid))
    print(f"已启动（pid {pid}）")
    _wait_healthy(install)


def cmd_stop() -> None:
    install = load_install()
    if _managed(install, "stop"):
        return
    pid = _read_pid(install)
    if not _pid_alive(pid):
        _pid_file(install).unlink(missing_ok=True)
        print("没有在运行")
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        if not _pid_alive(pid):
            break
        time.sleep(0.5)
    if _pid_alive(pid):
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
    _pid_file(install).unlink(missing_ok=True)
    print(f"已停止（pid {pid}）")


def cmd_restart() -> None:
    install = load_install()
    if _managed(install, "restart"):
        _wait_healthy(install)
        return
    cmd_stop()
    cmd_start()


def cmd_log(lines: int = 40) -> None:
    install = load_install()
    log_path = Path(install["data"]) / "server.log"
    if not log_path.is_file():
        print(f"还没有日志：{log_path}")
        return
    text = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in text[-lines:]:
        print(line)


# ── 系统服务 ─────────────────────────────────────────────
def _service_unit_path(install: dict) -> Path | None:
    if sys.platform.startswith("linux"):
        return Path("/etc/systemd/system/compile-excel-server.service")
    if sys.platform == "darwin":
        return (Path.home() / "Library" / "LaunchAgents"
                / "io.github.qingshanfeihu.compile-excel-server.plist")
    return None


_ACCOUNT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")


def _systemd_quote(arg: str) -> str:
    """ExecStart 的一个参数：整体加双引号；反斜杠、引号转义，% 与 $ 双写（systemd 的说明符与变量展开）。"""
    escaped = (arg.replace("\\", "\\\\").replace('"', '\\"')
               .replace("%", "%%").replace("$", "$$"))
    return f'"{escaped}"'


def _service_account(install: dict, override: str | None = None) -> str:
    """服务以谁的身份跑：--user 指定，否则取数据目录的属主（服务要读写的就是它）。"""
    if override:
        return override
    try:
        import pwd

        return pwd.getpwuid(Path(install["data"]).stat().st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return ""


def _unit_content(install: dict, account: str = "") -> tuple[str, str]:
    argv = _serve_argv(install)
    if sys.platform.startswith("linux"):
        user_line = f"User={account}\n" if account else ""
        # 日志照旧写进 <数据目录>/server.log（ces log 看的就是它）；路径带空白时 systemd 写不了，
        # 只好留在 journal 里（journalctl -u compile-excel-server）
        log = f"{install['data']}/server.log"
        log_lines = ("" if any(ch.isspace() for ch in log) else
                     f"StandardOutput=append:{log.replace('%', '%%')}\n"
                     f"StandardError=append:{log.replace('%', '%%')}\n")
        return "compile-excel-server.service", f"""\
[Unit]
Description=compile-excel-server (KMS / knowledge / artifact distribution)
After=network.target

[Service]
{user_line}ExecStart={' '.join(_systemd_quote(part) for part in argv)}
{log_lines}Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    if sys.platform == "darwin":
        plist_args = "".join(
            f"    <string>{xml_escape(part)}</string>\n" for part in argv).rstrip()
        log = xml_escape(f"{install['data']}/server.log")
        return "io.github.qingshanfeihu.compile-excel-server.plist", f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.github.qingshanfeihu.compile-excel-server</string>
  <key>ProgramArguments</key>
  <array>
{plist_args}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"""
    return "", ""


def cmd_service(action: str, user: str | None = None) -> None:
    install = load_install()
    account = ""
    if sys.platform.startswith("linux") and action in ("install", "print"):
        # launchd 用的是 LaunchAgents（当前登录用户），只有 systemd 要写 User=
        account = _service_account(install, user)
        if not _ACCOUNT_RE.match(account):
            print(f"查不到用哪个账号运行服务：{account!r}（用 --user <账号> 指定）")
            raise SystemExit(64)
        if account == "root":
            print("注意：服务会以 root 运行。建议建一个普通账号，把数据目录交给它，再用 --user 指定。",
                  file=sys.stderr)
    name, content = _unit_content(install, account)
    if not name:
        print("这个系统不支持自动开启开机自启（Windows 可以用 NSSM）")
        raise SystemExit(1)
    unit = _service_unit_path(install)
    if action == "print":
        print(f"── {unit} ──")
        print(content)
        return
    sudo_hint = f"sudo {self_command('service', action)}"
    if action == "install":
        try:
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text(content, encoding="utf-8")
        except PermissionError:
            print(f"没有权限写 {unit}，请用管理员身份运行：{sudo_hint}")
            raise SystemExit(1) from None
        # 日志文件先按数据目录的属主建好：sudo 下由 systemd 新建会归 root，之后普通用户写不进去
        log = Path(install["data"]) / "server.log"
        try:
            log.touch(exist_ok=True)
            owner = Path(install["data"]).stat()
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                os.chown(log, owner.st_uid, owner.st_gid)
        except OSError:
            pass
        # 用 ces start 起的实例占着端口，系统服务会起不来：先停掉它
        pid = _read_pid(install)
        if _pid_alive(pid):
            os.kill(pid, signal.SIGTERM)
            _pid_file(install).unlink(missing_ok=True)
            time.sleep(1)
        if sys.platform.startswith("linux"):
            _system(["systemctl", "daemon-reload"])
            if _system(["systemctl", "enable", "--now", SERVICE_NAME]) != 0:
                print(f"注册了服务单元，但启动失败：看 systemctl status {SERVICE_NAME}")
                raise SystemExit(1)
            print(f"已开启开机自启并启动（systemd，以 {account} 身份运行）")
        else:
            _system(["launchctl", "unload", str(unit)], quiet=True)
            _system(["launchctl", "load", str(unit)])
            print("已开启开机自启并启动（launchd）")
        return
    if action == "remove":
        if unit and unit.exists():
            try:
                if sys.platform.startswith("linux"):
                    if _system(["systemctl", "disable", "--now", SERVICE_NAME]) != 0:
                        raise PermissionError
                else:
                    _system(["launchctl", "unload", str(unit)], quiet=True)
                unit.unlink()
            except PermissionError:
                print(f"没有权限关闭开机自启，请用管理员身份运行：{sudo_hint}")
                raise SystemExit(1) from None
            print("已关闭开机自启")
        else:
            print("本来就没有开启开机自启")
        return
    print(f"用法：ces service install|remove|print（没有 {action} 这个动作）")
    raise SystemExit(64)


def cmd_uninstall(purge: bool) -> None:
    install = load_install()
    if autostart_registered(install):
        try:
            cmd_service("remove")
        except SystemExit as exc:
            if exc.code not in (0, None):
                print("开机自启没关掉，卸载没有继续（否则系统服务会指向已删除的程序）。")
                raise
    cmd_stop()
    if purge:
        import shutil

        shutil.rmtree(install["data"], ignore_errors=True)
        print(f"已删除数据目录：{install['data']}")
    else:
        print(f"数据目录保留：{install['data']}（以后重装时选同一个目录即可接着用）")
    INSTALL_JSON.unlink(missing_ok=True)
    _remove_program()
    print("已卸载。")


def _remove_program() -> None:
    """安装包形态：删掉程序（<程序根>/current 与 versions/）和 ~/.local/bin 里指向它的链接。
    只删安装脚本建的这几样，程序根目录里别的东西不动；源码安装不删代码目录（那是你的 git 检出）。"""
    if not getattr(sys, "frozen", False):
        print(f"源码安装：代码目录 {ROOT} 没有删，需要的话手动删除。")
        return
    import shutil

    exe = Path(sys.executable).resolve()
    prefix = program_prefix()
    if prefix.resolve() not in exe.parents:
        print(f"程序不在安装脚本的目录里（{exe}），没有删除，需要的话手动删除。")
        return
    bin_dir = Path(os.environ.get("CES_BIN_DIR") or Path.home() / ".local" / "bin")
    for name in ("ces", "compile-excel-server"):
        link = bin_dir / name
        try:
            if link.is_symlink() and link.resolve() == exe:
                link.unlink()
        except OSError:
            pass
    current = prefix / "current"
    if current.is_symlink():
        current.unlink()
    else:
        shutil.rmtree(current, ignore_errors=True)
    shutil.rmtree(prefix / "versions", ignore_errors=True)
    (prefix / "VERSION").unlink(missing_ok=True)
    try:
        prefix.rmdir()  # 空了才删
        print(f"已删除程序：{prefix}")
    except OSError:
        print(f"已删除程序（{prefix} 下的 current 与 versions；目录里别的文件没动）")


def cmd_setup(args: list[str]) -> None:
    from deploy import setup as setup_mod

    sys.argv = [str(setup_mod.__file__ or "setup.py"), *args]
    raise SystemExit(setup_mod.main())


def cmd_serve(data: str, port: int, host: str, tls_cert: str = "", tls_key: str = "",
              insecure_lan: bool = False) -> int:
    from deploy.tls_policy import serve_tls_problem, uvicorn_tls_kwargs

    problem = serve_tls_problem(host, tls_cert, tls_key, insecure_lan)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    os.environ["CES_DATA_DIR"] = str(Path(data).expanduser().resolve())
    import uvicorn

    import server

    uvicorn.run(server.app, host=host, port=port, log_level="warning",
                **uvicorn_tls_kwargs(tls_cert, tls_key))
    return 0


def cmd_audit(rest: list[str]) -> int:
    from deploy import audit_log

    data, args = _admin_args(rest)
    action = args[0] if args else ""
    if action == "verify":
        try:
            result = audit_log.verify_all(data)
        except (OSError, ValueError) as exc:
            result = {"ok": False, "reason": f"audit key unreadable ({type(exc).__name__})"}
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 1
    if action == "rotate":
        new_key = _pop_flag(args, "--new-key")
        try:
            info = audit_log.rotate(data, new_key=new_key,
                                    fields={"via": "ces", "os_user": _os_user()})
        except (OSError, ValueError) as exc:
            print(f"轮换失败，未改动：{exc}")
            return 1
        print(f"已封存 {info['sealed_segment']}"
              + ("（其密钥另存同名 .key，0600）" if info["sealed_keyed"] else "")
              + f"；新链从 {data / 'audit.log'} 起"
              + ("，已换新的审计签名密钥" if info["key_rotated"] else ""))
        return 0
    print("用法：ces audit verify | rotate [--new-key]")
    print("  verify：逐段复核审计日志，查有没有行被改、被删")
    print("  rotate：封存当前日志（移到 audit_archive/，连同当时的密钥），从新文件接着记；"
          "--new-key 同时换签名密钥")
    return 64


# ── 身份与客户端配置（直接读写数据目录里的 auth.db / client_config.json）──
def _admin_args(rest: list[str]) -> tuple[Path, list[str]]:
    """剥出 --data；没给就用安装登记里的数据目录。"""
    data = ""
    remaining: list[str] = []
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg == "--data" and index + 1 < len(rest):
            data = rest[index + 1]
            index += 2
            continue
        if arg.startswith("--data="):
            data = arg.split("=", 1)[1]
        else:
            remaining.append(arg)
        index += 1
    if not data:
        data = load_install()["data"]
    path = Path(data).expanduser().resolve()
    if not path.is_dir():
        print(f"数据目录不存在：{path}（先运行 ces setup）")
        raise SystemExit(2)
    return path, remaining


def _pop_option(args: list[str], name: str) -> str | None:
    if name in args:
        index = args.index(name)
        if index + 1 >= len(args):
            print(f"{name} 缺少取值")
            raise SystemExit(64)
        value = args[index + 1]
        del args[index:index + 2]
        return value
    return None


def _pop_flag(args: list[str], name: str) -> bool:
    if name in args:
        args.remove(name)
        return True
    return False


def _os_user() -> str:
    import getpass

    try:
        user = getpass.getuser()
    except (OSError, KeyError, ImportError):
        user = ""
    sudo = os.environ.get("SUDO_USER") or ""
    return f"{sudo}(sudo:{user})" if sudo and sudo != user else user


def _admin_audit(data: Path, event: str, **fields) -> None:
    """管理命令对身份、配置、注册表的改动写进服务端审计链（与服务进程共用文件锁，prev 不会接错）。
    调用方保证不含任何访问码、secret、令牌。"""
    from deploy.audit_log import AuditLog

    record = {"event": event, "via": "ces", "os_user": _os_user(), **fields}
    if not AuditLog(data).append(record):
        print(f"警告：审计日志写不进 {data / 'audit.log'}（本次改动已生效）", file=sys.stderr)


def _issue_secret(label: str, out: str | None, generate, apply, *, replace: bool = False) -> int:
    """一次性凭据的发放顺序：先生成，再落文件，最后才改库。

    给了 --out：凭据先写进目标同目录的临时文件（0600），写不了就不动库；库改好后原子改名到位，
    改库失败就删掉临时文件。万一最后改名失败，凭据还在那个临时文件里（给出路径）——
    不会出现库里已经换了哈希、凭据本身却哪儿都没有的情况。没给 --out：改库后在终端显示一次。"""
    if out and not replace and Path(out).expanduser().exists():
        # 新建账号或客户端时不覆盖已有文件：那可能是别人在用的访问码或密钥
        print(f"文件已存在：{Path(out).expanduser()}。换个文件名，或确认没用后先删掉它；库没有任何改动")
        return 1
    secret = generate()
    if not out:
        apply(secret)
        print(f"{label}（只显示这一次）：{secret}")
        return 0
    target = Path(out).expanduser()
    try:
        if target.is_dir():
            raise IsADirectoryError(f"{target} 是目录")
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.",
                                   suffix=".tmp")  # mkstemp 建的就是 0600
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(secret + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        print(f"写不了 {target}（{exc}）；库没有任何改动")
        return 1
    try:
        apply(secret)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    try:
        os.replace(tmp, target)
    except OSError as exc:
        print(f"{label}已生效，但移到 {target} 失败（{exc}）；它在 {tmp}（权限 600），"
              "交给本人后删除")
        return 1
    print(f"{label}已写入 {target}（权限 600），交给本人后删除这个文件")
    return 0


def cmd_users(rest: list[str]) -> int:
    from auth_store import (
        DEFAULT_USER_SCOPES,
        SCOPES,
        AuthError,
        AuthStore,
        new_access_code,
        normalize_scopes,
    )

    data, args = _admin_args(rest)
    store = AuthStore(data / "auth.db")
    action = args[0] if args else ""
    try:
        if action == "add" and len(args) >= 2:
            scopes = _pop_option(args, "--scopes")
            out = _pop_option(args, "--out")
            name = args[1]
            wanted = scopes.split() if scopes is not None else None

            def add(code: str) -> None:
                store.add_user(name, wanted, code=code)
                _admin_audit(data, "admin_user_added", username=name,
                             scope=normalize_scopes(wanted if wanted is not None
                                                    else list(DEFAULT_USER_SCOPES)))

            return _issue_secret(f"用户 {name} 的访问码", out, new_access_code, add)
        if action == "list":
            users = store.list_users()
            for user in users:
                state = "停用" if user["disabled"] else "启用"
                print(f"{user['username']:<20} {state}  {_scope_labels(user['scopes'].split())}")
            if not users:
                print("还没有账号：ces users add <用户名>")
            return 0
        if action in ("disable", "enable") and len(args) >= 2:
            store.set_user_disabled(args[1], action == "disable")
            _admin_audit(data, f"admin_user_{action}d", username=args[1])
            print(f"已停用 {args[1]}（已登录的会话全部失效）" if action == "disable"
                  else f"已启用 {args[1]}")
            return 0
        if action == "reset-code" and len(args) >= 2:
            out = _pop_option(args, "--out")
            name = args[1]

            def reset(code: str) -> None:
                store.reset_code(name, code=code)
                _admin_audit(data, "admin_user_code_reset", username=name)

            return _issue_secret(f"用户 {name} 的新访问码（旧的登录已全部失效）", out,
                                 new_access_code, reset, replace=True)
        if action == "scopes" and len(args) >= 3:
            granted = store.set_user_scopes(args[1], args[2].split())
            _admin_audit(data, "admin_user_scopes_set", username=args[1], scope=granted)
            print(f"已更新 {args[1]} 的权限（需要重新登录）：{_scope_labels(granted)}")
            return 0
    except AuthError as exc:
        print(str(exc))
        return 1
    print("用法：ces users add <用户名> [--scopes \"权限1 权限2\"] [--out 文件] | list | "
          "disable <用户名> | enable <用户名> | reset-code <用户名> [--out 文件] | "
          "scopes <用户名> \"权限1 权限2\"")
    print(f"默认权限：{' '.join(DEFAULT_USER_SCOPES)}")
    print("全部权限：")
    for key, note in SCOPES.items():
        print(f"  {key:<16} {note}")
    return 64


def cmd_clients(rest: list[str]) -> int:
    from auth_store import AuthError, AuthStore, new_client_secret, normalize_scopes

    data, args = _admin_args(rest)
    store = AuthStore(data / "auth.db")
    action = args[0] if args else ""
    try:
        if action == "add" and len(args) >= 2:
            scopes = _pop_option(args, "--scopes")
            out = _pop_option(args, "--out")
            if not scopes:
                print("服务客户端要用 --scopes 指定权限（例如网关用 \"introspect bundles:read\"）")
                return 64
            client_id = args[1]

            def add(secret: str) -> None:
                store.add_client(client_id, scopes.split(), secret=secret)
                _admin_audit(data, "admin_client_added", client_id=client_id,
                             scope=normalize_scopes(scopes))

            return _issue_secret(f"客户端 {client_id} 的密钥", out,
                                 new_client_secret, add)
        if action == "rotate-secret" and len(args) >= 2:
            out = _pop_option(args, "--out")
            client_id = args[1]

            def rotate(secret: str) -> None:
                store.rotate_client_secret(client_id, secret=secret)
                _admin_audit(data, "admin_client_secret_rotated", client_id=client_id)

            return _issue_secret(
                f"客户端 {client_id} 的新密钥（旧密钥已失效，已签发的令牌用到过期）",
                out, new_client_secret, rotate, replace=True)
        if action == "list":
            clients = store.list_clients()
            for client in clients:
                print(f"{client['client_id']:<20} {_scope_labels(client['scopes'].split())}")
            if not clients:
                print("还没有服务客户端")
            return 0
        if action == "remove" and len(args) >= 2:
            store.remove_client(args[1])
            _admin_audit(data, "admin_client_removed", client_id=args[1])
            print(f"已删除客户端 {args[1]}（它的令牌全部失效）")
            return 0
    except AuthError as exc:
        print(str(exc))
        return 1
    print("用法：ces clients add <名称> --scopes \"权限1 权限2\" [--out 文件] | list | "
          "remove <名称> | rotate-secret <名称> [--out 文件]")
    return 64


def cmd_tokens(rest: list[str]) -> int:
    from auth_store import AuthStore

    data, args = _admin_args(rest)
    store = AuthStore(data / "auth.db")
    action = args[0] if args else ""
    if action == "revoke":
        user = _pop_option(args, "--user")
        client = _pop_option(args, "--client")
        if bool(user) == bool(client):
            print("用法：ces tokens revoke --user <用户名> | --client <客户端名称>")
            return 64
        kind, subject = ("user", user) if user else ("client", client)
        count = store.revoke_subject(kind, subject)
        _admin_audit(data, "admin_tokens_revoked", subject_kind=kind, subject=subject,
                     count=count)
        print(f"已撤销 {subject} 的 {count} 个令牌")
        return 0
    if action == "purge":
        count = store.purge_expired()
        _admin_audit(data, "admin_tokens_purged", count=count)
        print(f"已清理 {count} 个过期超过一天的令牌记录")
        return 0
    print("用法：ces tokens revoke --user <用户名> | --client <客户端名称> | purge")
    return 64


def cmd_config(rest: list[str]) -> int:
    import client_config

    data, args = _admin_args(rest)
    action = args[0] if args else ""
    try:
        if action == "show":
            print(json.dumps(client_config.document(data), ensure_ascii=False, indent=1))
            return 0
        if action == "set" and len(args) == 3:
            client_config.set_key(data, args[1], args[2])
            _admin_audit(data, "admin_config_set", key=args[1])
            print(f"已设置 {args[1]}")
            return 0
        if action == "unset" and len(args) == 2:
            removed = client_config.unset_key(data, args[1])
            _admin_audit(data, "admin_config_unset", key=args[1], removed=removed)
            print(f"{'已删除' if removed else '本来就没有'} {args[1]}")
            return 0
        if action == "import-env" and len(args) == 2:
            imported, skipped = client_config.import_env(data, Path(args[1]).expanduser())
            _admin_audit(data, "admin_config_imported",
                         keys=[line.split(" → ", 1)[-1] for line in imported])
            for line in imported:
                print(f"导入 {line}")
            for line in skipped:
                print(f"跳过 {line}")
            if not imported and not skipped:
                print("没有可导入的地址（只导入门户与缺陷系统地址，账号口令不导入）")
            return 0
    except client_config.ConfigError as exc:
        print(str(exc))
        return 1
    print("用法：ces config show | set <项> <地址> | unset <项> | import-env <KEY=value 文件>")
    print("可以设置的项：")
    for key, note in client_config.KEYS.items():
        print(f"  {key:<28} {note}")
    return 64


RESTART_HINT = "重启服务后生效（ces restart）"


def cmd_docs(rest: list[str]) -> int:
    from deploy.setup import copy_docs

    data, args = _admin_args(rest)
    docs_dir = data / "docs"
    action = args[0] if args else ""
    if action == "list":
        files = sorted(docs_dir.rglob("*.md")) if docs_dir.is_dir() else []
        for path in files:
            print(f"  {path.relative_to(docs_dir)}")
        print(f"共 {len(files)} 篇手册（{docs_dir}）")
        return 0
    if action == "add" and len(args) >= 2:
        force = _pop_flag(args, "--force")
        total = 0
        for raw in args[1:]:
            source = Path(raw).expanduser()
            if source.is_dir() and not any(source.rglob("*.md")):
                print(f"目录里没有 .md 文件：{source}")
                return 1
            if not source.exists() or (source.is_file() and source.suffix != ".md"):
                print(f"不存在，或不是 .md 文件：{source}")
                return 1
            docs_dir.mkdir(parents=True, exist_ok=True)
            copied = copy_docs(source, docs_dir, force)
            total += len(copied)
            print(f"已导入 {source}（{len(copied)} 篇）")
        _admin_audit(data, "admin_docs_added", files=total)
        print(RESTART_HINT)
        return 0
    print("用法：ces docs list | add <目录或 .md 文件>... [--force]（--force：同名文件内容不同时覆盖）")
    return 64


def _write_meta(data: Path, meta: dict) -> None:
    path = data / "artifacts_meta.json"
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    path.chmod(0o600)


def cmd_artifacts(rest: list[str]) -> int:
    from deploy import gen_meta
    from deploy.setup import copy_artifact

    data, args = _admin_args(rest)
    action = args[0] if args else ""
    try:
        meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {"device_build": "LOCAL_SANDBOX", "artifacts": {}}
    if action == "list":
        build, kms = _build_and_kms(data)
        print(f"构建号  ：{build if build != '-' else '（没有设置）'}")
        print(f"KMS 地址：{kms or '（没有）'}")
        for name, entry in sorted((meta.get("artifacts") or {}).items()):
            if (data / "artifacts" / name).is_file():
                print(f"  {name}  版本 {(entry or {}).get('version') or '-'}")
        return 0
    if action == "add" and len(args) >= 2:
        force = _pop_flag(args, "--force")
        target = data / "artifacts"
        target.mkdir(parents=True, exist_ok=True)
        versions: dict[str, str] = {}
        for raw in args[1:]:
            text, _, version = raw.partition(":")
            src = Path(text).expanduser()
            if not src.is_file():
                print(f"文件不存在：{src}")
                return 1
            print(copy_artifact(src, target, force))
            if version:
                versions[src.name] = version
        gen_meta.generate_meta(data, version_map=versions)
        _admin_audit(data, "admin_artifacts_added", files=len(args) - 1)
        print(RESTART_HINT)
        return 0
    if action == "build" and len(args) == 2:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", args[1]):
            print("构建号只能含字母、数字和 . _ -，最长 64 位")
            return 64
        meta["device_build"] = args[1]
        _write_meta(data, meta)
        _admin_audit(data, "admin_device_build_set", device_build=args[1])
        print(f"旧版接口的构建号改为 {args[1]}；{RESTART_HINT}")
        return 0
    if action == "kms" and len(args) == 2:
        if args[1] == "none":
            meta.pop("kms_addr", None)
        elif re.fullmatch(r"[A-Za-z0-9._-]+:\d{1,5}", args[1]):
            meta["kms_addr"] = args[1]
        else:
            print("KMS 地址要写成 主机:端口，例如 10.0.0.90:8443；不用 KMS 写 none")
            return 64
        _write_meta(data, meta)
        _admin_audit(data, "admin_kms_set", kms=meta.get("kms_addr", ""))
        print(f"KMS 地址已{'清除' if args[1] == 'none' else '设为 ' + args[1]}；{RESTART_HINT}")
        return 0
    print("用法：ces artifacts list | add <文件>[:版本]... [--force] | build <构建号> | "
          "kms <主机:端口|none>")
    return 64


def cmd_version() -> None:
    from ces_version import __version__

    print(__version__)


def _restart_after_update(install: dict | None, was_running: bool) -> None:
    """更新后让在跑的服务用上新版本：交给系统服务，或用新程序执行 restart。"""
    if not install or not was_running:
        return
    if autostart_registered(install):
        try:
            _managed(install, "restart")
        except SystemExit:
            print("服务还在用旧版本运行，请用管理员身份重启：sudo systemctl restart "
                  f"{SERVICE_NAME}")
        return
    subprocess.run([stable_executable(), "restart"], check=False, env=system_env())


def cmd_update(rest: list[str]) -> int:
    version = _pop_option(rest, "--version")
    if not getattr(sys, "frozen", False):
        print("这是源码安装：在代码目录里 git pull，再 ces restart。")
        return 1
    install = installed()
    was_running = bool(install and _health(install))
    url = f"https://raw.githubusercontent.com/{REPO}/main/install.sh"
    # 装回同一个位置：程序根目录从当前程序的路径推出来，命令链接的目录沿用安装时的
    env = {**system_env(), "CES_UPDATE": "1", "CES_PREFIX": str(program_prefix())}
    links = [Path(os.environ.get("CES_BIN_DIR") or Path.home() / ".local/bin") / "ces"]
    if links[0].is_symlink():
        env["CES_BIN_DIR"] = str(links[0].parent)
    if version:
        env["CES_VERSION"] = version
    print(f"下载安装脚本：{url}")
    rc = subprocess.run(["bash", "-c", f'set -o pipefail; curl -fsSL "{url}" | bash'],
                        env=env, check=False).returncode
    if rc != 0:
        print("更新失败，原来的版本没有动。")
        return 1
    _restart_after_update(install, was_running)
    print("更新完成。数据目录与配置没有改动。")
    return 0


def _scope_labels(scopes: list[str]) -> str:
    from auth_store import SCOPES

    return "、".join(SCOPES.get(scope, scope) for scope in scopes) or "（没有权限）"


def _import_dir(reg, build: str, kind: str, directory: Path, replace_kind: bool) -> dict:
    """目录里的文件叠加到 candidate 上：同路径的条目换成目录里的版本，其余条目（含同类别的其他
    文件）原样保留——`ces generate` 的产物目录只有本次改动的投影，按类整体替换会把没改的全丢掉。
    replace_kind：先丢掉 candidate 里这一类的全部条目（目录必须是这一类的完整集合）。"""
    import mimetypes

    from registry import check_entry_path

    fresh: dict[str, dict] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = check_entry_path(kind, f"{kind}/{path.relative_to(directory).as_posix()}")
        media = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        blob = reg.put_blob_file(path, media)
        fresh[rel.casefold()] = {"kind": kind, "path": rel, "sha256": blob["sha256"],
                                 "media_type": media, "meta": {}}
    base = reg.channel_bundle(build, "candidate")
    kept: list[dict] = []
    replaced = 0
    if base:
        for entry in reg.bundle_manifest(base)["entries"]:
            if entry["path"].casefold() in fresh:
                replaced += 1
            elif not (replace_kind and entry["kind"] == kind):
                kept.append({k: entry[k] for k in ("kind", "path", "sha256", "media_type", "meta")})
    mode = "replace-kind" if replace_kind else "overlay"
    result = reg.submit_bundle(build, [*fresh.values(), *kept], publisher="ces-cli",
                               source={"importer": "ces registry import-dir", "kind": kind,
                                       "mode": mode, "base": base or ""})
    result["import"] = {"mode": mode, "base": base, "files": len(fresh), "replaced": replaced,
                        "kept": len(kept)}
    return result


def cmd_registry(rest: list[str]) -> int:
    from registry import CHANNELS, GC_GRACE_SECONDS, KINDS, Registry, RegistryError

    data, args = _admin_args(rest)
    try:
        reg = Registry(data / "registry")
    except RegistryError as exc:  # $CES_STABLE_REQUIRED_KINDS 写错
        print(str(exc))
        return 2
    action = args[0] if args else ""
    try:
        if action == "list":
            builds = reg.list_builds()
            for build in builds:
                channels = "  ".join(f"{name} → {info['bundle_id'][:12]}"
                                     for name, info in sorted(build["channels"].items()))
                print(f"{build['build']:<36} {build['bundles']} 个包  {channels or '（还没有通道）'}")
            if not builds:
                print("还没有任何构建：用 ces registry import-dir 导入，或用 tools/ 下的发布脚本发布")
            return 0
        if action == "bundles" and len(args) == 2:
            bundles = reg.list_bundles(args[1])
            if not bundles:
                print(f"构建 {args[1]} 下还没有包")
                return 1
            for bundle in bundles:
                where = "、".join(bundle["channels"]) or "-"
                print(f"{bundle['bundle_id'][:12]}  {bundle['created_at']}  "
                      f"{'自检通过' if bundle['checks_ok'] else '自检未过'}  "
                      f"{bundle['entries']:>4} 个文件  通道 {where:<18} 发布者 {bundle['publisher']}")
            return 0
        if action == "show" and len(args) >= 2:
            channel = _pop_option(args, "--channel") or "stable"
            bundle_id = reg.channel_bundle(args[1], channel)
            manifest = reg.bundle_manifest(bundle_id) if bundle_id else None
            if manifest is None:
                print(f"{args[1]} 的 {channel} 通道是空的")
                return 1
            print(json.dumps({k: v for k, v in manifest.items() if k != "entries"},
                             ensure_ascii=False, indent=1))
            for entry in manifest["entries"]:
                print(f"  {entry['kind']:<12} {entry['sha256'][:12]} {entry['bytes']:>10}  "
                      f"{entry['path']}")
            return 0
        if action == "import-dir" and len(args) >= 4:
            replace_kind = _pop_flag(args, "--replace-kind")
            build, kind, directory = args[1], args[2], Path(args[3]).expanduser()
            if kind not in KINDS or not directory.is_dir():
                print(f"用法：ces registry import-dir <构建号> <{'|'.join(KINDS)}> <目录> "
                      "[--replace-kind]")
                return 64
            result = _import_dir(reg, build, kind, directory, replace_kind)
            LAST_IMPORT.clear()
            LAST_IMPORT.update(result, build=build)
            _admin_audit(data, "admin_bundle_imported", build=build, kind=kind,
                         bundle_id=result["bundle_id"], created=result["created"],
                         mode=result["import"]["mode"], checks_ok=result["checks"]["ok"])
            print(json.dumps(result, ensure_ascii=False, indent=1))
            return 0
        if action == "promote" and len(args) >= 3:
            channel = _pop_option(args, "--channel") or "stable"
            expect = _pop_option(args, "--expect")
            if channel not in CHANNELS:
                print(f"通道只能是 {', '.join(CHANNELS)}")
                return 64
            if len(args) == 3:
                changed = reg.set_channel(args[1], channel, args[2], "ces-cli", expect=expect)
                _admin_audit(data, "admin_channel_set", build=args[1], channel=channel,
                             bundle_id=args[2], changed=changed, expect=expect)
                print(f"{args[1]} 的 {channel} 已指向 {args[2]}" if changed
                      else f"{args[1]} 的 {channel} 本来就指向 {args[2]}，未改动")
                return 0
        if action == "verify":
            problems = reg.verify_all()
            for line in problems:
                print(line)
            print("全部文件完好" if not problems else f"{len(problems)} 个文件有问题")
            return 0 if not problems else 1
        if action == "gc":
            hours = _pop_option(args, "--grace-hours")
            try:
                grace = float(hours) if hours is not None else GC_GRACE_SECONDS / 3600
            except ValueError:
                print("--grace-hours 要是数字（小时）")
                return 64
            deleted = reg.gc(grace_s=grace * 3600)
            _admin_audit(data, "admin_registry_gc", deleted=deleted, grace_hours=grace)
            print(f"已删除 {deleted} 个没有包引用、且 {grace:g} 小时内没有再上传过的文件")
            return 0
    except RegistryError as exc:
        print(str(exc))
        return 1
    print("用法：ces registry list | bundles <构建号> | show <构建号> [--channel 通道] | "
          "import-dir <构建号> <类别> <目录> [--replace-kind] | "
          "promote <构建号> <包> [--channel 通道] [--expect <包>|none] | "
          "verify | gc [--grace-hours 24]")
    return 64


def cmd_generate(rest: list[str]) -> int:
    import argparse

    from generators.chain import DEFAULT_STEPS, STEPS
    from generators.runner import GenerateError, run

    parser = argparse.ArgumentParser(
        prog="ces generate",
        description="按 InfoTest 批入口的顺序重生编译投影；产物目录可直接交给 "
                    "ces registry import-dir <build> projections <out>")
    parser.add_argument("--inputs", help="InfoTest 仓根布局的输入目录（不改它，复制一份再跑）")
    parser.add_argument("--out", help="本次新写或改动的投影放这里")
    parser.add_argument("--steps", default=",".join(DEFAULT_STEPS),
                        help=f"逗号分隔；缺省 {','.join(DEFAULT_STEPS)}")
    parser.add_argument("--raw-build", default="", help="设备 OS 原始 build（命令树分区）")
    parser.add_argument("--execution-build", default="")
    parser.add_argument("--version", default="", help="产品版本轴（如 10.5）")
    parser.add_argument("--vendor", default="", help="含 cex_core 的目录（缺省 gateway/vendor）")
    parser.add_argument("--report", default="", help="报告另存到这里（JSON）")
    parser.add_argument("--list", action="store_true", help="列出步骤、所需输入后退出")
    args = parser.parse_args(rest)
    if args.list:
        for name, step in STEPS.items():
            flag = "默认" if step.default else "点名"
            print(f"{name:<26} {flag}  {step.note}")
            for need in step.needs:
                print(f"{'':<32}需要 {need}")
        return 0
    if getattr(sys, "frozen", False):
        print("ces generate 只在源码安装里可用（每一步要起一个 Python 子进程）")
        return 2
    if not args.inputs or not args.out:
        parser.print_usage()
        return 64
    params = {"raw_build": args.raw_build, "execution_build": args.execution_build,
              "version": args.version}
    try:
        report = run(Path(args.inputs), Path(args.out),
                     steps=[s for s in args.steps.split(",") if s.strip()],
                     params={k: v for k, v in params.items() if v},
                     vendor=Path(args.vendor) if args.vendor else None)
    except GenerateError as exc:
        print(str(exc))
        return 2
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["ok"] else 1


# ── 入口 ─────────────────────────────────────────────────
def dispatch(argv: list[str]) -> int:
    """执行一条子命令（命令行与菜单共用）；返回退出码。"""
    if not argv:
        print(__doc__)
        return 64
    command, rest = argv[0], list(argv[1:])
    if command in ("help", "-h", "--help"):
        print(__doc__)
        return 0
    if command in ("version", "--version"):
        cmd_version()
    elif command == "status":
        cmd_status()
    elif command == "link":
        return cmd_link(rest)
    elif command == "start":
        cmd_start()
    elif command == "stop":
        cmd_stop()
    elif command == "restart":
        cmd_restart()
    elif command == "log":
        cmd_log()
    elif command == "serve":
        import argparse

        parser = argparse.ArgumentParser(prog="ces serve")
        parser.add_argument("--data", required=True)
        parser.add_argument("--port", type=int, default=DEFAULT_PORT)
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--tls-cert", default="")
        parser.add_argument("--tls-key", default="")
        parser.add_argument("--insecure-lan", action="store_true",
                            help="允许在非回环地址上不配证书（只用于可信实验网）")
        args = parser.parse_args(rest)
        return cmd_serve(args.data, args.port, args.host, args.tls_cert, args.tls_key,
                         args.insecure_lan)
    elif command == "service":
        user = _pop_option(rest, "--user")
        if not rest or rest[0] not in ("install", "remove", "print"):
            print("用法：ces service install|remove|print [--user 服务账号]"
                  "（systemd 用哪个账号运行，缺省取数据目录的属主）")
            return 64
        cmd_service(rest[0], user)
    elif command == "uninstall":
        cmd_uninstall("--purge" in rest)
    elif command == "update":
        return cmd_update(rest)
    elif command == "setup":
        cmd_setup(rest)
    elif command == "users":
        return cmd_users(rest)
    elif command == "clients":
        return cmd_clients(rest)
    elif command == "tokens":
        return cmd_tokens(rest)
    elif command == "tls":
        return cmd_tls(rest)
    elif command == "config":
        return cmd_config(rest)
    elif command == "docs":
        return cmd_docs(rest)
    elif command == "artifacts":
        return cmd_artifacts(rest)
    elif command == "registry":
        return cmd_registry(rest)
    elif command == "generate":
        return cmd_generate(rest)
    elif command == "audit":
        return cmd_audit(rest)
    else:
        print(f"没有这个子命令：{command}\n")
        print(__doc__)
        return 64
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv:
        return dispatch(argv)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        # 被脚本调用、没有终端：不进菜单（免得卡在等输入），打印子命令说明
        print(__doc__)
        return 64
    import ces_menu

    return ces_menu.main()


if __name__ == "__main__":
    sys.exit(main())
