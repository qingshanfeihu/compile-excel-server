#!/usr/bin/env python3
"""compile-excel-server 统一入口（ces）。

子命令：
  （无参数）        管理菜单（x-ui 式：状态/启停/日志/服务/重配/卸载）
  setup [...]      配置向导与非交互安装（转发 deploy/setup.py）
  serve            前台运行服务（服务管理器/调试用）
  status           实例状态（进程/健康/配置摘要）
  start|stop|restart|log   进程管理（pidfile + healthz）
  service install|remove|print   注册 systemd/launchd 服务
  uninstall [--purge]        停止并移除安装（--purge 连数据一起删）
  users add|list|disable|enable|reset-code|scopes   用户与访问码（只存哈希）
  clients add|list|remove    服务客户端（网关 introspect、发布导入器）
  tokens revoke|purge        按用户/客户端撤销令牌、清理过期令牌
  config show|set|unset|import-env   组织下发给客户端的地址常量
  registry list|show|import-dir|promote|verify|gc   数据包注册表
  audit verify               复核审计日志（哈希链 + 实例密钥 hmac）

管理命令默认作用于安装登记里的数据目录，可用 --data <目录> 指定。

打包形态（PyInstaller onedir）与源码形态行为一致：serve/start 用
sys.executable 自引用，不依赖用户 Python 环境。
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

if getattr(sys, "frozen", False):  # PyInstaller onedir
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    ROOT = Path(__file__).resolve().parent


def _config_root() -> Path:
    override = os.environ.get("CES_CONFIG_ROOT")
    if override:
        return Path(override)
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "compile-excel-server"
    return Path.home() / ".config" / "compile-excel-server"


CONFIG_ROOT = _config_root()
INSTALL_JSON = CONFIG_ROOT / "install.json"

MENU = """
════════════════════════════════════════
 compile-excel-server 管理面板
════════════════════════════════════════
  1. 状态
  2. 启动
  3. 停止
  4. 重启
  5. 查看日志（尾部）
  6. 注册系统服务（systemd/launchd）
  7. 移除系统服务
  8. 重新配置（安装向导）
  9. 卸载
  0. 退出
════════════════════════════════════════
"""


# ── 安装登记 ──────────────────────────────────────────────
def load_install() -> dict:
    try:
        data = json.loads(INSTALL_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"未找到安装登记 {INSTALL_JSON}——先运行: ces setup")
        raise SystemExit(2)
    if not isinstance(data, dict) or "data" not in data:
        print(f"安装登记损坏: {INSTALL_JSON}——重跑 ces setup")
        raise SystemExit(2)
    return data


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
        print(f"警告：监听 {_host(install)} 未配 TLS，令牌明文过网。用 ces setup 重配证书，"
              "或在 install.json 写 tls_cert/tls_key（确认是可信实验网则写 insecure_lan: true 消除本提示）。",
              file=sys.stderr)
        argv.append("--insecure-lan")
    return argv


def _serve_argv(install: dict) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "serve",
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


# ── 子命令 ───────────────────────────────────────────────
def cmd_status() -> None:
    install = load_install()
    pid = _read_pid(install)
    alive = _pid_alive(pid)
    health = _health(install)
    print("compile-excel-server 状态")
    print(f"  进程    : {'运行中 pid=' + str(pid) if alive else '未运行'}")
    print(f"  健康    : {'OK ' + json.dumps(health, ensure_ascii=False) if health else '不可达'}")
    print(f"  数据    : {install['data']}")
    print(f"  端口    : {install['port']}")
    print(f"  监听    : {_host(install)}")
    print(f"  代码    : {install.get('repo', '-')}")
    unit = _service_unit_path(install)
    print(f"  服务    : {unit if unit and unit.exists() else '未注册（ces service install）'}")


def cmd_start() -> None:
    install = load_install()
    if _pid_alive(_read_pid(install)):
        print(f"已在运行（pid={_read_pid(install)}）")
        return
    if _health(install):
        print(f"端口 {install['port']} 已有实例（无 pidfile）")
        return
    pid = _detached_popen(_serve_argv(install), Path(install["data"]) / "server.log")
    _pid_file(install).write_text(str(pid))
    print(f"已启动 pid={pid}")
    for _ in range(40):
        if _health(install, timeout=1):
            print(f"healthz: {_health(install)}")
            return
        time.sleep(0.5)
    print("探活失败，看 <数据目录>/server.log", file=sys.stderr)
    raise SystemExit(1)


def cmd_stop() -> None:
    install = load_install()
    pid = _read_pid(install)
    if not _pid_alive(pid):
        _pid_file(install).unlink(missing_ok=True)
        print("未在运行")
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
    print(f"已停止（pid={pid}）")


def cmd_restart() -> None:
    cmd_stop()
    cmd_start()


def cmd_log(lines: int = 40) -> None:
    install = load_install()
    log_path = Path(install["data"]) / "server.log"
    if not log_path.is_file():
        print(f"暂无日志: {log_path}")
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


def _unit_content(install: dict) -> tuple[str, str]:
    argv = _serve_argv(install)
    if sys.platform.startswith("linux"):
        return "compile-excel-server.service", f"""\
[Unit]
Description=compile-excel-server (KMS / knowledge / artifact distribution)
After=network.target

[Service]
ExecStart={' '.join(argv)}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    if sys.platform == "darwin":
        plist_args = "".join(
            f"    <string>{part}</string>\n" for part in argv).rstrip()
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
  <key>StandardOutPath</key><string>{install['data']}/server.log</string>
  <key>StandardErrorPath</key><string>{install['data']}/server.log</string>
</dict></plist>
"""
    return "", ""


def cmd_service(action: str) -> None:
    install = load_install()
    name, content = _unit_content(install)
    if not name:
        print("当前平台无内置服务注册：Windows 可用 NSSM（见 README）")
        raise SystemExit(1)
    unit = _service_unit_path(install)
    if action == "print":
        print(f"── {unit} ──")
        print(content)
        return
    if action == "install":
        try:
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text(content, encoding="utf-8")
        except PermissionError:
            print(f"无权限写 {unit}；unit 内容如下，请以管理员写入：")
            print(content)
            raise SystemExit(1)
        if sys.platform.startswith("linux"):
            os.system("systemctl daemon-reload && "
                      "systemctl enable --now compile-excel-server")
            print("已注册并启动（systemd）")
        else:
            os.system(f"launchctl unload '{unit}' >/dev/null 2>&1; "
                      f"launchctl load '{unit}'")
            print("已注册并启动（launchd）")
        return
    if action == "remove":
        if unit and unit.exists():
            if sys.platform.startswith("linux"):
                os.system("systemctl disable --now compile-excel-server")
            else:
                os.system(f"launchctl unload '{unit}' >/dev/null 2>&1")
            unit.unlink()
            print("已移除服务")
        else:
            print("服务未注册")
        return
    print(f"未知 service 动作: {action}（install|remove|print）")
    raise SystemExit(64)


def cmd_uninstall(purge: bool) -> None:
    install = load_install()
    try:
        cmd_service("remove")
    except SystemExit:
        pass
    cmd_stop()
    if purge:
        import shutil

        shutil.rmtree(install["data"], ignore_errors=True)
        print(f"已删除数据目录: {install['data']}")
    INSTALL_JSON.unlink(missing_ok=True)
    print("已卸载（安装登记已清除；二进制/代码目录请手动删除）")


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
    from gateway.audit_chain import verify

    data, args = _admin_args(rest)
    if args[:1] != ["verify"]:
        print("用法: ces audit verify [--data 目录]")
        return 64
    key = None
    key_path = data / "audit_hmac_key"
    if key_path.is_file():
        key = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
    result = verify(data / "audit.log", key)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


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
        print(f"数据目录不存在: {path}（先 ces setup）")
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


def _emit_secret(label: str, value: str, out: str | None) -> None:
    """一次性凭据：给 --out 就写 0600 文件，否则只在这里显示一次。"""
    if out:
        target = Path(out).expanduser()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value + "\n")
        os.chmod(target, 0o600)
        print(f"{label}已写入 {target}（0600），交给本人后删除该文件")
        return
    print(f"{label}（只显示这一次，库里只存哈希）: {value}")


def cmd_users(rest: list[str]) -> int:
    from auth_store import DEFAULT_USER_SCOPES, SCOPES, AuthError, AuthStore

    data, args = _admin_args(rest)
    store = AuthStore(data / "auth.db")
    action = args[0] if args else ""
    try:
        if action == "add" and len(args) >= 2:
            scopes = _pop_option(args, "--scopes")
            out = _pop_option(args, "--out")
            code = store.add_user(args[1], scopes.split() if scopes is not None else None)
            _emit_secret(f"用户 {args[1]} 的访问码", code, out)
            return 0
        if action == "list":
            for user in store.list_users():
                state = "停用" if user["disabled"] else "启用"
                print(f"{user['username']:<24} {state}  {user['scopes']}")
            return 0
        if action in ("disable", "enable") and len(args) >= 2:
            store.set_user_disabled(args[1], action == "disable")
            print(f"已{'停用（并撤销其全部令牌）' if action == 'disable' else '启用'}: {args[1]}")
            return 0
        if action == "reset-code" and len(args) >= 2:
            out = _pop_option(args, "--out")
            code = store.reset_code(args[1])
            _emit_secret(f"用户 {args[1]} 的新访问码（旧令牌已撤销）", code, out)
            return 0
        if action == "scopes" and len(args) >= 3:
            granted = store.set_user_scopes(args[1], args[2].split())
            print(f"已更新 {args[1]} 的 scope（旧令牌已撤销）: {' '.join(granted)}")
            return 0
    except AuthError as exc:
        print(str(exc))
        return 1
    print("用法: ces users add <名> [--scopes \"a b\"] [--out 文件] | list | disable <名> | "
          "enable <名> | reset-code <名> [--out 文件] | scopes <名> \"a b\"")
    print(f"默认 scope: {' '.join(DEFAULT_USER_SCOPES)}")
    print("全部 scope: " + ", ".join(f"{k}（{v}）" for k, v in SCOPES.items()))
    return 64


def cmd_clients(rest: list[str]) -> int:
    from auth_store import AuthError, AuthStore

    data, args = _admin_args(rest)
    store = AuthStore(data / "auth.db")
    action = args[0] if args else ""
    try:
        if action == "add" and len(args) >= 2:
            scopes = _pop_option(args, "--scopes")
            out = _pop_option(args, "--out")
            if not scopes:
                print("服务客户端必须显式给 --scopes（例：网关用 \"introspect\"）")
                return 64
            secret = store.add_client(args[1], scopes.split())
            _emit_secret(f"客户端 {args[1]} 的 client secret", secret, out)
            return 0
        if action == "list":
            for client in store.list_clients():
                print(f"{client['client_id']:<24} {client['scopes']}")
            return 0
        if action == "remove" and len(args) >= 2:
            store.remove_client(args[1])
            print(f"已删除客户端并撤销其令牌: {args[1]}")
            return 0
    except AuthError as exc:
        print(str(exc))
        return 1
    print("用法: ces clients add <id> --scopes \"introspect\" [--out 文件] | list | remove <id>")
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
            print("用法: ces tokens revoke --user <名> | --client <id>")
            return 64
        kind, subject = ("user", user) if user else ("client", client)
        count = store.revoke_subject(kind, subject)
        print(f"已撤销 {subject} 的 {count} 个令牌")
        return 0
    if action == "purge":
        print(f"已清理 {store.purge_expired()} 个过期超过一天的令牌记录")
        return 0
    print("用法: ces tokens revoke --user <名> | --client <id> | purge")
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
            print(f"已设置 {args[1]}")
            return 0
        if action == "unset" and len(args) == 2:
            removed = client_config.unset_key(data, args[1])
            print(f"{'已删除' if removed else '本来就没有'} {args[1]}")
            return 0
        if action == "import-env" and len(args) == 2:
            imported, skipped = client_config.import_env(data, Path(args[1]).expanduser())
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
    print("用法: ces config show | set <键> <地址> | unset <键> | import-env <KEY=value 文件>")
    print("可用键: " + ", ".join(f"{k}（{v}）" for k, v in client_config.KEYS.items()))
    return 64


def cmd_registry(rest: list[str]) -> int:
    import mimetypes

    from registry import CHANNELS, KINDS, Registry, RegistryError

    data, args = _admin_args(rest)
    reg = Registry(data / "registry")
    action = args[0] if args else ""
    try:
        if action == "list":
            for build in reg.list_builds():
                channels = ", ".join(f"{name}={info['bundle_id'][:12]}"
                                     for name, info in sorted(build["channels"].items()))
                print(f"{build['build']:<40} 包 {build['bundles']} 个  {channels or '（无通道）'}")
            return 0
        if action == "show" and len(args) >= 2:
            channel = _pop_option(args, "--channel") or "stable"
            bundle_id = reg.channel_bundle(args[1], channel)
            manifest = reg.bundle_manifest(bundle_id) if bundle_id else None
            if manifest is None:
                print(f"{args[1]} 的 {channel} 通道没有包")
                return 1
            print(json.dumps({k: v for k, v in manifest.items() if k != "entries"},
                             ensure_ascii=False, indent=1))
            for entry in manifest["entries"]:
                print(f"  {entry['kind']:<12} {entry['sha256'][:12]} {entry['bytes']:>10}  "
                      f"{entry['path']}")
            return 0
        if action == "import-dir" and len(args) >= 4:
            build, kind, directory = args[1], args[2], Path(args[3]).expanduser()
            if kind not in KINDS or not directory.is_dir():
                print(f"用法: ces registry import-dir <build> <{'|'.join(KINDS)}> <目录>")
                return 64
            entries = []
            for path in sorted(directory.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                rel = path.relative_to(directory).as_posix()
                media = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                blob = reg.put_blob_file(path, media)
                entries.append({"kind": kind, "path": f"{kind}/{rel}",
                                "sha256": blob["sha256"], "media_type": media, "meta": {}})
            base = reg.channel_bundle(build, "candidate")
            if base:
                # 在 candidate 基础上替换这一类，其余类原样保留
                old = reg.bundle_manifest(base)
                entries += [{k: e[k] for k in ("kind", "path", "sha256", "media_type", "meta")}
                            for e in old["entries"] if e["kind"] != kind]
            result = reg.submit_bundle(build, entries, publisher="ces-cli",
                                       source={"importer": "ces registry import-dir"})
            print(json.dumps(result, ensure_ascii=False, indent=1))
            return 0
        if action == "promote" and len(args) >= 3:
            channel = _pop_option(args, "--channel") or "stable"
            if channel not in CHANNELS:
                print(f"通道只能是 {', '.join(CHANNELS)}")
                return 64
            reg.set_channel(args[1], channel, args[2], "ces-cli")
            print(f"{args[1]} 的 {channel} 已指向 {args[2]}")
            return 0
        if action == "verify":
            problems = reg.verify_all()
            for line in problems:
                print(line)
            print("全部 blob 完好" if not problems else f"{len(problems)} 个 blob 有问题")
            return 0 if not problems else 1
        if action == "gc":
            print(f"已删除 {reg.gc()} 个没有包引用的 blob")
            return 0
    except RegistryError as exc:
        print(str(exc))
        return 1
    print("用法: ces registry list | show <build> [--channel c] | "
          "import-dir <build> <kind> <目录> | promote <build> <bundle_id> [--channel c] | "
          "verify | gc")
    return 64


# ── 菜单 ─────────────────────────────────────────────────
def menu() -> None:
    while True:
        print(MENU)
        try:
            choice = input("选择 [0-9]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        actions = {
            "1": cmd_status,
            "2": cmd_start,
            "3": cmd_stop,
            "4": cmd_restart,
            "5": cmd_log,
            "6": lambda: cmd_service("install"),
            "7": lambda: cmd_service("remove"),
            "8": lambda: cmd_setup([]),
            "9": lambda: cmd_uninstall(False),
        }
        if choice == "0" or choice == "":
            return
        handler = actions.get(choice)
        if handler is None:
            print("无效选择")
            continue
        try:
            handler()
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"（命令返回 {exc.code}）")


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        menu()
        return 0
    command, rest = argv[0], argv[1:]
    if command == "status":
        cmd_status()
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
        parser.add_argument("--port", type=int, default=8900)
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--tls-cert", default="")
        parser.add_argument("--tls-key", default="")
        parser.add_argument("--insecure-lan", action="store_true",
                            help="允许在非回环地址上不配 TLS（只用于可信实验网）")
        args = parser.parse_args(rest)
        return cmd_serve(args.data, args.port, args.host, args.tls_cert, args.tls_key,
                         args.insecure_lan)
    elif command == "service":
        if not rest or rest[0] not in ("install", "remove", "print"):
            print("用法: ces service install|remove|print")
            return 64
        cmd_service(rest[0])
    elif command == "uninstall":
        cmd_uninstall("--purge" in rest)
    elif command == "setup":
        cmd_setup(rest)
    elif command == "users":
        return cmd_users(rest)
    elif command == "clients":
        return cmd_clients(rest)
    elif command == "tokens":
        return cmd_tokens(rest)
    elif command == "config":
        return cmd_config(rest)
    elif command == "registry":
        return cmd_registry(rest)
    elif command == "audit":
        return cmd_audit(rest)
    else:
        print(__doc__)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main())
