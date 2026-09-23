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
import urllib.request
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


def healthz(port: int, timeout: float = 2.0) -> dict | None:
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=timeout) as resp:
            return json.loads(resp.read())
    except (OSError, ValueError):
        return None


def _serve_argv(install: dict) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "serve",
                "--data", install["data"], "--port", str(install["port"])]
    return [sys.executable, str(ROOT / "ces_main.py"), "serve",
            "--data", install["data"], "--port", str(install["port"])]


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
    health = healthz(install["port"])
    print("compile-excel-server 状态")
    print(f"  进程    : {'运行中 pid=' + str(pid) if alive else '未运行'}")
    print(f"  健康    : {'OK ' + json.dumps(health, ensure_ascii=False) if health else '不可达'}")
    print(f"  数据    : {install['data']}")
    print(f"  端口    : {install['port']}")
    print(f"  代码    : {install.get('repo', '-')}")
    unit = _service_unit_path(install)
    print(f"  服务    : {unit if unit and unit.exists() else '未注册（ces service install）'}")


def cmd_start() -> None:
    install = load_install()
    if _pid_alive(_read_pid(install)):
        print(f"已在运行（pid={_read_pid(install)}）")
        return
    if healthz(install["port"]):
        print(f"端口 {install['port']} 已有实例（无 pidfile）")
        return
    pid = _detached_popen(_serve_argv(install), Path(install["data"]) / "server.log")
    _pid_file(install).write_text(str(pid))
    print(f"已启动 pid={pid}")
    for _ in range(40):
        if healthz(install["port"], timeout=1):
            print(f"healthz: {healthz(install['port'])}")
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


def cmd_serve(data: str, port: int, host: str) -> None:
    os.environ["CES_DATA_DIR"] = str(Path(data).expanduser().resolve())
    import uvicorn

    import server

    uvicorn.run(server.app, host=host, port=port, log_level="warning")


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
        args = parser.parse_args(rest)
        cmd_serve(args.data, args.port, args.host)
    elif command == "service":
        if not rest or rest[0] not in ("install", "remove", "print"):
            print("用法: ces service install|remove|print")
            return 64
        cmd_service(rest[0])
    elif command == "uninstall":
        cmd_uninstall("--purge" in rest)
    elif command == "setup":
        cmd_setup(rest)
    else:
        print(__doc__)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main())
