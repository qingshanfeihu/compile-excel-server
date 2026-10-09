#!/usr/bin/env python3
"""compile-excel-server 安装与配置（ces setup；Windows / Linux / macOS 同一入口）。

两种用法：
  ces setup                         配置向导：只问两件事（数据目录、给谁用），其余用默认值；
                                    每答一题存一次草稿，中断后重跑从断点继续
  ces setup --data D [...]          不提问，按参数安装（脚本、CI 用）
  ces setup --options-file F        按向导存下的 install.options.json 重装

  参数：--data 目录  --port 端口（默认 8900）  --host 监听地址（默认 127.0.0.1，局域网用 0.0.0.0）
        --tls-auto（用内置 CA 自动签发证书）  --tls-cert C --tls-key K（自备证书）
        --insecure-lan（局域网明文，只用于可信实验网）  --start（装完启动）
        旧版工件与手册也可以一起导入：--device-build B --kms 主机:端口 --artifact 文件[:版本] --docs 目录
        --force（同名文件覆盖）  --sample（生成合成样例，自测用）  --yes（缺依赖时不问直接装）

手册、旧版工件、构建号、KMS 地址装好以后在管理菜单（ces）里随时导入和修改。
本工具不收集任何口令；审计签名密钥、证书私钥都在部署时生成，只存在数据目录里。
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DIR = Path(__file__).resolve().parent

if __package__:  # 作为 deploy.setup 包导入（PyInstaller/ces 入口）
    from . import (  # noqa: E402
        certs,
        gen_meta,
        paths,
        provision,
        sample_data,
        tls_policy,
    )
else:  # 直接运行: python deploy/setup.py
    sys.path.insert(0, str(DEPLOY_DIR))
    sys.path.insert(0, str(REPO_ROOT))
    import certs  # noqa: E402
    import gen_meta  # noqa: E402
    import paths  # noqa: E402
    import provision  # noqa: E402
    import sample_data  # noqa: E402
    import tls_policy  # noqa: E402

DEFAULT_PORT = 8900


CONFIG_ROOT = paths.config_root()
DRAFT_PATH = CONFIG_ROOT / "wizard.draft.json"
INSTALL_JSON = CONFIG_ROOT / "install.json"

# 证书方式：auto＝内置 CA 自动签发；files＝自备证书；plain＝不用证书（可信实验网明文）
TLS_CHOICES = ("auto", "files", "plain")


class WizardInterrupt(Exception):
    """用户中断（Ctrl+C / EOF）——草稿已随答随存。"""


# ── 终端小工具 ─────────────────────────────────────────────
def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"{prompt}{suffix}：")
    except (EOFError, KeyboardInterrupt):
        raise WizardInterrupt() from None
    return raw.strip() or default


def ask_yes(prompt: str, default: bool = True) -> bool:
    raw = ask(f"{prompt} [{'Y/n' if default else 'y/N'}]").lower()
    return default if not raw else raw in ("y", "yes", "是")


def is_number(raw: str) -> bool:
    """只认 ASCII 数字（str.isdigit 会放过上标数字，int() 却转不了）。"""
    return bool(raw) and raw.isascii() and raw.isdigit()


def ask_choice(prompt: str, options: list[str], default: int = 1) -> int:
    for index, text in enumerate(options, start=1):
        print(f"   {index}. {text}")
    while True:
        raw = ask(prompt, str(default))
        if is_number(raw) and 1 <= int(raw) <= len(options):
            return int(raw)
        print(f"  请输入 1 到 {len(options)} 之间的编号。")


def step_head(no: int, total: int, title: str, note: str) -> None:
    print()
    print("─" * 56)
    print(f" 第 {no}/{total} 步：{title}")
    print(f" {note}")
    print("─" * 56)


def expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw)))


def load_previous_install() -> dict:
    """重新配置时拿上次的答案当默认值。"""
    try:
        data = json.loads(INSTALL_JSON.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ── 草稿（断点续填）────────────────────────────────────────
DRAFT_KEYS = ("progress", "data", "scope", "tls", "tls_cert", "tls_key", "port")


def save_draft(state: dict) -> None:
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(CONFIG_ROOT), prefix=".wizard.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump({k: state.get(k) for k in DRAFT_KEYS}, stream, ensure_ascii=False, indent=1)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, str(DRAFT_PATH))


def load_draft() -> dict:
    try:
        data = json.loads(DRAFT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def draft_message() -> None:
    print()
    if DRAFT_PATH.is_file():
        print("⏸  已中断，答过的题已存下来。重新运行 ces setup 会从断点继续。")
    else:
        print("⏸  已中断，还没有存下任何答案。")


# ── 向导 ──────────────────────────────────────────────────
def welcome() -> None:
    print()
    print("═" * 56)
    print(" compile-excel-server 配置向导")
    print("═" * 56)
    print(" 只问两件事：数据放在哪里、给谁用。其余都用默认值，装好后在管理菜单（ces）里改。")
    print(" 回车接受方括号里的默认值；Ctrl+C 可随时中断，下次从断点继续。")


def _scope_label(state: dict) -> str:
    if state.get("scope") != "lan":
        return "只在这台电脑上用（http://127.0.0.1）"
    return {"auto": "局域网，自动生成证书（推荐）",
            "files": f"局域网，自备证书 {state.get('tls_cert')}",
            "plain": "局域网，不用证书（明文，只限可信实验网）"}[state.get("tls") or "auto"]


def previous_tls_choice(previous: dict) -> int:
    """上次安装用的证书方式对应的编号：1 内置 CA，2 自备证书，3 明文。"""
    cert = str(previous.get("tls_cert") or "")
    data = str(previous.get("data") or "")
    if cert and data and certs.is_builtin(Path(data), cert):
        return 1
    if cert:
        return 2
    if previous.get("insecure_lan") or (previous.get("host") and not tls_policy.is_loopback_host(
            str(previous["host"]))):
        return 3
    return 1


def wizard() -> dict:
    previous = load_previous_install()
    state: dict = {"progress": 0, "data": "", "scope": "", "tls": "", "tls_cert": "",
                   "tls_key": "", "port": ""}
    welcome()
    saved = load_draft()
    if saved.get("progress"):
        print(f"\n⏳ 上次填到第 {saved['progress']} 步。")
        if ask_yes("从断点继续？", True):
            state.update({k: saved[k] for k in DRAFT_KEYS if k in saved and saved[k] is not None})
            if "scope" not in saved:  # 旧版向导的草稿：只有数据目录还能沿用，其余重新问
                state["progress"] = min(int(state["progress"] or 0), 1)
        else:
            DRAFT_PATH.unlink(missing_ok=True)

    def done(step: int) -> None:
        state["progress"] = step
        save_draft(state)

    if state["progress"] >= 1:
        print(f"\n ✓ 第 1 步（沿用）：数据目录 {state['data']}")
    else:
        step_head(1, 2, "数据目录",
                  "账号、编译数据、手册、证书、审计日志都放在这里，权限会设为只有你能读写。")
        default = previous.get("data") or str(Path.home() / "ces-data")
        state["data"] = str(expand_path(ask("数据目录", default)))
        done(1)

    if state["progress"] >= 2:
        print(f" ✓ 第 2 步（沿用）：{_scope_label(state)}，端口 {state['port']}")
    else:
        step_head(2, 2, "给谁用", "决定服务监听哪个地址、用户怎么连进来。")
        was_lan = not tls_policy.is_loopback_host(str(previous.get("host") or "127.0.0.1"))
        choice = ask_choice("请选择", [
            "只在这台电脑上用（自己试用）",
            "给局域网里的其他电脑用",
        ], 2 if was_lan else 1)
        state["scope"] = "lan" if choice == 2 else "local"
        if state["scope"] == "lan":
            print("\n 用户的登录令牌要经过网络，需要 https 证书：")
            # 重新配置时默认沿用上次的方式，免得一路回车把自备证书或明文换成内置 CA
            last = previous_tls_choice(previous)
            tls = ask_choice("证书怎么来", [
                "自动生成（推荐）：用本服务自带的 CA 签发，用户拿连接串就能自动核对",
                "使用已有证书：填证书和私钥文件的路径",
                "不用证书：明文传输，只在可信的实验网里用",
            ], last)
            state["tls"] = TLS_CHOICES[tls - 1]
            if state["tls"] == "files":
                while True:
                    cert = expand_path(ask("证书文件（PEM）", previous.get("tls_cert") or ""))
                    key = expand_path(ask("私钥文件（PEM）", previous.get("tls_key") or ""))
                    if cert.is_file() and key.is_file():
                        state["tls_cert"], state["tls_key"] = str(cert), str(key)
                        break
                    print("  文件不存在，请重输。")
        while True:
            port = ask("端口", str(previous.get("port") or DEFAULT_PORT))
            if is_number(port) and 1 <= int(port) <= 65535:
                state["port"] = port
                break
            print("  端口要是 1 到 65535 之间的数字。")
        done(2)

    print()
    print("═" * 56)
    print(f" 数据目录：{state['data']}")
    print(f" 给谁用  ：{_scope_label(state)}")
    print(f" 端口    ：{state['port']}")
    print("═" * 56)
    if not ask_yes("按以上配置安装并启动？", True):
        print("已取消；答案已存下，重新运行 ces setup 可以接着改。")
        raise SystemExit(130)
    return state


def wizard_options(state: dict) -> dict:
    lan = state.get("scope") == "lan"
    tls = state.get("tls") if lan else ""
    return {
        "data": state["data"],
        "port": int(state.get("port") or DEFAULT_PORT),
        "host": "0.0.0.0" if lan else "127.0.0.1",
        "tls_auto": tls == "auto",
        "tls_cert": state.get("tls_cert") or "" if tls == "files" else "",
        "tls_key": state.get("tls_key") or "" if tls == "files" else "",
        "insecure_lan": tls == "plain",
        "start": True,
        "restart": True,
    }


# ── 安装执行 ──────────────────────────────────────────────
def ensure_deps(interactive: bool) -> None:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return
    except ImportError:
        pass
    if interactive and not ask_yes("缺少 fastapi / uvicorn，现在用 pip 安装？", True):
        raise SystemExit(1)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q",
         "-r", str(REPO_ROOT / "requirements.txt")],
        check=True,
    )


def copy_artifact(src: Path, dst_dir: Path, force: bool) -> str:
    dst = dst_dir / src.name
    if dst.exists():
        if dst.read_bytes() == src.read_bytes():
            return f"= {src.name}（内容一致，跳过拷贝）"
        if not force:
            return f"! {src.name} 已存在且内容不同，没有覆盖（要覆盖加 --force）"
        dst.write_bytes(src.read_bytes())
        return f"+ {src.name}（覆盖）"
    dst.write_bytes(src.read_bytes())
    return f"+ {src.name}"


def copy_docs(source: Path, docs_dir: Path, force: bool) -> list[Path]:
    """导入手册：同名且内容相同的跳过；内容不同时 force 才覆盖，否则保留原文件并提示。
    返回导入后与来源一致的文件。"""
    pairs = ([(source, docs_dir / source.name)] if source.is_file()
             else [(md, docs_dir / md.relative_to(source)) for md in sorted(source.rglob("*.md"))])
    copied: list[Path] = []
    for src, dst in pairs:
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() and dst.read_bytes() != src.read_bytes() and not force:
            print(f"  ! {dst.relative_to(docs_dir)} 已存在且内容不同，没有覆盖（要覆盖加 --force）")
            continue
        if not dst.exists() or dst.read_bytes() != src.read_bytes():
            dst.write_bytes(src.read_bytes())
        copied.append(dst)
    return copied


probe_host = tls_policy.probe_host


def client_url(host: str, port: int, tls: bool = False) -> str:
    host = (host or "127.0.0.1").strip()
    scheme = "https" if tls else "http"
    if host in ("0.0.0.0", "::"):
        return f"{scheme}://{lan_ip()}:{port}"
    return f"{scheme}://{host}:{port}"


def healthz_ok(port: int, timeout: float = 1.5,
               host: str = "127.0.0.1", tls_cert: str = "") -> dict | None:
    return tls_policy.healthz(port, host=host, tls_cert=tls_cert, timeout=timeout)


def _tls_serve_argv(tls: dict) -> list[str]:
    argv: list[str] = []
    if tls.get("tls_cert"):
        argv += ["--tls-cert", str(tls["tls_cert"]), "--tls-key", str(tls["tls_key"])]
    if tls.get("insecure_lan"):
        argv.append("--insecure-lan")
    return argv


def _stop_pid(pid_file: Path) -> None:
    """按 pid 文件停实例：先礼后兵，10 秒没退就强制结束（不然会和新实例抢端口）。"""
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        return
    for _ in range(20):
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.5)
    else:
        try:
            os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            time.sleep(0.5)
        except OSError:
            pass
    pid_file.unlink(missing_ok=True)


def start_server(data_dir: Path, port: int, host: str = "127.0.0.1",
                 tls: dict | None = None, *, restart: bool = False) -> None:
    """后台起服务并探活。restart：已有本数据目录的实例时先停掉它（重新配置后要按新配置起）。"""
    tls = tls or {}
    cert = str(tls.get("tls_cert") or "")
    pid_file = data_dir / "server.pid"
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            if not restart:
                print(f"      已经在运行（pid {pid}），不重复启动")
                return
            print(f"      停掉旧实例（pid {pid}），按新配置启动")
            _stop_pid(pid_file)
        except (ValueError, ProcessLookupError, PermissionError):
            pid_file.unlink(missing_ok=True)  # 残留 pidfile
    if healthz_ok(port, host=host, tls_cert=cert):
        print(f"      端口 {port} 上已经有实例在运行（不是本向导起的），不重复启动")
        return
    log_path = data_dir / "server.log"
    log = open(log_path, "ab")
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0))
    else:
        kwargs["start_new_session"] = True
    # 两种形态都走 ces serve：TLS 规则与参数只有一处
    if getattr(sys, "frozen", False):  # PyInstaller 包：自引用 serve 子命令
        serve_argv = [sys.executable, "serve"]
    else:
        serve_argv = [sys.executable, str(REPO_ROOT / "ces_main.py"), "serve"]
    serve_argv += ["--data", str(data_dir), "--port", str(port), "--host", host,
                   *_tls_serve_argv(tls)]
    proc = subprocess.Popen(serve_argv, stdout=log, stderr=log, **kwargs)
    pid_file.write_text(str(proc.pid))
    print(f"      pid {proc.pid}，日志 {log_path}")
    for _ in range(40):
        if healthz_ok(port, timeout=1, host=host, tls_cert=cert):
            print("      服务已就绪")
            return
        time.sleep(0.5)
    print(f"      服务没有响应，看日志 {log_path}", file=sys.stderr)
    raise SystemExit(1)


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))  # 不真发包，只为让系统选出对外的网卡地址
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _set_meta(data_dir: Path, device_build: str, kms: str) -> None:
    """没有旧版工件时也能设构建号、KMS 地址（gen_meta 要求工件目录非空）。"""
    path = data_dir / "artifacts_meta.json"
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {"artifacts": {}}
    if device_build:
        if not all(ch.isalnum() or ch in "._-" for ch in device_build) or len(device_build) > 64:
            print(f"构建号不合法：{device_build!r}（只能含字母、数字和 . _ -，最长 64 位）",
                  file=sys.stderr)
            raise SystemExit(64)
        meta["device_build"] = device_build
    if kms:
        meta["kms_addr"] = kms
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    path.chmod(0o600)


def import_extras(options: dict, data_dir: Path, force: bool) -> None:
    """命令行给了旧版工件、手册、构建号、KMS 地址时一起导入（向导不问这些，装好后在菜单里导入）。"""
    raw_artifacts = options.get("artifacts") or []
    raw_docs = options.get("docs") or []
    device_build = str(options.get("device_build") or "")
    kms = str(options.get("kms") or "")
    sample = bool(options.get("sample"))
    if not (raw_artifacts or raw_docs or device_build or kms or sample):
        return
    print("      导入旧版工件与手册 …")
    artifacts_dir = data_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    version_map: dict[str, str] = {}
    for entry in raw_artifacts:
        src_text, _, version = str(entry).partition(":")
        src = expand_path(src_text)
        if not src.is_file():
            print(f"  工件不存在：{src}", file=sys.stderr)
            raise SystemExit(66)
        print(f"  {copy_artifact(src, artifacts_dir, force)}")
        if version:
            version_map[src.name] = version
    docs_dir = data_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    for entry in raw_docs:
        source = expand_path(str(entry))
        if not source.exists():
            print(f"  手册路径不存在：{source}", file=sys.stderr)
            raise SystemExit(66)
        copied = copy_docs(source, docs_dir, force)
        print(f"  + {source}（{len(copied)} 篇）")
    if sample:
        print("      生成合成样例（自测用，不含任何内部资产）")
        sample_data.generate(data_dir, force=True)
    if any(path.is_file() for path in artifacts_dir.iterdir()):
        gen_meta.generate_meta(data_dir, device_build=device_build, kms=kms,
                               version_map=version_map,
                               default_version=str(options.get("default_version") or ""))
    elif device_build or kms:
        _set_meta(data_dir, device_build, kms)


def _launcher() -> str:
    return "ces" if getattr(sys, "frozen", False) else f"python {REPO_ROOT / 'ces_main.py'}"


def _ces_main():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import ces_main

    return ces_main


def print_next_steps(install: dict) -> None:
    ces_main = _ces_main()
    info = ces_main.connection_info(install)
    launcher = _launcher()
    print()
    print("════ 安装完成 ════")
    print(f"连接串（原样发给用户）：{info['link']}")
    print(f"管理菜单：{launcher}（建账号、导入数据、启停服务、开机自启都在里面）")
    print("接下来：")
    print(f"  1. 建账号：{launcher} users add <用户名>；把用户名、访问码和连接串一起发给本人")
    print("  2. 发布编译数据：管理菜单 → 编译数据 → 导入目录（或用 tools/ 下的发布脚本）")
    print("  3. 用户在编译助手里说“初始化编译工作区，连接串是 …”，再按提示在浏览器里登录")
    if info["local_only"]:
        print("注意：服务只监听本机，别的电脑连不上；要给局域网用，重新运行 ces setup 选第 2 项。")
    elif info["tls"] == "plain":
        print("注意：没有用证书，用户初始化时要说明“这是可信实验网，允许明文”。")


def _refresh_autostart(install: dict) -> bool:
    """注册过开机自启时，按新配置重写服务单元并重启；返回 True 表示已交给系统服务处理。"""
    ces_main = _ces_main()
    if not ces_main.autostart_registered(install):
        return False
    print("      已注册开机自启：按新配置更新服务单元并重启")
    try:
        ces_main.cmd_service("install")
    except SystemExit:
        print("      没能更新开机自启的服务单元（上面写了原因）；服务还在按旧配置运行",
              file=sys.stderr)
        return True
    try:
        ces_main.cmd_restart()
    except SystemExit:
        print("      服务按新配置重启后没有响应，看日志：ces log", file=sys.stderr)
    return True


def run_install(options: dict, interactive: bool = False) -> None:
    if not str(options.get("data") or "").strip():
        print("必须给数据目录（--data）", file=sys.stderr)
        raise SystemExit(64)
    data_dir = expand_path(str(options["data"])).resolve()
    force = bool(options.get("force"))
    port = int(options.get("port") or DEFAULT_PORT)
    host = str(options.get("host") or "127.0.0.1").strip()
    tls_auto = bool(options.get("tls_auto"))
    tls = {"tls_cert": str(options.get("tls_cert") or "").strip(),
           "tls_key": str(options.get("tls_key") or "").strip(),
           "insecure_lan": bool(options.get("insecure_lan"))}
    if tls_auto and (tls["tls_cert"] or tls["insecure_lan"]):
        print("--tls-auto 不能和 --tls-cert、--insecure-lan 同时用", file=sys.stderr)
        raise SystemExit(64)
    if not tls_auto:
        problem = tls_policy.serve_tls_problem(host, tls["tls_cert"], tls["tls_key"],
                                               tls["insecure_lan"])
        if problem:
            print(problem, file=sys.stderr)
            raise SystemExit(64)

    print("════ 安装 compile-excel-server ════")
    print(f"数据目录：{data_dir}")
    print("[1/4] 检查依赖 …")
    ensure_deps(interactive)

    print("[2/4] 准备数据目录 …")
    provision.provision(data_dir, sample=False)
    import_extras(options, data_dir, force)

    print("[3/4] 证书 …")
    if tls_auto:
        try:
            cert, key = certs.ensure_server_cert(data_dir, certs.local_names(host))
        except certs.CertError as exc:
            print(f"      {exc}", file=sys.stderr)
            raise SystemExit(1) from None
        tls["tls_cert"], tls["tls_key"] = str(cert), str(key)
        print(f"      已用内置 CA 签发，包含：{', '.join(certs.cert_info(cert)['names'])}")
    elif tls["tls_cert"]:
        print(f"      使用自备证书：{tls['tls_cert']}")
    elif tls["insecure_lan"]:
        print("      不用证书（明文，只限可信实验网）")
    else:
        print("      只在本机用，不需要证书")

    previous = load_previous_install()
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    install = {"repo": str(REPO_ROOT), "data": str(data_dir), "port": port, "host": host,
               **{k: v for k, v in tls.items() if v}}
    if previous.get("advertise_host"):
        install["advertise_host"] = previous["advertise_host"]
    INSTALL_JSON.write_text(json.dumps(install, ensure_ascii=False, indent=1), encoding="utf-8")
    old_data = str(previous.get("data") or "")
    if options.get("start") and old_data and Path(old_data).resolve() != data_dir:
        # 换了数据目录：旧目录的实例还占着端口、提供着旧数据，先停掉
        old_pid = Path(old_data) / "server.pid"
        if old_pid.is_file():
            print(f"      停掉旧数据目录（{old_data}）的实例")
            _stop_pid(old_pid)

    if options.get("start"):
        print(f"[4/4] 启动服务（端口 {port}）…")
        if not _refresh_autostart(install):
            start_server(data_dir, port, host, tls, restart=bool(options.get("restart")))
    else:
        print(f"[4/4] 没有要求启动；启动：{_launcher()} start")
    print_next_steps(install)


def offer_first_user(data_dir: str) -> None:
    """向导装完、还没有任何账号时，顺手建第一个。"""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from auth_store import AuthStore, valid_name

    if AuthStore(Path(data_dir) / "auth.db").list_users():
        return
    print()
    if not ask_yes("现在建第一个账号？", True):
        return
    while True:
        name = ask("用户名（字母、数字、. _ -）")
        if not name:
            return
        if valid_name(name):
            break
        print("  用户名只能含字母、数字和 . _ -，以字母或数字开头。")
    _ces_main().cmd_users(["add", name, "--data", data_dir])
    print("把用户名、访问码和上面的连接串一起发给本人。")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ces setup", description="compile-excel-server 安装与配置（不带参数进入配置向导）")
    parser.add_argument("--options-file", default="", help="按向导存下的 install.options.json 安装")
    parser.add_argument("--data", default="", help="数据目录")
    parser.add_argument("--port", type=int, default=0, help=f"端口（默认 {DEFAULT_PORT}）")
    parser.add_argument("--host", default="",
                        help="监听地址（默认 127.0.0.1 只本机；局域网用 0.0.0.0）")
    parser.add_argument("--tls-auto", action="store_true", help="用内置 CA 自动签发服务器证书")
    parser.add_argument("--tls-cert", default="", help="自备证书（PEM）")
    parser.add_argument("--tls-key", default="", help="自备证书的私钥（PEM）")
    parser.add_argument("--insecure-lan", action="store_true",
                        help="局域网监听但不用证书（只用于可信实验网）")
    parser.add_argument("--start", action="store_true", help="装完启动")
    parser.add_argument("--device-build", default="", help="旧版接口的构建号")
    parser.add_argument("--kms", default="", help="KMS 地址（主机:端口）")
    parser.add_argument("--artifact", action="append", default=[], help="旧版工件 文件[:版本]（可重复）")
    parser.add_argument("--docs", action="append", default=[], help="手册目录或 .md 文件（可重复）")
    parser.add_argument("--force", action="store_true", help="同名文件内容不同时覆盖")
    parser.add_argument("--sample", action="store_true", help="生成合成样例（自测用）")
    parser.add_argument("--yes", action="store_true", help="缺依赖时不问，直接安装")
    args = parser.parse_args()

    try:
        if args.options_file:
            options = json.loads(Path(args.options_file).expanduser().read_text(encoding="utf-8"))
            run_install(options, interactive=False)
            return 0
        if any([args.data, args.device_build, args.kms, args.artifact, args.docs, args.port,
                args.host, args.start, args.force, args.sample, args.tls_auto, args.tls_cert,
                args.insecure_lan]):
            run_install({
                "data": args.data, "device_build": args.device_build, "kms": args.kms,
                "artifacts": args.artifact, "docs": args.docs,
                "port": args.port or DEFAULT_PORT, "host": args.host or "127.0.0.1",
                "tls_auto": args.tls_auto, "tls_cert": args.tls_cert, "tls_key": args.tls_key,
                "insecure_lan": args.insecure_lan, "start": args.start,
                "force": args.force, "sample": args.sample,
            }, interactive=not args.yes)
            return 0
        state = wizard()
        options = wizard_options(state)
        opt_file = Path(state["data"]) / "install.options.json"
        opt_file.parent.mkdir(parents=True, exist_ok=True)
        opt_file.write_text(json.dumps(options, ensure_ascii=False, indent=1) + "\n",
                            encoding="utf-8")
        try:
            os.chmod(opt_file, 0o600)
        except OSError:
            pass
        DRAFT_PATH.unlink(missing_ok=True)
        run_install(options, interactive=True)
        offer_first_user(state["data"])
        print(f"\n这次的答案存在 {opt_file}；以后重装不想再答题："
              f"{_launcher()} setup --options-file {opt_file}")
        return 0
    except (WizardInterrupt, KeyboardInterrupt):
        draft_message()
        return 130


if __name__ == "__main__":
    sys.exit(main())
