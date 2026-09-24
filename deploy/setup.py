#!/usr/bin/env python3
"""compile-excel-server 跨平台安装部署（Windows / Linux / macOS 同一入口）。

两种模式：
  1. 配置向导（缺省，无参数即进入）：欢迎词 + 逐步说明/示例，一次问一项，
     回车接受默认值；每答一题即时存草稿，Ctrl+C/异常退出后重跑自动从断点
     继续；确认后生成 install.options.json 并进入安装。
  2. 非交互安装：python setup.py --options-file <install.options.json>
     （向导产物可复跑可留档；2.90/CI 免访谈）。

用法：
  python deploy/setup.py                      # 配置向导
  python deploy/setup.py --options-file F     # 按存档安装
  python deploy/setup.py --data D --device-build B --artifact A[:V] --docs DIR
              --kms host:port --port 8900 --start [--force] [--sample] [--yes]

平台差异处理：草稿/配置目录 Windows 用 %APPDATA%，其他用 ~/.config；
服务后台启动 Windows 用 DETACHED_PROCESS，其他用 start_new_session。
本工具不收集任何机密（openkm/KMS 地址为非机密网络地址）。
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DIR = Path(__file__).resolve().parent

if __package__:  # 作为 deploy.setup 包导入（PyInstaller/ces 入口）
    from . import gen_meta, provision, sample_data  # noqa: E402
else:  # 直接运行: python deploy/setup.py
    sys.path.insert(0, str(DEPLOY_DIR))
    import gen_meta  # noqa: E402
    import provision  # noqa: E402
    import sample_data  # noqa: E402

def _config_root() -> Path:
    override = os.environ.get("CES_CONFIG_ROOT")
    if override:
        return Path(override)
    if os.name == "nt" and os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "compile-excel-server"
    return Path.home() / ".config" / "compile-excel-server"


CONFIG_ROOT = _config_root()
DRAFT_PATH = CONFIG_ROOT / "wizard.draft.json"
INSTALL_JSON = CONFIG_ROOT / "install.json"

STEPS = [
    ("数据目录", "工件/手册/元数据/审计/密钥的落脚点"),
    ("device_build", "构建标识，工件清单按它区分"),
    ("openkm/KMS", "知识管理/密钥服务地址（可选）"),
    ("工件文件", "xml 命令树 / xlsx 模板 / tar.gz 框架…"),
    ("cli-app 手册", "docs/query 检索的 markdown"),
    ("监听端口", "客户端 COMPILE_EXCEL_SERVER 指向这里"),
    ("覆盖与启动", "同名文件策略 + 装完即起"),
]


class WizardInterrupt(Exception):
    """用户中断（Ctrl+C / EOF）——草稿已随答随存。"""


# ── 终端小工具 ─────────────────────────────────────────────
def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"{prompt}{suffix}: ")
    except EOFError:
        raise WizardInterrupt()
    return raw.strip() or default


def ask_yes_no(prompt: str, default: str = "y") -> bool:
    raw = ask(f"{prompt} (回车={default})", "")
    value = raw or default
    return value.strip().lower() in ("y", "yes")


def step_head(no: str, title: str, note: str, example: str = "") -> None:
    print()
    print("─" * 44)
    print(f" ▶ 第 {no} 步 · {title}")
    print(f" 说明: {note}")
    if example:
        print(f" 示例: {example}")
    print("─" * 44)


def expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw)))


def welcome() -> None:
    print()
    print("╔" + "═" * 60 + "╗")
    print("║        compile-excel-server  配置向导" + " " * 22 + "║")
    print("║        KMS · 知识库 · 工件分发平台" + " " * 22 + "║")
    print("╚" + "═" * 60 + "╝")
    print()
    print(" 本向导帮你完成一台 compile-excel-server 的部署配置，共 7 步：")
    print()
    for index, (title, note) in enumerate(STEPS, start=1):
        circled = "①②③④⑤⑥⑦"[index - 1]
        print(f"   {circled} {title:<14} {note}")
    print()
    print(" 约定：一次问一项，回车接受 [默认值]；路径支持 ~ 并校验存在性；")
    print("      每答一题即时存草稿——Ctrl+C 或异常退出后重跑向导可从断点继续；")
    print("      配置确认后先存档（install.options.json，可复跑可留档）再执行安装；")
    print("      本向导不收集任何密码/机密——实例密钥由部署阶段自动生成。")
    print()


# ── 草稿（断点续填）────────────────────────────────────────
def save_draft(progress: int, state: dict) -> None:
    state["progress"] = progress
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(CONFIG_ROOT), prefix=".wizard.", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(state, stream, ensure_ascii=False, indent=1)
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


def draft_message(state: dict) -> None:
    print()
    launcher = ("ces setup" if getattr(sys, "frozen", False)
                else f"python {Path(__file__)}")
    if DRAFT_PATH.is_file():
        progress = int(state.get("progress") or 0)
        print(f"⏸  已中断——进度已存草稿: {DRAFT_PATH}")
        print(f"    重跑 {launcher} 将从第 {progress + 1} 步继续。")
    else:
        print("⏸  已中断——尚未保存任何进度。")


# ── 向导 ──────────────────────────────────────────────────
def wizard() -> dict:
    state: dict = {
        "progress": 0, "data": "", "device_build": "", "kms": "",
        "port": "", "host": "", "force": "n", "start": "y",
        "artifacts": [], "docs": [],
    }
    resume = False
    welcome()

    if DRAFT_PATH.is_file():
        saved = load_draft()
        if saved:
            progress = int(saved.get("progress") or 0)
            print(f"⏳ 检测到未完成的配置草稿（已填到第 {progress} 步）：")
            if saved.get("data"):
                print(f"     数据目录={saved['data']}  device_build="
                      f"{saved.get('device_build') or '未填'}")
            if saved.get("artifacts") or saved.get("docs"):
                print(f"     工件 {len(saved.get('artifacts') or [])} 个 / "
                      f"手册 {len(saved.get('docs') or [])} 个来源")
            if ask_yes_no("从断点继续吗？", "y"):
                resume = True
                state.update({k: v for k, v in saved.items() if k in state})
                state["progress"] = progress
                print(f"  ✓ 已恢复草稿，从第 {progress + 1} 步继续。")
            else:
                DRAFT_PATH.unlink(missing_ok=True)
                print("  ✓ 已丢弃旧草稿，重新开始。")

    def done(step: int) -> None:
        state["progress"] = step
        save_draft(step, state)

    # 1/7 数据目录
    if resume and state["progress"] >= 1:
        print(f" ✓ 第1步·数据目录（沿用草稿）: {state['data']}")
    else:
        step_head("1/7", "数据目录",
                  "工件、手册、元数据、审计日志与实例密钥全部放在这个目录；"
                  "建议单独磁盘/分区，内网机器常用 /opt/ces/data。目录会被设为 700。",
                  "~/ces-data（本机沙盒） 或 /opt/ces/data（内网部署）")
        data = expand_path(ask("数据目录", str(Path.home() / "ces-data")))
        state["data"] = str(data)
        done(1)

    default_build = "LOCAL_SANDBOX"
    default_kms = ""
    meta_path = Path(state["data"]) / "artifacts_meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            default_build = str(meta.get("device_build") or default_build)
            default_kms = str(meta.get("kms_addr") or "")
            print(f"  （检测到既有部署：device_build={default_build} "
                  f"openkm/KMS={default_kms or '无'}——回车即沿用）")
        except (OSError, json.JSONDecodeError):
            pass
    if state.get("device_build"):
        default_build = state["device_build"]
    if state.get("kms"):
        default_kms = state["kms"]

    # 2/7 device_build
    if resume and state["progress"] >= 2:
        print(f" ✓ 第2步·device_build（沿用草稿）: {state['device_build']}")
    else:
        step_head("2/7", "device_build 构建标识",
                  "工件清单（manifest）按构建标识区分；客户端 fetch 时按它核对是否拿到了"
                  "对的工件集。应与发布产物（如晋升回执）里的构建标识一致，"
                  "限字母数字 . _ - 。",
                  "BUILD_10_5_0_585 或 v585-promoted")
        while True:
            value = ask("device_build", default_build)
            if value and len(value) <= 64 and all(
                    ch.isalnum() or ch in "._-" for ch in value):
                state["device_build"] = value
                break
            print("  标识非法（限字母数字 . _ -，≤64 位），请重输。")
        done(2)

    # 3/7 openkm/KMS
    if resume and state["progress"] >= 3:
        print(f" ✓ 第3步·openkm/KMS（沿用草稿）: {state['kms'] or '（未配置）'}")
    else:
        step_head("3/7", "openkm / KMS 地址（可选）",
                  "知识管理/密钥服务的 host:port。配置后会透出到 /healthz 与 manifest，"
                  "客户端与 preflight 可据此探活；暂无该服务直接回车跳过，"
                  "之后可改 meta 补配。",
                  "10.0.0.90:8443 或 km.internal:8443")
        state["kms"] = ask("openkm/KMS 地址 host:port（无则回车跳过）", default_kms)
        done(3)

    # 4/7 工件
    if resume and state["progress"] >= 4:
        print(f" ✓ 第4步·工件（沿用草稿）: {len(state['artifacts'])} 个")
    else:
        step_head("4/7", "工件文件（可多个）",
                  "要向客户端下发的文件：xml 命令树、xlsx 运行模板、tar.gz 框架子集等。"
                  "路径后可加 :版本 指定版本号（不加则自动记 installed-日期）。"
                  "SHA256 由服务启动时对文件字节快照，无需手填。",
                  "/data/pub/cmdtree_585.xml:0.1-585  或  "
                  "/data/pub/excel_template.xlsx:585-promoted")
        artifacts: list = list(state["artifacts"] or [])
        if artifacts:
            print(f" 草稿里已录入 {len(artifacts)} 个，继续追加（空行结束）：")
            for entry in artifacts:
                print(f"   ✓ 已录入 {Path(entry.split(':', 1)[0]).name}")
        else:
            print(" 逐个输入，空行结束：")
        while True:
            raw = ask(f"  工件[{len(artifacts) + 1}] 路径[:版本]", "")
            if not raw:
                break
            spec = raw
            src_text, _, version = spec.partition(":")
            src = expand_path(src_text)
            if not src.is_file():
                print(f"  文件不存在: {src}")
                continue
            artifacts.append(f"{src}:{version}" if version else str(src))
            print(f"  ✓ {src.name}")
            state["artifacts"] = artifacts
            save_draft(3, state)  # 多值逐条存草稿（步号停在 3，重跑回本步续录）
        if not artifacts:
            print("  （未提供工件；可稍后手工放入 <数据目录>/artifacts/ 再跑 gen_meta）")
        state["artifacts"] = artifacts
        done(4)

    # 5/7 手册
    if resume and state["progress"] >= 5:
        print(f" ✓ 第5步·cli-app 手册（沿用草稿）: {len(state['docs'])} 个来源")
    else:
        step_head("5/7", "cli-app 手册（可多个）",
                  "docs/query 检索的数据源：cli-app 的使用文档/方法参考等 markdown。"
                  "目录会递归收集其中全部 *.md（保留子目录结构），"
                  "也可只给单个 .md 文件。",
                  "/data/docs/cli-app-manuals（目录） 或 /data/docs/EXCEL_FUNCS.md（单文件）")
        docs: list = list(state["docs"] or [])
        if docs:
            print(f" 草稿里已录入 {len(docs)} 个来源，继续追加（空行结束）：")
            for entry in docs:
                print(f"   ✓ 已录入 {entry}")
        else:
            print(" 逐个输入，空行结束：")
        while True:
            raw = ask(f"  手册[{len(docs) + 1}] 路径", "")
            if not raw:
                break
            path = expand_path(raw)
            if path.is_dir():
                count = len(list(path.rglob("*.md")))
                if count == 0:
                    print(f"  目录里没有 .md: {path}")
                    continue
                docs.append(str(path))
                print(f"  ✓ {path}（{count} 篇）")
            elif path.is_file() and path.suffix == ".md":
                docs.append(str(path))
                print(f"  ✓ {path.name}")
            else:
                print(f"  路径不存在或非 .md: {path}")
                continue
            state["docs"] = docs
            save_draft(4, state)
        if not docs:
            print("  （未提供手册；知识库检索将为空）")
        state["docs"] = docs
        done(5)

    # 6/7 端口
    if resume and state["progress"] >= 6:
        print(f" ✓ 第6步·监听端口（沿用草稿）: {state['port']}")
    else:
        step_head("6/7", "监听端口",
                  "服务监听端口。客户端安装后 export "
                  "COMPILE_EXCEL_SERVER=http://<本机IP>:<此端口> 即可登录拉取。"
                  "默认 8900。",
                  "8900（默认） 或 9443（内网惯例）")
        while True:
            raw = ask("监听端口", state.get("port") or "8900")
            if raw.isdigit() and 1 <= int(raw) <= 65535:
                state["port"] = raw
                break
            print("  端口非法，请重输。")
        print("  监听地址：只给本机用填 127.0.0.1；要让局域网里其他机器登录拉取，填 0.0.0.0。")
        while True:
            raw = ask("监听地址", state.get("host") or "127.0.0.1").strip()
            if raw and " " not in raw:
                state["host"] = raw
                break
            print("  地址非法，请重输。")
        done(6)

    # 7/7 覆盖与启动
    if resume and state["progress"] >= 7:
        print(f" ✓ 第7步·覆盖与启动（沿用草稿）: "
              f"覆盖={state['force']} 启动={state['start']}")
    else:
        step_head("7/7", "覆盖策略与启动",
                  "同名工件/手册内容不同时：覆盖=直接替换（适合重装/升级），"
                  "跳过=保留现状（适合追加部署）。装完即启动会后台拉起服务并探活 healthz。",
                  "升级场景覆盖选 y；首次部署回车即可")
        state["force"] = "y" if ask_yes_no("同名文件内容不同时覆盖？", "n") else "n"
        save_draft(6, state)
        state["start"] = "y" if ask_yes_no("装完即启动服务？", "y") else "n"
        done(7)

    # 汇总确认
    print()
    print("════════════ 配置汇总（确认后才会写盘）════════════")
    print(f" 数据目录     : {state['data']}")
    print(f" device_build : {state['device_build']}")
    print(f" openkm/KMS   : {state['kms'] or '（未配置）'}")
    print(f" 工件（{len(state['artifacts'])} 个）:")
    for entry in state["artifacts"]:
        src, _, version = entry.partition(":")
        name = Path(src).name
        print(f"   - {name}" + (f":{version}" if version else ""))
    if not state["artifacts"]:
        print("   （无）")
    print(f" 手册（{len(state['docs'])} 个来源）:")
    for entry in state["docs"]:
        print(f"   - {entry}")
    if not state["docs"]:
        print("   （无）")
    print(f" 监听端口     : {state['port']}")
    print(f" 监听地址     : {state.get('host') or '127.0.0.1'}")
    print(f" 覆盖策略     : {'同名即覆盖' if state['force'] == 'y' else '内容不同则跳过'}")
    print(f" 装完启动     : {'是' if state['start'] == 'y' else '否'}")
    print("══════════════════════════════════════════════════")
    if not ask_yes_no("确认按以上配置部署？", "y"):
        print(f"已取消（草稿保留: {DRAFT_PATH}，可重跑向导继续）")
        raise SystemExit(130)
    return state


# ── 安装执行 ──────────────────────────────────────────────
def ensure_deps(interactive: bool) -> None:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return
    except ImportError:
        pass
    if interactive and not ask_yes_no("缺 fastapi/uvicorn，现在 pip 安装？", "y"):
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
            return f"! {src.name} 已存在且内容不同（--force 覆盖），本次跳过"
        dst.write_bytes(src.read_bytes())
        return f"+ {src.name}（覆盖）"
    dst.write_bytes(src.read_bytes())
    return f"+ {src.name}"


def copy_docs(source: Path, docs_dir: Path, force: bool) -> list[Path]:
    copied: list[Path] = []
    if source.is_file():
        dst = docs_dir / source.name
        if not dst.exists() or force or dst.read_bytes() != source.read_bytes():
            dst.write_bytes(source.read_bytes())
        copied.append(dst)
        return copied
    for md in sorted(source.rglob("*.md")):
        rel = md.relative_to(source)
        dst = docs_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists() or force or dst.read_bytes() != md.read_bytes():
            dst.write_bytes(md.read_bytes())
        copied.append(dst)
    return copied


def probe_host(host: str) -> str:
    """探活用的地址：监听全部网卡时走回环，绑定具体地址时直连该地址。"""
    host = (host or "").strip()
    if host in ("", "0.0.0.0", "::", "localhost"):
        return "127.0.0.1"
    return host


def client_url(host: str, port: int) -> str:
    host = (host or "127.0.0.1").strip()
    if host in ("0.0.0.0", "::"):
        return f"http://{lan_ip()}:{port}"
    return f"http://{host}:{port}"


def healthz_ok(port: int, timeout: float = 1.5,
               host: str = "127.0.0.1") -> dict | None:
    try:
        with urllib.request.urlopen(
                f"http://{probe_host(host)}:{port}/healthz", timeout=timeout) as resp:
            return json.loads(resp.read())
    except (OSError, ValueError):
        return None


def start_server(data_dir: Path, port: int, host: str = "127.0.0.1") -> None:
    pid_file = data_dir / "server.pid"
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text().strip())
            os.kill(pid, 0)
            print(f"      已有实例运行中（pid={pid}），不再重复启动")
            return
        except (ValueError, ProcessLookupError, PermissionError):
            pid_file.unlink(missing_ok=True)  # 残留 pidfile
    if healthz_ok(port, host=host):
        print(f"      端口 {port} 已有实例在跑（无 pidfile，不再重复启动）")
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
    if getattr(sys, "frozen", False):  # PyInstaller 包：自引用 serve 子命令
        serve_argv = [sys.executable, "serve",
                      "--data", str(data_dir), "--port", str(port), "--host", host]
    else:
        serve_argv = [sys.executable, str(REPO_ROOT / "server.py"),
                      "--data", str(data_dir), "--port", str(port), "--host", host]
    proc = subprocess.Popen(serve_argv, stdout=log, stderr=log, **kwargs)
    pid_file.write_text(str(proc.pid))
    print(f"      pid={proc.pid} 日志={log_path}")
    for _ in range(40):
        if healthz_ok(port, timeout=1, host=host):
            print(f"      healthz: {healthz_ok(port, host=host)}")
            return
        time.sleep(0.5)
    print(f"      探活失败，看 {log_path}", file=sys.stderr)
    raise SystemExit(1)


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def run_install(options: dict, interactive: bool = False) -> None:
    data_dir = expand_path(str(options.get("data") or ""))
    if not str(data_dir):
        print("必须提供 --data（或经向导/options 文件）", file=sys.stderr)
        raise SystemExit(64)
    force = bool(options.get("force"))
    port = int(options.get("port") or 8900)
    host = str(options.get("host") or "127.0.0.1").strip()

    print("════ compile-excel-server 安装部署 ════")
    print(f"仓库: {REPO_ROOT}")
    print(f"数据: {data_dir}")

    print("[0/6] 依赖检查 ...")
    ensure_deps(interactive)
    print(f"      python={'.'.join(map(str, sys.version_info[:3]))} 依赖 OK")

    print("[1/6] provision 数据目录与实例凭据 ...")
    provision.provision(data_dir, sample=False)

    print("[2/6] 工件灌入 ...")
    artifacts_dir = data_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    version_map: dict[str, str] = {}
    raw_artifacts = options.get("artifacts") or []
    if raw_artifacts:
        for entry in raw_artifacts:
            src_text, _, version = str(entry).partition(":")
            src = expand_path(src_text)
            if not src.is_file():
                print(f"  工件不存在: {src}", file=sys.stderr)
                raise SystemExit(66)
            print(f"  {copy_artifact(src, artifacts_dir, force)}")
            if version:
                version_map[src.name] = version
    else:
        print("      （未提供工件；--sample 将生成合成工件）")

    print("[3/6] cli-app 手册灌入 ...")
    docs_dir = data_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    raw_docs = options.get("docs") or []
    if raw_docs:
        total = 0
        for entry in raw_docs:
            source = expand_path(str(entry))
            if not source.exists():
                print(f"  手册路径不存在: {source}", file=sys.stderr)
                raise SystemExit(66)
            copied = copy_docs(source, docs_dir, force)
            total += len(copied)
            label = source.name if source.is_file() else str(source)
            print(f"  + {label}（{len(copied)} 篇）")
        print(f"      共 {total} 篇 markdown")
    else:
        print("      （未提供 --docs；--sample 将生成合成手册）")

    print("[4/6] 生成 artifacts_meta.json ...")
    artifacts_dir = data_dir / "artifacts"
    has_artifacts = artifacts_dir.is_dir() and any(
        entry.is_file() for entry in artifacts_dir.iterdir())
    if options.get("sample") and not has_artifacts:
        # 工件要等第 5 步 --sample 生成；此处先生成 meta 会因工件目录为空而中止安装。
        print("      （工件由 --sample 在第 5 步生成，meta 随后生成）")
    else:
        gen_meta.generate_meta(
            data_dir,
            device_build=str(options.get("device_build") or ""),
            kms=str(options.get("kms") or ""),
            version_map=version_map,
            default_version=str(options.get("default_version") or ""),
        )

    if options.get("sample"):
        print("[5/6] 生成合成样例（自测，零内部资产） ...")
        sample_data.generate(data_dir, force=True)
        gen_meta.generate_meta(
            data_dir,
            device_build=str(options.get("device_build") or ""),
            kms=str(options.get("kms") or ""),
            version_map={},
            default_version="",
        )
    else:
        print("[5/6] （未启用 --sample）")

    if options.get("start"):
        print(f"[6/6] 启动并探活（:{port}） ...")
        start_server(data_dir, port, host)
    else:
        launcher = ("ces serve" if getattr(sys, "frozen", False)
                    else f"python {REPO_ROOT / 'server.py'}")
        print(f"[6/6] （未传 --start）手动启动："
              f"{launcher} --data {data_dir} --port {port} --host {host}")

    print("════ 部署完成 ════")
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    INSTALL_JSON.write_text(
        json.dumps({"repo": str(REPO_ROOT), "data": str(data_dir), "port": port,
                    "host": host},
                   ensure_ascii=False, indent=1),
        encoding="utf-8")
    launcher = "ces" if getattr(sys, "frozen", False) else f"python {REPO_ROOT / 'ces_main.py'}"
    print(f"管理：{launcher}（无参数进菜单；status/start/stop/log/service 子命令）")
    print(f"客户端接入：export COMPILE_EXCEL_SERVER={client_url(host, port)}"
          "  → login.py → fetch.py")
    if probe_host(host) == "127.0.0.1" and host not in ("0.0.0.0", "::"):
        print("注意：当前只监听本机；其他机器要接入，用 --host 0.0.0.0 重装或在向导里改监听地址。")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="compile-excel-server 跨平台安装部署（无参数进入配置向导）")
    parser.add_argument("--options-file", default="",
                        help="按存档安装（向导产物，免访谈）")
    parser.add_argument("--data", default="")
    parser.add_argument("--device-build", default="")
    parser.add_argument("--kms", default="")
    parser.add_argument("--artifact", action="append", default=[],
                        help="工件路径[:版本]（可重复）")
    parser.add_argument("--docs", action="append", default=[],
                        help="cli-app 手册目录/文件（可重复）")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--host", default="",
                        help="监听地址（默认 127.0.0.1；局域网访问用 0.0.0.0）")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--sample", action="store_true")
    parser.add_argument("--yes", action="store_true", help="非交互确认（装依赖等）")
    args = parser.parse_args()

    try:
        if args.options_file:
            options = json.loads(
                Path(args.options_file).read_text(encoding="utf-8"))
            run_install(options, interactive=False)
            return 0
        if any([args.data, args.device_build, args.kms, args.artifact,
                args.docs, args.port, args.host, args.start, args.force,
                args.sample]):
            run_install({
                "data": args.data, "device_build": args.device_build,
                "kms": args.kms, "artifacts": args.artifact, "docs": args.docs,
                "port": args.port or 8900, "host": args.host or "127.0.0.1",
                "start": args.start,
                "force": args.force, "sample": args.sample,
            }, interactive=not args.yes)
            return 0
        # 无参数：配置向导
        state = wizard()
        options = {
            "data": state["data"],
            "device_build": state["device_build"],
            "kms": state["kms"],
            "port": state["port"] or "8900",
            "host": state.get("host") or "127.0.0.1",
            "force": state["force"] == "y",
            "start": state["start"] == "y",
            "artifacts": state["artifacts"],
            "docs": state["docs"],
        }
        opt_file = Path(state["data"]) / "install.options.json"
        opt_file.parent.mkdir(parents=True, exist_ok=True)
        opt_file.write_text(
            json.dumps(options, ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        try:
            os.chmod(opt_file, 0o600)
        except OSError:
            pass
        DRAFT_PATH.unlink(missing_ok=True)  # 配置确认完成，清草稿
        print()
        print(f"✓ 配置已存档: {opt_file}")
        print(f"✓ 复跑/升级（免访谈）: python {Path(__file__)} --options-file {opt_file}")
        print()
        print("开始执行安装 ...")
        run_install(options, interactive=False)
        return 0
    except (WizardInterrupt, KeyboardInterrupt):
        draft_message(load_draft())
        return 130


if __name__ == "__main__":
    sys.exit(main())
