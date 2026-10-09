"""ces 管理菜单：编号选择 + 一问一答（仿 x-ui 的管理脚本）。

菜单只负责收集参数：真正执行时调 ces_main.dispatch，与子命令是同一套代码；每做完一步显示对应的命令，
用熟了可以直接敲命令或写进脚本。列表里的对象（账号、客户端、构建、包）按编号选，不用手打名字；
会让别人掉线、删东西的操作先说清后果，默认选"否"。
"""

from __future__ import annotations

import glob
import os
import re
import shlex
import sys
import unicodedata
from pathlib import Path

import ces_main as ces

WIDTH = 60
LINE = "─" * WIDTH
DOUBLE = "═" * WIDTH


class Back(Exception):
    """Ctrl+C / Ctrl+D：回到上一级。"""


# ── 输入输出 ─────────────────────────────────────────────
def width(text: str) -> int:
    """终端里的显示宽度：中文等宽字符占两格（颜色控制符不占）。"""
    text = re.sub(r"\033\[[0-9;]*m", "", text)
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def pad(text: str, cells: int) -> str:
    return text + " " * max(cells - width(text), 1)


def _color(text: str, code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def green(text: str) -> str:
    return _color(text, "32")


def red(text: str) -> str:
    return _color(text, "31")


def yellow(text: str) -> str:
    return _color(text, "33")


def _input(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        raise Back() from None


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return _input(f"{prompt}{suffix}：").strip() or default


def is_number(raw: str) -> bool:
    """只认 ASCII 数字（str.isdigit 会放过上标数字，int() 却转不了）。"""
    return re.fullmatch(r"[0-9]+", raw) is not None


def ask_yes(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = _input(f"{prompt} [{hint}]：").strip().lower()
    return default if not raw else raw in ("y", "yes", "是")


def pause() -> None:
    try:
        _input("\n按回车返回")
    except Back:
        pass


def _complete_path(text: str, state: int) -> str | None:
    home = os.path.expanduser("~")
    pattern = os.path.expanduser(text) + "*"
    matches = []
    for match in sorted(glob.glob(pattern)):
        if os.path.isdir(match):
            match += "/"
        if text.startswith("~"):
            match = "~" + match[len(home):]
        matches.append(match)
    return matches[state] if state < len(matches) else None


def ask_path(prompt: str, default: str = "", *, kind: str = "any") -> str:
    """问一个路径，Tab 补全；kind=file/dir/any 时检查它存在且类型对，kind=new 不检查。"""
    try:
        import readline
    except ImportError:
        readline = None
    if readline is not None:
        readline.set_completer_delims(" \t\n")
        readline.set_completer(_complete_path)
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    try:
        while True:
            raw = ask(f"{prompt}（Tab 补全）", default)
            if not raw:
                return ""
            path = Path(raw).expanduser()
            if kind == "file" and not path.is_file():
                print(f"  找不到文件：{path}（文件要先传到这台服务器上）")
            elif kind == "dir" and not path.is_dir():
                print(f"  找不到目录：{path}（目录要先传到这台服务器上）")
            elif kind == "any" and not path.exists():
                print(f"  找不到：{path}（要先传到这台服务器上）")
            else:
                return str(path)
    finally:
        if readline is not None:
            readline.set_completer(None)


def choose(title: str, items: list[str], *, allow_empty: bool = False) -> int | None:
    """编号列表里选一项，返回下标；0 或回车返回 None。"""
    if not items:
        print(f"  （{title}：没有可选的）")
        return None
    print(f"\n{title}：")
    for index, item in enumerate(items, start=1):
        print(f"  {index:>2}. {item}")
    print("   0. 返回")
    while True:
        raw = _input(f"请选择 [0-{len(items)}]：").strip()
        if raw in ("", "0"):
            return None
        if is_number(raw) and 1 <= int(raw) <= len(items):
            return int(raw) - 1
        print("  没有这个编号，请重输。")


def choose_many(title: str, items: list[tuple[str, str]], selected: set[str]) -> list[str]:
    """多选：items 是 (值, 说明)；输入编号（空格或逗号分隔），回车保留当前选择。"""
    print(f"\n{title}（✓ 是当前选择）：")
    for index, (value, note) in enumerate(items, start=1):
        mark = "✓" if value in selected else " "
        print(f"  {index:>2}. [{mark}] {note}  （{value}）")
    while True:
        raw = _input("输入要的编号，空格分隔；回车保留当前选择：").strip()
        if not raw:
            return [value for value, _ in items if value in selected]
        parts = [p for p in re.split(r"[\s,，]+", raw) if p]
        if all(is_number(p) and 1 <= int(p) <= len(items) for p in parts):
            return [items[int(p) - 1][0] for p in sorted(set(parts), key=int)]
        print("  编号不对，请重输。")


def run(*argv: str) -> int:
    """执行一条子命令（与命令行同一套代码），然后显示对应的命令。"""
    print(LINE)
    try:
        code = ces.dispatch(list(argv))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except KeyboardInterrupt:
        print("\n已中断。")
        code = 130
    except Exception as exc:  # noqa: BLE001  菜单不能因为一条命令出错就整个退出
        print(red(f"出错了：{type(exc).__name__}: {exc}"))
        code = 1
    print(LINE)
    print(f"对应命令：ces {shlex.join(argv)}")
    if code not in (0, None):
        print(yellow(f"（没有成功，返回码 {code}）"))
    return code or 0


def offer_restart() -> None:
    install = ces.installed()
    try:
        running = bool(install and ces._health(install))
    except Exception:  # noqa: BLE001  探活失败就当没在运行
        running = False
    if running and ask_yes("现在重启服务让改动生效？", True):
        run("restart")


def _secret_out(what: str, default: str = "") -> list[str]:
    """问把一次性凭据存到哪里。有默认文件时回车就存到默认文件，输入 - 只显示在屏幕上。"""
    if default:
        print(f"{what}只会出现这一次，建议存成文件（权限 600）。回车存到默认文件；输入 - 只显示在屏幕上。")
    else:
        print(f"{what}只会出现这一次。输入文件路径就存成文件（权限 600）；直接回车只显示在屏幕上。")
    while True:
        out = ask_path("保存到文件", default, kind="new")
        if out in ("", "-"):
            return []
        if Path(out).expanduser().exists():
            print(f"  {out} 已经存在，换一个文件名（不覆盖已有的访问码或密钥文件）。")
            default = ""
            continue
        return ["--out", out]


# ── 首页 ─────────────────────────────────────────────────
def _registry():
    from registry import Registry

    install = ces.installed()
    return Registry(Path(install["data"]) / "registry") if install else None


def _store():
    from auth_store import AuthStore

    install = ces.installed()
    return AuthStore(Path(install["data"]) / "auth.db") if install else None


def header() -> None:
    from ces_version import __version__

    print()
    print(DOUBLE)
    title = " compile-excel-server 管理菜单"
    version = f"版本 {__version__}"
    print(title + " " * max(WIDTH - width(title) - width(version), 1) + version)
    print(DOUBLE)
    install = ces.installed()
    if install is None:
        print(f" {yellow('还没有配置。')}选 1 开始配置（大约两分钟）。")
        return
    try:
        health = ces._health(install, timeout=1.5)
        state = green("● 运行中") if health else red("● 未运行")
        auto = "是" if ces.autostart_registered(install) else "否"
        info = ces.connection_info(install)
        print(" " + pad("服务", 10) + pad(state, 20) + pad("开机自启", 12) + auto)
        print(" " + pad("连接串", 10) + info["link"])
        print(" " + pad("证书", 10) + info["tls_label"])
    except Exception as exc:  # noqa: BLE001  首页只是概览，读不出来也不能挡住菜单
        print(f" （读取服务状态失败：{exc}）")
    try:
        builds = _registry().list_builds()
        stable = [f"{b['build']} → {b['channels']['stable']['bundle_id'][:12]}"
                  for b in builds if "stable" in b["channels"]]
        published = (f"；已发布：{'，'.join(stable[:2])}" + ("…" if len(stable) > 2 else "")
                     if stable else "；还没有发布到 stable")
        print(" " + pad("编译数据", 10) + f"{len(builds)} 个构建{published}")
        users = _store().list_users()
        disabled = sum(1 for u in users if u["disabled"])
        clients = _store().list_clients()
        count = f"{len(users)} 个" + (f"（停用 {disabled}）" if disabled else "")
        print(" " + pad("账号", 10) + pad(count, 20) + pad("服务客户端", 12) + f"{len(clients)} 个")
    except Exception as exc:  # noqa: BLE001
        print(f" （读取数据目录失败：{exc}）")


MAIN_ITEMS = [
    ("服务管理", "启动、停止、重启、看日志、开机自启"),
    ("账号", "新建、停用、重置访问码、修改权限"),
    ("服务客户端", "网关、发布器用的密钥"),
    ("编译数据", "导入、发布、回滚、校验、清理"),
    ("手册与旧版工件", "知识库手册、旧版工件、构建号、KMS 地址"),
    ("连接与证书", "连接串、重新签发证书、网关证书"),
    ("客户端配置", "下发给用户的网关、门户、缺陷系统地址"),
    ("审计日志", "复核、轮换"),
    ("重新配置", "重新运行配置向导"),
    ("更新", "更新到最新版本"),
    ("卸载", ""),
]


def run_menu() -> int:
    while True:
        header()
        install = ces.installed()
        print(LINE)
        if install is None:
            print("   1. 开始配置")
            print("   0. 退出")
            print(LINE)
            try:
                raw = _input("请选择 [0-1]：").strip()
            except Back:
                return 0
            if raw == "1":
                try:
                    run("setup")
                except Back:
                    pass
                pause()
            elif raw in ("0", ""):
                return 0
            continue
        for index, (name, note) in enumerate(MAIN_ITEMS, start=1):
            print(f"  {index:>2}. {pad(name, 16)}{note}")
        print("   0. 退出")
        print(LINE)
        try:
            raw = _input(f"请选择 [0-{len(MAIN_ITEMS)}]：").strip()
        except Back:
            return 0
        if raw in ("0", ""):
            return 0
        handler = HANDLERS.get(raw)
        if handler is None:
            print("没有这个编号。")
            continue
        try:
            if handler() == "exit":
                return 0
        except Back:
            continue


def submenu(title: str, items: list[tuple[str, object]]) -> None:
    """二级菜单：做完一项停一下，回车回到本级；0 回首页。"""
    while True:
        print(f"\n{DOUBLE}\n {title}\n{LINE}")
        for index, (name, _) in enumerate(items, start=1):
            print(f"  {index:>2}. {name}")
        print("   0. 返回首页")
        print(LINE)
        raw = _input(f"请选择 [0-{len(items)}]：").strip()
        if raw in ("0", ""):
            return
        if not is_number(raw) or not 1 <= int(raw) <= len(items):
            print("没有这个编号。")
            continue
        try:
            items[int(raw) - 1][1]()
        except Back:
            print("已取消。")
        pause()


# ── 1. 服务管理 ───────────────────────────────────────────
def menu_service() -> None:
    def stop() -> None:
        if ask_yes("停止后用户暂时不能登录、同步，确定停止？"):
            run("stop")

    def autostart_on() -> None:
        if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() != 0:
            print("注册系统服务要管理员权限，请运行：")
            print(f"  sudo {ces.self_command('service', 'install')}")
            print("（服务会以数据目录的属主运行，不是 root。）")
            return
        run("service", "install")

    submenu("服务管理", [
        ("查看运行状态", lambda: run("status")),
        ("启动", lambda: run("start")),
        ("停止", stop),
        ("重启", lambda: run("restart")),
        ("看日志（最后 40 行）", lambda: run("log")),
        ("开启开机自启", autostart_on),
        ("关闭开机自启", lambda: run("service", "remove")),
    ])


# ── 2. 账号 ──────────────────────────────────────────────
def _user_scopes() -> list[tuple[str, str]]:
    from auth_store import SCOPES

    return [(k, v) for k, v in SCOPES.items() if k != "introspect"]


def _pick_user(title: str, *, disabled: bool | None = None) -> str | None:
    users = [u for u in _store().list_users()
             if disabled is None or bool(u["disabled"]) == disabled]
    index = choose(title, [f"{u['username']}{'（已停用）' if u['disabled'] else ''}"
                           for u in users])
    return None if index is None else users[index]["username"]


def menu_users() -> None:
    from auth_store import DEFAULT_USER_SCOPES, valid_name

    def add() -> None:
        while True:
            name = ask("新账号的用户名（字母、数字、. _ -）")
            if not name:
                return
            if valid_name(name):
                break
            print("  用户名只能含字母、数字和 . _ -，以字母或数字开头。")
        argv = ["users", "add", name]
        if not ask_yes("用默认权限（编译、检索手册、在跳板机上跑用例）？", True):
            scopes = choose_many("选择权限", _user_scopes(), set(DEFAULT_USER_SCOPES))
            argv += ["--scopes", " ".join(scopes)]
        argv += _secret_out("访问码")
        if run(*argv) == 0:
            info = ces.connection_info(ces.load_install())
            print(f"\n把三样东西发给 {name} 本人：用户名、访问码、连接串")
            print(f"  连接串：{info['link']}")

    def disable() -> None:
        name = _pick_user("停用哪个账号", disabled=False)
        if name and ask_yes(f"停用后 {name} 已登录的会话全部失效，也不能再登录。确定？"):
            run("users", "disable", name)

    def enable() -> None:
        name = _pick_user("启用哪个账号", disabled=True)
        if name:
            run("users", "enable", name)

    def reset() -> None:
        name = _pick_user("给哪个账号重置访问码")
        if name and ask_yes(f"重置后 {name} 的旧访问码作废、已登录的会话全部失效。确定？"):
            run("users", "reset-code", name, *_secret_out("新访问码"))

    def scopes() -> None:
        name = _pick_user("修改哪个账号的权限")
        if not name:
            return
        current = next(u for u in _store().list_users() if u["username"] == name)
        chosen = choose_many(f"{name} 的权限", _user_scopes(), set(current["scopes"].split()))
        if not chosen:
            print("至少要留一项权限；想让他不能登录，用“停用账号”。")
            return
        if ask_yes("改权限会让他已登录的会话失效（重新登录即可）。确定？", True):
            run("users", "scopes", name, " ".join(chosen))

    def revoke() -> None:
        name = _pick_user("让哪个账号的所有会话下线")
        if name and ask_yes(f"{name} 需要重新登录。确定？"):
            run("tokens", "revoke", "--user", name)

    submenu("账号", [
        ("查看全部账号", lambda: run("users", "list")),
        ("新建账号", add),
        ("停用账号", disable),
        ("启用账号", enable),
        ("重置访问码", reset),
        ("修改权限", scopes),
        ("让某人的所有会话下线", revoke),
        ("清理过期的登录记录", lambda: run("tokens", "purge")),
    ])


# ── 3. 服务客户端 ─────────────────────────────────────────
def _pick_client(title: str) -> str | None:
    clients = _store().list_clients()
    index = choose(title, [f"{c['client_id']}  （{c['scopes']}）" for c in clients])
    return None if index is None else clients[index]["client_id"]


def menu_clients() -> None:
    def add(kind: str) -> None:
        if kind == "gateway":
            print("网关装在跳板机上，用这个客户端核验用户的登录、读取规则文件。")
            client_id = ask("客户端名称", "gateway")
            scopes = "introspect bundles:read"
            default_out = str(Path.home() / f"{client_id}-client.secret")
        else:
            print("发布器把编译数据上传到服务端（tools/ 下的发布脚本用）。")
            client_id = ask("客户端名称", "publisher")
            scopes = "bundles:publish bundles:read"
            default_out = str(Path.home() / f"{client_id}-client.secret")
        if run("clients", "add", client_id, "--scopes", scopes,
               *_secret_out("客户端密钥", default_out)) == 0 and kind == "gateway":
            print("\n把密钥文件拷到跳板机（权限保持 600），gateway.toml 里 [server] client_secret_file 指向它。")

    def rotate() -> None:
        client_id = _pick_client("给哪个客户端换密钥")
        if client_id and ask_yes(f"换完后 {client_id} 的旧密钥立即失效，要把新密钥换到它那台机器上。确定？"):
            run("clients", "rotate-secret", client_id, *_secret_out("新密钥"))

    def remove() -> None:
        client_id = _pick_client("删除哪个客户端")
        if client_id and ask_yes(f"删除后 {client_id} 立即不能再用。确定？"):
            run("clients", "remove", client_id)

    submenu("服务客户端", [
        ("查看全部", lambda: run("clients", "list")),
        ("新建网关客户端", lambda: add("gateway")),
        ("新建发布客户端", lambda: add("publisher")),
        ("更换密钥", rotate),
        ("删除", remove),
    ])


# ── 4. 编译数据 ───────────────────────────────────────────
KIND_LABELS = {
    "cmdtree": "命令树",
    "projections": "投影（规则与派生表）",
    "manual": "手册",
    "spec": "规格书",
    "template": "Excel 模板",
    "framework": "测试框架",
    "footprints": "回填记录",
}


def _pick_build(title: str, *, allow_new: bool = False) -> str | None:
    from registry import valid_build

    builds = [b["build"] for b in _registry().list_builds()]
    items = builds + (["（新建一个构建）"] if allow_new else [])
    index = choose(title, items)
    if index is None:
        return None
    if index < len(builds):
        return builds[index]
    while True:
        name = ask("构建号（与设备 show version 里的执行构建一致，字母、数字和 . _ -）")
        if not name or valid_build(name):
            return name or None
        print("  构建号不合法，请重输。")


def _short(bundle_id: str | None) -> str:
    return bundle_id[:12] if bundle_id else "（空）"


def menu_registry() -> None:
    from registry import KINDS

    def bundles() -> None:
        build = _pick_build("查看哪个构建")
        if build:
            run("registry", "bundles", build)

    def show() -> None:
        build = _pick_build("查看哪个构建")
        if not build:
            return
        index = choose("哪个通道", ["stable（用户默认用的）", "candidate（待发布的）"])
        if index is not None:
            run("registry", "show", build, "--channel", ("stable", "candidate")[index])

    def promote(build: str | None = None, bundle_id: str | None = None) -> None:
        """把 candidate（或指定的包，例如刚导入的那个）发布到 stable。"""
        build = build or _pick_build("发布哪个构建")
        if not build:
            return
        reg = _registry()
        candidate = bundle_id or reg.channel_bundle(build, "candidate")
        stable = reg.channel_bundle(build, "stable")
        if not candidate:
            print(f"{build} 还没有待发布的包（candidate 为空），先导入。")
            return
        if candidate == stable:
            print(f"{build} 的 stable 已经是最新的 candidate（{_short(candidate)}），不用再发布。")
            return
        print(f"把 {build} 的 stable 从 {_short(stable)} 换成 {_short(candidate)}。")
        print("用户下次同步就会拿到新数据。")
        if ask_yes("确定发布？"):
            run("registry", "promote", build, candidate, "--expect", stable or "none")

    def import_dir() -> None:
        build = _pick_build("导入到哪个构建", allow_new=True)
        if not build:
            return
        index = choose("这个目录里是哪一类数据", [f"{KIND_LABELS.get(k, k)}（{k}）" for k in KINDS])
        if index is None:
            return
        kind = KINDS[index]
        directory = ask_path("目录", kind="dir")
        if not directory:
            return
        argv = ["registry", "import-dir", build, kind, directory]
        print("默认按文件路径叠加：同名文件换成新的，其余保留。")
        if ask_yes(f"改成整类替换（先清掉 candidate 里所有{KIND_LABELS.get(kind, kind)}）？"):
            argv.append("--replace-kind")
        if run(*argv) == 0 and ces.LAST_IMPORT.get("build") == build:
            imported = ces.LAST_IMPORT["bundle_id"]
            if not ces.LAST_IMPORT.get("checks", {}).get("ok", True):
                print("这次导入的包没通过服务端自检，不能发布到 stable。")
            elif ask_yes(f"现在就把这次导入的包 {_short(imported)} 发布到 stable？"):
                promote(build, imported)

    def rollback() -> None:
        build = _pick_build("回滚哪个构建")
        if not build:
            return
        reg = _registry()
        stable = reg.channel_bundle(build, "stable")
        older = [b for b in reg.list_bundles(build)
                 if b["checks_ok"] and b["bundle_id"] != stable]
        index = choose(f"{build} 的 stable 当前是 {_short(stable)}，换回哪一个",
                       [f"{_short(b['bundle_id'])}  {b['created_at']}  {b['entries']} 个文件  "
                        f"发布者 {b['publisher']}" for b in older])
        if index is None:
            return
        target = older[index]["bundle_id"]
        if ask_yes(f"确定把 stable 换回 {_short(target)}？用户下次同步会拿到这个旧版本。"):
            run("registry", "promote", build, target, "--expect", stable or "none")

    def gc() -> None:
        print("删除没有任何包引用、而且 24 小时内没有再上传过的文件（正在进行的发布不受影响）。")
        if ask_yes("确定清理？"):
            run("registry", "gc")

    submenu("编译数据", [
        ("查看构建与发布情况", lambda: run("registry", "list")),
        ("查看某个构建的全部包", bundles),
        ("查看包里的文件", show),
        ("导入目录（进入待发布）", import_dir),
        ("发布到 stable", promote),
        ("回滚 stable 到旧版本", rollback),
        ("校验全部文件", lambda: run("registry", "verify")),
        ("清理没用的文件", gc),
    ])


# ── 5. 手册与旧版工件 ─────────────────────────────────────
def menu_legacy() -> None:
    def add_docs() -> None:
        source = ask_path("手册目录或 .md 文件")
        if not source:
            return
        argv = ["docs", "add", source]
        if ask_yes("同名文件内容不同时覆盖？"):
            argv.append("--force")
        if run(*argv) == 0:
            offer_restart()

    def add_artifacts() -> None:
        argv = ["artifacts", "add"]
        print("逐个输入文件，空行结束。版本号可选（不填记为安装日期）。")
        while True:
            path = ask_path(f"第 {len(argv) - 1} 个文件", kind="file")
            if not path:
                break
            version = ask("版本号（可不填）")
            argv.append(f"{path}:{version}" if version else path)
        if len(argv) == 2:
            return
        if ask_yes("同名文件内容不同时覆盖？"):
            argv.append("--force")
        if run(*argv) == 0:
            offer_restart()

    def build() -> None:
        value = ask("旧版接口用的构建号（字母、数字和 . _ -）")
        if value and run("artifacts", "build", value) == 0:
            offer_restart()

    def kms() -> None:
        value = ask("KMS 地址（主机:端口；不用 KMS 输入 none）")
        if value and run("artifacts", "kms", value) == 0:
            offer_restart()

    submenu("手册与旧版工件", [
        ("查看手册", lambda: run("docs", "list")),
        ("导入手册", add_docs),
        ("查看旧版工件、构建号、KMS 地址", lambda: run("artifacts", "list")),
        ("导入旧版工件", add_artifacts),
        ("设置旧版构建号", build),
        ("设置 KMS 地址", kms),
    ])


# ── 6. 连接与证书 ─────────────────────────────────────────
def menu_tls() -> None:
    def renew() -> None:
        print("证书默认包含本机的主机名和各网卡地址，以前加过的地址也会保留。"
              "用户用别的地址（域名、映射出去的 IP）访问时，在这里加上。")
        extra = ask("要加上的地址（空格分隔，可不填）")
        drop = ask("要去掉的地址（空格分隔，可不填）")
        argv = ["tls", "renew"]
        for name in extra.split():
            argv += ["--name", name]
        for name in drop.split():
            argv += ["--remove", name]
        if run(*argv) == 0:
            offer_restart()

    def gateway() -> None:
        names = ask("跳板机的 IP 或主机名（空格分隔）")
        if not names:
            return
        out = ask_path("证书放到哪个目录", str(Path.home() / "cexg-tls"), kind="new")
        if out:
            run("tls", "gateway", *names.split(), "--out", out)

    def set_host() -> None:
        print("连接串默认写本机默认路由那块网卡的地址。多网卡、用户在别的网段、经端口映射访问时，在这里指定。")
        value = ask("连接串里的地址（IP 或主机名；输入 auto 改回自动选择）")
        if value and run("link", "--host", value) == 0:
            offer_restart()

    submenu("连接与证书", [
        ("显示连接串", lambda: run("link")),
        ("设置连接串里的地址", set_host),
        ("查看证书", lambda: run("tls", "show")),
        ("重新签发服务器证书（加地址）", renew),
        ("为跳板机网关签发证书", gateway),
    ])


# ── 7. 客户端配置 ─────────────────────────────────────────
def menu_config() -> None:
    import client_config

    keys = list(client_config.KEYS.items())

    def set_key() -> None:
        index = choose("设置哪一项", [f"{note}（{key}）" for key, note in keys])
        if index is not None:
            value = ask("地址（http 或 https 开头，不要带账号口令）")
            if value:
                run("config", "set", keys[index][0], value)

    def unset_key() -> None:
        index = choose("删除哪一项", [f"{note}（{key}）" for key, note in keys])
        if index is not None:
            run("config", "unset", keys[index][0])

    def import_env() -> None:
        path = ask_path("KEY=value 格式的文件", kind="file")
        if path:
            run("config", "import-env", path)

    submenu("客户端配置", [
        ("查看", lambda: run("config", "show")),
        ("设置一项", set_key),
        ("删除一项", unset_key),
        ("从文件导入", import_env),
    ])


# ── 8. 审计日志 ───────────────────────────────────────────
def menu_audit() -> None:
    def rotate(new_key: bool) -> None:
        print("把当前审计日志封存到 audit_archive/，从新文件接着记；服务不用重启。")
        if new_key:
            print("同时换审计签名密钥（旧密钥随封存的那一段一起保存，复核要用）。")
        if ask_yes("确定？"):
            run("audit", "rotate", *(["--new-key"] if new_key else []))

    submenu("审计日志", [
        ("复核（检查有没有被改、被删）", lambda: run("audit", "verify")),
        ("封存当前段，起新文件", lambda: rotate(False)),
        ("封存并更换签名密钥", lambda: rotate(True)),
    ])


# ── 9–11 ────────────────────────────────────────────────
def menu_setup() -> None:
    print("重新运行配置向导：数据目录里的账号、编译数据、审计日志都会保留。")
    if ask_yes("继续？", True):
        run("setup")
        pause()


def menu_update() -> str | None:
    if not ask_yes("下载并安装最新版本？数据目录和配置不会动。", True):
        return None
    if run("update") == 0:
        print("请重新运行 ces 进入新版本的菜单。")
        return "exit"
    pause()
    return None


def menu_uninstall() -> str | None:
    if not ask_yes("卸载 compile-excel-server（停止服务、关闭开机自启、删除程序）？"):
        return None
    argv = ["uninstall"]
    if ask_yes(red("同时删除数据目录？账号、编译数据、审计日志全部删除，无法恢复")):
        if ask("确认请输入 删除", "") != "删除":
            print("没有确认，数据目录保留。")
        else:
            argv.append("--purge")
    run(*argv)
    return "exit"


HANDLERS = {
    "1": menu_service,
    "2": menu_users,
    "3": menu_clients,
    "4": menu_registry,
    "5": menu_legacy,
    "6": menu_tls,
    "7": menu_config,
    "8": menu_audit,
    "9": menu_setup,
    "10": menu_update,
    "11": menu_uninstall,
}


def main() -> int:
    try:
        return run_menu()
    except KeyboardInterrupt:
        print()
        return 0
