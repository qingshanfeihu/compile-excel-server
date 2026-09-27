"""串口初始化：网关进程里用 pty 直接起控制台命令（默认 `cu -s 9600 -l ttyS<n>`），不再 ssh 到本机，
因此不需要本机口令。

与 InfoTest tools.init_device 的区别：
- 设备命令全部来自 gateway.toml 的 init_device.commands（占位符 {idx} {port1} {port2} {port3}），
  代码里不写任何设备命令；
- 每一步都要等到配置模式提示符，等不到就判这台设备失败并停在那一步（InfoTest 读不到提示符也照发下一条，
  最后仍报 ok）；
- 登录状态机沿用 InfoTest _ser_console_login 的分支，但每一步都核对提示符。
"""

from __future__ import annotations

import os
import pty
import re
import select
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_PROMPT = r"\(config\)#"


class ConsoleError(RuntimeError):
    pass


class Console:
    def __init__(self, argv: list[str]):
        self.argv = argv
        pid, fd = pty.fork()
        if pid == 0:  # 子进程
            try:
                os.execvp(argv[0], argv)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.buffer = ""

    def send(self, text: str) -> None:
        os.write(self.fd, text.encode("utf-8"))

    def read_until(self, pattern: str, timeout: float) -> tuple[bool, str]:
        regexp = re.compile(pattern)
        deadline = time.monotonic() + timeout
        seen = ""
        while True:
            match = regexp.search(self.buffer)
            if match:
                seen += self.buffer[:match.end()]
                self.buffer = self.buffer[match.end():]
                return True, seen
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                seen += self.buffer
                self.buffer = ""
                return False, seen
            ready, _, _ = select.select([self.fd], [], [], min(remaining, 0.2))
            if ready:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    seen += self.buffer
                    self.buffer = ""
                    return False, seen
                self.buffer += chunk.decode("utf-8", errors="ignore")

    def close(self, grace: float = 3.0) -> None:
        """先 SIGTERM；grace 秒内不退（cu 卡在串口上常不理 TERM）就 SIGKILL，不让网关线程一直等。"""
        for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, grace)):
            try:
                os.kill(self.pid, sig)
            except ProcessLookupError:
                pass
            if _reaped(self.pid, wait):
                break
        try:
            os.close(self.fd)
        except OSError:
            pass


def _reaped(pid: int, timeout: float) -> bool:
    """timeout 秒内等子进程退出并收尸；子进程已经不在也算。"""
    deadline = time.monotonic() + timeout
    while True:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if done:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def console_holders(tty: str, proc_root: Path = Path("/proc")) -> list[int]:
    """同一用户下占着这条串口线的 cu 进程：参数里恰好是这个设备（ttyS1 或 /dev/ttyS1），
    不按子串认——ttyS1 不能连带 ttyS10–ttyS19。"""
    found = []
    uid = os.getuid()
    for proc in proc_root.iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            if proc.stat().st_uid != uid:
                continue
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        words = [a.decode("utf-8", "ignore") for a in argv if a]
        if not words or os.path.basename(words[0]) != "cu":
            continue
        # -l ttyS1、-lttyS1、--line=ttyS1 三种写法取出的设备名都要与目标完全相同
        values = set(words[1:]) | {w[2:] for w in words[1:] if w.startswith("-l")} \
            | {w.split("=", 1)[1] for w in words[1:] if "=" in w}
        if values & {tty, f"/dev/{tty}"}:
            found.append(int(proc.name))
    return found


def _kill_console_holders(tty: str) -> list[int]:
    killed = []
    for pid in console_holders(tty):
        try:
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except OSError:
            pass
    return killed


@dataclass
class InitResult:
    device: int
    tty: str
    status: str = "error"
    failed_step: str = ""
    log: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"device": self.device, "tty": self.tty, "status": self.status,
                "failed_step": self.failed_step, "log": self.log}


def _login(con: Console, hostname: str, user: str, passwd: str, timeout: float) -> bool:
    """沿用 InfoTest _ser_console_login 的分支，每一步都核对提示符；返回是否进到特权模式。"""
    host = re.escape(hostname or "APV")
    con.send("\n")
    ok, out = con.read_until(
        rf"(ogin)|(assword:)|({host}#)|Mode\]#|Init\]#|Standby\]#|Active\]#|\]>|(\]#)|"
        rf"(config\)#)|(\$ )|(\# )|({host}>)", timeout)
    if not ok:
        return False

    def enable_if_needed(text: str) -> bool:
        if re.search(r">\s*$", text.rstrip()) or re.search(rf"{host}>", text):
            con.send("enable\n")
            ok2, text = con.read_until(r"(#)|(sword:)", timeout)
            if not ok2:
                return False
            if "sword:" in text:
                con.send(passwd + "\n")
                ok2, _ = con.read_until("#", timeout)
                return ok2
        return True

    if re.search(rf"{host}>", out) or re.search(r"\]>", out):
        con.send("quit\n")
        ok, out = con.read_until(r"(ogin)|(\]#)|(\]\$)|(# )", timeout)
        if not ok:
            return False
    if "ogin" in out:
        con.send(user + "\n")
        if not con.read_until("sword:", timeout)[0]:
            return False
        con.send(passwd + "\n")
        ok, out = con.read_until(r"(#)|(>)", timeout)
        if not ok or not enable_if_needed(out):
            return False
    elif "assword:" in out:
        con.send(passwd + "\n")
        ok, out = con.read_until(r"(#)|(>)", timeout)
        if not ok or not enable_if_needed(out):
            return False
    elif re.search(r"\$ |\# ", out):
        con.send("su\n")
        if not con.read_until("sword:", timeout)[0]:
            return False
        con.send(passwd + "\n")
        if not con.read_until("#", timeout)[0]:
            return False
    con.send("terminal length 0\n")
    return con.read_until("#", timeout)[0]


def init_one(idx: int, *, console_argv: list[str], tty: str, hostname: str, user: str,
             passwd: str, commands: list[str], long_commands: dict[str, int],
             step_timeout: float, login_timeout: float) -> InitResult:
    result = InitResult(device=idx, tty=tty)
    con = Console(console_argv)
    try:
        ok, out = con.read_until(r"(Connected\.)|(Line in use)", login_timeout)
        if "Line in use" in out:
            killed = _kill_console_holders(tty)
            result.log.append(f"line in use; stopped {len(killed)} console process(es)")
            con.close()
            time.sleep(1)
            con = Console(console_argv)
            ok, out = con.read_until(r"Connected\.", login_timeout)
        if not ok:
            result.failed_step = "connect"
            return result
        if not _login(con, hostname, user, passwd, login_timeout):
            result.failed_step = "login"
            return result
        result.log.append("login ok")
        con.send("conf ter\n")
        ok, out = con.read_until(r"#", step_timeout)
        if "Someone else is in config mode" in out:
            con.send("conf ter force\n")
            ok, out = con.read_until(r"#", step_timeout)
        if not ok or not re.search(CONFIG_PROMPT, out):
            result.failed_step = "enter config mode"
            return result
        for command in commands:
            con.send(command + "\n")
            timeout = float(long_commands.get(command, step_timeout))
            ok, _ = con.read_until(CONFIG_PROMPT, timeout)
            if not ok:
                result.failed_step = command
                result.log.append(f"no config prompt within {timeout:.0f}s after: {command}")
                return result
            result.log.append(f"ok: {command}")
        result.status = "ok"
        return result
    finally:
        con.close()


def render_commands(template: list[str], idx: int, port_names: list[str]) -> list[str]:
    values = {"idx": idx, "port1": port_names[0], "port2": port_names[1], "port3": port_names[2]}
    return [line.format(**values) for line in template]
