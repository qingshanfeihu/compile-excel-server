"""串口控制台：占线进程按设备名精确认（ttyS1 不连带 ttyS10–19）；
关控制台时不理 TERM 的进程会被 KILL。"""

from __future__ import annotations

import os
import sys
import time

from gateway import console


def _fake_proc(root, pid: int, *argv: str) -> None:
    entry = root / str(pid)
    entry.mkdir()
    (entry / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")


def test_console_holders_match_the_exact_device(tmp_path):
    _fake_proc(tmp_path, 101, "cu", "-s", "9600", "-l", "ttyS1")
    _fake_proc(tmp_path, 102, "/usr/bin/cu", "-l", "/dev/ttyS1")
    _fake_proc(tmp_path, 103, "cu", "-lttyS1")
    _fake_proc(tmp_path, 104, "cu", "--line=/dev/ttyS1")
    _fake_proc(tmp_path, 110, "cu", "-s", "9600", "-l", "ttyS10")
    _fake_proc(tmp_path, 111, "cu", "-l", "/dev/ttyS12")
    _fake_proc(tmp_path, 112, "minicom", "-D", "/dev/ttyS1")
    (tmp_path / "self").mkdir()
    assert sorted(console.console_holders("ttyS1", tmp_path)) == [101, 102, 103, 104]
    assert console.console_holders("ttyS10", tmp_path) == [110]


def test_close_kills_a_console_that_ignores_sigterm():
    script = ("import signal, sys, time\n"
              "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
              "print('Connected.', flush=True)\n"
              "time.sleep(60)\n")
    con = console.Console([sys.executable, "-c", script])
    assert con.read_until(r"Connected\.", 10)[0]
    started = time.monotonic()
    con.close(grace=0.5)
    assert time.monotonic() - started < 5, "close 不能一直等一个不理 TERM 的进程"
    try:
        os.kill(con.pid, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive, "进程已被 KILL 并收尸"
