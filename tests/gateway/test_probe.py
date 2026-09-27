"""只读探测：命令只许 show/get 一族与安全字符；
代理读回显要等到锚在末尾的设备提示符，等不到就标 truncated。"""

from __future__ import annotations

import sys
import types

import pytest

from gateway import framework
from gateway.agent import jumphost_agent

from test_gateway import ALICE, _lease


class FakeChan:
    """invoke_shell 的替身：每条发出去的命令对应一串分块到达的回显。"""

    def __init__(self, script):
        self.script = script
        self.pending = ["Last login: today\r\n", "APV>"]

    def send(self, text):
        self.pending.extend(self.script.get(text.strip(), ["\r\nAPV#"]))

    def recv_ready(self):
        return bool(self.pending)

    def recv(self, _size):
        return self.pending.pop(0).encode()


def _probe(monkeypatch, output_chunks, command="show running-config"):
    chan = FakeChan({"enable": ["enable\r\n", "APV#"], "terminal length 0":
                     ["terminal length 0\r\nAPV#"], command: output_chunks})
    client = types.SimpleNamespace(set_missing_host_key_policy=lambda policy: None,
                                   connect=lambda **kw: None, invoke_shell=lambda: chan,
                                   close=lambda: None)
    monkeypatch.setitem(sys.modules, "paramiko", types.SimpleNamespace(
        SSHClient=lambda: client, AutoAddPolicy=object))
    monkeypatch.setattr(jumphost_agent, "PROMPT_WAIT_S", 1.0)
    monkeypatch.setattr(jumphost_agent, "COMMAND_WAIT_S", 1.0)
    monkeypatch.setattr(jumphost_agent, "QUIET_S", 0.05)
    return jumphost_agent.op_probe({"ip": "192.0.2.70", "user": "u", "passwd": "p",
                                    "command": command})


def test_output_with_hash_lines_arriving_in_chunks_is_read_to_the_prompt(monkeypatch):
    out = _probe(monkeypatch, [
        "show running-config\r\n", "# generated config\r\nslb real http r1 192.0.2.1 80\r\n",
        "#\r\nslb real http r2 192.0.2.2 80\r\n", "APV#"])
    assert out["output"].splitlines() == [
        "# generated config", "slb real http r1 192.0.2.1 80", "#",
        "slb real http r2 192.0.2.2 80", "APV#"]
    assert "truncated" not in out


def test_missing_prompt_is_reported_as_truncated(monkeypatch):
    out = _probe(monkeypatch, ["show running-config\r\n", "slb real http r1 192.0.2.1 80\r\n"])
    assert out["truncated"] is True and "no device prompt" in out["note"]
    assert "slb real http r1 192.0.2.1 80" in out["output"]


@pytest.mark.parametrize("command", [
    "conf t", "show version; reboot", "show version\nreboot", "show\x1bversion", "",
    "show version | include slb", "show running-config > /tmp/x", "show `reboot`",
    "show $(reboot)", "show version && reboot", "show version & reboot", "shows version",
    "show a\\b", 'show slb real "r1', "show <x>", "show " + "x" * 200])
def test_probe_show_refuses_anything_but_one_plain_show_or_get_line(fake_env, command):
    gw = fake_env["gateway"]
    out = gw.call(ALICE, "probe_show", {**_lease(gw), "command": command})
    assert out["ok"] is False and "show/get" in out["error"], command


def test_probe_show_passes_plain_show_and_get_lines(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw)
    sent = []
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: (
        sent.append(cmd) or {"command": cmd, "output": "ok"}))
    for command in ("show version", 'show slb real http "r1"', "show ip route 3ffd::/64",
                    "get system status", "  SHOW  statistics  slb  "):
        assert gw.call(ALICE, "probe_show", {**lease, "command": command})["ok"], command
    assert sent[-1] == "SHOW  statistics  slb"
