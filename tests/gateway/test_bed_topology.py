"""bed_topology：网关在跳板机本机合成本床 network_topology.json（InfoTest 生成器同一套纯函数）。

地址一律用文档地址段（192.0.2/24、198.51.100/24、203.0.113/24）；10.4/16 是生成器认定的管理网。
"""

from __future__ import annotations

import importlib
import sys
import textwrap

import pytest

from gateway import bed, framework
from gateway.agent import jumphost_agent

from test_gateway import ALICE, _lease

CONF = textwrap.dedent("""\
    [comm]
    ssh_ips = 192.0.2.70, 192.0.2.71
    marks = exec%%APV0,APV1
    [env]
    routera = 10.4.0.206
    server231 = 10.4.0.231
    [other]
    mysql_ip = 10.4.0.9
    [array_ustack]
    user = admin
    passwd = devpass
    hostname = APV
    """)
JUMPHOST_ADDR = textwrap.dedent("""\
    1: lo    inet 127.0.0.1/8 scope host lo
    2: ens160    inet 10.4.0.100/16 brd 10.4.255.255 scope global ens160
    3: ens192    inet 192.0.2.215/24 brd 192.0.2.255 scope global ens192
    3: ens192    inet 203.0.113.215/24 brd 203.0.113.255 scope global ens192
    """)
HOSTS = {
    "routera": {"ip": "10.4.0.206", "output": textwrap.dedent("""\
        2: ens160    inet 203.0.113.206/24 brd 203.0.113.255 scope global ens160
        3: ens224    inet 10.4.0.206/16 brd 10.4.255.255 scope global ens224
        """)},
    "server231": {"ip": "10.4.0.231", "output": textwrap.dedent("""\
        2: ens160    inet 192.0.2.231/24 brd 192.0.2.255 scope global ens160
        3: ens224    inet 10.4.0.231/16 brd 10.4.255.255 scope global ens224
        """)},
}
SHOW_IP = textwrap.dedent("""\
    show ip address
    ip address "port1" 192.0.2.70 255.255.255.0
    ip address "port1" 3ffd::70 64
    ip address "port2" 203.0.113.70 255.255.255.0
    APV#
    """)


def _engine():
    bed._generator()  # 建立 cex_core 别名
    return importlib.import_module("cex_core.engine.ist_core.tools._shared.env_facts")


def test_show_ip_address_is_parsed_per_port():
    assert bed.parse_show_ip_address(SHOW_IP) == {
        "port1": {"ipv4": "192.0.2.70/24", "ipv6": "3ffd::70/64"},
        "port2": {"ipv4": "203.0.113.70/24"}}


def test_collect_builds_the_bed_facts_the_authoring_gates_read(fake_env, monkeypatch):
    cfg = fake_env["gateway"].cfg
    cfg.conf_path.write_text(CONF, encoding="utf-8")
    monkeypatch.setattr(bed, "_local", lambda argv: JUMPHOST_ADDR if argv[0] == "ip" else "")
    probed: list[int] = []

    def probe(index: int) -> str:
        probed.append(index)
        return SHOW_IP

    result = bed.collect(cfg, hosts=lambda hosts: {k: HOSTS[k] for k in hosts},
                         probe_show_ip=probe, reachable=lambda ip: ip == "192.0.2.70")
    topo = result["topology"]
    devices = {d["name"]: d for d in topo["devices"]}
    assert probed == [0], "APV1 is unreachable and must not be probed"
    assert devices["APV0"]["interfaces"]["port2"] == {"ipv4": "203.0.113.70/24"}
    assert "203.0.113.206/24" in devices["routerA"]["ipv4"]
    assert not any(c.startswith("10.4.") for d in topo["devices"] for c in d.get("ipv4") or [])
    assert result["observation"]["unreachable_devices"] == ["192.0.2.71"]
    assert topo["_bed"] == {"conf": cfg.conf_name, "build": cfg.build}
    assert len(result["sha256"]) == 64 and "APV0" in result["rag_md"]

    facts = _engine().EnvFacts(topo)
    assert "203.0.113.70" in facts.listener_ips(), "VIP on the router's segment"
    assert "192.0.2.70" not in facts.listener_ips(), "no router or client on the server segment"
    assert "192.0.2.231" in facts.service_ips()
    assert dict(facts.listener_trigger_pairs()) == {"203.0.113.70": ["routera"]}, \
        "traffic to the VIP is triggered from the router on its segment"
    assert facts.is_reachable("203.0.113.70") and not facts.is_reachable("181.37.68.13")


def test_agent_takes_exactly_one_literal_framework_credential(tmp_path):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "ssh_server.py").write_text(
        'import paramiko\nssh = paramiko.SSHClient()\n'
        'ssh.connect(hostname=h, port=22, username="test", password="pw")\n', encoding="utf-8")
    assert jumphost_agent.framework_credentials(str(tmp_path)) == ("test", "pw")
    (lib / "ssh_server.py").write_text(
        'a.connect(username="u1", password="p1")\nb.connect(username="u2", password="p2")\n',
        encoding="utf-8")
    with pytest.raises(RuntimeError, match="exactly one"):
        jumphost_agent.framework_credentials(str(tmp_path))


def test_tool_needs_the_lease_and_serves_the_cache_until_refresh(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    calls: list[int] = []

    def fake_collect(cfg, **_kw):
        calls.append(1)
        return {"topology": {"devices": [{"name": "APV0"}]}, "sha256": "a" * 64,
                "rag_md": "", "observation": {}}

    monkeypatch.setattr(bed, "collect", fake_collect)
    assert gw.call(ALICE, "bed_topology", {"lease_id": "x", "token": 1})["ok"] is False
    lease = _lease(gw)
    first = gw.call(ALICE, "bed_topology", lease)
    assert first["ok"] and first["sha256"] == "a" * 64
    gw.call(ALICE, "bed_topology", lease)
    assert calls == [1], "second call is served from the gateway cache"
    gw.call(ALICE, "bed_topology", {**lease, "refresh": True})
    assert calls == [1, 1]


def test_agent_hosts_op_is_python38(tmp_path):
    import ast

    ast.parse(framework.AGENT.read_text(encoding="utf-8"), feature_version=(3, 8))
    assert "hosts" in jumphost_agent.OPS and "cex_core" not in sys.modules.get(
        "gateway.agent.jumphost_agent").__dict__
