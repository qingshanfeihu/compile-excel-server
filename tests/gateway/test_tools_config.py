"""工具与配置的几处约定：init_device 显式 device_count=0 是错；bed_topology 带常驻服务清单；
env_prepare 核对客户端编译用的构建。地址一律用文档地址段（192.0.2/24）。"""

from __future__ import annotations

import pytest

from conftest import BUILD

from gateway import bed, framework
from gateway.config import ConfigError, load

from test_gateway import ALICE, ROOT, _lease

SERVICES = """
[[bed.services]]
host = "server231"
ip = "192.0.2.231"
proto = "http"
port = 80
note = "nginx, / answers 200"

[[bed.services]]
host = "server232"
ip = "192.0.2.232"
proto = "DNS"
port = 53
"""


def test_init_device_refuses_an_explicit_zero_or_negative_device_count(fake_env):
    gw = fake_env["gateway"]
    lease = _lease(gw, ROOT)
    for count in (0, -1):
        out = gw.call(ROOT, "init_device", {**lease, "step": "prepare", "device_count": count})
        assert out["ok"] is False and "at least 1" in out["error"], out
    everything = gw.call(ROOT, "init_device", {**lease, "step": "prepare"})
    assert [d["device"] for d in everything["plan"]["devices"]] == [0, 1]
    one = gw.call(ROOT, "init_device", {**lease, "step": "prepare", "device_count": 1})
    assert [d["device"] for d in one["plan"]["devices"]] == [0]


def test_bed_services_come_from_the_config_and_ride_on_bed_topology(fake_env, tmp_path,
                                                                     monkeypatch):
    from gateway.tools import Gateway

    config = tmp_path / "with_services.toml"
    config.write_text(fake_env["config"].read_text(encoding="utf-8") + SERVICES,
                      encoding="utf-8")
    cfg = load(config)
    assert cfg.bed_services == (
        {"host": "server231", "ip": "192.0.2.231", "proto": "http", "port": 80,
         "note": "nginx, / answers 200"},
        {"host": "server232", "ip": "192.0.2.232", "proto": "dns", "port": 53, "note": ""})
    monkeypatch.setattr(bed, "collect", lambda cfg, **_kw: {
        "topology": {"devices": []}, "sha256": "a" * 64, "rag_md": "", "observation": {}})
    gw = Gateway(cfg, server=fake_env["server"])
    lease = _lease(gw)
    fresh = gw.call(ALICE, "bed_topology", {**lease, "refresh": True})
    cached = gw.call(ALICE, "bed_topology", lease)
    for out in (fresh, cached):
        assert out["ok"] and [s["host"] for s in out["services"]] == ["server231", "server232"]
        assert set(out["services"][0]) == {"host", "ip", "proto", "port", "note"}
    plain = fake_env["gateway"]
    assert plain.call(ALICE, "bed_topology", {**_lease(plain), "refresh": True})["services"] == []


@pytest.mark.parametrize("entry, message", [
    ('host = "s1"\nip = "192.0.2.9"\nproto = "ftp"\nport = 21', "proto"),
    ('host = "s1"\nip = "not-an-ip"\nproto = "tcp"\nport = 21', "ip"),
    ('host = "s1"\nip = "192.0.2.9"\nproto = "tcp"\nport = 0', "port"),
    ('host = "s 1"\nip = "192.0.2.9"\nproto = "tcp"\nport = 22', "host"),
    ('host = "s1"\nip = "192.0.2.9"\nproto = "tcp"\nport = 22\nuser = "x"', "未知字段"),
])
def test_bad_bed_services_are_refused_at_load(fake_env, tmp_path, entry, message):
    config = tmp_path / "bad.toml"
    config.write_text(fake_env["config"].read_text(encoding="utf-8")
                      + f"\n[[bed.services]]\n{entry}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load(config)


def test_env_prepare_checks_the_client_build(fake_env, monkeypatch):
    gw = fake_env["gateway"]
    lease = _lease(gw)
    monkeypatch.setattr(framework, "device_reachable", lambda ip, **_: True)
    monkeypatch.setattr(framework, "probe", lambda cfg, cmd, build, idx: {
        "output": f"Software Version : {BUILD}\n"})
    wrong = gw.call(ALICE, "env_prepare", {**lease, "device_build": "OTHER_BUILD_9"})
    assert wrong["ok"] is False and "OTHER_BUILD_9" in wrong["error"] and BUILD in wrong["error"]
    matched = gw.call(ALICE, "env_prepare", {**lease, "device_build": BUILD})
    assert matched["ok"] and matched["build_checked"] is True and matched["ready"], matched
    legacy = gw.call(ALICE, "env_prepare", lease)
    assert legacy["ok"] and legacy["build_checked"] is False and legacy["ready"], legacy
