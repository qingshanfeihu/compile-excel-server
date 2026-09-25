"""本床拓扑事实（network_topology.json）：网关就在跳板机上，本机取事实、按 InfoTest 生成器同一套纯函数合成。

编写阶段的判据（可达性、VIP 选取、触发机与目标同段、真实服务器地址）都读这份文件
（引擎 env_facts）。InfoTest 由工作站经跳板机一跳 ssh 采集；这里网关自己采：
- 跳板机本机：``ip -o addr show``（二层域）与 ``arp -an``（只进观察）；
- conf ``[env]`` 里的各台主机：代理用框架自己的字面凭据登上去取 ``ip -o addr show``；
- 被测设备（CLI，不吃 ip 命令）：经只读探测取 ``show ip address``，作为绑定到本床
  ``ssh_ips`` 的 overlay 交给合成。探不到的设备只进观察，不拿别的床的地址充数。
合成函数来自 cex_core（InfoTest scripts/gen_network_topology.py 的抽取副本），不重写。
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import re
import subprocess
import sys
from typing import Any, Callable

from .config import GatewayConfig

_ADDR_LINE = re.compile(r'^ip address "(?P<port>[^"]+)"\s+(?P<ip>\S+)\s+(?P<mask>\S+)\s*$')


def _generator():
    """抽取来的引擎按顶层包名 ``cex_core`` 自引用；网关里它是 ``gateway.vendor.cex_core``。"""
    if "cex_core" not in sys.modules:
        sys.modules["cex_core"] = importlib.import_module("gateway.vendor.cex_core")
    return importlib.import_module("cex_core.engine.scripts.gen_network_topology")


def _local(argv: list[str]) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def parse_show_ip_address(text: str) -> dict[str, dict[str, str]]:
    """``show ip address`` → {端口: {"ipv4": cidr, "ipv6": cidr}}（APV CLI 的回显形态）。"""
    ports: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        m = _ADDR_LINE.match(line.strip())
        if not m:
            continue
        ip, mask = m.group("ip"), m.group("mask")
        try:
            if ":" in ip:
                cidr = str(ipaddress.ip_interface(f"{ip}/{int(mask)}"))
                ports.setdefault(m.group("port"), {})["ipv6"] = cidr
            else:
                cidr = str(ipaddress.ip_interface(f"{ip}/{mask}"))
                ports.setdefault(m.group("port"), {})["ipv4"] = cidr
        except ValueError:
            continue
    return ports


def apv_overlay(gen: Any, conf: Any, show_ip: dict[int, str]) -> dict[str, Any]:
    """探到的被测设备接口，写成绑定到本床 conf ssh_ips 的 overlay（合成函数只接受这样的）。"""
    devices = []
    for index, ip in enumerate(conf.device_ips):
        text = show_ip.get(index)
        if not text:
            continue
        ports = parse_show_ip_address(text)
        if not ports:
            continue
        name = conf.device_names[index] if index < len(conf.device_names) else f"APV{index}"
        devices.append({
            "name": name, "type": gen.device_type(name),
            "ipv4": sorted(p["ipv4"] for p in ports.values() if p.get("ipv4")),
            "ipv6": sorted(p["ipv6"] for p in ports.values() if p.get("ipv6")),
            "interfaces": {port: dict(sorted(v.items())) for port, v in sorted(ports.items())},
        })
    return {"applies_to": {"device_ssh_ips": list(conf.device_ips)}, "devices": devices}


def collect(cfg: GatewayConfig, *, hosts: Callable[[dict[str, str]], dict[str, Any]],
            probe_show_ip: Callable[[int], str], reachable: Callable[[str], bool]) -> dict[str, Any]:
    gen = _generator()
    raw = cfg.conf_path.read_text(encoding="utf-8", errors="replace")
    conf_text = "\n".join(line for line in raw.splitlines()
                          if not line.strip().startswith(("<<<<<<", "======", ">>>>>>")))
    conf = gen.parse_conf(conf_text)
    addresses = gen.parse_ip_addr(_local(["ip", "-o", "addr", "show"]))
    neighbors = gen.parse_arp(_local(["arp", "-an"]))
    domains = gen.group_l2_domains(addresses, neighbors)

    probed = hosts(dict(conf.hosts))
    host_addresses = {name: gen.parse_ip_addr(v["output"])
                      for name, v in probed.items() if v.get("output")}
    show_ip: dict[int, str] = {}
    unreachable_apv: list[str] = []
    for index, ip in enumerate(conf.device_ips):
        if reachable(ip):
            show_ip[index] = probe_show_ip(index)
        else:
            unreachable_apv.append(ip)

    topology = gen.build_topology(conf=conf, jumphost_addresses=addresses, domains=domains,
                                  host_addresses=host_addresses,
                                  overlay=apv_overlay(gen, conf, show_ip), previous=None)
    gen.assign_domain_members(domains, topology["devices"])
    for record, domain in zip(topology["_l2_domains"], domains, strict=True):
        record["members"] = list(domain.members)
    observation = {
        "unprobed_devices": topology.pop("_unprobed_this_run", []),
        "host_key_mismatch_devices": sorted(gen.canonical_device_name(k)
                                            for k, v in probed.items()
                                            if v.get("error") == "host_key_mismatch"),
        "host_errors": {k: v["error"] for k, v in sorted(probed.items()) if v.get("error")},
        "unreachable_devices": unreachable_apv,
        "unregistered_neighbours": gen.unregistered_neighbours(domains, neighbors,
                                                               topology["devices"]),
    }
    topology["_bed"] = {"conf": cfg.conf_name, "build": cfg.build}
    text = json.dumps(topology, ensure_ascii=False, indent=2) + "\n"
    return {"topology": topology, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "rag_md": gen.render_rag_md(topology), "observation": observation}
