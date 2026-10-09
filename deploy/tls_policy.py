"""服务端监听与 TLS 的规则（ces serve、ces setup、server.py 共用一份）。

监听非回环地址时必须配 TLS：客户端带着 OAuth 令牌来，明文会让同网段的人直接拿到令牌。
确认是可信实验网、暂时没有证书时，显式 --insecure-lan 才放行（与网关 gateway.toml 同一条规则）。

本机探活（status/start/setup 的 healthz）在开了 TLS 时走 https：信任锚就是部署自己的证书文件，
证书链照常校验；只因为探的是回环地址，不再比对证书里的主机名。
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.request
from pathlib import Path


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve_tls_problem(host: str, tls_cert: str = "", tls_key: str = "",
                      insecure_lan: bool = False) -> str:
    """返回拒绝启动的原因；没问题返回空串。"""
    if bool(tls_cert) != bool(tls_key):
        return "--tls-cert 与 --tls-key 要么都给，要么都不给"
    for path in (tls_cert, tls_key):
        if path and not Path(path).expanduser().is_file():
            return f"TLS 文件不存在: {path}"
    if not tls_cert and not is_loopback_host(host) and not insecure_lan:
        return (f"监听 {host} 不是回环地址：令牌会明文过网。配 --tls-cert/--tls-key，"
                "或确认是可信实验网后加 --insecure-lan")
    return ""


def uvicorn_tls_kwargs(tls_cert: str, tls_key: str) -> dict:
    if not tls_cert:
        return {}
    return {"ssl_certfile": str(Path(tls_cert).expanduser()),
            "ssl_keyfile": str(Path(tls_key).expanduser())}


def probe_host(host: str) -> str:
    """探活地址：监听全部网卡时走回环，绑定具体地址时直连该地址。"""
    host = (host or "").strip()
    if host in ("", "0.0.0.0", "::", "localhost"):
        return "127.0.0.1"
    return host


def healthz(port: int, host: str = "127.0.0.1", tls_cert: str = "",
            timeout: float = 2.0) -> dict | None:
    scheme = "https" if tls_cert else "http"
    context = None
    if tls_cert:
        cert = Path(tls_cert).expanduser()
        # 内置 CA 签的证书：信任锚用旁边的 ca.pem；别的证书以它自己为锚（允许不完整的链）
        ca = cert.parent / "ca.pem" if cert.name == "server.pem" else None
        anchor = ca if ca is not None and ca.is_file() else cert
        context = ssl.create_default_context(cafile=str(anchor))
        context.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
        context.check_hostname = False
    try:
        with urllib.request.urlopen(f"{scheme}://{probe_host(host)}:{port}/healthz",
                                    timeout=timeout, context=context) as resp:
            return json.loads(resp.read())
    except (OSError, ValueError):
        return None
