"""HTTP 层的健壮性：TLS 握手不在 accept() 里做、空闲连接会被断开、坏的 Content-Length 回 400。"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request

import pytest

from gateway import service


def _serve(gw, monkeypatch, *, tls=None, idle=None):
    if idle is not None:
        monkeypatch.setattr(service, "IDLE_TIMEOUT_S", idle)
    object.__setattr__(gw.cfg, "port", 0)
    if tls:
        object.__setattr__(gw.cfg, "tls_cert", tls[0])
        object.__setattr__(gw.cfg, "tls_key", tls[1])
    httpd = service.build_server(gw)
    httpd.handshake_timeout = 1.0
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _closed_within(sock: socket.socket, seconds: float) -> bool:
    sock.settimeout(seconds)
    try:
        return sock.recv(1) == b""
    except (socket.timeout, ConnectionResetError):
        return False


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI for a cert")
def test_idle_tcp_peer_does_not_block_the_tls_listener(fake_env, tmp_path, monkeypatch):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    httpd = _serve(fake_env["gateway"], monkeypatch, tls=(cert, key))
    port = httpd.server_address[1]
    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.check_hostname = False
    idle = socket.create_connection(("127.0.0.1", port))   # 连上，一个字节也不发
    try:
        time.sleep(0.2)
        started = time.time()
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/healthz", context=ctx,
                                    timeout=5) as resp:
            assert resp.status == 200
        assert time.time() - started < 2, "别的客户端不该等空闲连接"
        assert _closed_within(idle, 5), "握手超时后空闲连接被断开"
    finally:
        idle.close()
        httpd.shutdown()
        httpd.server_close()


def test_idle_plain_connection_is_dropped_after_the_handler_timeout(fake_env, monkeypatch):
    httpd = _serve(fake_env["gateway"], monkeypatch, idle=0.5)
    idle = socket.create_connection(("127.0.0.1", httpd.server_address[1]))
    try:
        assert _closed_within(idle, 5)
    finally:
        idle.close()
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("length", ["abc", "-5", "1e3"])
def test_bad_content_length_gets_400_not_a_dropped_connection(fake_env, monkeypatch, length):
    httpd = _serve(fake_env["gateway"], monkeypatch)
    try:
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5) as sock:
            sock.sendall(("POST /mcp HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer run-token\r\n"
                          f"Content-Length: {length}\r\n\r\n").encode())
            reply = sock.recv(4096).decode("latin-1")
        assert reply.split("\r\n", 1)[0].endswith(" 400 Bad Request"), reply
    finally:
        httpd.shutdown()
        httpd.server_close()
