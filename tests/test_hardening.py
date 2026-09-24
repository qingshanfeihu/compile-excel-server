"""E9 加固：审计哈希链、服务端 TLS 规则与 https 探活、旧安装兼容。"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from deploy import tls_policy  # noqa: E402
from gateway.audit_chain import GENESIS, AuditChain, line_hash, verify  # noqa: E402

PY = sys.executable


def _write(chain: AuditChain, n: int) -> None:
    for i in range(n):
        chain.append({"event": "e", "i": i})


def test_chain_verifies_and_survives_a_restart(tmp_path):
    log = tmp_path / "audit.log"
    _write(AuditChain(log), 3)
    _write(AuditChain(log), 2)  # 新进程接着写：从文件最后一行接上
    result = verify(log)
    assert result == {"ok": True, "lines": 5, "chained": 5, "legacy": 0}
    first = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert first["prev"] == GENESIS


def test_edits_and_deletions_break_the_chain(tmp_path):
    log = tmp_path / "audit.log"
    _write(AuditChain(log), 5)
    lines = log.read_text(encoding="utf-8").splitlines()
    edited = lines.copy()
    edited[2] = edited[2].replace('"i": 2', '"i": 99')
    log.write_text("\n".join(edited) + "\n", encoding="utf-8")
    assert verify(log)["line"] == 4
    log.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")
    assert verify(log)["line"] == 3


def test_hmac_is_checked_when_the_key_is_given(tmp_path):
    log = tmp_path / "audit.log"
    key = os.urandom(32)
    _write(AuditChain(log, key=key), 3)
    assert verify(log, key)["ok"]
    assert verify(log, os.urandom(32)) == {"ok": False, "line": 1, "reason": "hmac mismatch"}
    # 没有密钥的人重算整条链：prev 能接上，但 hmac 过不了
    body_lines = [line.split("\thmac=")[0] for line in log.read_text(encoding="utf-8").splitlines()]
    forged, prev = [], GENESIS
    for body in body_lines:
        record = json.loads(body)
        record["prev"] = prev
        raw = json.dumps(record, ensure_ascii=False)
        forged.append(raw)
        prev = line_hash(raw)
    log.write_text("\n".join(forged) + "\n", encoding="utf-8")
    assert verify(log)["ok"] and not verify(log, key)["ok"]


def test_legacy_lines_are_accepted_only_before_the_chain(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text('{"event": "old1"}\n{"event": "old2"}\n', encoding="utf-8")
    _write(AuditChain(log), 2)
    assert verify(log) == {"ok": True, "lines": 4, "chained": 2, "legacy": 2}
    with open(log, "a", encoding="utf-8") as stream:
        stream.write('{"event": "sneaked in"}\n')
    assert verify(log)["reason"] == "line without prev after the chain began"


def test_ces_audit_verify_uses_the_instance_key(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    key = os.urandom(32)
    (data / "audit_hmac_key").write_text(key.hex(), encoding="utf-8")
    _write(AuditChain(data / "audit.log", key=key), 3)
    run = lambda: subprocess.run([PY, str(REPO_ROOT / "ces_main.py"), "audit", "verify",  # noqa: E731
                                  "--data", str(data)], capture_output=True, text=True, timeout=60)
    ok = run()
    assert ok.returncode == 0 and json.loads(ok.stdout)["ok"], ok.stdout + ok.stderr
    (data / "audit_hmac_key").write_text(os.urandom(32).hex(), encoding="utf-8")
    bad = run()
    assert bad.returncode == 1 and json.loads(bad.stdout)["reason"] == "hmac mismatch"


@pytest.mark.parametrize("host,cert,key,insecure,refused", [
    ("127.0.0.1", "", "", False, False),
    ("localhost", "", "", False, False),
    ("::1", "", "", False, False),
    ("0.0.0.0", "", "", False, True),
    ("10.1.2.3", "", "", False, True),
    ("0.0.0.0", "", "", True, False),
    ("0.0.0.0", "CERT", "", False, True),
])
def test_serve_tls_rule(tmp_path, host, cert, key, insecure, refused):
    if cert:
        cert = str(tmp_path / "c.pem")
        Path(cert).write_text("x", encoding="utf-8")
    assert bool(tls_policy.serve_tls_problem(host, cert, key, insecure)) is refused


def test_ces_serve_refuses_plaintext_on_a_lan_address(tmp_path):
    proc = subprocess.run([PY, str(REPO_ROOT / "ces_main.py"), "serve", "--data", str(tmp_path),
                           "--host", "0.0.0.0", "--port", "1"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and "--insecure-lan" in proc.stderr


def test_serve_argv_keeps_legacy_installs_running(capsys):
    import ces_main

    legacy = ces_main._serve_argv({"data": "/d", "port": 8900, "host": "0.0.0.0"})
    assert "--insecure-lan" in legacy and "警告" in capsys.readouterr().err
    tls = ces_main._serve_argv({"data": "/d", "port": 8900, "host": "0.0.0.0",
                                "tls_cert": "/c.pem", "tls_key": "/k.pem"})
    assert tls[tls.index("--tls-cert") + 1] == "/c.pem" and "--insecure-lan" not in tls
    local = ces_main._serve_argv({"data": "/d", "port": 8900, "host": "127.0.0.1"})
    assert "--insecure-lan" not in local and "--tls-cert" not in local


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_tls_server_answers_https_probes(tmp_path):
    pytest.importorskip("uvicorn")
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    gen = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                          "-subj", "/CN=ces.test", "-keyout", str(key), "-out", str(cert)],
                         capture_output=True, text=True, timeout=120)
    assert gen.returncode == 0, gen.stderr
    data = tmp_path / "data"
    prov = subprocess.run([PY, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(data),
                           "--sample"], capture_output=True, text=True, timeout=120)
    assert prov.returncode == 0, prov.stdout + prov.stderr
    port = _free_port()
    proc = subprocess.Popen([PY, str(REPO_ROOT / "ces_main.py"), "serve", "--data", str(data),
                             "--host", "127.0.0.1", "--port", str(port),
                             "--tls-cert", str(cert), "--tls-key", str(key)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        health = None
        for _ in range(60):
            health = tls_policy.healthz(port, tls_cert=str(cert), timeout=1)
            if health:
                break
            time.sleep(0.25)
        assert health and health.get("ok") is True, health
        assert tls_policy.healthz(port, timeout=1) is None, "plain http must not be served"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
