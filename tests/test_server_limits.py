"""未认证可达入口的上限与探活面（进程内 TestClient，合成数据）。

覆盖：请求体超限回 413（表单、清单、blob；声明长度与 chunked 两种）、单个来源刷不满待处理设备码、
访问码 / client secret 校验不在事件循环线程里跑、检索词去重与上限、坏手册跳过而不是拖垮启动、
/healthz 只答活着。
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(data),
         "--sample"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    monkeypatch.setenv("CES_DATA_DIR", str(data))
    import server

    server._init_data(data)
    server._device_flows.clear()
    return server, TestClient(server.app), data


def _basic(client_id: str, secret: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


def _publisher(server, client) -> dict[str, str]:
    secret = server.AUTH_STORE.add_client("publisher", ["bundles:publish", "bundles:read"])
    token = client.post("/token", data={"grant_type": "client_credentials"},
                        headers=_basic("publisher", secret)).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _chunks(total: int, size: int = 1024):
    for _ in range(total // size):
        yield b"x" * size


def test_oversized_form_bodies_get_413(env):
    _, client, _ = env
    big = b"a=" + b"x" * (64 << 10)  # 表单上限 8 KiB
    for path in ("/device_authorize", "/activate", "/token", "/revoke", "/v1/introspect"):
        res = client.post(path, content=big, headers=FORM)
        assert res.status_code == 413, (path, res.status_code)
        # 不声明长度（chunked）也一样：边读边数，超了就停
        res = client.post(path, content=_chunks(64 << 10), headers=FORM)
        assert res.status_code == 413, (path, res.status_code)
    assert client.post("/device_authorize", data={"client_id": "ok"}).status_code == 200


def test_publish_paths_have_explicit_limits(env, monkeypatch):
    server, client, _ = env
    pub = _publisher(server, client)
    monkeypatch.setattr(server, "MAX_MANIFEST_BYTES", 2048)
    manifest = json.dumps({"build": "B1", "entries": [], "pad": "x" * 4096}).encode()
    res = client.post("/v1/bundles", content=manifest,
                      headers={**pub, "Content-Type": "application/json"})
    assert res.status_code == 413
    monkeypatch.setattr(server, "MAX_BLOB_BYTES", 4096)
    payload = b"y" * 8192
    import hashlib

    sha = hashlib.sha256(payload).hexdigest()
    assert client.put(f"/v1/blobs/{sha}", content=payload, headers=pub).status_code == 413
    streamed = client.put(f"/v1/blobs/{sha}", content=_chunks(8192), headers=pub)
    assert streamed.status_code == 413
    assert server.REGISTRY.blob_info(sha) is None
    small = b"z" * 1024
    ok = client.put(f"/v1/blobs/{hashlib.sha256(small).hexdigest()}", content=small, headers=pub)
    assert ok.status_code == 201


def test_one_source_cannot_exhaust_pending_logins(env, monkeypatch):
    server, client, _ = env
    monkeypatch.setattr(server, "MAX_PENDING_FLOWS_PER_IP", 3, raising=False)
    for _ in range(3):
        assert client.post("/device_authorize", data={}).status_code == 200
    assert client.post("/device_authorize", data={}).status_code == 429
    # 另一个来源照常登录
    code = server.AUTH_STORE.add_user("lena")
    other = TestClient(server.app, client=("10.9.8.7", 50000))
    flow = other.post("/device_authorize", data={}).json()
    page = other.post("/activate", data={"user_code": flow["user_code"], "username": "lena",
                                         "access_code": code})
    assert page.status_code == 200
    token = other.post("/token", data={"grant_type": DEVICE_GRANT,
                                       "device_code": flow["device_code"]})
    assert token.status_code == 200


def test_secret_checks_run_off_the_event_loop(env, monkeypatch):
    server, client, _ = env
    seen: list[str] = []

    def spy(real):
        def wrapper(*args):
            try:
                asyncio.get_running_loop()
                seen.append("event-loop")
            except RuntimeError:
                seen.append("worker-thread")
            return real(*args)
        return wrapper

    monkeypatch.setattr(server.AUTH_STORE, "verify_client", spy(server.AUTH_STORE.verify_client))
    monkeypatch.setattr(server.AUTH_BACKEND, "authenticate", spy(server.AUTH_BACKEND.authenticate))
    client.post("/token", data={"grant_type": "client_credentials", "client_id": "nobody",
                                "client_secret": "x"})
    client.post("/v1/introspect", data={"token": "t"}, headers=_basic("nobody", "x"))
    flow = client.post("/device_authorize", data={}).json()
    client.post("/activate", data={"user_code": flow["user_code"], "username": "nobody",
                                   "access_code": "x"})
    assert seen == ["worker-thread"] * 3


def test_docs_query_terms_are_deduplicated_and_capped(env):
    server, client, data = env
    code = server.AUTH_STORE.add_user("nora", ["docs:query"])
    flow = client.post("/device_authorize", data={"scope": "docs:query"}).json()
    client.post("/activate", data={"user_code": flow["user_code"], "username": "nora",
                                   "access_code": code})
    token = client.post("/token", data={"grant_type": DEVICE_GRANT,
                                        "device_code": flow["device_code"]}).json()
    res = client.post("/v1/docs/query", data={"q": "manifest manifest MANIFEST sha256"},
                      headers={"Authorization": f"Bearer {token['access_token']}"})
    assert res.status_code == 200
    last = (data / "audit.log").read_text(encoding="utf-8").splitlines()[-1]
    record = json.loads(last.partition("\thmac=")[0])
    assert record["event"] == "docs_query" and record["terms"] == ["manifest", "sha256"]
    terms = server._query_terms(" ".join(f"term{i}" for i in range(500)) + " term1 TERM1")
    assert len(terms) == server.MAX_QUERY_TERMS == 32 and len(set(terms)) == len(terms)
    assert server._query_terms("x" * 100_000) == ["x" * server.MAX_QUERY_CHARS]
    assert all(doc["body_l"] == doc["body"].lower() for doc in server.DOCS)


def test_a_non_utf8_manual_is_skipped_not_fatal(env, capsys):
    server, _, data = env
    (data / "docs" / "latin1.md").write_bytes("# caf\xe9\n".encode("latin-1"))
    server._init_data(data)  # 等同重启：不崩
    docs = {doc["doc"] for doc in server.DOCS}
    assert "latin1.md" not in docs and docs, docs
    assert "latin1.md" in capsys.readouterr().err


def test_healthz_only_says_alive(env):
    _, client, _ = env
    assert client.get("/healthz").json() == {"ok": True, "service": "compile-excel-server"}
