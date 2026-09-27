"""身份层测试（进程内 TestClient，合成数据）。

覆盖：私有模拟后端的访问码校验与锁定、scope 取交集与逐路由校验、refresh 轮换与重放整族撤销、
撤销（持有人 / 停用用户 / 重置访问码）、client_credentials、introspect、客户端配置下发与拒收凭据、
库里与审计里都没有明文令牌和访问码、授权页转义。

跑法：python -m pytest tests/test_auth.py -v（需要 fastapi + httpx）
"""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


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


def _login(client: TestClient, username: str, code: str, scope: str = "") -> dict:
    form = {"client_id": "test"}
    if scope:
        form["scope"] = scope
    flow = client.post("/device_authorize", data=form).json()
    page = client.post("/activate", data={"user_code": flow["user_code"],
                                          "username": username, "access_code": code})
    assert page.status_code == 200, page.text
    tokens = client.post("/token", data={"grant_type": DEVICE_GRANT,
                                         "device_code": flow["device_code"]})
    assert tokens.status_code == 200, tokens.text
    return tokens.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _basic(client_id: str, secret: str) -> dict[str, str]:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def test_wrong_access_code_is_rejected_and_locks_after_repeated_failures(env):
    server, client, _ = env
    code = server.AUTH_STORE.add_user("alice")
    flow = client.post("/device_authorize", data={}).json()
    for _ in range(server.AUTH_BACKEND.MAX_FAILURES):
        bad = client.post("/activate", data={"user_code": flow["user_code"],
                                             "username": "alice", "access_code": "nope"})
        assert bad.status_code == 403
    # 锁定期内正确访问码也不放行
    locked = client.post("/activate", data={"user_code": flow["user_code"],
                                            "username": "alice", "access_code": code})
    assert locked.status_code == 403
    pending = client.post("/token", data={"grant_type": DEVICE_GRANT,
                                          "device_code": flow["device_code"]})
    assert pending.json()["error"] == "authorization_pending"


def test_unknown_user_and_empty_code_are_rejected(env):
    _, client, _ = env
    flow = client.post("/device_authorize", data={}).json()
    for form in ({"username": "ghost", "access_code": "x"},
                 {"username": "", "access_code": ""}):
        res = client.post("/activate", data={"user_code": flow["user_code"], **form})
        assert res.status_code == 403


def test_granted_scope_is_intersection_and_routes_enforce_it(env):
    server, client, _ = env
    code = server.AUTH_STORE.add_user("bob", ["docs:query"])
    tokens = _login(client, "bob", code, scope="artifacts:read docs:query")
    assert tokens["scope"] == "docs:query"
    headers = _bearer(tokens["access_token"])
    assert client.post("/v1/docs/query", data={"q": "x"}, headers=headers).status_code == 200
    denied = client.get("/v1/artifacts/manifest", headers=headers)
    assert denied.status_code == 403
    assert 'insufficient_scope' in denied.headers["www-authenticate"]
    assert client.get("/v1/config/client", headers=headers).status_code == 403


def test_user_without_any_requested_scope_is_denied(env):
    server, client, _ = env
    code = server.AUTH_STORE.add_user("carol", ["docs:query"])
    flow = client.post("/device_authorize", data={"scope": "bundles:read"}).json()
    res = client.post("/activate", data={"user_code": flow["user_code"],
                                         "username": "carol", "access_code": code})
    assert res.status_code == 403
    token = client.post("/token", data={"grant_type": DEVICE_GRANT,
                                        "device_code": flow["device_code"]})
    assert token.json()["error"] == "access_denied"


def test_unknown_scope_request_is_refused(env):
    _, client, _ = env
    res = client.post("/device_authorize", data={"scope": "artifacts:read root"})
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_scope"


def test_refresh_rotates_and_replay_revokes_the_family(env):
    server, client, _ = env
    code = server.AUTH_STORE.add_user("dave")
    first = _login(client, "dave", code)
    second = client.post("/token", data={"grant_type": "refresh_token",
                                         "refresh_token": first["refresh_token"]}).json()
    assert second["refresh_token"] != first["refresh_token"]
    assert client.get("/v1/whoami", headers=_bearer(second["access_token"])).status_code == 200
    replay = client.post("/token", data={"grant_type": "refresh_token",
                                         "refresh_token": first["refresh_token"]})
    assert replay.status_code == 400
    # 重放说明旧 refresh 可能被复制：新签发的整族一起作废
    assert client.get("/v1/whoami", headers=_bearer(second["access_token"])).status_code == 401
    again = client.post("/token", data={"grant_type": "refresh_token",
                                        "refresh_token": second["refresh_token"]})
    assert again.status_code == 400


def test_holder_can_revoke_and_disable_or_reset_revokes_everything(env):
    server, client, data = env
    code = server.AUTH_STORE.add_user("erin")
    tokens = _login(client, "erin", code)
    assert client.post("/revoke", data={"token": tokens["access_token"]}).status_code == 200
    assert client.get("/v1/whoami", headers=_bearer(tokens["access_token"])).status_code == 401
    assert client.post("/revoke", data={"token": "never-issued"}).status_code == 200

    tokens = _login(client, "erin", code)
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "ces_main.py"), "users", "disable", "erin",
         "--data", str(data)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert client.get("/v1/whoami", headers=_bearer(tokens["access_token"])).status_code == 401
    refreshed = client.post("/token", data={"grant_type": "refresh_token",
                                            "refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 400

    server.AUTH_STORE.set_user_disabled("erin", False)
    tokens = _login(client, "erin", code)
    new_code = server.AUTH_STORE.reset_code("erin")
    assert client.get("/v1/whoami", headers=_bearer(tokens["access_token"])).status_code == 401
    flow = client.post("/device_authorize", data={}).json()
    old = client.post("/activate", data={"user_code": flow["user_code"],
                                         "username": "erin", "access_code": code})
    assert old.status_code == 403
    assert _login(client, "erin", new_code)["access_token"]


def test_client_credentials_and_introspect(env):
    server, client, _ = env
    gateway_secret = server.AUTH_STORE.add_client("gateway", ["introspect"])
    publisher_secret = server.AUTH_STORE.add_client("publisher", ["bundles:publish"])
    code = server.AUTH_STORE.add_user("frank")
    tokens = _login(client, "frank", code, scope="artifacts:read jumphost:run")

    assert client.post("/v1/introspect", data={"token": tokens["access_token"]}).status_code == 401
    wrong = client.post("/v1/introspect", data={"token": tokens["access_token"]},
                        headers=_basic("gateway", "bad"))
    assert wrong.status_code == 401
    no_scope = client.post("/v1/introspect", data={"token": tokens["access_token"]},
                           headers=_basic("publisher", publisher_secret))
    assert no_scope.status_code == 403

    info = client.post("/v1/introspect", data={"token": tokens["access_token"]},
                       headers=_basic("gateway", gateway_secret)).json()
    assert info["active"] is True
    assert info["username"] == "frank"
    assert set(info["scope"].split()) == {"artifacts:read", "jumphost:run"}
    assert info["exp"] > info["iat"]

    client.post("/revoke", data={"token": tokens["access_token"]})
    gone = client.post("/v1/introspect", data={"token": tokens["access_token"]},
                       headers=_basic("gateway", gateway_secret)).json()
    assert gone == {"active": False}

    issued = client.post("/token", data={"grant_type": "client_credentials"},
                         headers=_basic("publisher", publisher_secret))
    assert issued.status_code == 200
    body = issued.json()
    assert body["scope"] == "bundles:publish"
    assert "refresh_token" not in body
    whoami = client.get("/v1/whoami", headers=_bearer(body["access_token"])).json()
    assert whoami["kind"] == "client" and whoami["sub"] == "publisher"
    bad = client.post("/token", data={"grant_type": "client_credentials",
                                      "client_id": "publisher", "client_secret": "x"})
    assert bad.status_code == 401


def test_client_config_is_served_to_scope_holders_and_rejects_credentials(env):
    server, client, data = env
    import client_config

    code = server.AUTH_STORE.add_user("gina")
    token = _login(client, "gina", code, scope="config:read")["access_token"]
    assert client.get("/v1/config/client").status_code == 401
    empty = client.get("/v1/config/client", headers=_bearer(token)).json()
    assert empty == {"schema": client_config.SCHEMA}

    client_config.set_key(data, "gateway.url", "https://gw.example.test/mcp")
    served = client.get("/v1/config/client", headers=_bearer(token)).json()
    assert served["gateway"]["url"] == "https://gw.example.test/mcp"

    with pytest.raises(client_config.ConfigError):
        client_config.set_key(data, "portal.login_url", "https://user:pw@portal.example.test/")
    with pytest.raises(client_config.ConfigError):
        client_config.set_key(data, "portal.password", "https://x.example.test/")

    # 管理员手改文件塞进凭据：服务端拒绝下发，不把内容带出去
    (data / "client_config.json").write_text(
        '{"schema": "cex.client-config/v1", "portal": {"password": "hunter2"}}',
        encoding="utf-8")
    broken = client.get("/v1/config/client", headers=_bearer(token))
    assert broken.status_code == 503
    assert "hunter2" not in broken.text


def test_import_env_takes_only_whitelisted_addresses_and_never_echoes(env, tmp_path):
    _, _, data = env
    source = tmp_path / "source.env"
    source.write_text(
        "PORTAL_LOGIN_URL=https://portal.example.test/login\n"
        "PORTAL_LOGIN_USER=someone\n"
        "PORTAL_LOGIN_PASS=hunter2\n"
        "export ZENTAO_BASE_URL='https://zentao.example.test'\n"
        "BUGZILLA_BASE_URL=https://u:p@bugzilla.example.test/\n",
        encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "ces_main.py"), "config", "import-env", str(source),
         "--data", str(data)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for value in ("hunter2", "someone", "portal.example.test", "u:p@"):
        assert value not in proc.stdout
    stored = (data / "client_config.json").read_text(encoding="utf-8")
    assert "portal.example.test/login" in stored and "zentao.example.test" in stored
    assert "hunter2" not in stored and "someone" not in stored and "bugzilla" not in stored


def test_store_and_audit_hold_no_plaintext_secrets(env):
    server, client, data = env
    code = server.AUTH_STORE.add_user("hank")
    secret = server.AUTH_STORE.add_client("gw", ["introspect"])
    tokens = _login(client, "hank", code)
    client.post("/token", data={"grant_type": "refresh_token",
                                "refresh_token": tokens["refresh_token"]})
    client.post("/v1/introspect", data={"token": tokens["access_token"]},
                headers=_basic("gw", secret))
    blobs = b""
    for name in ("auth.db", "auth.db-wal"):
        path = data / name
        if path.exists():
            blobs += path.read_bytes()
    audit = (data / "audit.log").read_text(encoding="utf-8")
    for value in (code, secret, tokens["access_token"], tokens["refresh_token"]):
        assert value.encode() not in blobs
        assert value not in audit
    assert oct((data / "auth.db").stat().st_mode & 0o777) == "0o600"


def test_activate_page_escapes_user_supplied_code(env):
    _, client, _ = env
    page = client.get("/activate", params={"user_code": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;" in page.text
    assert page.headers["x-frame-options"] == "DENY"


# ── 授权与兑换之间账号有变：兑换时按账号现状再核一次；refresh 同理 ──────────────────
def _approve(client: TestClient, username: str, code: str, scope: str) -> dict:
    flow = client.post("/device_authorize", data={"client_id": "test", "scope": scope}).json()
    page = client.post("/activate", data={"user_code": flow["user_code"],
                                          "username": username, "access_code": code})
    assert page.status_code == 200, page.text
    return flow


def _redeem(client: TestClient, flow: dict):
    return client.post("/token", data={"grant_type": DEVICE_GRANT,
                                       "device_code": flow["device_code"]})


def test_redemption_rechecks_the_account(env):
    server, client, _ = env
    store = server.AUTH_STORE
    code = store.add_user("ivy", ["artifacts:read", "jumphost:run", "jumphost:admin"])
    flow = _approve(client, "ivy", code, "jumphost:run jumphost:admin")
    store.set_user_scopes("ivy", ["artifacts:read", "jumphost:run"])  # 收回 admin
    issued = _redeem(client, flow)
    assert issued.status_code == 200 and issued.json()["scope"] == "jumphost:run"

    flow = _approve(client, "ivy", code, "jumphost:run")
    store.set_user_disabled("ivy", True)
    denied = _redeem(client, flow)
    assert denied.status_code == 400 and denied.json()["error"] == "access_denied"
    store.set_user_disabled("ivy", False)

    flow = _approve(client, "ivy", code, "jumphost:run")
    store.reset_code("ivy")  # 访问码泄漏后重置：已批准、未兑换的设备码也作废
    denied = _redeem(client, flow)
    assert denied.status_code == 400 and denied.json()["error"] == "access_denied"

    code = store.reset_code("ivy")
    flow = _approve(client, "ivy", code, "jumphost:run")
    store.set_user_scopes("ivy", ["artifacts:read"])
    assert _redeem(client, flow).json()["error"] == "access_denied"


def test_refresh_and_lookup_use_the_current_scopes(env):
    server, client, data = env
    code = server.AUTH_STORE.add_user("jack", ["artifacts:read", "docs:query"])
    tokens = _login(client, "jack", code, scope="artifacts:read docs:query")
    # 权限收回但令牌没被撤销（例如直接改库、以后的上游身份后端）：旧令牌与 refresh 都不再带它
    import sqlite3

    with sqlite3.connect(data / "auth.db") as conn:
        conn.execute("UPDATE users SET scopes='docs:query' WHERE username='jack'")
    who = client.get("/v1/whoami", headers=_bearer(tokens["access_token"])).json()
    assert who["scope"] == "docs:query"
    assert client.get("/v1/artifacts/manifest",
                      headers=_bearer(tokens["access_token"])).status_code == 403
    refreshed = client.post("/token", data={"grant_type": "refresh_token",
                                            "refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200 and refreshed.json()["scope"] == "docs:query"
    with sqlite3.connect(data / "auth.db") as conn:
        conn.execute("UPDATE users SET scopes='config:read' WHERE username='jack'")
    gone = client.post("/token", data={"grant_type": "refresh_token",
                                       "refresh_token": refreshed.json()["refresh_token"]})
    assert gone.status_code == 400 and gone.json()["error"] == "invalid_grant"


# ── 登录失败计数：只数真实账号，表有上界 ──────────────────────────────────────────
def test_failure_table_tracks_only_real_accounts_and_is_bounded(env, monkeypatch):
    server, client, _ = env
    backend = server.AUTH_BACKEND
    flow = client.post("/device_authorize", data={}).json()
    for name in [f"ghost{i}" for i in range(40)] + ["bad name", "x" * 300, "../etc"]:
        res = client.post("/activate", data={"user_code": flow["user_code"],
                                             "username": name, "access_code": "nope"})
        assert res.status_code == 403
    assert backend._failures == {}
    names = [f"real{i}" for i in range(6)]
    for name in names:
        server.AUTH_STORE.add_user(name)
    monkeypatch.setattr(backend, "MAX_TRACKED", 4)
    for name in names:
        client.post("/activate", data={"user_code": flow["user_code"], "username": name,
                                       "access_code": "nope"})
    assert 0 < len(backend._failures) <= 4


# ── secret 哈希：新格式是加盐 HMAC；旧 PBKDF2 哈希照认并在校验通过时换格式 ────────────
def test_secret_hashes_are_fast_and_legacy_rows_migrate(env):
    server, client, data = env
    import sqlite3

    import auth_store

    secret = server.AUTH_STORE.add_client("legacy-gw", ["introspect"])
    with sqlite3.connect(data / "auth.db") as conn:
        salt, stored = conn.execute("SELECT secret_salt, secret_hash FROM clients"
                                    " WHERE client_id='legacy-gw'").fetchone()
        assert bytes(stored).startswith(b"hs256$")
        conn.execute("UPDATE clients SET secret_hash=? WHERE client_id='legacy-gw'",
                     (auth_store._legacy_hash(secret, salt),))
    assert server.AUTH_STORE.verify_client("legacy-gw", "wrong") is None
    with sqlite3.connect(data / "auth.db") as conn:
        still = conn.execute("SELECT secret_hash FROM clients WHERE client_id='legacy-gw'"
                             ).fetchone()[0]
    assert not bytes(still).startswith(b"hs256$")
    assert server.AUTH_STORE.verify_client("legacy-gw", secret)["client_id"] == "legacy-gw"
    with sqlite3.connect(data / "auth.db") as conn:
        migrated = conn.execute("SELECT secret_hash FROM clients WHERE client_id='legacy-gw'"
                                ).fetchone()[0]
    assert bytes(migrated).startswith(b"hs256$")
    assert server.AUTH_STORE.verify_client("legacy-gw", secret) is not None
    # 用户访问码同理
    code = server.AUTH_STORE.add_user("kate")
    with sqlite3.connect(data / "auth.db") as conn:
        salt = conn.execute("SELECT code_salt FROM users WHERE username='kate'").fetchone()[0]
        conn.execute("UPDATE users SET code_hash=? WHERE username='kate'",
                     (auth_store._legacy_hash(code, salt),))
    assert _login(client, "kate", code)["access_token"]
    with sqlite3.connect(data / "auth.db") as conn:
        assert bytes(conn.execute("SELECT code_hash FROM users WHERE username='kate'"
                                  ).fetchone()[0]).startswith(b"hs256$")


def test_rotate_client_secret_keeps_issued_tokens(env):
    server, client, _ = env
    old = server.AUTH_STORE.add_client("pub2", ["bundles:read"])
    token = client.post("/token", data={"grant_type": "client_credentials"},
                        headers=_basic("pub2", old)).json()["access_token"]
    new = server.AUTH_STORE.rotate_client_secret("pub2")
    assert new != old
    assert client.post("/token", data={"grant_type": "client_credentials"},
                       headers=_basic("pub2", old)).status_code == 401
    assert client.post("/token", data={"grant_type": "client_credentials"},
                       headers=_basic("pub2", new)).status_code == 200
    assert client.get("/v1/whoami", headers=_bearer(token)).status_code == 200
