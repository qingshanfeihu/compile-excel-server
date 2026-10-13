"""静态密钥鉴权：网关只认 hub 的密钥，本地比对 SHA-256，不回调任何服务端。

换密钥不重启、权限不对回 503、actor 头只进审计和租约持有人、管理密钥才看得到 init_device、
[server] 配置被拒绝、规则文件来自本地。
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conftest import ADMIN_TOKEN, RUN_TOKEN, write_secret_digest

from gateway import service
from gateway.auth import ADMIN_SCOPES, RUN_SCOPES, ActorError, AuthError, StaticSecretAuth
from gateway.config import ConfigError, load


def _http(gw):
    object.__setattr__(gw.cfg, "port", 0)
    httpd = service.build_server(gw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(body, token=None, actor=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if actor:
            headers["X-Circle-Hub-Actor"] = actor
        req = urllib.request.Request(base + "/mcp", data=json.dumps(body).encode(),
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"null")

    return httpd, post


def test_only_the_hub_secret_is_accepted_and_the_admin_secret_adds_admin(fake_env):
    auth = fake_env["gateway"].auth
    assert auth.caller(RUN_TOKEN).scopes == RUN_SCOPES
    assert auth.caller(RUN_TOKEN).subject == "circle-hub"
    assert auth.caller(ADMIN_TOKEN).scopes == ADMIN_SCOPES
    assert auth.caller("guess") is None and auth.caller("") is None and auth.caller(None) is None
    # 摘要本身不是密钥：拿着文件里的 SHA-256 来调用也不行
    assert auth.caller(fake_env["secret_file"].read_text().strip()) is None


def test_actor_header_only_names_the_subject_and_bad_actors_are_refused(fake_env):
    auth = fake_env["gateway"].auth
    assert auth.caller(RUN_TOKEN, "alice").subject == "circle-hub/alice"
    assert auth.caller(RUN_TOKEN, "task_c4a9/developer").subject == "circle-hub/task_c4a9/developer"
    with pytest.raises(ActorError):
        auth.caller(RUN_TOKEN, "al ice")
    with pytest.raises(ActorError):
        auth.caller(RUN_TOKEN, "-x")
    assert auth.caller("guess", "alice") is None, "密钥不对时 actor 不参与判断"


def test_rotating_the_secret_file_takes_effect_without_a_restart(fake_env):
    auth = fake_env["gateway"].auth
    assert auth.caller(RUN_TOKEN) is not None
    write_secret_digest(fake_env["secret_file"], "new-secret")
    assert auth.caller(RUN_TOKEN) is None
    assert auth.caller("new-secret").scopes == RUN_SCOPES


def test_a_bad_secret_file_is_a_gateway_problem_not_a_caller_problem(fake_env):
    auth = fake_env["gateway"].auth
    secret: Path = fake_env["secret_file"]
    secret.chmod(0o644)
    with pytest.raises(AuthError, match="0600"):
        auth.caller(RUN_TOKEN)
    secret.chmod(0o600)
    secret.write_text("not a digest\n", encoding="utf-8")
    with pytest.raises(AuthError, match="SHA-256"):
        auth.caller(RUN_TOKEN)
    secret.unlink()
    with pytest.raises(AuthError, match="不存在"):
        auth.caller(RUN_TOKEN)


def test_http_layer_maps_auth_outcomes_to_401_503_and_400(fake_env):
    gw = fake_env["gateway"]
    httpd, post = _http(gw)
    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    try:
        assert post(listing)[0] == 401
        assert post(listing, "guess")[0] == 401
        status, run = post(listing, RUN_TOKEN)
        names = {t["name"] for t in run["result"]["tools"]}
        assert status == 200 and "init_device" not in names and "case_submit" in names
        _, admin = post(listing, ADMIN_TOKEN)
        assert "init_device" in {t["name"] for t in admin["result"]["tools"]}
        status, body = post(listing, RUN_TOKEN, actor="bad actor")
        assert status == 400 and "X-Circle-Hub-Actor" in body["error"]
        # 租约持有人是 hub/actor：换一个 actor 拿不到同一个租约的 token
        acquire = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "lease_acquire", "arguments": {}}}
        _, mine = post(acquire, RUN_TOKEN, actor="alice")
        assert mine["result"]["structuredContent"]["ok"] is True
        status_call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "lease_status", "arguments": {}}}
        _, theirs = post(status_call, RUN_TOKEN, actor="bob")
        assert theirs["result"]["structuredContent"]["holder"] == "circle-hub/alice"
        assert "token" not in theirs["result"]["structuredContent"]
        fake_env["secret_file"].chmod(0o644)
        status, body = post(listing, RUN_TOKEN)
        assert status == 503 and "misconfigured" in body["error"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_retired_server_section_is_refused_with_directions(fake_env, tmp_path):
    text = fake_env["config"].read_text(encoding="utf-8")
    legacy = tmp_path / "legacy.toml"
    legacy.write_text(text + '\n[server]\nurl = "https://ces.example.test:8900"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match=r"\[server\] 已废弃.*\[hub\]"):
        load(legacy)
    missing = tmp_path / "missing.toml"
    missing.write_text(text.replace('secret_sha256_file = ', 'secret_sha256_file_x = '),
                       encoding="utf-8")
    with pytest.raises(ConfigError, match="hub.secret_sha256_file"):
        load(missing)


def test_grammar_defaults_to_the_state_dir_and_can_point_elsewhere(fake_env, tmp_path):
    gw = fake_env["gateway"]
    assert gw.cfg.grammar_file == gw.cfg.state_dir / "domain_grammar.json"
    assert "destructive_commands" in gw.grammar()
    elsewhere = tmp_path / "rules" / "domain_grammar.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text(json.dumps({"destructive_commands": {"patterns": []}}), encoding="utf-8")
    config = tmp_path / "elsewhere.toml"
    config.write_text(fake_env["config"].read_text(encoding="utf-8").replace(
        "[hub]\n", f'[hub]\ngrammar_file = "{elsewhere}"\n'), encoding="utf-8")
    cfg = load(config)
    assert cfg.grammar_file == elsewhere
    bad = tmp_path / "rules" / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    object.__setattr__(gw.cfg, "grammar_file", bad)
    gw._grammar = None
    with pytest.raises(Exception, match="JSON object"):
        gw.grammar()


def test_cexg_check_reports_the_secret_file_and_the_rules_file(fake_env):
    from conftest import REPO_ROOT

    proc = subprocess.run([sys.executable, "-m", "gateway.cexg", "check", "--config",
                           str(fake_env["config"])], cwd=REPO_ROOT, capture_output=True,
                          text=True, timeout=120)
    report = json.loads(proc.stdout)
    by_name = {c["check"]: c for c in report["checks"]}
    assert by_name["hub_secret"]["ok"] and by_name["hub_admin_secret"]["ok"]
    assert by_name["grammar_file"]["ok"]
    assert RUN_TOKEN not in proc.stdout and "run-token" not in proc.stdout
    auth = StaticSecretAuth("circle-hub", fake_env["secret_file"])
    assert auth.caller(ADMIN_TOKEN) is None, "没配管理密钥时管理密钥不算数"
