"""网关的服务端客户端对真 compile-excel-server：令牌内省（含撤销后失效）与从 stable 包取规则文件。"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_e2e import PY, REPO_ROOT, Server, _http_token, provision_sample  # noqa: E402

from gateway import introspect  # noqa: E402
from gateway.introspect import IntrospectError, ServerClient  # noqa: E402


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    data = provision_sample(tmp_path_factory.mktemp("gw_srv"))
    secret = data.parent / "gateway.secret"
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "ces_main.py"), "clients", "add", "gateway", "--scopes",
         "introspect bundles:read", "--data", str(data), "--out", str(secret)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sys.path.insert(0, str(REPO_ROOT))
    from registry import Registry

    reg = Registry(data / "registry")
    meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    reg.import_legacy_dir("SAMPLE_BUILD_LOCAL", data / "artifacts", meta["artifacts"])
    grammar = json.dumps({"destructive_commands": {"patterns": [r"\breboot\b"]}}).encode()
    src = data.parent / "domain_grammar.json"
    src.write_bytes(grammar)
    stable = reg.bundle_manifest(reg.channel_bundle("SAMPLE_BUILD_LOCAL", "stable"))
    entries = [{k: e[k] for k in ("kind", "path", "sha256", "media_type", "meta")}
               for e in stable["entries"]]
    blob = reg.put_blob_file(src, "application/json")
    entries.append({"kind": "projections", "path": "projections/domain_grammar.json",
                    "sha256": blob["sha256"], "media_type": "application/json", "meta": {}})
    result = reg.submit_bundle("SAMPLE_BUILD_LOCAL", entries, publisher="test")
    reg.set_channel("SAMPLE_BUILD_LOCAL", "stable", result["bundle_id"], "test")
    server = Server(data)
    yield server, secret, grammar
    server.stop()


def test_introspect_and_revocation(live, monkeypatch):
    server, secret, _ = live
    # 缓存窗口（默认 30 秒）内撤销不会立刻生效；这里关掉缓存验证撤销本身能传到网关
    monkeypatch.setattr(introspect, "CACHE_SECONDS", 0.0)
    client = ServerClient(server.base, "gateway", secret)
    token = _http_token(server)
    info = client.introspect(token)
    assert info["active"] is True and info["username"] == "tester"
    assert client.introspect("not-a-token") == {"active": False}
    body = urllib.parse.urlencode({"token": token}).encode()
    urllib.request.urlopen(urllib.request.Request(server.base + "/revoke", data=body), timeout=10)
    time.sleep(0.05)
    assert client.introspect(token)["active"] is False
    wrong = ServerClient(server.base, "gateway", secret.parent / "gateway.secret.bad")
    (secret.parent / "gateway.secret.bad").write_text("nope", encoding="utf-8")
    (secret.parent / "gateway.secret.bad").chmod(0o600)
    with pytest.raises(IntrospectError, match="401"):
        wrong.introspect(token)


def test_fetch_grammar_from_stable_bundle(live):
    server, secret, grammar = live
    client = ServerClient(server.base, "gateway", secret)
    assert client.fetch_bundle_file("SAMPLE_BUILD_LOCAL", "projections/domain_grammar.json") == grammar
    with pytest.raises(IntrospectError, match="no projections/missing.json"):
        client.fetch_bundle_file("SAMPLE_BUILD_LOCAL", "projections/missing.json")
