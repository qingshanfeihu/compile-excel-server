"""数据包注册表测试（进程内 TestClient，合成数据）。

覆盖：发布闭环（client_credentials → PUT blob → POST 包 → candidate → 切 stable → 下载）、
哈希不符拒收、引用缺失与路径越界拒收、自检不过不能进 stable、同内容重复发布是空操作、
scope 校验、旧目录导入不覆盖导入器发布的 stable、全量复核与垃圾回收。
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

BUILD = "SAMPLE_BUILD_LOCAL"
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
    client = TestClient(server.app)
    secret = server.AUTH_STORE.add_client("publisher", ["bundles:publish", "bundles:read"])
    raw = base64.b64encode(f"publisher:{secret}".encode()).decode()
    issued = client.post("/token", data={"grant_type": "client_credentials"},
                         headers={"Authorization": f"Basic {raw}"}).json()
    return server, client, data, {"Authorization": f"Bearer {issued['access_token']}"}


def _user_headers(server, client, scope: str) -> dict[str, str]:
    code = server.AUTH_STORE.add_user(f"u{abs(hash(scope)) % 10000}", scope.split())
    flow = client.post("/device_authorize", data={"scope": scope}).json()
    client.post("/activate", data={"user_code": flow["user_code"],
                                   "username": f"u{abs(hash(scope)) % 10000}",
                                   "access_code": code})
    token = client.post("/token", data={"grant_type": DEVICE_GRANT,
                                        "device_code": flow["device_code"]}).json()
    return {"Authorization": f"Bearer {token['access_token']}"}


def _put(client, headers, payload: bytes, media: str = "application/octet-stream") -> str:
    sha = hashlib.sha256(payload).hexdigest()
    res = client.put(f"/v1/blobs/{sha}", content=payload,
                     headers={**headers, "Content-Type": media})
    assert res.status_code in (200, 201), res.text
    return sha


def _entries(client, headers, build_files: dict[str, tuple[str, bytes]]) -> list[dict]:
    entries = []
    for path, (kind, payload) in build_files.items():
        entries.append({"kind": kind, "path": path, "sha256": _put(client, headers, payload),
                        "media_type": "application/octet-stream", "meta": {}})
    return entries


FILES = {
    "cmdtree/vendor_stdlib_x.json": ("cmdtree", b'{"commands": []}'),
    "template/excel_runtime_template.xlsx": ("template", b"PK\x03\x04tmpl"),
    "spec/docs/规格说明.md": ("spec", "# 规格\n".encode()),
}


def test_publish_promote_and_download(env):
    _, client, _, pub = env
    entries = _entries(client, pub, FILES)
    res = client.post("/v1/bundles", json={"build": "B1", "entries": entries,
                                           "source": {"importer": "test"}}, headers=pub)
    assert res.status_code == 201, res.text
    bundle_id = res.json()["bundle_id"]
    assert res.json()["checks"]["ok"] is True

    assert client.get("/v1/builds/B1/bundle", headers=pub).status_code == 404
    candidate = client.get("/v1/builds/B1/bundle", params={"channel": "candidate"},
                           headers=pub).json()
    assert candidate["bundle_id"] == bundle_id
    assert {e["path"] for e in candidate["entries"]} == set(FILES)

    promoted = client.post("/v1/builds/B1/channels/stable", data={"bundle_id": bundle_id},
                           headers=pub)
    assert promoted.status_code == 200, promoted.text
    stable = client.get("/v1/builds/B1/bundle", headers=pub).json()
    assert stable["bundle_id"] == bundle_id and stable["source"] == {"importer": "test"}
    for entry in stable["entries"]:
        body = client.get(f"/v1/blobs/{entry['sha256']}", headers=pub).content
        assert body == FILES[entry["path"]][1]

    builds = {b["build"]: b for b in client.get("/v1/builds", headers=pub).json()["builds"]}
    assert builds["B1"]["channels"]["stable"]["bundle_id"] == bundle_id


def test_identical_resubmit_is_a_noop(env):
    _, client, _, pub = env
    entries = _entries(client, pub, FILES)
    first = client.post("/v1/bundles", json={"build": "B1", "entries": entries}, headers=pub)
    again = client.post("/v1/bundles", json={"build": "B1", "entries": entries[::-1]},
                        headers=pub)
    assert again.status_code == 200
    assert again.json()["bundle_id"] == first.json()["bundle_id"]
    assert again.json()["created"] is False


def test_blob_hash_mismatch_is_rejected_and_leaves_nothing(env):
    server, client, data, pub = env
    claimed = hashlib.sha256(b"what I say").hexdigest()
    res = client.put(f"/v1/blobs/{claimed}", content=b"what I send", headers=pub)
    assert res.status_code == 422
    assert server.REGISTRY.blob_info(claimed) is None
    assert list((data / "registry" / "tmp").iterdir()) == []
    assert client.put("/v1/blobs/not-a-sha", content=b"x", headers=pub).status_code == 400


def test_bundle_refs_and_paths_are_validated(env):
    _, client, _, pub = env
    sha = _put(client, pub, b"x")
    missing = hashlib.sha256(b"never uploaded").hexdigest()
    bad = [
        {"kind": "cmdtree", "path": "cmdtree/a.json", "sha256": missing},
        {"kind": "cmdtree", "path": "cmdtree/../../etc/passwd", "sha256": sha},
        {"kind": "cmdtree", "path": "template/a.json", "sha256": sha},
        {"kind": "spec", "path": "spec/.hidden", "sha256": sha},
        {"kind": "spec", "path": "spec/a\\b.md", "sha256": sha},
        {"kind": "spec", "path": "/spec/a.md", "sha256": sha},
        {"kind": "secrets", "path": "secrets/a", "sha256": sha},
    ]
    for entry in bad:
        res = client.post("/v1/bundles", json={"build": "B1", "entries": [entry]}, headers=pub)
        assert res.status_code == 422, entry
    dup = [{"kind": "spec", "path": "spec/A.md", "sha256": sha},
           {"kind": "spec", "path": "spec/a.md", "sha256": sha}]
    assert client.post("/v1/bundles", json={"build": "B1", "entries": dup},
                       headers=pub).status_code == 422
    assert client.post("/v1/bundles", json={"build": "../x", "entries": [
        {"kind": "spec", "path": "spec/a.md", "sha256": sha}]}, headers=pub).status_code == 422


def test_bundle_failing_self_check_cannot_become_stable(env):
    _, client, _, pub = env
    entries = _entries(client, pub, {"spec/a.md": ("spec", b"# a")})
    res = client.post("/v1/bundles", json={"build": "B2", "entries": entries}, headers=pub)
    assert res.status_code == 201
    assert res.json()["checks"]["ok"] is False
    refused = client.post("/v1/builds/B2/channels/stable",
                          data={"bundle_id": res.json()["bundle_id"]}, headers=pub)
    assert refused.status_code == 422
    other = client.post("/v1/builds/B1/channels/candidate",
                        data={"bundle_id": res.json()["bundle_id"]}, headers=pub)
    assert other.status_code == 422, "指针只能指向同一构建的包"


def test_scopes_guard_read_and_publish(env):
    server, client, _, pub = env
    reader = _user_headers(server, client, "bundles:read")
    docs_only = _user_headers(server, client, "docs:query")
    payload = b"reader cannot publish"
    sha = hashlib.sha256(payload).hexdigest()
    assert client.put(f"/v1/blobs/{sha}", content=payload, headers=reader).status_code == 403
    assert client.post("/v1/bundles", json={}, headers=reader).status_code == 403
    assert client.get("/v1/builds", headers=reader).status_code == 200
    assert client.get("/v1/builds", headers=docs_only).status_code == 403
    assert client.get(f"/v1/blobs/{sha}").status_code == 401


def test_legacy_dir_does_not_override_importer_stable(env):
    server, client, data, pub = env
    legacy = client.get(f"/v1/builds/{BUILD}/bundle", headers=pub).json()
    assert legacy["publisher"] == "legacy-import"
    entries = _entries(client, pub, FILES)
    res = client.post("/v1/bundles", json={"build": BUILD, "entries": entries}, headers=pub)
    client.post(f"/v1/builds/{BUILD}/channels/stable",
                data={"bundle_id": res.json()["bundle_id"]}, headers=pub)
    (data / "artifacts" / "cmdtree_sample.xml").write_text("<cmdtree changed/>", encoding="utf-8")
    server._init_data(data)  # 等同重启
    stable = client.get(f"/v1/builds/{BUILD}/bundle", headers=pub).json()
    assert stable["bundle_id"] == res.json()["bundle_id"]


def test_legacy_restart_picks_up_changed_artifacts(env):
    server, client, data, pub = env
    before = client.get(f"/v1/builds/{BUILD}/bundle", headers=pub).json()["bundle_id"]
    (data / "artifacts" / "cmdtree_sample.xml").write_text("<cmdtree v2/>", encoding="utf-8")
    server._init_data(data)
    after = client.get(f"/v1/builds/{BUILD}/bundle", headers=pub).json()["bundle_id"]
    assert after != before


def test_verify_and_gc(env):
    server, client, _, pub = env
    kept = _put(client, pub, b"referenced later")
    orphan = _put(client, pub, b"never referenced")
    client.post("/v1/bundles", json={"build": "B3", "entries": [
        {"kind": "cmdtree", "path": "cmdtree/a.json", "sha256": kept}]}, headers=pub)
    assert server.REGISTRY.verify_all() == []
    path = server.REGISTRY.blob_path(kept)
    os.chmod(path, 0o644)
    path.write_bytes(b"tampered")
    assert any(kept in problem for problem in server.REGISTRY.verify_all())
    assert server.REGISTRY.gc() >= 1
    assert server.REGISTRY.blob_info(orphan) is None
    assert server.REGISTRY.blob_info(kept) is not None


def test_ces_registry_cli_import_promote_verify(tmp_path):
    data = tmp_path / "d"
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(data),
         "--sample"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    import registry as reg_mod

    reg = reg_mod.Registry(data / "registry")
    reg.import_legacy_dir(BUILD, data / "artifacts", {
        "cmdtree_sample.xml": {}, "sample_runtime_template.xlsx": {}})
    spec_dir = tmp_path / "spec"
    (spec_dir / "docs").mkdir(parents=True)
    (spec_dir / "docs" / "a.md").write_text("# a", encoding="utf-8")

    def ces(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(REPO_ROOT / "ces_main.py"), "registry",
                               *args, "--data", str(data)],
                              capture_output=True, text=True, timeout=60)

    out = ces("import-dir", BUILD, "spec", str(spec_dir))
    assert out.returncode == 0, out.stdout
    import json as _json

    bundle_id = _json.loads(out.stdout)["bundle_id"]
    manifest = reg.bundle_manifest(bundle_id)
    assert {e["kind"] for e in manifest["entries"]} == {"cmdtree", "template", "spec"}
    assert ces("promote", BUILD, bundle_id).returncode == 0
    assert reg.channel_bundle(BUILD, "stable") == bundle_id
    assert ces("verify").returncode == 0
    assert ces("promote", BUILD, "0" * 64).returncode == 1
