"""数据包注册表测试（进程内 TestClient，合成数据）。

覆盖：发布闭环（client_credentials → PUT blob → POST 包 → candidate → 切 stable → 下载）、
哈希不符拒收、引用缺失与路径越界拒收、自检不过不能进 stable、同内容重复发布是空操作（不动通道）、
切通道带 expect、stable 的服务端 kind 下限、非有限数拒收、scope 校验、旧目录导入不覆盖导入器
发布的 stable/candidate、旧版下载按 device_build、全量复核与带宽限期的垃圾回收、import-dir 按路径叠加。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
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
    "projections/domain_grammar.json": ("projections", b'{"destructive_commands": {}}'),
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
    assert server.REGISTRY.gc(grace_s=0) >= 1
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
    # 没有 projections 进不了 stable（服务端下限），补上之后再切
    refused = ces("promote", BUILD, bundle_id)
    assert refused.returncode == 1 and "projections" in refused.stdout
    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    (proj_dir / "domain_grammar.json").write_text("{}", encoding="utf-8")
    out = ces("import-dir", BUILD, "projections", str(proj_dir))
    assert out.returncode == 0, out.stdout
    bundle_id = _json.loads(out.stdout)["bundle_id"]
    assert {e["kind"] for e in reg.bundle_manifest(bundle_id)["entries"]} == {
        "cmdtree", "template", "spec", "projections"}
    assert ces("promote", BUILD, bundle_id).returncode == 0
    assert reg.channel_bundle(BUILD, "stable") == bundle_id
    assert ces("verify").returncode == 0
    assert ces("promote", BUILD, "0" * 64).returncode == 1


# ── 通道指针：同内容重发不动指针、expect 核对、重启不拨回导入器的 candidate ──────────
def _submit(client, pub, files: dict[str, tuple[str, bytes]], build: str = "B1") -> dict:
    res = client.post("/v1/bundles", json={"build": build, "entries": _entries(client, pub, files)},
                      headers=pub)
    assert res.status_code in (200, 201), res.text
    return res.json()


def _promote(client, pub, bundle_id: str, build: str = "B1", channel: str = "stable",
             **extra: str):
    return client.post(f"/v1/builds/{build}/channels/{channel}",
                       data={"bundle_id": bundle_id, **extra}, headers=pub)


def test_unchanged_resubmit_moves_no_channel(env):
    server, client, _, pub = env
    first = _submit(client, pub, FILES)
    second = _submit(client, pub, {**FILES, "spec/b.md": ("spec", b"# b")})
    assert server.REGISTRY.channel_bundle("B1", "candidate") == second["bundle_id"]
    again = _submit(client, pub, FILES)  # 例如 cron 重跑了上一版的内容
    assert again["created"] is False and again["bundle_id"] == first["bundle_id"]
    assert server.REGISTRY.channel_bundle("B1", "candidate") == second["bundle_id"]
    assert again["channels"] == {"candidate": second["bundle_id"], "stable": None}


def test_promote_with_expect_refuses_a_pointer_that_moved(env):
    server, client, data, pub = env
    a = _submit(client, pub, FILES)["bundle_id"]
    b = _submit(client, pub, {**FILES, "spec/b.md": ("spec", b"# b")})["bundle_id"]
    assert _promote(client, pub, a, expect="none").json()["changed"] is True
    assert _promote(client, pub, a).json()["changed"] is False  # 同一指针：空操作
    stale = _promote(client, pub, b, expect="none")
    assert stale.status_code == 409 and stale.json()["current"] == a
    assert _promote(client, pub, b, expect=a).status_code == 200
    # 运维回滚到 a 之后，拿着旧认知（以为还是 a）的发布方不能把它拨回 b
    assert _promote(client, pub, a, expect=b).status_code == 200
    assert _promote(client, pub, b, expect=b).status_code == 409
    assert server.REGISTRY.channel_bundle("B1", "stable") == a
    assert _promote(client, pub, b, expect="garbage").status_code == 422
    cli = subprocess.run([sys.executable, str(REPO_ROOT / "ces_main.py"), "registry", "promote",
                          "B1", b, "--expect", b, "--data", str(data)],
                         capture_output=True, text=True, timeout=60)
    assert cli.returncode == 1 and a in cli.stdout
    assert server.REGISTRY.channel_bundle("B1", "stable") == a


def test_restart_does_not_repoint_an_importer_candidate(env):
    server, client, data, pub = env
    legacy = server.REGISTRY.channel_bundle(BUILD, "stable")
    assert server.REGISTRY.channel_bundle(BUILD, "candidate") == legacy
    mine = _submit(client, pub, FILES, build=BUILD)["bundle_id"]
    server._init_data(data)  # 等同重启：旧目录没变
    assert server.REGISTRY.channel_bundle(BUILD, "candidate") == mine
    assert server.REGISTRY.channel_bundle(BUILD, "stable") == legacy
    (data / "artifacts" / "cmdtree_sample.xml").write_text("<cmdtree v3/>", encoding="utf-8")
    server._init_data(data)  # 旧目录变了：stable（旧目录导入的）跟着走，candidate 仍是导入器的
    assert server.REGISTRY.channel_bundle(BUILD, "candidate") == mine
    assert server.REGISTRY.channel_bundle(BUILD, "stable") not in (legacy, mine)


def test_legacy_restart_moves_a_legacy_candidate(env):
    server, _, data, _ = env
    before = server.REGISTRY.channel_bundle(BUILD, "candidate")
    (data / "artifacts" / "cmdtree_sample.xml").write_text("<cmdtree v4/>", encoding="utf-8")
    server._init_data(data)
    after = server.REGISTRY.channel_bundle(BUILD, "candidate")
    assert after != before and after == server.REGISTRY.channel_bundle(BUILD, "stable")


# ── stable 的服务端下限：发布方声明的 required_kinds 放不宽 ──────────────────────────
def test_stable_needs_the_server_minimum_kinds(env, monkeypatch):
    server, client, _, pub = env
    body = b"# only a manual\n"
    only_manual = client.post("/v1/bundles", json={
        "build": "B4", "required_kinds": [],
        "entries": [{"kind": "manual", "path": "manual/x.md", "sha256": _put(client, pub, body)}]},
        headers=pub).json()
    assert only_manual["checks"]["ok"] is True  # 发布方说什么都不必备
    refused = _promote(client, pub, only_manual["bundle_id"], build="B4")
    assert refused.status_code == 422 and "cmdtree" in refused.json()["detail"]
    assert server.REGISTRY.channel_bundle("B4", "stable") is None
    # 下限可配：部署侧显式放宽后才放行
    import registry as reg_mod

    monkeypatch.setenv(reg_mod.STABLE_KINDS_ENV, "manual")
    relaxed = reg_mod.Registry(server.REGISTRY.root)
    assert relaxed.stable_kinds == ("manual",)
    assert relaxed.set_channel("B4", "stable", only_manual["bundle_id"], "test") is True
    monkeypatch.setenv(reg_mod.STABLE_KINDS_ENV, "cmdtree bogus")
    with pytest.raises(reg_mod.RegistryError, match="bogus"):
        reg_mod.Registry(server.REGISTRY.root)


def test_rollback_to_the_legacy_bundle_is_not_blocked_by_the_minimum(env):
    server, client, data, pub = env
    legacy = server.REGISTRY.channel_bundle(BUILD, "stable")
    kinds = {e["kind"] for e in server.REGISTRY.bundle_manifest(legacy)["entries"]}
    assert "projections" not in kinds  # 旧目录导入的包没有投影
    mine = _submit(client, pub, FILES, build=BUILD)["bundle_id"]
    assert _promote(client, pub, mine, build=BUILD).status_code == 200
    back = subprocess.run([sys.executable, str(REPO_ROOT / "ces_main.py"), "registry", "promote",
                           BUILD, legacy, "--expect", mine, "--data", str(data)],
                          capture_output=True, text=True, timeout=60)
    assert back.returncode == 0, back.stdout
    assert server.REGISTRY.channel_bundle(BUILD, "stable") == legacy
    # 保留名不发给账号/客户端：经接口发布的包冒充不了旧目录导入的包
    from auth_store import AuthError

    for name in ("legacy-import", "ces-cli"):
        with pytest.raises(AuthError):
            server.AUTH_STORE.add_client(name, ["bundles:publish"])
        with pytest.raises(AuthError):
            server.AUTH_STORE.add_user(name, ["bundles:publish"])


# ── 非有限数：进了库清单就发不出去 ─────────────────────────────────────────────────
def test_non_finite_numbers_are_rejected(env):
    server, client, _, pub = env
    entries = _entries(client, pub, FILES)
    for literal in ("NaN", "Infinity", "-Infinity", "1e999"):
        raw = f'{{"build": "B5", "source": {{"x": {literal}}}, "entries": {json.dumps(entries)}}}'
        raw = raw.encode()
        res = client.post("/v1/bundles", content=raw,
                          headers={**pub, "Content-Type": "application/json"})
        assert res.status_code == 400, (literal, res.text)
    assert server.REGISTRY.channel_bundle("B5", "candidate") is None
    import registry as reg_mod

    bad = [dict(entries[0], meta={"ratio": float("nan")})]
    with pytest.raises(reg_mod.RegistryError, match="有限"):
        server.REGISTRY.submit_bundle("B5", bad, publisher="test")


# ── 旧版下载按 device_build 取 ──────────────────────────────────────────────────
def test_legacy_download_honors_device_build(env):
    server, client, _, pub = env
    payload = b"<cmdtree build-two/>"
    entries = [
        {"kind": "cmdtree", "path": "cmdtree/cmdtree_sample.xml", "sha256": _put(client, pub, payload),
         "media_type": "application/xml", "meta": {"legacy_name": "cmdtree_sample.xml"}},
        *[e for e in _entries(client, pub, FILES) if e["kind"] != "cmdtree"],
    ]
    res = client.post("/v1/bundles", json={"build": "B2X", "entries": entries}, headers=pub)
    assert _promote(client, pub, res.json()["bundle_id"], build="B2X").status_code == 200
    reader = _user_headers(server, client, "artifacts:read")
    other = client.get("/v1/artifacts/cmdtree_sample.xml", params={"device_build": "B2X"},
                       headers=reader)
    assert other.status_code == 200 and other.content == payload
    default = client.get("/v1/artifacts/cmdtree_sample.xml", headers=reader)
    assert default.status_code == 200 and default.content != payload
    assert client.get("/v1/artifacts/cmdtree_sample.xml", params={"device_build": "NOPE"},
                      headers=reader).status_code == 404


# ── gc 宽限期：刚上传、清单还没登记的 blob 不回收 ───────────────────────────────────
def test_gc_spares_recent_uploads(env):
    server, client, _, pub = env
    fresh = _put(client, pub, b"uploaded, bundle not posted yet")
    assert server.REGISTRY.gc() == 0
    assert server.REGISTRY.blob_info(fresh) is not None
    old = time.time() - 3 * 24 * 3600
    with server.REGISTRY._conn() as conn:
        conn.execute("UPDATE blobs SET created_at=? WHERE sha256=?", (old, fresh))
    _put(client, pub, b"uploaded, bundle not posted yet")  # 再上传一次：宽限期重新起算
    assert server.REGISTRY.gc() == 0
    with server.REGISTRY._conn() as conn:
        conn.execute("UPDATE blobs SET created_at=? WHERE sha256=?", (old, fresh))
    assert server.REGISTRY.gc() == 1
    assert server.REGISTRY.blob_info(fresh) is None


# ── import-dir：按路径叠加到 candidate 上（ces generate 的产物只有改动的投影）──────────
def test_import_dir_overlays_per_path(env, tmp_path):
    server, client, data, pub = env
    base = _submit(client, pub, {**FILES,
                                 "projections/blocks_schema.json": ("projections", b"{}"),
                                 "projections/capability_atlas.json": ("projections", b"old")},
                   build="B6")["bundle_id"]
    out = tmp_path / "generate_out"
    out.mkdir()
    (out / "capability_atlas.json").write_bytes(b"new")

    def ces(*args: str) -> dict:
        proc = subprocess.run([sys.executable, str(REPO_ROOT / "ces_main.py"), "registry",
                               *args, "--data", str(data)],
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    overlaid = ces("import-dir", "B6", "projections", str(out))
    manifest = server.REGISTRY.bundle_manifest(overlaid["bundle_id"])
    paths = {e["path"]: e["sha256"] for e in manifest["entries"]}
    assert {p for p in paths if p.startswith("projections/")} == {
        "projections/domain_grammar.json", "projections/blocks_schema.json",
        "projections/capability_atlas.json"}
    assert paths["projections/capability_atlas.json"] == hashlib.sha256(b"new").hexdigest()
    assert overlaid["import"] == {"mode": "overlay", "base": base, "files": 1, "replaced": 1,
                                  "kept": len(FILES) + 1}
    replaced = ces("import-dir", "B6", "projections", str(out), "--replace-kind")
    kinds = [e["path"] for e in server.REGISTRY.bundle_manifest(replaced["bundle_id"])["entries"]
             if e["kind"] == "projections"]
    assert kinds == ["projections/capability_atlas.json"]
