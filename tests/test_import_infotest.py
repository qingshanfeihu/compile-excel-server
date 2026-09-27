"""发布通道 tools/import_infotest.py 的测试。

- Publisher：用假的解析结果对真服务端（uvicorn 子进程）走完整发布：取令牌 → 上传 blob →
  登记进 candidate → 切 stable；同内容重发是空操作；自检不过不切 stable。
- 切 stable 不覆盖别人的决定：同内容重发时 stable 已被回滚到别的包就不动；新包切 stable 时带
  expect=<登记时看到的 stable>，这期间有人动过 stable（服务端回 409）就不动，如实报当前指针。
- 确定性打包：同样的文件内容，mtime 不同也打出同样的字节。
- 凭据文件必须是 0600。
- 对真实 InfoTest 的负向验证（可选）：设 IMPORT_INFOTEST_ROOT 指向一份**没有跑过批入口**
  的 InfoTest 仓，断言导入器干净拒绝、逐项列出缺失且不往 InfoTest 写任何文件。spec 同步源
  已配置的机器上这一步会真的去同步，所以默认不跑。
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import import_infotest as imp  # noqa: E402
from test_e2e import PY, Server, provision_sample  # noqa: E402


@pytest.fixture(scope="module")
def publish_env(tmp_path_factory):
    data = provision_sample(tmp_path_factory.mktemp("ces_import"))
    secret_file = data.parent / "publisher.secret"
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "ces_main.py"), "clients", "add", "publisher",
         "--scopes", "bundles:publish bundles:read", "--data", str(data),
         "--out", str(secret_file)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    server = Server(data)
    yield server, secret_file
    server.stop()


def _resolution(extra: bytes = b"", build: str = "IMPORT_TEST_BUILD") -> imp.Resolution:
    entries = [
        imp.Entry(kind, f"{kind}/sample_{kind}.json",
                  json.dumps({"kind": kind}).encode() + extra, "application/json",
                  {"legacy_name": f"sample_{kind}.json"} if kind == "cmdtree" else {})
        for kind in imp.KINDS
    ]
    # 真解析器在 resolve() 末尾做出包前扫描并记下结论；Publisher 只收扫描过且干净的
    return imp.Resolution(build, entries, {"importer": "test",
                                           "credential_scan": {"status": "clean"}},
                          [{"key": "identity", "status": "ok", "evidence": ""}])


def test_publish_promote_and_noop(publish_env):
    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    first = pub.publish(_resolution(), promote=True)
    assert first["created"] is True and first["promoted"] is True
    assert first["uploaded_blobs"] == len(imp.KINDS)
    again = pub.publish(_resolution(), promote=True)
    assert again["bundle_id"] == first["bundle_id"]
    assert again["created"] is False and again["uploaded_blobs"] == 0


def test_large_blob_republish_and_cross_kind_duplicate(publish_env):
    """大 blob（超过套接字缓冲）重发与同一次发布里跨 kind 重复：都不能断管。

    服务端已有的 blob 也要读完请求体再回，否则客户端还在发送时连接被关（EPIPE）；
    同一次发布里内容相同的条目只传一次。
    """
    server, secret_file = publish_env
    big = os.urandom(4 * 1024 * 1024)
    res = _resolution(b" big")
    res.entries += [imp.Entry("template", "template/contract.bin", big),
                    imp.Entry("projections", "projections/contract.bin", big)]
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    first = pub.publish(res, promote=False)
    assert first["created"] is True
    assert first["uploaded_blobs"] == len(imp.KINDS) + 1
    again = pub.publish(res, promote=False)
    assert again["bundle_id"] == first["bundle_id"] and again["uploaded_blobs"] == 0


def test_put_existing_large_blob_reads_the_whole_body(publish_env):
    """直接对服务端：同一个大 blob PUT 两次，第二次回 created=false 而不是断管。"""
    import hashlib
    import urllib.request

    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    pub.login()
    big = os.urandom(16 * 1024 * 1024)
    digest = hashlib.sha256(big).hexdigest()
    for expected in (True, False):
        req = urllib.request.Request(
            f"{server.base}/v1/blobs/{digest}", data=big, method="PUT",
            headers={"Authorization": f"Bearer {pub._token}",
                     "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            assert json.loads(resp.read())["created"] is expected


def test_promote_refused_when_required_kind_missing(publish_env):
    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    partial = _resolution(b" partial")
    partial.entries = [e for e in partial.entries if e.kind != "footprints"]
    with pytest.raises(imp.PublishError, match="footprints"):
        pub.publish(partial, promote=True)


def _stable(server, secret_file, build: str) -> str | None:
    """当前 stable 指针（用只读令牌读，不经 Publisher）。"""
    basic = base64.b64encode(f"publisher:{imp.read_secret_file(secret_file)}".encode()).decode()
    req = urllib.request.Request(
        f"{server.base}/token", data=b"grant_type=client_credentials&scope=bundles%3Aread",
        headers={"Authorization": f"Basic {basic}",
                 "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        token = json.loads(resp.read())["access_token"]
    req = urllib.request.Request(f"{server.base}/v1/builds/{build}/bundle?channel=stable",
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())["bundle_id"]
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
        return None


def _set_stable(pub: imp.Publisher, build: str, bundle_id: str) -> None:
    """运维手工切 stable（例如回滚）。"""
    if not pub._token:
        pub.login()
    status, raw = pub._request(
        "POST", f"/v1/builds/{build}/channels/stable",
        data=urllib.parse.urlencode({"bundle_id": bundle_id}).encode(),
        headers=pub._auth({"Content-Type": "application/x-www-form-urlencoded"}))
    assert status == 200, raw


def test_republishing_the_stable_content_is_a_no_op(publish_env):
    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    build = "PROMOTE_NOOP"
    first = pub.publish(_resolution(b" a", build), promote=True)
    assert first["promotion"]["status"] == "promoted" and first["promoted"] is True
    again = pub.publish(_resolution(b" a", build), promote=True)
    assert again["created"] is False and again["promoted"] is False
    assert again["promotion"]["status"] == "already_stable"
    assert _stable(server, secret_file, build) == first["bundle_id"]


def test_unchanged_content_does_not_undo_an_operator_rollback(publish_env):
    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    build = "PROMOTE_ROLLBACK"
    old = pub.publish(_resolution(b" old", build), promote=True)
    new = pub.publish(_resolution(b" new", build), promote=True)
    assert new["promoted"] and _stable(server, secret_file, build) == new["bundle_id"]
    _set_stable(pub, build, old["bundle_id"])  # 运维回滚
    again = pub.publish(_resolution(b" new", build), promote=True)
    assert again["created"] is False and again["promoted"] is False
    assert again["promotion"]["status"] == "left_alone_unchanged"
    assert again["promotion"]["stable"] == old["bundle_id"]
    assert _stable(server, secret_file, build) == old["bundle_id"], "the rollback stands"


def test_promotion_does_not_overwrite_a_concurrent_stable_change(publish_env):
    server, secret_file = publish_env
    build = "PROMOTE_RACE"
    secret = imp.read_secret_file(secret_file)
    first = imp.Publisher(server.base, "publisher", secret).publish(
        _resolution(b" first", build), promote=True)
    other = imp.Publisher(server.base, "publisher", secret).publish(
        _resolution(b" other", build), promote=False)
    sent: list[dict] = []

    class Racing(imp.Publisher):
        def _request(self, method, path, *, data=None, headers=None):
            if path.endswith("/channels/stable") and not sent:
                sent.append(dict(urllib.parse.parse_qsl(data.decode())))
                _set_stable(imp.Publisher(server.base, "publisher", secret), build,
                            other["bundle_id"])  # 登记与切 stable 之间，别人动了 stable
            return super()._request(method, path, data=data, headers=headers)

    result = Racing(server.base, "publisher", secret).publish(_resolution(b" third", build),
                                                              promote=True)
    assert sent == [{"bundle_id": result["bundle_id"], "expect": first["bundle_id"]}]
    assert result["promoted"] is False
    assert result["promotion"]["status"] == "left_alone_conflict"
    assert result["promotion"]["stable"] == other["bundle_id"]
    assert _stable(server, secret_file, build) == other["bundle_id"]


def test_bad_secret_is_refused(publish_env):
    server, _ = publish_env
    with pytest.raises(imp.PublishError, match="取令牌失败"):
        imp.Publisher(server.base, "publisher", "wrong").publish(_resolution(), promote=False)


def test_deterministic_tar_ignores_mtime(tmp_path):
    root = tmp_path / "tree"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "b.json").write_text("{}", encoding="utf-8")
    first = imp.deterministic_tar_gz(root)
    os.utime(root / "b.json", (time.time() + 3600, time.time() + 3600))
    assert imp.deterministic_tar_gz(root) == first
    (root / "b.json").write_text('{"changed": true}', encoding="utf-8")
    assert imp.deterministic_tar_gz(root) != first


def test_secret_file_must_be_private(tmp_path):
    path = tmp_path / "secret"
    path.write_text("s3cret", encoding="utf-8")
    os.chmod(path, 0o644)
    with pytest.raises(imp.PublishError, match="0600"):
        imp.read_secret_file(path)
    os.chmod(path, 0o600)
    assert imp.read_secret_file(path) == "s3cret"


@pytest.mark.skipif(not os.environ.get("IMPORT_INFOTEST_ROOT"),
                    reason="设 IMPORT_INFOTEST_ROOT 指向未跑过批入口的 InfoTest 仓才跑")
def test_real_infotest_without_convergence_is_refused_cleanly(tmp_path):
    root = Path(os.environ["IMPORT_INFOTEST_ROOT"]).resolve()
    marker = tmp_path / "marker"
    marker.write_text("", encoding="utf-8")
    proc = subprocess.run(
        [os.environ.get("IMPORT_INFOTEST_PYTHON", PY), str(REPO_ROOT / "tools" / "import_infotest.py"),
         "--infotest-root", str(root), "--device-build", "SampleOS Beta.PRD-PLAT.9.9.0.101",
         "--dry-run"], capture_output=True, text=True, timeout=600)
    assert proc.returncode == 3, proc.stdout[-2000:] + proc.stderr[-2000:]
    report = json.loads(proc.stdout)
    refused = {item["key"] for item in report["refused"]}
    assert {"template", "cmdtree", "framework"} <= refused
    written = [p for top in ("runtime", "knowledge") for p in (root / top).rglob("*")
               if p.is_file() and "__pycache__" not in p.parts
               and p.stat().st_mtime > marker.stat().st_mtime]
    assert written == [], f"导入器不应往 InfoTest 写文件：{written[:5]}"


INFOTEST_ROOT = Path(os.environ.get("INFOTEST_ROOT") or REPO_ROOT.parent / "InfoTest_Engine")
INFOTEST_PYTHON = Path(os.environ.get("INFOTEST_PYTHON")
                       or Path.home() / ".venvs" / "infotest-engine" / "bin" / "python")


@pytest.mark.skipif(not (INFOTEST_ROOT / "main" / "kms" / "spec_generation.py").is_file()
                    or not INFOTEST_PYTHON.is_file(),
                    reason="需要同级 InfoTest 检出和它的 venv（INFOTEST_ROOT / INFOTEST_PYTHON）")
def test_spec_entries_carry_the_generation_sync_ledger(tmp_path):
    """规格书代际清单登记了 state.tsv 的 sha256，客户端重建代际时逐字节核对：导入器必须发它。
    代际由 InfoTest 自己的发布器生成，导入器按 InfoTest 自己的解析函数取数。"""
    script = f'''
import json, sys
from pathlib import Path
sys.path.insert(0, {str(INFOTEST_ROOT)!r})
sys.path.insert(0, {str(REPO_ROOT / "tools")!r})
from main.kms import spec_generation as g
root = Path({str(tmp_path)!r})
gid, staging = g._new_staging_generation(root / "knowledge" / "data" / "spec")
(staging / "docs" / "12345_Listener_Spec.md").write_text("# spec\\n", encoding="utf-8")
g.save_state(staging / "state.tsv", {{}})
g._publish_generation(staging, gid)
import import_infotest as imp
resolver = imp.InfoTestResolver(root, "B")
resolver._spec()
print(json.dumps({{"gid": gid, "entries": {{e.path: e.data.hex() for e in resolver.entries}}}}))
'''
    proc = subprocess.run([str(INFOTEST_PYTHON), "-c", script], capture_output=True, text=True,
                          timeout=300)
    assert proc.returncode == 0, proc.stderr[-3000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    generation = tmp_path / "knowledge" / "data" / "spec" / "generations" / out["gid"]
    entries = {path: bytes.fromhex(data) for path, data in out["entries"].items()}
    assert set(entries) == {"spec/manifest.json", "spec/index.json", "spec/state.tsv",
                            "spec/docs/12345_Listener_Spec.md"}
    assert entries["spec/state.tsv"] == (generation / "state.tsv").read_bytes()
