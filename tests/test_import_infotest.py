"""发布通道 tools/import_infotest.py 的测试。

- Publisher：用假的解析结果对真服务端（uvicorn 子进程）走完整发布：取令牌 → 上传 blob →
  登记进 candidate → 切 stable；同内容重发是空操作；自检不过不切 stable。
- 确定性打包：同样的文件内容，mtime 不同也打出同样的字节。
- 凭据文件必须是 0600。
- 对真实 InfoTest 的负向验证（可选）：设 IMPORT_INFOTEST_ROOT 指向一份**没有跑过批入口**
  的 InfoTest 仓，断言导入器干净拒绝、逐项列出缺失且不往 InfoTest 写任何文件。spec 同步源
  已配置的机器上这一步会真的去同步，所以默认不跑。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
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


def _resolution(extra: bytes = b"") -> imp.Resolution:
    entries = [
        imp.Entry(kind, f"{kind}/sample_{kind}.json",
                  json.dumps({"kind": kind}).encode() + extra, "application/json",
                  {"legacy_name": f"sample_{kind}.json"} if kind == "cmdtree" else {})
        for kind in imp.KINDS
    ]
    return imp.Resolution("IMPORT_TEST_BUILD", entries, {"importer": "test"},
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


def test_promote_refused_when_required_kind_missing(publish_env):
    server, secret_file = publish_env
    pub = imp.Publisher(server.base, "publisher", imp.read_secret_file(secret_file))
    partial = _resolution(b" partial")
    partial.entries = [e for e in partial.entries if e.kind != "footprints"]
    with pytest.raises(imp.PublishError, match="footprints"):
        pub.publish(partial, promote=True)


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
