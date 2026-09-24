"""compile-excel-server 端到端测试（自包含：合成数据，零内部资产）。

覆盖：provision 部署初始化与实例凭据生成、设备流登录、数据包同步的 SHA 校验与不符即拒、
断网明示回退、docs 检索、token 过期自动 refresh、错误 token 拒绝、审计日志 HMAC 完整性、
以及**防泄漏守卫**（git 跟踪内容出现内部资产指纹即失败）。客户端是 skills 仓的 `bin/cex_tool`
（与 skill 在各 harness 里用的是同一套工具）。

跑法（仓库根，带 fastapi 的解释器）：python -m pytest tests/ -v
env：CEX_TOOL 缺省为同级目录 ../compile-excel-skills/bin/cex_tool；
找不到时，依赖它的用例跳过（不算失败）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CEX_TOOL = Path(os.environ.get("CEX_TOOL")
                or REPO_ROOT.parent / "compile-excel-skills" / "bin" / "cex_tool")
PY = sys.executable
SAMPLE_BUILD = "SAMPLE_BUILD_LOCAL"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

needs_cex_tool = pytest.mark.skipif(
    not CEX_TOOL.is_file(),
    reason=f"找不到 skills 仓客户端 {CEX_TOOL}（设 CEX_TOOL，"
           "或把 compile-excel-skills 放在同级目录）",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# 私有模拟后端：测试账号由 `ces users add` 建，访问码写到 0600 文件再读回
ACCESS_CODES: dict[str, str] = {}


def add_user(data: Path, username: str, scopes: str | None = None) -> str:
    out = data.parent / f"{data.name}.{username}.code"
    argv = [PY, str(REPO_ROOT / "ces_main.py"), "users", "add", username,
            "--data", str(data), "--out", str(out)]
    if scopes is not None:
        argv += ["--scopes", scopes]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    code = out.read_text(encoding="utf-8").strip()
    assert code not in proc.stdout, "--out 时访问码不应再出现在终端输出里"
    out.unlink()
    ACCESS_CODES[f"{data}:{username}"] = code
    return code


def access_code(data: Path, username: str) -> str:
    return ACCESS_CODES[f"{data}:{username}"]


def provision_sample(target: Path) -> Path:
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "deploy" / "provision.py"),
         "--data", str(target), "--sample"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for username in ("tester", "e2e-user"):
        add_user(target, username)
    return target


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    """provision --sample：部署初始化 + 合成工件/手册 + 实例审计密钥 + 测试账号。"""
    return provision_sample(tmp_path_factory.mktemp("ces_data"))


class Server:
    def __init__(self, data: Path, env_extra: dict[str, str] | None = None):
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.data = data
        env = {**os.environ, "CES_DATA_DIR": str(data), **(env_extra or {})}
        self.proc = subprocess.Popen(
            [PY, "-m", "uvicorn", "server:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--log-level", "warning"],
            cwd=REPO_ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=1) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.2)
        self.stop()
        raise RuntimeError("server failed to start")

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def post_form(self, path: str, data: dict[str, str]) -> tuple[int, dict]:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, {}


@pytest.fixture()
def server(data_dir):
    srv = Server(data_dir)
    yield srv
    srv.stop()


@pytest.fixture()
def short_ttl_server(data_dir):
    srv = Server(data_dir, {"CES_ACCESS_TTL": "2"})
    yield srv
    srv.stop()


class ClientEnv:
    """一个项目文件夹 + skills 仓的 cex_tool（子进程，与 harness 里走同一套工具）。"""

    def __init__(self, base: str, tmp: Path):
        self.workspace = tmp / "project"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.env = {**os.environ, "CEX_WORKSPACE": str(self.workspace)}
        self.env.pop("CEX_HOME", None)
        init = self.tool("cex_init", server=base, device_build=SAMPLE_BUILD)
        assert init["ok"], init

    def tool(self, name: str, **args) -> dict:
        proc = subprocess.run(
            [PY, str(CEX_TOOL), name, json.dumps({"workspace": str(self.workspace), **args})],
            capture_output=True, text=True, env=self.env, timeout=120,
        )
        assert proc.returncode in (0, 1), proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    def login(self, server: Server, username: str = "tester") -> dict:
        started = self.tool("cex_login_start")
        assert started["ok"], started
        status, _body = server.post_form(
            "/activate", {"user_code": started["user_code"], "username": username,
                          "access_code": access_code(server.data, username)})
        assert status == 200
        done = self.tool("cex_login_wait", timeout_s=30)
        assert done["ok"], done
        return done

    def sync(self) -> dict:
        return self.tool("cex_sync")

    def docs(self, query: str, limit: int = 3) -> dict:
        return self.tool("cex_docs_query", q=query, limit=limit)

    def bundle_dir(self) -> Path:
        return self.workspace / ".compile-excel" / "bundle" / SAMPLE_BUILD

    def token_path(self) -> Path:
        return self.workspace / ".compile-excel" / "token.json"


@pytest.fixture()
def client_env(server, tmp_path):
    return ClientEnv(server.base, tmp_path)


# ── 防泄漏守卫：git 跟踪内容不得出现内部资产指纹 ──────────────────────
# 标记串运行时拼装（源码只存分片，避免守卫扫到自身）
_INTERNAL_MARKERS = [
    "46aa14df" + "ffbe767ec486dc6b" + "186d582458d666de8a8f6aec2294f920077a45f9",  # 真模板 SHA
    "ca32544f" + "34bbd8662e14320e" + "1cec7ca7892df63a3852a24f496ae2e2eb1fdf6c",  # 契约 SHA
    "Info" + "secOS",   # 内部构建名
    "APV" + "_HG_K",     # 内部构建号段
]
INTERNAL_MARKERS = [m for m in _INTERNAL_MARKERS if m]


def test_no_internal_assets_in_repo():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    assert tracked, "git 仓库应为非空"
    offenders = []
    for name in tracked:
        path = REPO_ROOT / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for marker in INTERNAL_MARKERS:
            if marker in text:
                offenders.append(f"{name}: 含内部指纹 {marker[:16]}…")
    assert not offenders, "内部资产泄漏风险：\n" + "\n".join(offenders)


def test_data_dir_gitignored(data_dir):
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "data/" in gitignore


# ── 部署初始化 ────────────────────────────────────────────────────────

def test_provision_generates_instance_credentials(data_dir):
    key_path = data_dir / "audit_hmac_key"
    assert key_path.is_file()
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert len(bytes.fromhex(key_path.read_text().strip())) == 32
    meta = json.loads((data_dir / "artifacts_meta.json").read_text(encoding="utf-8"))
    assert meta["device_build"] == SAMPLE_BUILD  # --sample 覆盖了骨架占位


@needs_cex_tool
def test_audit_log_hmac(data_dir, server, client_env):
    client_env.login(server)
    assert client_env.sync()["ok"]
    assert client_env.docs("manifest sha256")["ok"]
    time.sleep(0.3)
    key = bytes.fromhex((data_dir / "audit_hmac_key").read_text().strip())
    lines = (data_dir / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert lines, "审计日志应有记录"
    for line in lines:
        body, sep, mac = line.rpartition("\thmac=")
        assert sep, f"审计行缺 hmac：{line[:60]}"
        assert hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest() == mac
    joined = "\n".join(lines)
    assert "access_token" not in joined and "refresh_token" not in joined
    token = json.loads(client_env.token_path().read_text(encoding="utf-8"))
    for secret in (token["access_token"], token["refresh_token"],
                   access_code(data_dir, "tester")):
        assert secret not in joined


# ── 分发闭环（客户端在 skills 仓）────────────────────────────────────

# 旧 artifacts 目录导成的 legacy-import 包：条目路径是 <kind>/<文件名>
LEGACY_ENTRIES = {"template/sample_runtime_template.xlsx", "framework/framework_tree.tar.gz",
                  "cmdtree/cmdtree_sample.xml"}


@needs_cex_tool
def test_full_loop_login_sync_docs(client_env, server):
    result = client_env.login(server, username="e2e-user")
    assert result["ok"] is True
    mode = stat.S_IMODE(os.stat(client_env.token_path()).st_mode)
    assert mode == 0o600

    synced = client_env.sync()
    assert synced["ok"] and synced["source"] == "server", synced
    assert synced["build"] == SAMPLE_BUILD and synced["downloaded"] == len(LEGACY_ENTRIES)
    manifest = json.loads((client_env.bundle_dir() / "manifest.json").read_text(encoding="utf-8"))
    assert {e["path"] for e in manifest["entries"]} == LEGACY_ENTRIES
    for entry in manifest["entries"]:
        data = (client_env.bundle_dir() / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]

    docs = client_env.docs("device_authorize user_code", limit=2)
    assert docs["ok"] and docs["results"], docs


@needs_cex_tool
def test_wrong_token_rejected(client_env):
    token_path = client_env.token_path()
    token_path.write_text(json.dumps({
        "access_token": "bogus", "refresh_token": "bogus", "expires_at": 0,
        "server": json.loads((client_env.workspace / ".compile-excel" / "config.json")
                             .read_text(encoding="utf-8"))["server"],
    }), encoding="utf-8")
    os.chmod(token_path, 0o600)
    assert client_env.sync()["ok"] is False
    assert client_env.docs("x")["ok"] is False


@needs_cex_tool
def test_sha_mismatch_rejected(client_env, server, data_dir):
    client_env.login(server)
    first = client_env.sync()
    assert first["ok"], first
    target = client_env.bundle_dir() / "framework" / "framework_tree.tar.gz"
    manifest = json.loads((client_env.bundle_dir() / "manifest.json").read_text(encoding="utf-8"))
    sha = next(e["sha256"] for e in manifest["entries"] if e["path"] == "framework/framework_tree.tar.gz")
    target.unlink()  # 本地缺了这一件，下次同步必须重新下载

    # 下载发的是注册表里的不可变 blob：演练篡改 blob 本身，客户端必须按清单 SHA 拒收
    blob = data_dir / "registry" / "blobs" / "sha256" / sha[:2] / sha
    original = blob.read_bytes()
    os.chmod(blob, 0o644)
    try:
        blob.write_bytes(original + b"\x00tamper")
        second = client_env.sync()
        assert second["ok"] is False and "SHA256" in second["error"], second
        assert not target.exists()
        assert not list(target.parent.glob("*.part"))
    finally:
        blob.write_bytes(original)
        os.chmod(blob, 0o444)


def test_live_artifact_edits_do_not_leak_into_downloads(server, data_dir):
    """旧版下载发的是登记时的 blob：运行中改 artifacts 目录，下载内容仍与清单一致。"""
    token = _http_token(server)
    headers = {"Authorization": f"Bearer {token}"}
    with urllib.request.urlopen(urllib.request.Request(
            server.base + "/v1/artifacts/manifest", headers=headers), timeout=10) as resp:
        manifest = json.loads(resp.read())
    entry = next(a for a in manifest["artifacts"] if a["name"] == "cmdtree_sample.xml")
    live = data_dir / "artifacts" / "cmdtree_sample.xml"
    original = live.read_bytes()
    try:
        live.write_bytes(original + b"<!-- edited while running -->")
        with urllib.request.urlopen(urllib.request.Request(
                server.base + "/v1/artifacts/cmdtree_sample.xml", headers=headers),
                timeout=10) as resp:
            body = resp.read()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
    finally:
        live.write_bytes(original)


@needs_cex_tool
def test_offline_fallback_explicit(client_env, server):
    client_env.login(server)
    assert client_env.sync()["source"] == "server"
    server.stop()
    second = client_env.sync()
    assert second["ok"] and second["source"] == "cache", second
    assert "cached bundle" in second["note"]
    assert client_env.docs("x")["ok"] is False


@needs_cex_tool
def test_token_expiry_auto_refresh(short_ttl_server, tmp_path):
    env = ClientEnv(short_ttl_server.base, tmp_path)
    env.login(short_ttl_server)
    old = json.loads(env.token_path().read_text(encoding="utf-8"))
    time.sleep(2.5)
    assert env.sync()["ok"]
    new = json.loads(env.token_path().read_text(encoding="utf-8"))
    assert new["access_token"] != old["access_token"]
    assert new["refresh_token"] != old["refresh_token"]
    assert env.docs("token")["ok"]


def test_manifest_requires_auth(server):
    status, _ = server.post_form("/v1/artifacts/manifest", {})
    # GET 版本
    req = urllib.request.Request(server.base + "/v1/artifacts/manifest")
    try:
        with urllib.request.urlopen(req, timeout=5):
            status = 200
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 401


def test_ces_entrypoint_without_install(tmp_path):
    """ces 入口在未安装时应给出明确指引（退出码 2）。"""
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "ces_main.py"), "status"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "CES_CONFIG_ROOT": str(tmp_path)},
    )
    assert proc.returncode == 2
    assert "ces setup" in (proc.stdout + proc.stderr)


def test_ces_setup_options_file_end_to_end(tmp_path):
    """ces setup --options-file 全链路（安装→登记→工件/手册落位，不起服务）。"""
    art = tmp_path / "tree.xml"
    art.write_text("<cmdtree/>", encoding="utf-8")
    docs = tmp_path / "manuals"
    docs.mkdir()
    (docs / "m.md").write_text("# 手册\n工件下发", encoding="utf-8")
    data = tmp_path / "d"
    options = tmp_path / "opt.json"
    options.write_text(json.dumps({
        "data": str(data), "device_build": "CES_E2E", "kms": "127.0.0.1:8443",
        "port": 8917, "host": "0.0.0.0", "start": False, "force": False,
        "artifacts": [f"{art}:0.1"], "docs": [str(docs)],
    }), encoding="utf-8")
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "ces_main.py"), "setup", "--options-file", str(options)],
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "CES_CONFIG_ROOT": str(tmp_path / "cfg")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    assert meta["device_build"] == "CES_E2E"
    assert meta["kms_addr"] == "127.0.0.1:8443"
    assert (data / "artifacts" / "tree.xml").is_file()
    assert (data / "docs" / "m.md").is_file()
    install_state = json.loads(
        (tmp_path / "cfg" / "install.json").read_text(encoding="utf-8"))
    assert install_state["data"] == str(data)
    assert install_state["port"] == 8917
    # 监听地址一路透传到安装登记与实际起服务的 argv（此前恒绑 127.0.0.1）
    assert install_state["host"] == "0.0.0.0"
    sys.path.insert(0, str(REPO_ROOT))
    try:
        import ces_main
    finally:
        sys.path.pop(0)
    argv = ces_main._serve_argv(install_state)
    assert argv[argv.index("--host") + 1] == "0.0.0.0"


def _http_token(server: "Server") -> str:
    """不依赖 skill 仓脚本，直接走设备授权流拿 access token。"""
    status, flow = server.post_form(
        "/device_authorize", {"client_id": "e2e", "scope": "artifacts:read docs:query"})
    assert status == 200
    status, _ = server.post_form(
        "/activate", {"user_code": flow["user_code"], "username": "tester",
                      "access_code": access_code(server.data, "tester")})
    assert status == 200
    status, tokens = server.post_form(
        "/token", {"grant_type": DEVICE_GRANT, "device_code": flow["device_code"]})
    assert status == 200, tokens
    return tokens["access_token"]


def _docs_query(server: "Server", token: str, query: str) -> list[dict]:
    body = urllib.parse.urlencode({"q": query, "limit": "10"}).encode()
    req = urllib.request.Request(
        server.base + "/v1/docs/query", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["results"]


def test_docs_are_indexed_recursively_and_symlinks_stay_inside(tmp_path):
    """setup 按子目录拷贝手册；检索必须覆盖子目录，且不能经软链读到数据目录外。"""
    data = provision_sample(tmp_path / "d")
    nested = data / "docs" / "cli" / "10.5"
    nested.mkdir(parents=True)
    (nested / "cli_cn.md").write_text("# 子目录手册\nzzsubdirtoken", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("# 外部\nzzoutsidetoken", encoding="utf-8")
    (data / "docs" / "escape.md").symlink_to(outside)
    srv = Server(data)
    try:
        token = _http_token(srv)
        hits = _docs_query(srv, token, "zzsubdirtoken")
        assert [hit["doc"] for hit in hits] == ["cli/10.5/cli_cn.md"]
        assert _docs_query(srv, token, "zzoutsidetoken") == []
    finally:
        srv.stop()


def test_setup_sample_install_from_empty_data_dir(tmp_path):
    """--sample 的空目录安装：meta 要等样例工件生成后再生成，不能在第 4 步因工件为空中止。"""
    data = tmp_path / "d"
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "deploy" / "setup.py"), "--data", str(data),
         "--device-build", "SAMPLE_BUILD_LOCAL", "--sample", "--port", "8918", "--yes"],
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "CES_CONFIG_ROOT": str(tmp_path / "cfg")},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    assert meta["device_build"] == "SAMPLE_BUILD_LOCAL"
    assert meta["artifacts"], "样例工件应已登记进 meta"
