"""compile-excel-server 端到端测试（自包含：合成数据，零内部资产）。

覆盖：provision 部署初始化与实例凭据生成、login 设备流（客户端脚本来自
skill 仓）、fetch SHA 校验与不符即拒、断网明示回退、docs 检索、token 过期
自动 refresh、错误 token 401、审计日志 HMAC 完整性、以及**防泄漏守卫**
（git 跟踪内容出现内部资产指纹即失败）。

跑法（仓库根，带 fastapi 的解释器）：python -m pytest tests/ -v
env：SKILL_SCRIPTS_DIR 缺省 ~/Public/circle/compile-excel-skills/compile-excel/scripts
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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
SKILL_SCRIPTS = Path(
    os.environ.get("SKILL_SCRIPTS_DIR")
    or (Path.home() / "Public" / "circle" / "compile-excel-skills" / "compile-excel" / "scripts")
)
PY = sys.executable
LOGIN = SKILL_SCRIPTS / "login.py"
FETCH = SKILL_SCRIPTS / "fetch.py"
DOCS = SKILL_SCRIPTS / "docs_query.py"
SAMPLE_BUILD = "SAMPLE_BUILD_LOCAL"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    """provision --sample：部署初始化 + 合成工件/手册 + 实例审计密钥。"""
    target = tmp_path_factory.mktemp("ces_data")
    proc = subprocess.run(
        [PY, str(REPO_ROOT / "deploy" / "provision.py"),
         "--data", str(target), "--sample"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return target


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
    def __init__(self, base: str, tmp: Path):
        self.env = {
            **os.environ,
            "COMPILE_EXCEL_SERVER": base,
            "COMPILE_EXCEL_CONFIG_DIR": str(tmp / "config"),
            "COMPILE_EXCEL_CACHE_DIR": str(tmp / "cache"),
        }
        self.tmp = tmp

    def run(self, script: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [PY, str(script), *args],
            capture_output=True, text=True, env=self.env, timeout=120,
        )

    def login(self, server: Server, username: str = "tester") -> dict:
        proc = subprocess.Popen(
            [PY, str(LOGIN), "--no-browser"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.env,
        )
        user_code = None
        assert proc.stdout is not None
        for line in proc.stdout:
            match = re.search(r"DEVICE_FLOW user_code=(\S+)", line)
            if match:
                user_code = match.group(1)
                break
        assert user_code, "login.py 未输出设备码"
        status, _body = server.post_form(
            "/activate", {"user_code": user_code, "username": username})
        assert status == 200
        stdout, stderr = proc.communicate(timeout=60)
        assert proc.returncode == 0, stdout + stderr
        return json.loads(stdout.strip().splitlines()[-1])

    def token_path(self) -> Path:
        return Path(self.env["COMPILE_EXCEL_CONFIG_DIR"]) / "token"


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


def test_audit_log_hmac(data_dir, server, client_env):
    client_env.login(server)
    client_env.run(FETCH)
    client_env.run(DOCS, "--q", "manifest sha256")
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


# ── 分发闭环（客户端在 skill 仓）─────────────────────────────────────

def test_full_loop_login_fetch_docs(client_env, server):
    result = client_env.login(server, username="e2e-user")
    assert result["ok"] is True
    mode = stat.S_IMODE(os.stat(client_env.token_path()).st_mode)
    assert mode == 0o600

    fetched = client_env.run(FETCH)
    assert fetched.returncode == 0, fetched.stdout + fetched.stderr
    payload = json.loads(fetched.stdout)
    assert payload["source"] == "server"
    assert payload["device_build"] == SAMPLE_BUILD
    names = {a["name"] for a in payload["artifacts"]}
    assert names == {"sample_runtime_template.xlsx", "framework_tree.tar.gz",
                     "cmdtree_sample.xml"}
    cache = Path(client_env.env["COMPILE_EXCEL_CACHE_DIR"]) / SAMPLE_BUILD
    for entry in payload["artifacts"]:
        data = (cache / entry["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]

    docs = client_env.run(DOCS, "--q", "device_authorize user_code", "--limit", "2")
    assert docs.returncode == 0, docs.stdout
    assert json.loads(docs.stdout)["results"]


def test_wrong_token_rejected(client_env):
    config_dir = Path(client_env.env["COMPILE_EXCEL_CONFIG_DIR"])
    config_dir.mkdir(parents=True, exist_ok=True)
    token_path = config_dir / "token"
    token_path.write_text(json.dumps({
        "access_token": "bogus", "refresh_token": "bogus",
        "expires_at": 0, "server": client_env.env["COMPILE_EXCEL_SERVER"],
    }), encoding="utf-8")
    os.chmod(token_path, 0o600)
    assert client_env.run(FETCH).returncode != 0
    assert client_env.run(DOCS, "--q", "x").returncode != 0


def test_sha_mismatch_rejected(client_env, server, data_dir):
    client_env.login(server)
    first = client_env.run(FETCH)
    assert first.returncode == 0, first.stdout
    build = SAMPLE_BUILD
    cache = Path(client_env.env["COMPILE_EXCEL_CACHE_DIR"]) / build
    good = (cache / "framework_tree.tar.gz").read_bytes()

    artifact = data_dir / "artifacts" / "framework_tree.tar.gz"
    original = artifact.read_bytes()
    try:
        artifact.write_bytes(original + b"\x00tamper")
        second = client_env.run(FETCH)
        assert second.returncode != 0
        assert "SHA256" in second.stdout
        assert (cache / "framework_tree.tar.gz").read_bytes() == good
        assert not list(cache.glob("*.part"))
    finally:
        artifact.write_bytes(original)


def test_offline_fallback_explicit(client_env, server):
    client_env.login(server)
    assert client_env.run(FETCH).returncode == 0
    server.stop()
    second = client_env.run(FETCH)
    assert second.returncode == 0, second.stdout + second.stderr
    payload = json.loads(second.stdout)
    assert payload["source"] == "cache"
    assert "缓存" in payload["note"]
    assert client_env.run(DOCS, "--q", "x").returncode != 0


def test_token_expiry_auto_refresh(short_ttl_server, tmp_path):
    env = ClientEnv(short_ttl_server.base, tmp_path)
    env.login(short_ttl_server)
    old = json.loads(env.token_path().read_text(encoding="utf-8"))
    time.sleep(2.5)
    fetched = env.run(FETCH)
    assert fetched.returncode == 0, fetched.stdout + fetched.stderr
    new = json.loads(env.token_path().read_text(encoding="utf-8"))
    assert new["access_token"] != old["access_token"]
    assert env.run(DOCS, "--q", "token").returncode == 0


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
