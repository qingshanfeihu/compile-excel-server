"""管理面（ces 命令行 + 部署向导）。

覆盖：改动身份/配置/注册表的管理命令写进服务端审计链，且与服务进程交替写入后链照样完整；
`ces audit rotate [--new-key]` 封存旧段、换钥后 `ces audit verify` 仍通过，篡改旧段或删掉旧段密钥
能被发现；一次性凭据先落文件再改库（--out 写不了就不建账号、不覆盖已有文件）；client secret 轮换；
systemd unit 写 User= 且参数加引号；安装向导断点续填不丢 TLS 答案。
"""

from __future__ import annotations

import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

PY = sys.executable


@pytest.fixture()
def data(tmp_path, monkeypatch):
    target = tmp_path / "data"
    proc = subprocess.run([PY, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(target),
                           "--sample"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    monkeypatch.setenv("CES_DATA_DIR", str(target))
    return target


def ces(data: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([PY, str(REPO_ROOT / "ces_main.py"), *args, "--data", str(data)],
                          capture_output=True, text=True, timeout=60)


def _records(path: Path) -> list[dict]:
    return [json.loads(line.partition("\thmac=")[0])
            for line in path.read_text(encoding="utf-8").splitlines()]


def _server(data: Path):
    import server

    server._init_data(data)
    return server


def test_admin_mutations_share_the_server_audit_chain(data, tmp_path):
    server = _server(data)
    server._audit("probe_before")
    out = {name: tmp_path / name for name in ("code1", "code2", "gw1", "gw2")}
    steps = [
        ("users", "add", "alice", "--out", str(out["code1"])),
        ("users", "scopes", "alice", "docs:query config:read"),
        ("users", "disable", "alice"),
        ("users", "enable", "alice"),
        ("users", "reset-code", "alice", "--out", str(out["code2"])),
        ("clients", "add", "gw", "--scopes", "introspect", "--out", str(out["gw1"])),
        ("clients", "rotate-secret", "gw", "--out", str(out["gw2"])),
        ("clients", "remove", "gw"),
        ("tokens", "revoke", "--user", "alice"),
        ("tokens", "purge"),
        ("config", "set", "gateway.url", "https://gw.example.test/mcp"),
        ("config", "unset", "gateway.url"),
        ("registry", "gc"),
    ]
    for index, step in enumerate(steps):
        proc = ces(data, *step)
        assert proc.returncode == 0, (step, proc.stdout, proc.stderr)
        server._audit("probe_between", step=index)  # 服务进程与管理命令交替写同一条链
    events = [record["event"] for record in _records(data / "audit.log")]
    for event in ("admin_user_added", "admin_user_scopes_set", "admin_user_disabled",
                  "admin_user_enabled", "admin_user_code_reset", "admin_client_added",
                  "admin_client_secret_rotated", "admin_client_removed", "admin_tokens_revoked",
                  "admin_tokens_purged", "admin_config_set", "admin_config_unset",
                  "admin_registry_gc"):
        assert event in events, event
    assert events[0] == "probe_before" and events.count("probe_between") == len(steps)
    verified = ces(data, "audit", "verify")
    assert verified.returncode == 0 and json.loads(verified.stdout)["ok"], verified.stdout
    text = (data / "audit.log").read_text(encoding="utf-8")
    for path in out.values():
        assert path.read_text(encoding="utf-8").strip() not in text


def test_concurrent_writers_keep_one_valid_chain(data):
    script = (f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r})\n"
              "from pathlib import Path\nfrom deploy.audit_log import AuditLog\n"
              f"log = AuditLog(Path({str(data)!r}))\n"
              "for i in range(60):\n    log.append({'event': 'writer', 'n': i})\n")
    procs = [subprocess.Popen([PY, "-c", script]) for _ in range(4)]
    server = _server(data)
    for i in range(60):
        server._audit("server_writer", n=i)
    assert all(proc.wait(timeout=60) == 0 for proc in procs)
    result = json.loads(ces(data, "audit", "verify").stdout)
    assert result["ok"] and result["lines"] >= 300, result


def test_audit_rotation_with_a_new_key_keeps_verify_green(data):
    server = _server(data)
    server._audit("before_rotation")
    old_key = (data / "audit_hmac_key").read_text(encoding="utf-8")
    rotated = ces(data, "audit", "rotate", "--new-key")
    assert rotated.returncode == 0, rotated.stdout + rotated.stderr
    assert (data / "audit_hmac_key").read_text(encoding="utf-8") != old_key
    assert stat.S_IMODE(os.stat(data / "audit_hmac_key").st_mode) == 0o600
    server._audit("after_rotation")  # 运行中的服务接着写：新文件、新钥
    assert ces(data, "users", "add", "otto").returncode == 0
    assert ces(data, "audit", "rotate").returncode == 0  # 不换钥也能封段
    server._audit("third_segment")
    result = json.loads(ces(data, "audit", "verify").stdout)
    assert result["ok"] and [s["segment"] for s in result["segments"]] == [
        "audit-0001.log", "audit-0002.log", "audit.log"], result
    archive = data / "audit_archive"
    assert (archive / "audit-0001.key").read_text(encoding="utf-8") == old_key
    assert stat.S_IMODE(os.stat(archive / "audit-0001.key").st_mode) == 0o600

    segment = archive / "audit-0001.log"
    original = segment.read_text(encoding="utf-8")
    segment.write_text(original.replace("before_rotation", "before_rotatioN"), encoding="utf-8")
    broken = ces(data, "audit", "verify")
    assert broken.returncode == 1 and json.loads(broken.stdout)["segment"] == "audit-0001.log"
    segment.write_text(original, encoding="utf-8")
    key = (archive / "audit-0001.key").read_text(encoding="utf-8")
    (archive / "audit-0001.key").unlink()
    assert ces(data, "audit", "verify").returncode == 1
    (archive / "audit-0001.key").write_text(key, encoding="utf-8")
    segment.unlink()
    assert ces(data, "audit", "verify").returncode == 1


def test_secret_file_comes_first_and_is_never_clobbered(data, tmp_path):
    unwritable = tmp_path / "missing-dir" / "code"
    failed = ces(data, "users", "add", "mia", "--out", str(unwritable))
    assert failed.returncode == 1 and "Traceback" not in failed.stderr
    assert "mia" not in ces(data, "users", "list").stdout
    failed = ces(data, "clients", "add", "gw", "--scopes", "introspect", "--out", str(unwritable))
    assert failed.returncode == 1
    assert "gw" not in ces(data, "clients", "list").stdout

    existing = tmp_path / "gw.secret"
    assert ces(data, "clients", "add", "gw", "--scopes", "introspect",
               "--out", str(existing)).returncode == 0
    first = existing.read_text(encoding="utf-8")
    duplicate = ces(data, "clients", "add", "gw", "--scopes", "introspect", "--out", str(existing))
    assert duplicate.returncode == 1
    assert existing.read_text(encoding="utf-8") == first, "失败的 add 不能覆盖在用的 secret 文件"
    assert not list(tmp_path.glob(".gw.secret.*"))
    rotated = ces(data, "clients", "rotate-secret", "gw", "--out", str(existing))
    assert rotated.returncode == 0, rotated.stdout
    second = existing.read_text(encoding="utf-8")
    assert second != first and second.strip() not in rotated.stdout
    assert stat.S_IMODE(os.stat(existing).st_mode) == 0o600
    from auth_store import AuthStore

    store = AuthStore(data / "auth.db")
    assert store.verify_client("gw", first.strip()) is None
    assert store.verify_client("gw", second.strip()) is not None
    assert ces(data, "clients", "rotate-secret", "nope").returncode == 1


def test_systemd_unit_names_the_account_and_quotes_arguments(monkeypatch, tmp_path):
    import ces_main

    install = {"data": str(tmp_path / "data dir %h $HOME"), "port": 8900, "host": "127.0.0.1"}
    monkeypatch.setattr(sys, "platform", "linux")
    _, unit = ces_main._unit_content(install, "cesvc")
    assert "\nUser=cesvc\n" in unit
    exec_line = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert f'"{PY}"' in exec_line
    assert '"--data" "' + str(tmp_path / "data dir %%h $$HOME") + '"' in exec_line
    import getpass

    assert ces_main._service_account({"data": str(tmp_path)}) == getpass.getuser()
    assert ces_main._service_account({"data": str(tmp_path)}, "svc") == "svc"
    monkeypatch.setattr(sys, "platform", "darwin")
    _, plist = ces_main._unit_content({"data": str(tmp_path / "a&b<c>"), "port": 8900,
                                       "host": "127.0.0.1"})
    parsed = plistlib.loads(plist.encode("utf-8"))
    assert str(tmp_path / "a&b<c>") in parsed["ProgramArguments"]
    assert parsed["StandardOutPath"] == f"{tmp_path / 'a&b<c>'}/server.log"


@pytest.mark.parametrize("tls", [
    {"tls_cert": "/etc/ces/cert.pem", "tls_key": "/etc/ces/key.pem", "insecure_lan": ""},
    {"tls_cert": "", "tls_key": "", "insecure_lan": "y"},
])
def test_wizard_resume_keeps_tls_answers(tmp_path, monkeypatch, tls):
    from deploy import setup as setup_mod

    draft_path = tmp_path / "wizard.draft.json"
    monkeypatch.setattr(setup_mod, "CONFIG_ROOT", tmp_path)
    monkeypatch.setattr(setup_mod, "DRAFT_PATH", draft_path)
    draft_path.write_text(json.dumps({
        "progress": 7, "data": str(tmp_path / "d"), "device_build": "B", "kms": "",
        "port": "8900", "host": "0.0.0.0", **tls, "force": "n", "start": "n",
        "artifacts": [], "docs": []}), encoding="utf-8")
    answers = iter(["y", "y"])  # 从断点继续？确认部署？
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    state = setup_mod.wizard()
    for key, value in tls.items():
        assert state[key] == value, key
