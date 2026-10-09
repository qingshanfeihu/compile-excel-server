"""新手上手路径：配置向导、内置 CA 与连接串、授权页、管理菜单、手册与旧版工件命令。

覆盖：内置 CA 签发的服务器证书写进本机地址、地址已全时不重签；--tls-auto 装完即起 https，
/ca.pem 的指纹与连接串一致、拿它能校验服务器证书；不给工件也能装完（以前在生成工件清单时退出）；
向导只问两件事、断点续填不丢证书选择；网关证书与服务器证书出自同一个 CA；授权页设备码只显示一次、
权限用中文、授权后分开列出已获得与未获得的权限；菜单按编号建账号、调用与命令行同一套代码；
没有终端时不进菜单；回滚用的包列表；手册导入不加 --force 不覆盖；版本号一处定义。
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

pytest.importorskip("cryptography")

from deploy import certs  # noqa: E402

PY = sys.executable


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _provision(target: Path) -> Path:
    proc = subprocess.run([PY, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(target)],
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return target


def _ces(env: dict, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PY, str(REPO_ROOT / "ces_main.py"), *args], capture_output=True,
                          text=True, timeout=120, env=env, input=stdin, check=False)


@pytest.fixture()
def cfg_env(tmp_path):
    return {**os.environ, "CES_CONFIG_ROOT": str(tmp_path / "cfg")}


# ── 内置 CA ──────────────────────────────────────────────
def test_builtin_ca_signs_a_server_cert_for_the_given_names(tmp_path):
    data = _provision(tmp_path / "data")
    cert, key = certs.ensure_server_cert(data, ["127.0.0.1", "ces.lab.example", "10.1.2.3"])
    info = certs.cert_info(cert)
    assert {"127.0.0.1", "ces.lab.example", "10.1.2.3"} <= set(info["names"])
    assert info["days_left"] > 700
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert oct(certs.ca_paths(data)[1].stat().st_mode & 0o777) == "0o600"
    ca_subject = certs.cert_info(certs.ca_paths(data)[0])["issuer"]
    assert info["issuer"] == ca_subject
    before = cert.read_bytes()
    certs.ensure_server_cert(data, ["127.0.0.1"])
    assert cert.read_bytes() == before, "地址都在、离到期还早：不重签"
    certs.ensure_server_cert(data, ["127.0.0.1", "new.lab.example"])
    assert "new.lab.example" in certs.cert_info(cert)["names"]
    assert "ces.lab.example" in certs.cert_info(cert)["names"], "重签时保留原有地址"
    with pytest.raises(certs.CertError):
        certs.issue(data, ["bad name!"], tmp_path / "x.pem", tmp_path / "x.key")


def test_install_with_tls_auto_serves_https_and_the_link_pins_the_ca(tmp_path, cfg_env):
    pytest.importorskip("uvicorn")
    port = _free_port()
    data = tmp_path / "data"
    proc = subprocess.run([PY, str(REPO_ROOT / "deploy" / "setup.py"), "--data", str(data),
                           "--host", "127.0.0.1", "--port", str(port), "--tls-auto", "--start",
                           "--yes"], capture_output=True, text=True, timeout=180, env=cfg_env, check=False)
    try:
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "安装完成" in proc.stdout and "#ca=" in proc.stdout
        link = next(line for line in _ces(cfg_env, "link").stdout.splitlines() if "#ca=" in line)
        url, _, pin = link.strip().partition("#ca=")
        assert url == f"https://127.0.0.1:{port}"
        # 客户端的做法：先不校验证书取 /ca.pem，核对指纹，再拿它校验服务器证书
        loose = ssl.create_default_context()
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        pem = urllib.request.urlopen(url + "/ca.pem", context=loose, timeout=10).read().decode()
        import hashlib

        assert hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() == pin
        strict = ssl.create_default_context(cadata=pem)
        health = json.loads(urllib.request.urlopen(url + "/healthz", context=strict,
                                                   timeout=10).read())
        assert health == {"ok": True, "service": "compile-excel-server"}
        status = _ces(cfg_env, "status").stdout
        assert "运行中" in status and "内置 CA" in status
    finally:
        _ces(cfg_env, "stop")


def test_install_without_artifacts_completes(tmp_path, cfg_env):
    """以前不给工件时，生成工件清单那一步以返回码 66 退出，安装登记也没写。"""
    data = tmp_path / "data"
    proc = subprocess.run([PY, str(REPO_ROOT / "deploy" / "setup.py"), "--data", str(data),
                           "--yes"], capture_output=True, text=True, timeout=120, env=cfg_env, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    install = json.loads((tmp_path / "cfg" / "install.json").read_text(encoding="utf-8"))
    assert install["data"] == str(data.resolve()) and install["host"] == "127.0.0.1"
    assert "只监听本机" in proc.stdout


def test_ca_endpoint_is_404_without_builtin_ca(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    data = _provision(tmp_path / "data")
    monkeypatch.setenv("CES_DATA_DIR", str(data))
    import server

    server._init_data(data)
    client = TestClient(server.app)
    assert client.get("/ca.pem").status_code == 404
    certs.ensure_server_cert(data, ["127.0.0.1"])
    served = client.get("/ca.pem")
    assert served.status_code == 200
    assert served.text == certs.ca_paths(data)[0].read_text()


# ── 向导 ─────────────────────────────────────────────────
def _wizard(monkeypatch, tmp_path, answers):
    from deploy import setup as setup_mod

    monkeypatch.setattr(setup_mod, "CONFIG_ROOT", tmp_path)
    monkeypatch.setattr(setup_mod, "DRAFT_PATH", tmp_path / "wizard.draft.json")
    monkeypatch.setattr(setup_mod, "INSTALL_JSON", tmp_path / "install.json")
    feed = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(feed))
    return setup_mod


def test_wizard_asks_two_things_and_defaults_to_auto_tls_for_lan(tmp_path, monkeypatch):
    data = tmp_path / "d"
    # 数据目录、给谁用（2＝局域网）、证书（回车＝自动生成）、端口（回车）、确认
    setup_mod = _wizard(monkeypatch, tmp_path, [str(data), "2", "", "", "y"])
    state = setup_mod.wizard()
    options = setup_mod.wizard_options(state)
    assert options["host"] == "0.0.0.0" and options["tls_auto"] is True
    assert options["port"] == 8900 and options["start"] is True
    assert not options["insecure_lan"] and not options["tls_cert"]

    (tmp_path / "wizard.draft.json").unlink()  # main() 在确认安装后清草稿
    setup_mod = _wizard(monkeypatch, tmp_path, [str(data), "", "", "y"])
    local = setup_mod.wizard_options(setup_mod.wizard())
    assert local["host"] == "127.0.0.1" and local["tls_auto"] is False


@pytest.mark.parametrize("tls", ["auto", "plain"])
def test_wizard_resume_keeps_the_certificate_choice(tmp_path, monkeypatch, tls):
    setup_mod = _wizard(monkeypatch, tmp_path, ["y", "y"])  # 从断点继续？确认安装？
    (tmp_path / "wizard.draft.json").write_text(json.dumps({
        "progress": 2, "data": str(tmp_path / "d"), "scope": "lan", "tls": tls,
        "tls_cert": "", "tls_key": "", "port": "9443"}), encoding="utf-8")
    options = setup_mod.wizard_options(setup_mod.wizard())
    assert options["port"] == 9443 and options["host"] == "0.0.0.0"
    assert options["tls_auto"] is (tls == "auto")
    assert options["insecure_lan"] is (tls == "plain")


# ── 证书命令 ─────────────────────────────────────────────
def test_gateway_cert_comes_from_the_same_ca(tmp_path, cfg_env):
    data = _provision(tmp_path / "data")
    cert, key = certs.ensure_server_cert(data, ["127.0.0.1"])
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "install.json").write_text(json.dumps({
        "data": str(data), "port": 8900, "host": "0.0.0.0",
        "tls_cert": str(cert), "tls_key": str(key)}), encoding="utf-8")
    out = tmp_path / "gw"
    proc = _ces(cfg_env, "tls", "gateway", "10.0.0.5", "jump1", "--out", str(out))
    assert proc.returncode == 0, proc.stdout
    info = certs.cert_info(out / "gateway.pem")
    assert set(info["names"]) == {"10.0.0.5", "jump1"}
    assert info["issuer"] == certs.cert_info(certs.ca_paths(data)[0])["issuer"]
    assert (out / "ca.pem").read_bytes() == certs.ca_paths(data)[0].read_bytes()
    assert oct((out / "gateway.key").stat().st_mode & 0o777) == "0o600"
    events = [json.loads(line.partition("\thmac=")[0])["event"]
              for line in (data / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert "admin_tls_gateway_issued" in events

    shown = _ces(cfg_env, "tls", "show").stdout
    assert "内置 CA 签发" in shown and "CA 指纹" in shown


def test_gateway_trusts_the_server_ca_from_its_config(tmp_path):
    from gateway import introspect
    from gateway.config import ConfigError, load

    sample = (REPO_ROOT / "gateway" / "gateway.example.toml").read_text(encoding="utf-8")
    secret = tmp_path / "client.secret"
    secret.write_text("x\n", encoding="utf-8")
    text = (sample.replace("/home/test/.config/cexg/client.secret", str(secret))
            .replace('ca_file = ""', f'ca_file = "{tmp_path / "missing.pem"}"'))
    (tmp_path / "gw.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="ca_file"):
        load(tmp_path / "gw.toml")
    message = str(introspect._unreachable(ssl.SSLCertVerificationError("self-signed")))
    assert "ca_file" in message


# ── 授权页 ───────────────────────────────────────────────
def test_activate_page_shows_the_code_once_and_scopes_in_plain_words(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from auth_store import AuthStore, new_access_code

    data = _provision(tmp_path / "data")
    monkeypatch.setenv("CES_DATA_DIR", str(data))
    import server

    server._init_data(data)
    server._device_flows.clear()
    code = new_access_code()
    AuthStore(data / "auth.db").add_user("alice", None, code=code)
    client = TestClient(server.app)
    flow = client.post("/device_authorize", data={
        "client_id": "compile-excel-skill",
        "scope": "artifacts:read bundles:read jumphost:run jumphost:admin"}).json()
    page = client.get("/activate", params={"user_code": flow["user_code"]}).text
    assert page.count('class="code"') == 1 and 'type="hidden" name="user_code"' in page
    assert "下载编译数据" in page and "初始化设备" in page and "编译助手" in page
    assert "jumphost:admin" not in page and "artifacts:read" not in page
    assert "访问码由管理员建账号时发给你" in page

    blank = client.get("/activate").text
    assert 'id="user_code"' in blank and "请输入终端里显示的设备码" in blank
    expired = client.get("/activate", params={"user_code": "NOPE"}).text
    assert "无效或已过期" in expired

    wrong = client.post("/activate", data={"user_code": flow["user_code"], "username": "alice",
                                           "access_code": "wrong"})
    assert wrong.status_code == 403 and f"user_code={flow['user_code']}" in wrong.text
    done = client.post("/activate", data={"user_code": flow["user_code"], "username": "alice",
                                          "access_code": code})
    assert done.status_code == 200
    granted, _, missing = done.text.partition("没有获得的权限")
    assert "在跳板机上租床、跑用例" in granted and "初始化设备" in missing


# ── 菜单 ─────────────────────────────────────────────────
def test_menu_creates_an_account_through_the_same_command(tmp_path, monkeypatch, capsys):
    import ces_main
    import ces_menu

    data = _provision(tmp_path / "data")
    install = tmp_path / "install.json"
    install.write_text(json.dumps({"data": str(data), "port": _free_port(),
                                   "host": "127.0.0.1"}), encoding="utf-8")
    monkeypatch.setattr(ces_main, "INSTALL_JSON", install)
    # 首页 → 2 账号 → 2 新建 → 用户名 → 默认权限 → 不存文件 → 回车返回 → 0 首页 → 0 退出
    feed = iter(["2", "2", "bob", "", "", "", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(feed))
    assert ces_menu.main() == 0
    out = capsys.readouterr().out
    assert "未运行" in out and "对应命令：ces users add bob" in out
    assert "用户 bob 的访问码（只显示这一次）：" in out
    from auth_store import AuthStore

    assert [u["username"] for u in AuthStore(data / "auth.db").list_users()] == ["bob"]


def test_ces_without_a_terminal_prints_help_instead_of_the_menu(tmp_path, cfg_env):
    proc = _ces(cfg_env, stdin="")
    assert proc.returncode == 64 and "ces（不带参数）进入管理菜单" in proc.stdout


# ── 回滚列表、手册、旧版工件 ─────────────────────────────
def test_bundles_are_listed_newest_first_with_their_channels(tmp_path):
    from registry import Registry

    reg = Registry(tmp_path / "registry", stable_kinds=())
    ids = []
    for index in range(2):
        blob = reg.put_blob_file(_text(tmp_path / f"f{index}.json", f'{{"v": {index}}}'))
        result = reg.submit_bundle("B1", [{"kind": "projections", "path": "projections/a.json",
                                           "sha256": blob["sha256"],
                                           "media_type": "application/json", "meta": {}}],
                                   publisher="tester", source={}, required_kinds=[])
        ids.append(result["bundle_id"])
        time.sleep(0.01)
    reg.set_channel("B1", "stable", ids[0], "tester")
    listed = reg.list_bundles("B1")
    assert [b["bundle_id"] for b in listed] == [ids[1], ids[0]]
    assert listed[0]["channels"] == ["candidate"] and listed[1]["channels"] == ["stable"]
    assert all(b["checks_ok"] for b in listed)


def _text(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_docs_and_legacy_commands_write_the_data_dir(tmp_path, cfg_env):
    data = _provision(tmp_path / "data")
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "install.json").write_text(json.dumps({
        "data": str(data), "port": 8900, "host": "127.0.0.1"}), encoding="utf-8")
    src = tmp_path / "manuals"
    (src / "sub").mkdir(parents=True)
    _text(src / "a.md", "# A\n")
    _text(src / "sub" / "b.md", "# B\n")
    added = _ces(cfg_env, "docs", "add", str(src))
    assert added.returncode == 0 and "2 篇" in added.stdout and "ces restart" in added.stdout
    _text(src / "a.md", "# A changed\n")
    kept = _ces(cfg_env, "docs", "add", str(src))
    assert "没有覆盖" in kept.stdout and (data / "docs" / "a.md").read_text() == "# A\n"
    _ces(cfg_env, "docs", "add", str(src), "--force")
    assert (data / "docs" / "a.md").read_text() == "# A changed\n"

    assert _ces(cfg_env, "artifacts", "build", "BUILD_1").returncode == 0
    assert _ces(cfg_env, "artifacts", "kms", "10.0.0.90:8443").returncode == 0
    assert _ces(cfg_env, "artifacts", "kms", "bad").returncode == 64
    meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    assert meta["device_build"] == "BUILD_1" and meta["kms_addr"] == "10.0.0.90:8443"
    artifact = _text(tmp_path / "tree.xml", "<x/>")
    assert _ces(cfg_env, "artifacts", "add", f"{artifact}:1.0").returncode == 0
    meta = json.loads((data / "artifacts_meta.json").read_text(encoding="utf-8"))
    assert meta["artifacts"]["tree.xml"]["version"] == "1.0"
    listed = _ces(cfg_env, "artifacts", "list").stdout
    assert "BUILD_1" in listed and "tree.xml" in listed


def test_publisher_accepts_the_connection_string(tmp_path):
    pytest.importorskip("uvicorn")
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import import_infotest as imp

    data = tmp_path / "data"
    subprocess.run([PY, str(REPO_ROOT / "deploy" / "provision.py"), "--data", str(data),
                    "--sample"], capture_output=True, timeout=60, check=True)
    cert, key = certs.ensure_server_cert(data, ["127.0.0.1"])
    secret_file = tmp_path / "publisher.secret"
    subprocess.run([PY, str(REPO_ROOT / "ces_main.py"), "clients", "add", "publisher", "--scopes",
                    "bundles:publish bundles:read", "--out", str(secret_file), "--data", str(data)],
                   capture_output=True, timeout=60, check=True)
    port = _free_port()
    proc = subprocess.Popen([PY, str(REPO_ROOT / "ces_main.py"), "serve", "--data", str(data),
                             "--host", "127.0.0.1", "--port", str(port), "--tls-cert", str(cert),
                             "--tls-key", str(key)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        from deploy import tls_policy

        for _ in range(60):
            if tls_policy.healthz(port, tls_cert=str(cert), timeout=1):
                break
            time.sleep(0.25)
        pin = certs.fingerprint(certs.ca_paths(data)[0])
        link = f"https://127.0.0.1:{port}#ca={pin}"
        pub = imp.Publisher(link, "publisher", imp.read_secret_file(secret_file))
        assert pub.server == f"https://127.0.0.1:{port}"
        pub.login()
        with pytest.raises(imp.PublishError, match="指纹"):
            imp.Publisher(f"https://127.0.0.1:{port}#ca={'0' * 64}", "publisher", "x")
        with pytest.raises(imp.PublishError, match="#ca="):
            imp.Publisher(f"https://127.0.0.1:{port}#ca=abc", "publisher", "x")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_version_is_defined_once():
    from ces_version import __version__
    from gateway.service import SERVER_INFO

    assert SERVER_INFO["version"] == __version__


# ── 审查发现的问题（回归） ───────────────────────────────
def _tls_server(cert: Path, key: Path, routes: dict[str, bytes]):
    """最小的 https 服务：按路径回固定内容（冒充服务端用）。"""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = routes.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write(body or b"")

        do_POST = do_GET  # noqa: N815

        def log_message(self, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_publisher_rejects_a_concatenated_ca_that_smuggles_in_another_ca(tmp_path):
    """冒充者在 /ca.pem 回“真 CA + 自己的 CA”：宽松解码会算出真 CA 的指纹，必须拒绝。"""
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    import import_infotest as imp

    real, fake = tmp_path / "real", tmp_path / "fake"
    real_ca = certs.ensure_ca(real).read_text()
    cert, key = certs.ensure_server_cert(fake, ["127.0.0.1"])
    fake_ca = certs.ca_paths(fake)[0].read_text()
    httpd = _tls_server(cert, key, {"/ca.pem": (real_ca + fake_ca).encode()})
    try:
        pin = certs.fingerprint(certs.ca_paths(real)[0])
        url = f"https://127.0.0.1:{httpd.server_address[1]}"
        with pytest.raises(imp.PublishError):
            imp.pinned_ca(url, pin)
        with pytest.raises(ValueError):
            imp.single_cert_der(real_ca + fake_ca)
        assert imp.single_cert_der(real_ca) == ssl.PEM_cert_to_DER_cert(real_ca)
    finally:
        httpd.shutdown()


def test_renew_keeps_added_names_and_can_remove_them(tmp_path):
    data = _provision(tmp_path / "data")
    cert, _ = certs.ensure_server_cert(data, ["127.0.0.1"])
    certs.ensure_server_cert(data, ["127.0.0.1", "ces.lab.example"], force=True)
    certs.ensure_server_cert(data, ["127.0.0.1"], force=True)  # 以后再续签，不带 --name
    assert "ces.lab.example" in certs.cert_info(cert)["names"]
    certs.ensure_server_cert(data, ["127.0.0.1"], force=True, remove=["ces.lab.example"])
    assert "ces.lab.example" not in certs.cert_info(cert)["names"]


def test_gateway_output_dir_keeps_its_permissions(tmp_path):
    data = _provision(tmp_path / "data")
    out = tmp_path / "shared"
    out.mkdir(mode=0o755)
    os.chmod(out, 0o755)
    certs.issue(data, ["10.0.0.5"], out / "gateway.pem", out / "gateway.key")
    assert oct(out.stat().st_mode & 0o777) == "0o755"
    assert oct((out / "gateway.key").stat().st_mode & 0o777) == "0o600"


def test_half_missing_ca_is_an_error_not_a_silent_new_ca(tmp_path):
    data = _provision(tmp_path / "data")
    certs.ensure_server_cert(data, ["127.0.0.1"])
    certs.ca_paths(data)[1].unlink()
    with pytest.raises(certs.CertError, match="不完整"):
        certs.ensure_server_cert(data, ["127.0.0.1", "new.example"])
    with pytest.raises(certs.CertError):
        certs._split_names(["服务器.example"])


def test_new_accounts_never_overwrite_an_existing_secret_file(tmp_path, cfg_env):
    data = _provision(tmp_path / "data")
    taken = _text(tmp_path / "someone.secret", "keep me\n")
    proc = _ces(cfg_env, "users", "add", "zoe", "--out", str(taken), "--data", str(data))
    assert proc.returncode == 1 and "已存在" in proc.stdout
    assert taken.read_text() == "keep me\n"
    assert "zoe" not in _ces(cfg_env, "users", "list", "--data", str(data)).stdout


def test_menu_survives_a_failing_command(monkeypatch, capsys):
    import ces_main
    import ces_menu

    def boom(argv):
        raise PermissionError("no write")

    monkeypatch.setattr(ces_main, "dispatch", boom)
    assert ces_menu.run("service", "remove") == 1
    assert "出错了" in capsys.readouterr().out
    assert not ces_menu.is_number("²") and ces_menu.is_number("12")


def test_import_then_publish_uses_the_imported_bundle(tmp_path, monkeypatch):
    import ces_main

    data = _provision(tmp_path / "data")
    install = tmp_path / "install.json"
    install.write_text(json.dumps({"data": str(data), "port": 8900, "host": "127.0.0.1"}),
                       encoding="utf-8")
    monkeypatch.setattr(ces_main, "INSTALL_JSON", install)
    first, second = tmp_path / "one", tmp_path / "two"
    for folder, value in ((first, "1"), (second, "2")):
        folder.mkdir()
        _text(folder / "a.json", value)
    assert ces_main.dispatch(["registry", "import-dir", "B1", "projections", str(first)]) == 0
    one = ces_main.LAST_IMPORT["bundle_id"]
    assert ces_main.dispatch(["registry", "import-dir", "B1", "projections", str(second)]) == 0
    # 再导一次第一份：内容相同不新建包、candidate 不动，但这次导入的就是第一份
    assert ces_main.dispatch(["registry", "import-dir", "B1", "projections", str(first)]) == 0
    assert ces_main.LAST_IMPORT["bundle_id"] == one and ces_main.LAST_IMPORT["build"] == "B1"


def test_old_wizard_drafts_only_keep_the_data_dir(tmp_path, monkeypatch):
    # 旧版草稿：progress 7、host=0.0.0.0、有证书，但没有 scope
    setup_mod = _wizard(monkeypatch, tmp_path, ["y", "2", "", "", "y"])
    (tmp_path / "wizard.draft.json").write_text(json.dumps({
        "progress": 7, "data": str(tmp_path / "d"), "host": "0.0.0.0",
        "tls_cert": "/etc/c.pem", "tls_key": "/etc/k.pem", "port": "8900"}), encoding="utf-8")
    options = setup_mod.wizard_options(setup_mod.wizard())
    assert options["data"] == str(tmp_path / "d") and options["host"] == "0.0.0.0"


def test_reconfigure_defaults_to_the_previous_certificate_choice(tmp_path):
    from deploy import setup as setup_mod

    data = _provision(tmp_path / "data")
    cert, _ = certs.ensure_server_cert(data, ["127.0.0.1"])
    assert setup_mod.previous_tls_choice({"data": str(data), "tls_cert": str(cert)}) == 1
    assert setup_mod.previous_tls_choice({"data": str(data), "tls_cert": "/etc/x.pem"}) == 2
    assert setup_mod.previous_tls_choice({"data": str(data), "host": "0.0.0.0",
                                          "insecure_lan": True}) == 3
    assert setup_mod.previous_tls_choice({}) == 1


def test_reconfiguring_to_another_data_dir_stops_the_old_instance(tmp_path, cfg_env):
    pytest.importorskip("uvicorn")
    port = _free_port()
    base = [PY, str(REPO_ROOT / "deploy" / "setup.py"), "--port", str(port), "--start", "--yes"]
    first = subprocess.run([*base, "--data", str(tmp_path / "one")], capture_output=True,
                           text=True, timeout=180, env=cfg_env, check=False)
    assert first.returncode == 0, first.stdout + first.stderr
    old_pid = int((tmp_path / "one" / "server.pid").read_text())
    try:
        second = subprocess.run([*base, "--data", str(tmp_path / "two")], capture_output=True,
                                text=True, timeout=180, env=cfg_env, check=False)
        assert second.returncode == 0, second.stdout + second.stderr
        assert "停掉旧数据目录" in second.stdout
        with pytest.raises(OSError):
            os.kill(old_pid, 0)
        assert "two" in _ces(cfg_env, "status").stdout
    finally:
        _ces(cfg_env, "stop")
        try:
            os.kill(old_pid, 9)
        except OSError:
            pass


def test_link_host_sets_the_address_and_adds_it_to_the_certificate(tmp_path, cfg_env):
    data = _provision(tmp_path / "data")
    cert, key = certs.ensure_server_cert(data, ["127.0.0.1"])
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "install.json").write_text(json.dumps({
        "data": str(data), "port": 8900, "host": "0.0.0.0",
        "tls_cert": str(cert), "tls_key": str(key)}), encoding="utf-8")
    proc = _ces(cfg_env, "link", "--host", "10.20.30.40")
    assert proc.returncode == 0, proc.stdout
    assert "https://10.20.30.40:8900#ca=" in proc.stdout and "已重新签发" in proc.stdout
    assert "10.20.30.40" in certs.cert_info(cert)["names"]
    assert "advertise_host" in (tmp_path / "cfg" / "install.json").read_text()
    back = _ces(cfg_env, "link", "--host", "auto")
    assert "改回自动选择" in back.stdout and "10.20.30.40:8900" not in back.stdout.split("连接串")[-1]
    assert _ces(cfg_env, "link", "--host", "bad host!").returncode == 64


def test_gateway_url_must_not_carry_the_connection_string(tmp_path):
    from gateway.config import ConfigError, load

    sample = (REPO_ROOT / "gateway" / "gateway.example.toml").read_text(encoding="utf-8")
    secret = _text(tmp_path / "client.secret", "x\n")
    text = (sample.replace("/home/test/.config/cexg/client.secret", str(secret))
            .replace('url = "https://ces.example.test:8900"',
                     f'url = "https://ces.example.test:8900#ca={"a" * 64}"'))
    (tmp_path / "gw.toml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="ca_file"):
        load(tmp_path / "gw.toml")


def test_systemd_unit_logs_to_the_data_dir(monkeypatch, tmp_path):
    import ces_main

    monkeypatch.setattr(sys, "platform", "linux")
    _, unit = ces_main._unit_content({"data": str(tmp_path / "data"), "port": 8900,
                                      "host": "127.0.0.1"}, "svc")
    assert f"StandardOutput=append:{tmp_path / 'data'}/server.log" in unit
    _, spaced = ces_main._unit_content({"data": str(tmp_path / "a b"), "port": 8900,
                                        "host": "127.0.0.1"}, "svc")
    assert "StandardOutput" not in spaced


def test_config_root_follows_the_sudo_user(monkeypatch):
    import getpass
    import pwd

    from deploy import paths

    monkeypatch.delenv("CES_CONFIG_ROOT", raising=False)
    monkeypatch.setenv("SUDO_USER", getpass.getuser())
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/var/root")))
    expected = Path(pwd.getpwnam(getpass.getuser()).pw_dir) / ".config" / "compile-excel-server"
    assert paths.config_root() == expected


def test_a_long_hostname_still_gets_a_ca(tmp_path, monkeypatch):
    """证书名称上限 64 个字符：主机名很长的机器（例如 CI 的 macOS 机器）以前生成 CA 直接失败。"""
    import socket as socket_mod

    long_name = "runner-very-long-hostname-" + "x" * 50 + ".local"
    monkeypatch.setattr(socket_mod, "gethostname", lambda: long_name)
    data = _provision(tmp_path / "data")
    cert, _ = certs.ensure_server_cert(data, ["127.0.0.1"])
    assert "127.0.0.1" in certs.cert_info(cert)["names"]
    assert certs.cert_info(certs.ca_paths(data)[0])["issuer"].startswith("CN=compile-excel-server CA")
