"""出包前凭据扫描（tools/import_infotest.py 的 CredentialScanner，两个发布通道共用）与发布端的闸。

- 值的各种写法都算：原文、大小写不同、XML 转义、URL 编码、JSON 转义；层层解开 tar.gz、xlsx；
  xlsx 共享串按富文本分段存时拼起来也查到；
- 命令树默认值闭包按引擎规则：纯字母数字的值按词边界；
- 报告只有位置与次数，从不带值；
- Publisher 只上传扫描过且干净的解析结果；--promote 时缺 stable 下限的 kind 在上传前就拒绝；
- 服务端地址：https 放行，http 只放行回环地址或显式 --insecure-lan，地址里不许带凭据；
- 过渡通道：compile_ref 里的原始命令树不进包；解析完做同一个扫描，带凭据就拒绝并指向
  tools/publish_data_dir.py。
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import tarfile
import urllib.parse
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import import_infotest as imp  # noqa: E402

SECRET = "Examp1e&Pw<2>"  # 文档用的假口令，带 XML 特殊字符


def _scanner(rule=imp.SUBSTRING, value=SECRET):
    return imp.CredentialScanner({value: rule})


@pytest.mark.parametrize("text", [
    f"password={SECRET}",
    f"PASSWORD={SECRET.upper()}",
    '<arg default_value="Examp1e&amp;Pw&lt;2&gt;"/>',
    "ftp://u:" + urllib.parse.quote(SECRET, safe="") + "@192.0.2.1/x",
    json.dumps({"pw": SECRET}, ensure_ascii=True),
])
def test_every_written_form_of_a_value_is_found(text):
    assert _scanner().scan("entry.txt", text.encode()) == [("entry.txt", 1)]


def test_containers_are_opened_layer_by_layer():
    book = io.BytesIO()
    with zipfile.ZipFile(book, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/sharedStrings.xml",
                   '<sst><si><r><t>Examp1e&amp;</t></r><r><t>Pw&lt;2&gt;</t></r></si></sst>')
        z.writestr("xl/other.xml", "<x/>")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in (("smoke/a.xlsx", book.getvalue()), ("smoke/b.py", b"x = 1\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    blob = gzip.compress(raw.getvalue())
    assert _scanner().scan("framework/tree.tar.gz", blob) == [
        ("framework/tree.tar.gz!smoke/a.xlsx!xl/sharedStrings.xml", 1)], \
        "the value is split across two rich-text runs and still found"


def test_token_rule_uses_word_boundaries_like_the_engine():
    scanner = _scanner(imp.TOKEN, "Admin1")
    assert scanner.scan("a", b"user admin1 here") == [("a", 1)]
    assert scanner.scan("a", b"Admin12 xadmin1 admin1x") == []
    assert _scanner(imp.SUBSTRING, "Admin1").scan("a", b"xadmin12") == [("a", 1)]


def test_report_names_locations_and_counts_only():
    hits = _scanner().scan("spec/docs/a.md", f"{SECRET} and {SECRET}".encode())
    rows = imp.describe_credential_hits(hits, {"spec/docs/a.md": "fix upstream"})
    assert rows == ["spec/docs/a.md: 2 (fix upstream)"]
    assert "Examp1e" not in json.dumps(rows)


def test_redaction_replaces_every_form_in_place():
    scanner = _scanner()
    text, count = scanner.replace(f'a={SECRET} b="Examp1e&amp;Pw&lt;2&gt;"', "CEX-REDACTED")
    assert count == 2 and text == 'a=CEX-REDACTED b="CEX-REDACTED"'


def _resolution(scan: dict | None, kinds=imp.KINDS) -> imp.Resolution:
    entries = [imp.Entry(kind, f"{kind}/x.json", b"{}", "application/json") for kind in kinds]
    return imp.Resolution("B", entries, {} if scan is None else {"credential_scan": scan}, [])


def test_publisher_uploads_only_scanned_clean_resolutions():
    pub = imp.Publisher("https://ces.example", "publisher", "secret")
    for scan in (None, {"status": "dirty"}):
        with pytest.raises(imp.PublishError, match="凭据扫描"):
            pub.publish(_resolution(scan), promote=False)  # 在任何网络请求之前拒绝


def test_promote_without_the_stable_floor_is_refused_before_uploading(monkeypatch):
    pub = imp.Publisher("https://ces.example", "publisher", "secret")
    lacking = _resolution({"status": "clean"}, kinds=("cmdtree", "manual"))
    with pytest.raises(imp.PublishError, match="projections"):
        pub.publish(lacking, promote=True, required_kinds=("cmdtree",))
    monkeypatch.setenv(imp.STABLE_FLOOR_ENV, "cmdtree manual")
    imp.Publisher.preflight(lacking, promote=True, required_kinds=("cmdtree",))


@pytest.mark.parametrize("url,insecure,ok", [
    ("https://ces.example", False, True),
    ("http://127.0.0.1:8900", False, True),
    ("http://localhost:8900", False, True),
    ("http://[::1]:8900", False, True),
    ("http://192.0.2.5:8900", False, False),
    ("http://192.0.2.5:8900", True, True),
    ("https://user:pw@ces.example", False, False),
    ("ftp://ces.example", False, False),
])
def test_publisher_refuses_plain_http_off_loopback(url, insecure, ok):
    if ok:
        assert imp.Publisher(url, "publisher", "secret", insecure_lan=insecure).server
    else:
        with pytest.raises(imp.PublishError):
            imp.Publisher(url, "publisher", "secret", insecure_lan=insecure)


def test_legacy_importer_never_ships_the_raw_command_tree(tmp_path):
    ref = tmp_path / "compile_ref"
    for name in ("cmdtree_585.xml", "vendor_stdlib_10.5_585.json", "domain_grammar.json",
                 "source_reconciliation_585.json", "excel_contract.json"):
        (ref / name).parent.mkdir(parents=True, exist_ok=True)
        (ref / name).write_text("{}", encoding="utf-8")
    assert [rel for rel, _path in imp.compile_ref_files(ref)] == ["domain_grammar.json"]


def test_legacy_importer_refuses_credentials_and_points_to_publish_data_dir(tmp_path):
    resolver = imp.InfoTestResolver(tmp_path, "B")

    def step(entry=None):
        def run():
            if entry is not None:
                resolver.entries.append(entry)
        return run

    for name in ("_identity", "_spec_sync", "_preflight", "_template", "_cmdtree", "_manual",
                 "_projections", "_footprints"):
        setattr(resolver, name, step())
    resolver.execution_build = "B"
    resolver._spec = step(imp.Entry("spec", "spec/docs/a.md", f"pw {SECRET}".encode()))
    resolver._framework = step(imp.Entry("framework", "framework/sync_meta.json", b"{}"))
    resolver._credential_values = lambda: {SECRET: imp.SUBSTRING}
    with pytest.raises(imp.ImportRefused) as info:
        resolver.resolve()
    (failure,) = info.value.failures
    assert failure["key"] == "credential_scan"
    assert failure["locations"] == ["spec/docs/a.md: 1"]
    assert "publish_data_dir.py" in failure["repair"]
    assert "Examp1e" not in json.dumps(info.value.failures, ensure_ascii=False)

    resolver.failures.clear()
    resolver.checks.clear()
    resolver.entries.clear()
    resolver._spec = step(imp.Entry("spec", "spec/docs/a.md", b"clean"))
    resolution = resolver.resolve()
    assert resolution.source["credential_scan"]["status"] == "clean"
