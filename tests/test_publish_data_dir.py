"""tools/publish_data_dir.py 与 tools/cmdtree_rederive.py 的测试（合成数据目录，不碰 InfoTest）。

- 重推导产物与原件比较时只放过身份字段，别处一点不同就拒绝（脱敏本身见 test_sanitize_cmdtree.py）；
- 解析器：命令树条目取重推导结果（代际清单、脱敏 XML、投影、带脱敏收据的 source.json），
  投影里拆卸图谱与领域文法换成重推导的那份，SSL 生命周期证据的图谱身份改绑，判据台账随包发；
  本地目录输出与客户端同步下来的包同形；
- 数据包不带凭据：框架树成员（.py、xlsx 里的 XML）与规格书里的凭据值、带口令的 URL userinfo
  换成占位，.sync_meta 的 by_path、规格书代际清单与索引随之改绑，代际号换成派生的；Excel 契约
  钉住的框架文件与手册不改写，里面带凭据就由出包前扫描点名拒绝（报位置与次数，不带值）；
- 手册 catalog 状态、足迹回填收据与客户端/InfoTest 同一组条件，不过就拒绝。
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import cmdtree_rederive as rd  # noqa: E402
import publish_data_dir as pdd  # noqa: E402

RAW_BUILD = "Example Beta.APV-X.10.5.0.585"
SECRET = "Examp1e-Pw"            # 文档用的假口令（框架闭包）
TREE_SECRET = "ex&mple-c0mm"      # 文档用的假 community（命令树默认值闭包，带 &）
SPEC_GID = "01787581400724023000-0123456789abcdef"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_rederived_artifacts_may_differ_only_in_identity():
    original = {"source": {"sha256": "a" * 64, "filename": "x.xml"},
                "stats": {"default_values_omitted": 3, "credential_fields_redacted": 2,
                          "value_domain": {"footprint_nodes_read": 1}},
                "headers": {"h": {"args": []}}}
    derived = json.loads(json.dumps(original))
    derived["source"]["sha256"] = "b" * 64
    derived["stats"]["default_values_omitted"] = 2
    derived["stats"]["credential_fields_redacted"] = 1
    derived["stats"]["value_domain"]["footprint_nodes_read"] = 5
    assert rd.same_but_identity(original, derived, rd._PROJECTION_IDENTITY)
    derived["headers"]["h"]["args"] = [{"position": 1}]
    assert not rd.same_but_identity(original, derived, rd._PROJECTION_IDENTITY)
    derived = json.loads(json.dumps(original))
    derived["source"]["filename"] = "y.xml"
    assert not rd.same_but_identity(original, derived, rd._PROJECTION_IDENTITY)


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def _xlsx(shared: str) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("xl/sharedStrings.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><sst count="2" uniqueCount="2">'
                   f"{shared}</sst>")
        z.writestr("xl/worksheets/sheet1.xml", '<?xml version="1.0"?><worksheet/>')
    return out.getvalue()


class FakeEngine:
    """引擎替身：闭包给定；规格书索引、手册 catalog 状态按引擎规则的简化版。"""

    def __init__(self, framework=(SECRET,), tree=(TREE_SECRET,)):
        self.framework = frozenset(framework)
        self.tree = frozenset(tree)
        self.parsed: list[int] = []

    def mirror_literals(self, root):
        return self.framework

    def xml_literals(self, raw):
        return self.tree

    def parse_literals(self, entries):
        for _rel, raw in entries:
            ast.parse(raw.decode("utf-8"))
        self.parsed.append(len(entries))
        return frozenset()

    @staticmethod
    def build_spec_index(spec_dir, state_path=None):
        entries = {}
        for path in sorted(Path(spec_dir).glob("*.md")):
            raw = path.read_bytes()
            body = raw.decode("utf-8", "replace")
            entries[path.name] = {"title": body.splitlines()[0] if body else "",
                                  "bug_numbers_body": sorted(set(re.findall(
                                      r"(?<!\d)(\d{5,6})(?!\d)", body))),
                                  "sha256": sha(raw), "size": len(raw), "lastmod_ms": 7}
        return {"schema": "ist.spec_index.v1", "generated_from": str(spec_dir),
                "coverage": {"total_files": len(entries),
                             "with_any_bug_number": sum(bool(e["bug_numbers_body"])
                                                        for e in entries.values())},
                "entries": entries}

    @staticmethod
    def catalog_status(version, family, root):
        md = Path(root) / version / f"{family}_cn.md"
        catalog = Path(root) / version / f"{family}_cn.catalog.json"
        if not md.is_file():
            return {"status": "md_missing"}
        if not catalog.is_file():
            return {"status": "catalog_missing", "catalog_sha256": ""}
        raw = catalog.read_bytes()
        if json.loads(raw).get("identity", {}).get("md_sha256") != sha(md.read_bytes()):
            return {"status": "identity_uncoupled", "catalog_sha256": sha(raw)}
        return {"status": "ok", "catalog_sha256": sha(raw)}


def make_root(tmp_path: Path, *, pinned_secret: bool = False, manual_secret: bool = False,
              receipt: dict | None = None, nodes: bool = True, xlsx_shared: str | None = None
              ) -> tuple[Path, tuple[str, str]]:
    root = tmp_path / "data"
    ref = root / "knowledge/data/compile_ref"
    mirror = root / "knowledge/framework/mirror"
    clear = _write(mirror / "lib/apv/clear.py", "rules = []\n")
    env = _write(mirror / "lib/env.py", "class Env:\n    pass\n"
                 + (f'\nSSH_PASSWORD = "{SECRET}"\n' if pinned_secret else ""))
    _write(mirror / "smoke_test/sdns/case_1.py",
           f'password = "{SECRET}"\n'
           f'url = "ftp://tester:{SECRET}@192.0.2.10/pub/a.txt"\n'
           'other = "ftp://svc:Other-pw9@192.0.2.11/b.txt"\n'
           'template = "ftp://%s:%s@%s/c.txt" % ("u", "p", "h")\n')
    _write(mirror / "smoke_test/sdns/case_1.xlsx", _xlsx(
        xlsx_shared if xlsx_shared is not None
        else f"<si><t>login</t></si><si><t>{SECRET}</t></si>"))
    _write(mirror / "lists/plain_err", "no credentials here\n")
    by_path = {p.relative_to(mirror).as_posix(): sha(p.read_bytes())
               for p in sorted(mirror.rglob("*")) if p.is_file()}
    _write(mirror / ".sync_meta.json", json.dumps({"version": 1, "by_path": by_path,
                                                   "synced_at": "2026-01-01T00:00:00Z",
                                                   "source": "example"}, indent=2))
    _write(ref / "mirror_manifest.json", json.dumps({"files": {"lib/env.py": sha(env.read_bytes())}},
                                                    indent=2))
    template = _write(ref / "excel_runtime_template.xlsx", b"template-bytes")
    contract_pin = "c" * 64
    _write(ref / "excel_contract.json", json.dumps({
        "contract_sha256": contract_pin, "source_hashes": {"lib/env.py": sha(env.read_bytes())}}))
    _write(ref / "excel_workbook_manifest.json", "{}")
    _write(ref / "command_teardown_atlas.json", json.dumps({"identity": {"sha256": "1" * 64}}))
    _write(ref / "domain_grammar.json", json.dumps({"x": 1}))
    _write(ref / "criterion_rules.json", "{}")
    _write(ref / "vendor_stdlib_10.5_585.json", "{}")  # 不进 projections（命令树类发重推导的那份）
    _write(ref / "cmdtree_585.xml", "<commands/>")      # 原始命令树也不进 projections
    manual = root / "knowledge/data/manual"
    pins_md, pins_catalog = {}, {}
    for fam, text in (("cli", "# cli\n"), ("app", "# app\n" + (
            f'Demo(config)#system plugin scp "192.0.2.20" "root" "/home/x.tgz" "{SECRET}"\n'
            if manual_secret else ""))):
        md = _write(manual / "10.5.0" / f"{fam}_cn.md", text)
        catalog = _write(manual / "10.5.0" / f"{fam}_cn.catalog.json", json.dumps({
            "schema": "ist.manual-command-catalog",
            "identity": {"adoc_sha256": {"Chapter1.adoc": "d" * 64}, "md_sha256": sha(md.read_bytes())},
            "signatures": [], "value_domains": [], "worked_examples": []}))
        pins_md[md.name] = sha(md.read_bytes())
        pins_catalog[catalog.name] = sha(catalog.read_bytes())
    _write(manual / ".sync_state.json", json.dumps({"cli:10.5.0": {"ok": 1}, "cli:10.4.6": {"ok": 1}}))
    gen = root / "knowledge/data/spec/generations" / SPEC_GID
    docs = {"a.md": ("# FTP import\n"
                     f"Use ftp://tester:{SECRET}@192.0.2.10/dir/file and the password is {SECRET}.\n"
                     "SFTP: sftp://ops:123456@192.0.2.12/backup (bug 23456)\n"),
            "b.md": "# Plain spec\nbug 34567\n"}
    for name, text in docs.items():
        _write(gen / "docs" / name, text)
    _write(gen / "state.tsv", "#savedAt=x\na.md\t1\nb.md\t2\n")
    index = (json.dumps(FakeEngine.build_spec_index(gen / "docs"), ensure_ascii=False, indent=2)
             + "\n").encode()
    _write(gen / "index.json", index)
    spec_manifest = (json.dumps({
        "schema": "ist.spec.generation", "generation_id": SPEC_GID, "created_at": "2026-01-01",
        "artifacts": {name: {"size": len((gen / name).read_bytes()),
                             "sha256": sha((gen / name).read_bytes())}
                      for name in ("state.tsv", "index.json")},
        "documents": {name: {"size": len(text.encode()), "sha256": sha(text.encode())}
                      for name, text in docs.items()}},
        sort_keys=True, separators=(",", ":")) + "\n").encode()
    _write(gen / "manifest.json", spec_manifest)
    _write(root / "knowledge/data/spec/active.json", json.dumps({
        "schema": "ist.spec.active", "generation_id": SPEC_GID, "manifest_sha256": sha(spec_manifest)}))
    footprints = root / "knowledge/footprints"
    if nodes:
        _write(footprints / "nodes_10.5.0/snmp.json", "{}")
    _write(footprints / ".receipt_nodes_10.5.0.json", json.dumps(receipt if receipt is not None else {
        "schema": "ist.footprint-backfill-receipt", "algo": "catalog-anchored-slice-per-family",
        "version": "10.5.0", "manual_sha256": pins_md, "catalog_sha256": pins_catalog,
        "batch_digests": 1, "complete": True}))
    _write(root / "runtime/excel_release/promotion_receipt.json", json.dumps({
        "status": "promoted", "device_build": pdd.execution_build(RAW_BUILD),
        "final_contract_sha256": contract_pin, "environment": "lab"}))
    _write(root / pdd.CRITERION_LEDGER, '{"rule_sha256": "r1"}\n{"rule_sha256": "r2"}\n')
    _write(root / pdd.SSL_LIFECYCLE_ASSET, json.dumps({"schema": "s", "contracts": [{
        "reference_evidence": {
            "clear_source": "knowledge/framework/mirror/lib/apv/clear.py",
            "clear_source_sha256": sha(clear.read_bytes()),
            "start_manual_source": "knowledge/data/manual/10.5.0/cli_cn.md",
            "start_manual_source_sha256": pins_md["cli_cn.md"],
            "teardown_atlas_identity_sha256": "1" * 64}}]}))
    _write(root / "runtime/command_tree/products/APV/platforms/X/builds/10.5_585/generations/g-old/"
                  "cmdtree_585.xml",
           '<commands><arg name="community" default_value="ex&amp;mple-c0mm"/></commands>')
    return root, (sha(template.read_bytes()), contract_pin)


@pytest.fixture
def data_root(tmp_path):
    return make_root(tmp_path)


def _fake_rederive(tmp_path: Path):
    out = tmp_path / "rederived"
    files = {
        "generation_manifest.json": _write(out / "manifest.json", '{"generation_id": "g-new"}'),
        "cmdtree_585.xml": _write(out / "cmdtree_585.xml", b"<commands/>"),
        "vendor_stdlib_10.5_585.json": _write(out / "vendor_stdlib_10.5_585.json", '{"p": 1}'),
        "command_teardown_atlas.json": _write(out / "atlas.json",
                                              json.dumps({"identity": {"sha256": "2" * 64}})),
        "domain_grammar.json": _write(out / "grammar.json", json.dumps({"x": 1, "rebound": True})),
    }
    calls = []

    def rederive(root, raw, manual, work):
        calls.append((raw, manual))
        original = next((root / "runtime/command_tree").rglob("cmdtree_585.xml"))
        return {"ok": True, "checks": {"projection": True},
                "sanitization": {"blanked_default_values": 3,
                                 "original_xml_sha256": sha(original.read_bytes())},
                "original_xml": {"path": str(original), "sha256": sha(original.read_bytes())},
                "generation": {"generation_id": "g-new", "manifest_sha256": "m" * 64,
                               "projection_sha256": "p" * 64, "source_sha256": "s" * 64,
                               "source_url": "local://x", "product": "APV", "platform": "X",
                               "version": "10.5", "device_build": "585", "full_version": raw,
                               "item_count": 1, "results_total": 1, "results_nonempty": 0},
                "files": {name: str(path) for name, path in files.items()}}
    return rederive, calls


def _resolver(root, pins, tmp_path, **kwargs):
    rederive, calls = _fake_rederive(tmp_path)
    kwargs.setdefault("engine", FakeEngine())
    return pdd.DataDirResolver(root, RAW_BUILD, "10.5.0", rederive=rederive, pins=pins,
                               work=tmp_path / "work", **kwargs), calls


def _members(tar: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(tar), mode="r:gz") as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def _refused(resolver) -> list[dict]:
    with pytest.raises(pdd.Refused) as info:
        resolver.resolve()
    assert SECRET not in str(info.value) and "mple-c0mm" not in str(info.value)
    return json.loads(str(info.value))


def test_resolver_ships_the_rederived_command_tree_and_rebinds_evidence(data_root, tmp_path):
    root, pins = data_root
    resolver, calls = _resolver(root, pins, tmp_path)
    res = resolver.resolve()
    paths = {entry.path: entry for entry in res.entries}
    assert calls == [(RAW_BUILD, "10.5.0")]
    assert {"cmdtree/generation_manifest.json", "cmdtree/cmdtree_585.xml",
            "cmdtree/vendor_stdlib_10.5_585.json", "cmdtree/source.json"} <= set(paths)
    source = json.loads(paths["cmdtree/source.json"].data)
    assert source["raw_xml_shipped"] == "sanitized" and source["generation_id"] == "g-new"
    assert source["sanitization"]["blanked_default_values"] == 3
    assert json.loads(paths["projections/command_teardown_atlas.json"].data)["identity"]["sha256"] == "2" * 64
    assert json.loads(paths["projections/domain_grammar.json"].data)["rebound"] is True
    assert "projections/vendor_stdlib_10.5_585.json" not in paths
    assert "projections/cmdtree_585.xml" not in paths, "the raw command tree never ships"
    ssl = json.loads(paths["projections/ssl_lifecycle_contract.json"].data)
    assert ssl["contracts"][0]["reference_evidence"]["teardown_atlas_identity_sha256"] == "2" * 64
    assert paths["projections/criterion_author_rules.jsonl"].data.count(b"\n") == 2
    assert json.loads(paths["manual/10.5.0/sync_state.json"].data) == {"cli:10.5.0": {"ok": 1}}
    assert res.source["credential_scan"]["status"] == "clean"
    for entry in res.entries:
        assert SECRET.encode() not in entry.data
    out = pdd.write_out_dir(res, tmp_path / "bundle")
    manifest = json.loads((tmp_path / "bundle/manifest.json").read_text())
    assert out["entries"] == len(manifest["entries"]) == len(res.entries)
    for row in manifest["entries"]:
        assert sha((tmp_path / "bundle" / row["path"]).read_bytes()) == row["sha256"]


def test_framework_members_are_redacted_and_the_sync_receipt_rebound(data_root, tmp_path):
    root, pins = data_root
    resolver, _calls = _resolver(root, pins, tmp_path)
    res = resolver.resolve()
    paths = {entry.path: entry for entry in res.entries}
    members = _members(paths["framework/framework_tree.tar.gz"].data)
    meta = json.loads(paths["framework/sync_meta.json"].data)
    original = json.loads((root / "knowledge/framework/mirror/.sync_meta.json").read_text())
    assert set(members) == set(meta["by_path"]) == set(original["by_path"])
    for rel, data in members.items():
        assert sha(data) == meta["by_path"][rel], f"{rel}: the shipped receipt describes the member"
    case = members["smoke_test/sdns/case_1.py"].decode()
    assert SECRET not in case
    assert 'password = "CEX-REDACTED"' in case
    assert '"ftp://CEX-REDACTED@192.0.2.10/pub/a.txt"' in case
    assert '"ftp://CEX-REDACTED@192.0.2.11/b.txt"' in case, "a URL password outside the closure too"
    assert '"ftp://%s:%s@%s/c.txt"' in case, "templates are not credentials"
    ast.parse(case)
    with zipfile.ZipFile(io.BytesIO(members["smoke_test/sdns/case_1.xlsx"])) as book:
        shared = book.read("xl/sharedStrings.xml").decode()
        assert "<t>CEX-REDACTED</t>" in shared and SECRET not in shared
        assert book.namelist() == ["[Content_Types].xml", "xl/sharedStrings.xml",
                                   "xl/worksheets/sheet1.xml"]
    for rel in ("lib/env.py", "lib/apv/clear.py", "lists/plain_err"):
        assert meta["by_path"][rel] == original["by_path"][rel], "untouched files keep their hash"
    assert meta["synced_at"] == original["synced_at"] and meta["version"] == 1
    tar_meta = paths["framework/framework_tree.tar.gz"].meta
    assert tar_meta["redacted_files"] == 2
    assert tar_meta["sync_receipt_sha256"] == sha(paths["framework/sync_meta.json"].data)
    assert res.source["framework_redaction"]["files"] == 2
    assert resolver.engine().parsed, "every .py is re-parsed after redaction (the client's closure)"
    again, _ = _resolver(root, pins, tmp_path / "again")
    rerun = {entry.path: entry.sha256 for entry in again.resolve().entries}
    assert rerun["framework/framework_tree.tar.gz"] == paths["framework/framework_tree.tar.gz"].sha256
    assert rerun["spec/manifest.json"] == paths["spec/manifest.json"].sha256, "deterministic bytes"


def test_spec_generation_is_redacted_and_its_identities_rebound(data_root, tmp_path):
    root, pins = data_root
    resolver, _calls = _resolver(root, pins, tmp_path)
    res = resolver.resolve()
    paths = {entry.path: entry for entry in res.entries}
    manifest_bytes = paths["spec/manifest.json"].data
    manifest = json.loads(manifest_bytes)
    assert manifest["generation_id"] != SPEC_GID
    assert re.fullmatch(r"01787581400724023000-[0-9a-f]{16}", manifest["generation_id"])
    assert manifest_bytes == (json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                              + "\n").encode(), "the manifest keeps its canonical form"
    meta = paths["spec/manifest.json"].meta
    assert meta == {"generation_id": manifest["generation_id"], "manifest_sha256": sha(manifest_bytes)}
    doc = paths["spec/docs/a.md"].data
    assert SECRET.encode() not in doc and b"123456" not in doc
    assert b"ftp://CEX-REDACTED@192.0.2.10/dir/file" in doc
    assert b"sftp://CEX-REDACTED@192.0.2.12/backup" in doc
    assert b"the password is CEX-REDACTED." in doc
    for name in ("a.md", "b.md"):
        data = paths[f"spec/docs/{name}"].data
        assert manifest["documents"][name] == {"size": len(data), "sha256": sha(data)}
    index_bytes = paths["spec/index.json"].data
    assert manifest["artifacts"]["index.json"] == {"size": len(index_bytes), "sha256": sha(index_bytes)}
    assert manifest["artifacts"]["state.tsv"]["sha256"] == sha(paths["spec/state.tsv"].data)
    index = json.loads(index_bytes)
    assert index["entries"]["a.md"]["sha256"] == sha(doc)
    assert index["entries"]["a.md"]["bug_numbers_body"] == ["23456"], \
        "a numeric password read as a bug number leaves the index with it"
    original = json.loads((root / "knowledge/data/spec/generations" / SPEC_GID / "index.json").read_text())
    assert index["entries"]["b.md"] == original["entries"]["b.md"]
    assert index["generated_from"] == original["generated_from"]
    assert res.source["spec_generation"] == manifest["generation_id"]
    assert res.source["spec_redaction"]["documents"] == 1


def test_contract_pinned_framework_file_with_credentials_is_refused_by_name(tmp_path):
    root, pins = make_root(tmp_path, pinned_secret=True)
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    assert set(failures) == {"credential_scan"}
    locations = failures["credential_scan"]["locations"]
    assert locations == ["framework/framework_tree.tar.gz!lib/env.py: 1 (pinned by "
                         "excel_contract.json source_hashes: remove the credential upstream, "
                         "then re-certify the contract)"]
    members = _members(next(e for e in resolver.entries
                            if e.path == "framework/framework_tree.tar.gz").data)
    assert members["lib/env.py"] == (root / "knowledge/framework/mirror/lib/env.py").read_bytes(), \
        "a contract-pinned file is never rewritten"


def test_manual_with_credentials_is_refused_by_name(tmp_path):
    root, pins = make_root(tmp_path, manual_secret=True)
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    assert set(failures) == {"credential_scan"}
    assert failures["credential_scan"]["locations"][0].startswith("manual/10.5.0/app_cn.md: 1 (")


def test_value_split_across_rich_text_runs_cannot_be_redacted_in_place(tmp_path):
    split = f"<si><r><t>{SECRET[:4]}</t></r><r><t>{SECRET[4:]}</t></r></si>"
    root, pins = make_root(tmp_path, xlsx_shared=split)
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    assert "cannot be redacted in place" in failures["framework"]["evidence"]
    assert "smoke_test/sdns/case_1.xlsx" in failures["framework"]["evidence"]


def test_footprint_receipt_that_failed_without_nodes_is_refused(tmp_path):
    root, pins = make_root(tmp_path, receipt={"status": "failed"}, nodes=False)
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    evidence = failures["footprints"]["evidence"]
    for part in ("status 'failed'", "complete is not true", "has no node files", "schema"):
        assert part in evidence
    assert not any(e.kind == "footprints" for e in resolver.entries), "no empty tar ships"


def test_footprint_receipt_must_pin_the_shipped_manual(tmp_path):
    root, pins = make_root(tmp_path)
    receipt_path = root / "knowledge/footprints/.receipt_nodes_10.5.0.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["manual_sha256"]["cli_cn.md"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt))
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    assert "manual_sha256 pins differ" in failures["footprints"]["evidence"]


def test_manual_catalog_must_be_coupled_to_its_md(tmp_path):
    root, pins = make_root(tmp_path)
    (root / "knowledge/data/manual/10.5.0/app_cn.md").write_text("# app changed\n")
    resolver, _calls = _resolver(root, pins, tmp_path)
    failures = {item["key"]: item for item in _refused(resolver)}
    assert "app: catalog status identity_uncoupled" in failures["manual"]["evidence"]


def test_resolver_refuses_evidence_bound_to_another_atlas(data_root, tmp_path):
    root, pins = data_root
    asset = root / pdd.SSL_LIFECYCLE_ASSET
    payload = json.loads(asset.read_text())
    payload["contracts"][0]["reference_evidence"]["teardown_atlas_identity_sha256"] = "9" * 64
    asset.write_text(json.dumps(payload))
    resolver, _calls = _resolver(root, pins, tmp_path)
    with pytest.raises(pdd.Refused, match="another teardown atlas"):
        resolver.resolve()


def test_resolver_refuses_when_rederivation_fails(data_root, tmp_path):
    root, pins = data_root
    resolver = pdd.DataDirResolver(
        root, RAW_BUILD, "10.5.0", pins=pins, work=tmp_path / "work", engine=FakeEngine(),
        rederive=lambda *_a: {"ok": False, "error": "differ beyond identity: projection"})
    with pytest.raises(pdd.Refused) as info:
        resolver.resolve()
    keys = {item["key"] for item in json.loads(str(info.value))}
    assert {"cmdtree", "projections", "credentials", "credential_scan"} <= keys, \
        "without the original XML there is no closure, and nothing ships unscanned"


def test_dump_like_keeps_the_original_json_form():
    doc = {"b": 1, "a": [1], "x": "中"}
    for original in (json.dumps(doc, ensure_ascii=False, indent=2).encode(),
                     (json.dumps(doc, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False) + "\n").encode(),
                     (json.dumps(doc, ensure_ascii=False, indent=1) + "\n").encode()):
        assert pdd.dump_like(original, json.loads(original)) == original
        changed = pdd.dump_like(original, {**json.loads(original), "b": 2})
        assert changed == original.replace(b'"b": 1', b'"b": 2').replace(b'"b":1', b'"b":2')


def test_out_dir_is_written_only_for_a_scanned_clean_resolution(tmp_path):
    unscanned = pdd.Resolution("B", [pdd.Entry("spec", "spec/docs/a.md", b"# a\n")], {}, [])
    with pytest.raises(pdd.PublishError, match="凭据扫描"):
        pdd.write_out_dir(unscanned, tmp_path / "out")
    assert not (tmp_path / "out").exists()
