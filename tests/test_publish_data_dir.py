"""tools/publish_data_dir.py 与 tools/cmdtree_rederive.py 的测试（合成数据目录，不碰 InfoTest）。

- 脱敏只置空凭据参数的 default_value，别的字节不动；默认值字面在 XML 别处还出现就拒绝；
- 重推导产物与原件比较时只放过身份字段，别处一点不同就拒绝；
- 解析器：命令树条目取重推导结果（代际清单、脱敏 XML、投影、带脱敏收据的 source.json），
  投影里拆卸图谱与领域文法换成重推导的那份，SSL 生命周期证据的图谱身份改绑，判据台账随包发；
  本地目录输出与客户端同步下来的包同形。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import cmdtree_rederive as rd  # noqa: E402
import publish_data_dir as pdd  # noqa: E402

XML = (b'<commands><scope type="global"><menu name="snmp">'
       b'<item name="community"><arguments>'
       b'<arg name="community" type="STRING" help_string="community string" default_value="s3cr3t-word"/>'
       b'<arg name="port" type="U16" help_string="port" default_value="161"/>'
       b'</arguments></item></menu></scope></commands>')


def _is_credential(*, name, arg_type, help_string):
    return name == "community"


def _closure(raw: bytes) -> frozenset[str]:
    import xml.etree.ElementTree as ET

    return frozenset(a.get("default_value") for a in ET.fromstring(raw).iter("arg")
                     if a.get("name") == "community" and a.get("default_value"))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_sanitize_blanks_only_credential_defaults():
    sanitized, receipt = rd.sanitize_xml(XML, _is_credential, _closure)
    assert b"s3cr3t-word" not in sanitized
    assert sanitized == XML.replace(b'default_value="s3cr3t-word"', b'default_value=""')
    assert b'default_value="161"' in sanitized, "non-credential defaults stay"
    assert receipt["blanked_default_values"] == 1 and receipt["distinct_literals_removed"] == 1


def test_sanitize_refuses_when_the_literal_also_occurs_elsewhere():
    leaky = XML.replace(b'help_string="port"', b'help_string="like s3cr3t-word"')
    with pytest.raises(rd.RederiveError, match="still occur"):
        rd.sanitize_xml(leaky, _is_credential, _closure)


def test_rederived_artifacts_may_differ_only_in_identity():
    original = {"source": {"sha256": "a" * 64, "filename": "x.xml"},
                "stats": {"default_values_omitted": 3, "value_domain": {"footprint_nodes_read": 1}},
                "headers": {"h": {"args": []}}}
    derived = json.loads(json.dumps(original))
    derived["source"]["sha256"] = "b" * 64
    derived["stats"]["default_values_omitted"] = 2
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


@pytest.fixture
def data_root(tmp_path):
    root = tmp_path / "data"
    ref = root / "knowledge/data/compile_ref"
    mirror = root / "knowledge/framework/mirror"
    clear = _write(mirror / "lib/apv/clear.py", "rules = []\n")
    fw = _write(mirror / "lib/env.py", "class Env: pass\n")
    _write(mirror / ".sync_meta.json", json.dumps({"by_path": {
        "lib/apv/clear.py": sha(clear.read_bytes()), "lib/env.py": sha(fw.read_bytes())},
        "synced_at": "2026-01-01T00:00:00Z", "source": "example"}))
    _write(ref / "mirror_manifest.json", json.dumps({"files": {"lib/env.py": sha(fw.read_bytes())}}))
    template = _write(ref / "excel_runtime_template.xlsx", b"template-bytes")
    contract_pin = "c" * 64
    _write(ref / "excel_contract.json", json.dumps({"contract_sha256": contract_pin,
                                                     "source_hashes": {"lib/env.py": sha(fw.read_bytes())}}))
    _write(ref / "excel_workbook_manifest.json", "{}")
    _write(ref / "command_teardown_atlas.json", json.dumps({"identity": {"sha256": "1" * 64}}))
    _write(ref / "domain_grammar.json", json.dumps({"x": 1}))
    _write(ref / "criterion_rules.json", "{}")
    _write(ref / "vendor_stdlib_10.5_585.json", "{}")  # 不进 projections（命令树类发重推导的那份）
    manual = _write(root / "knowledge/data/manual/10.5.0/cli_cn.md", "# cli\n")
    _write(root / "knowledge/data/manual/10.5.0/app_cn.md", "# app\n")
    _write(root / "knowledge/data/manual/10.5.0/cli_cn.catalog.json", "{}")
    _write(root / "knowledge/data/manual/10.5.0/app_cn.catalog.json", "{}")
    _write(root / "knowledge/data/manual/.sync_state.json", json.dumps({"cli:10.5.0": {"ok": 1},
                                                                         "cli:10.4.6": {"ok": 1}}))
    doc = b"# spec\n"
    spec_manifest = json.dumps({"documents": {"a.md": {"sha256": sha(doc)}}}).encode()
    gen = root / "knowledge/data/spec/generations/g1"
    _write(gen / "manifest.json", spec_manifest)
    _write(gen / "index.json", "{}")
    _write(gen / "state.tsv", "a.md\n")
    _write(gen / "docs/a.md", doc)
    _write(root / "knowledge/data/spec/active.json", json.dumps({"generation_id": "g1",
                                                                  "manifest_sha256": sha(spec_manifest)}))
    _write(root / "knowledge/footprints/nodes_10.5.0/snmp.json", "{}")
    _write(root / "knowledge/footprints/.receipt_nodes_10.5.0.json", json.dumps({"status": "complete"}))
    _write(root / "runtime/excel_release/promotion_receipt.json", json.dumps({
        "status": "promoted", "device_build": pdd.execution_build("Example Beta.APV-X.10.5.0.585"),
        "final_contract_sha256": contract_pin, "environment": "lab"}))
    _write(root / pdd.CRITERION_LEDGER, '{"rule_sha256": "r1"}\n{"rule_sha256": "r2"}\n')
    _write(root / pdd.SSL_LIFECYCLE_ASSET, json.dumps({"schema": "s", "contracts": [{
        "reference_evidence": {
            "clear_source": "knowledge/framework/mirror/lib/apv/clear.py",
            "clear_source_sha256": sha(clear.read_bytes()),
            "start_manual_source": "knowledge/data/manual/10.5.0/cli_cn.md",
            "start_manual_source_sha256": sha(manual.read_bytes()),
            "teardown_atlas_identity_sha256": "1" * 64}}]}))
    return root, (sha(template.read_bytes()), contract_pin)


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
        return {"ok": True, "checks": {"projection": True},
                "sanitization": {"blanked_default_values": 3, "original_xml_sha256": "o" * 64},
                "generation": {"generation_id": "g-new", "manifest_sha256": "m" * 64,
                               "projection_sha256": "p" * 64, "source_sha256": "s" * 64,
                               "source_url": "local://x", "product": "APV", "platform": "X",
                               "version": "10.5", "device_build": "585", "full_version": raw,
                               "item_count": 1, "results_total": 1, "results_nonempty": 0},
                "files": {name: str(path) for name, path in files.items()}}
    return rederive, calls


def test_resolver_ships_the_rederived_command_tree_and_rebinds_evidence(data_root, tmp_path):
    root, pins = data_root
    rederive, calls = _fake_rederive(tmp_path)
    resolver = pdd.DataDirResolver(root, "Example Beta.APV-X.10.5.0.585", "10.5.0",
                                   rederive=rederive, pins=pins, work=tmp_path / "work")
    res = resolver.resolve()
    paths = {entry.path: entry for entry in res.entries}
    assert calls == [("Example Beta.APV-X.10.5.0.585", "10.5.0")]
    assert {"cmdtree/generation_manifest.json", "cmdtree/cmdtree_585.xml",
            "cmdtree/vendor_stdlib_10.5_585.json", "cmdtree/source.json"} <= set(paths)
    source = json.loads(paths["cmdtree/source.json"].data)
    assert source["raw_xml_shipped"] == "sanitized" and source["generation_id"] == "g-new"
    assert source["sanitization"]["blanked_default_values"] == 3
    assert json.loads(paths["projections/command_teardown_atlas.json"].data)["identity"]["sha256"] == "2" * 64
    assert json.loads(paths["projections/domain_grammar.json"].data)["rebound"] is True
    assert "projections/vendor_stdlib_10.5_585.json" not in paths
    ssl = json.loads(paths["projections/ssl_lifecycle_contract.json"].data)
    assert ssl["contracts"][0]["reference_evidence"]["teardown_atlas_identity_sha256"] == "2" * 64
    assert paths["projections/criterion_author_rules.jsonl"].data.count(b"\n") == 2
    assert json.loads(paths["manual/10.5.0/sync_state.json"].data) == {"cli:10.5.0": {"ok": 1}}
    out = pdd.write_out_dir(res, tmp_path / "bundle")
    manifest = json.loads((tmp_path / "bundle/manifest.json").read_text())
    assert out["entries"] == len(manifest["entries"]) == len(res.entries)
    for row in manifest["entries"]:
        assert sha((tmp_path / "bundle" / row["path"]).read_bytes()) == row["sha256"]


def test_resolver_refuses_evidence_bound_to_another_atlas(data_root, tmp_path):
    root, pins = data_root
    asset = root / pdd.SSL_LIFECYCLE_ASSET
    payload = json.loads(asset.read_text())
    payload["contracts"][0]["reference_evidence"]["teardown_atlas_identity_sha256"] = "9" * 64
    asset.write_text(json.dumps(payload))
    rederive, _calls = _fake_rederive(tmp_path)
    resolver = pdd.DataDirResolver(root, "Example Beta.APV-X.10.5.0.585", "10.5.0",
                                   rederive=rederive, pins=pins, work=tmp_path / "work")
    with pytest.raises(pdd.Refused, match="another teardown atlas"):
        resolver.resolve()


def test_resolver_refuses_when_rederivation_fails(data_root, tmp_path):
    root, pins = data_root
    resolver = pdd.DataDirResolver(
        root, "Example Beta.APV-X.10.5.0.585", "10.5.0", pins=pins, work=tmp_path / "work",
        rederive=lambda *_a: {"ok": False, "error": "differ beyond identity: projection"})
    with pytest.raises(pdd.Refused) as info:
        resolver.resolve()
    keys = {item["key"] for item in json.loads(str(info.value))}
    assert {"cmdtree", "projections"} <= keys, "the atlas cannot be bound without the re-derivation"
