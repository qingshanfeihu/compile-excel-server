#!/usr/bin/env python3
"""命令树脱敏与重推导：去掉凭据默认值的 XML → 命令树代际、投影、拆卸图谱、领域文法。

数据包不发带凭据默认值的原始 XML（参数默认值里有凭据字面）。可客户端的引擎要核对来源：
投影记着 XML 的哈希、命令树代际清单记着 XML 与投影、拆卸图谱与领域文法的框架清理规则记着
XML 的哈希、SSL 生命周期证据记着拆卸图谱的身份。所以发布端先把凭据参数的 default_value 置空，
再**用引擎自己的函数**从这份 XML 把这些产物重新推导一遍（publish_local_command_tree、
gen_command_teardown_atlas），而不是改写身份字段。

判定：凭据参数按引擎同一条规则认（credential_literals.is_credential_argument）；脱敏后 XML
里不得再出现任何原凭据默认字面；重推导的产物与 InfoTest 已收敛的那份相比，只许身份字段
（XML 哈希、代际、清单、图谱身份）与省略默认值的计数不同——别处有一点不同就拒绝发布。

在临时数据根里跑（引擎在导入时按 CEX_ENGINE_DATA_ROOT 定路径，而且拆卸图谱脚本会就地收敛
compile_ref 里的文件），引擎用网关 vendor 里从 compile-excel-skills 同步来的 cex_core。
publish_data_dir.py 以子进程调用本脚本：

  python3 tools/cmdtree_rederive.py --data-root <InfoTest 布局根> --raw-build "<show version>" \\
      --work <临时目录>

stdout 最后一行是 JSON 结果（产物路径与核对结论）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR = REPO_ROOT / "gateway" / "vendor"
_ARG_TAG = re.compile(r"<arg\b[^>]*>")
_DEFAULT_ATTR = re.compile(r'\bdefault_value="[^"]*"')


class RederiveError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_xml(raw: bytes, is_credential_argument, default_literal_closure) -> tuple[bytes, dict[str, Any]]:
    """把凭据参数的 default_value 置空（只动这些属性，别的字节不变）。"""
    import xml.etree.ElementTree as ET

    text = raw.decode("utf-8")
    blanked = 0

    def blank(match: re.Match) -> str:
        nonlocal blanked
        tag = match.group(0)
        element = ET.fromstring(tag if tag.endswith("/>") else tag + "</arg>")
        if (element.get("default_value") or "").strip() and is_credential_argument(
                name=element.get("name"), arg_type=element.get("type"),
                help_string=element.get("help_string")):
            blanked += 1
            return _DEFAULT_ATTR.sub('default_value=""', tag)
        return tag

    literals = default_literal_closure(raw)
    sanitized = _ARG_TAG.sub(blank, text).encode("utf-8")
    remaining = sorted(value for value in literals if value in sanitized.decode("utf-8"))
    if remaining:
        raise RederiveError(f"{len(remaining)} credential default literal(s) still occur in the "
                            "sanitized XML outside default_value attributes")
    if default_literal_closure(sanitized):
        raise RederiveError("the sanitized XML still carries credential default values")
    ET.fromstring(sanitized)
    return sanitized, {"blanked_default_values": blanked,
                       "distinct_literals_removed": len(literals),
                       "rule": "credential_literals.is_credential_argument"}


def _without(value: Any, paths: list[tuple[str, ...]]) -> Any:
    value = json.loads(json.dumps(value))
    for path in paths:
        node = value
        for key in path[:-1]:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(path[-1], None)
    return value


# 重推导产物与原产物之间允许不同的字段：“绑定到哪份 XML”的身份，加上生成时读了多少输入的
# 计数（省略的默认值少了被置空的那几个；足迹语料随 InfoTest 收敛增长）。命令头一条都不许变
_PROJECTION_IDENTITY = [("source", "sha256"), ("stats", "default_values_omitted"),
                        ("stats", "value_domain", "footprint_nodes_read"),
                        ("stats", "value_domain", "footprint_commands_read")]
_ATLAS_IDENTITY = [("identity",), ("auxiliary_sources",)]
_GRAMMAR_IDENTITY = [("framework_cleanup_rules", "source_identity")]


def same_but_identity(original: Any, derived: Any, paths: list[tuple[str, ...]]) -> bool:
    return _without(original, paths) == _without(derived, paths)


def _copytree(src: Path, dst: Path) -> None:
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=False, dirs_exist_ok=True)


def stage_root(data_root: Path, work: Path, manual_version: str) -> Path:
    """临时数据根：重推导只读这些（手册 catalog、框架镜像、足迹、文法与图谱、XML）。"""
    root = work / "root"
    if root.exists():
        shutil.rmtree(root)
    _copytree(data_root / "knowledge/data/manual" / manual_version,
              root / "knowledge/data/manual" / manual_version)
    _copytree(data_root / "knowledge/framework/mirror", root / "knowledge/framework/mirror")
    footprints = data_root / "knowledge/footprints"
    for name in ("nodes", f"nodes_{manual_version}"):
        _copytree(footprints / name, root / "knowledge/footprints" / name)
    for name in (".receipt_nodes.json", f".receipt_nodes_{manual_version}.json"):
        if (footprints / name).is_file():
            (root / "knowledge/footprints").mkdir(parents=True, exist_ok=True)
            shutil.copyfile(footprints / name, root / "knowledge/footprints" / name)
    ref = root / "knowledge/data/compile_ref"
    ref.mkdir(parents=True, exist_ok=True)
    for name in ("domain_grammar.json", "command_teardown_atlas.json"):
        shutil.copyfile(data_root / "knowledge/data/compile_ref" / name, ref / name)
    (root / "workspace/inputs").mkdir(parents=True, exist_ok=True)
    return root


def run(data_root: Path, raw_build: str, root: Path) -> dict[str, Any]:
    """在 CEX_ENGINE_DATA_ROOT=root 的进程里跑（main 先设好再导入引擎）。"""
    from cex_core.engine.case_compiler.credential_literals import is_credential_argument
    from cex_core.engine.sync.command_tree_sync import (
        _xml_default_literal_closure,
        parse_build_identity,
        publish_local_command_tree,
        resolve_active_command_tree,
    )

    identity = parse_build_identity(raw_build)
    partition = (data_root / "runtime/command_tree/products" / identity.product / "platforms"
                 / identity.platform / "builds" / f"{identity.inventory_version}_{identity.build}")
    original = resolve_active_command_tree(product=identity.product, platform=identity.platform,
                                           version=identity.inventory_version,
                                           device_build=identity.build,
                                           store_root=data_root / "runtime/command_tree",
                                           _allow_stale_policy=True)
    if original is None or original.full_version != raw_build:
        raise RederiveError(f"no active command tree generation for {raw_build} under {partition}")
    raw_xml = original.xml_path.read_bytes()
    if sha256(raw_xml) != original.source_sha256:
        raise RederiveError("the active command tree XML drifted from its generation")
    sanitized, receipt = sanitize_xml(raw_xml, is_credential_argument, _xml_default_literal_closure)
    from cex_core.engine.scripts.maintenance.build_vendor_stdlib import (
        generate_vendor_stdlib_projection,
    )

    xml_input = root / "workspace/inputs" / f"cmdtree_{identity.build}.xml"
    xml_input.write_bytes(sanitized)
    derived = publish_local_command_tree(
        xml_path=xml_input, expected_sha256=sha256(sanitized), full_version=raw_build,
        version=identity.inventory_version, projection_builder=generate_vendor_stdlib_projection,
        store_root=root / "runtime/command_tree")
    from cex_core.engine.scripts import gen_command_teardown_atlas

    if gen_command_teardown_atlas.main(["--device-build", identity.build,
                                        "--version", identity.inventory_version]) != 0:
        raise RederiveError("the command teardown atlas did not regenerate")
    ref_old = data_root / "knowledge/data/compile_ref"
    ref_new = root / "knowledge/data/compile_ref"
    checks = {
        "projection": same_but_identity(json.loads(original.projection_path.read_text("utf-8")),
                                        json.loads(derived.projection_path.read_text("utf-8")),
                                        _PROJECTION_IDENTITY),
        "command_teardown_atlas": same_but_identity(
            json.loads((ref_old / "command_teardown_atlas.json").read_text("utf-8")),
            json.loads((ref_new / "command_teardown_atlas.json").read_text("utf-8")),
            _ATLAS_IDENTITY),
        "domain_grammar": same_but_identity(
            json.loads((ref_old / "domain_grammar.json").read_text("utf-8")),
            json.loads((ref_new / "domain_grammar.json").read_text("utf-8")),
            _GRAMMAR_IDENTITY),
    }
    omitted = (json.loads(original.projection_path.read_text("utf-8"))["stats"]["default_values_omitted"]
               - json.loads(derived.projection_path.read_text("utf-8"))["stats"]["default_values_omitted"])
    checks["omitted_defaults_delta"] = omitted == receipt["blanked_default_values"]
    if not all(checks.values()):
        raise RederiveError("re-derived artifacts differ beyond their XML identity: "
                            + ", ".join(name for name, ok in checks.items() if not ok))
    generation = derived.generation_root
    return {
        "ok": True, "checks": checks,
        "sanitization": {**receipt, "original_xml_sha256": original.source_sha256,
                         "sanitized_xml_sha256": derived.source_sha256,
                         "original_generation_id": original.generation_id},
        "generation": {"generation_id": derived.generation_id,
                       "manifest_sha256": derived.manifest_sha256,
                       "projection_sha256": derived.projection_sha256,
                       "source_sha256": derived.source_sha256, "source_url": derived.source_url,
                       "product": identity.product, "platform": identity.platform,
                       "version": identity.inventory_version, "device_build": identity.build,
                       "full_version": raw_build, "item_count": derived.item_count,
                       "results_total": derived.results_total,
                       "results_nonempty": derived.results_nonempty},
        "files": {
            "generation_manifest.json": str(generation / "manifest.json"),
            f"cmdtree_{identity.build}.xml": str(derived.xml_path),
            derived.projection_path.name: str(derived.projection_path),
            "command_teardown_atlas.json": str(ref_new / "command_teardown_atlas.json"),
            "domain_grammar.json": str(ref_new / "domain_grammar.json"),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--raw-build", required=True)
    parser.add_argument("--manual-version", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    if not (VENDOR / "cex_core" / "__init__.py").is_file():
        print(json.dumps({"ok": False, "error": "gateway/vendor/cex_core is missing; run "
                                                "tools/sync_gateway_vendor.py --only cex_core"}))
        return 2
    data_root = Path(args.data_root).resolve()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    root = stage_root(data_root, work, args.manual_version)
    os.environ["CEX_ENGINE_DATA_ROOT"] = str(root)
    sys.path.insert(0, str(VENDOR))
    try:
        result = run(data_root, args.raw_build, root)
    except Exception as exc:  # noqa: BLE001 — 子进程边界：原因回给发布端
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
