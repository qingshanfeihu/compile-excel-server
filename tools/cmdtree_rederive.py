#!/usr/bin/env python3
"""命令树脱敏与重推导：去掉凭据默认值的 XML → 命令树代际、投影、拆卸图谱、领域文法。

数据包不发带凭据默认值的原始 XML（参数默认值里有凭据字面）。可客户端的引擎要核对来源：
投影记着 XML 的哈希、命令树代际清单记着 XML 与投影、拆卸图谱与领域文法的框架清理规则记着
XML 的哈希、SSL 生命周期证据记着拆卸图谱的身份。所以发布端先把 XML 里的凭据字面去掉，
再**用引擎自己的函数**从这份 XML 把这些产物重新推导一遍（publish_local_command_tree、
gen_command_teardown_atlas），而不是改写身份字段。

凭据字面 = 引擎在**原始** XML 上算出的默认值闭包（command_tree_sync._xml_default_literal_closure：
凭据参数——按 credential_literals.is_credential_argument 认——的非占位默认值）。同一个值在别处
也会出现：非凭据参数的默认值、帮助文本、其他属性、元素文本，而且在 XML 里是转义后的写法
（& 写成 &amp;）。所以按解析器看到的值（展开实体后）逐个属性、逐段文本比对，每一处都去掉：
default_value 整个置空，别的属性与文本里把这个值换成 [redacted]（引擎投影里同一个标记，
command_tree_sync.xml_sensitive_literal_replace），别的字节一个不动。注释、CDATA 里出现就拒绝。
脱敏后重新解析：任何属性值、文本里还有凭据字面，或结构（元素、属性名）变了，就拒绝。

重推导的产物与 InfoTest 已收敛的那份相比，只许身份字段（XML 哈希、代际、清单、图谱身份）与
两个读入计数不同，且计数的差必须正好等于脱敏收据：投影的 default_values_omitted 少掉置空的
default_value 个数；credential_fields_redacted 少掉脱敏时已换成 [redacted] 的、投影会读的字段数
（非凭据参数的 name/length/limit/help_string——引擎本来会在投影里现场换成同一个标记，文本相同，
只是计数不再算它）。别处有一点不同就拒绝发布。

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
import urllib.parse
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
VENDOR = REPO_ROOT / "gateway" / "vendor"
REDACTED = "[redacted]"  # 与引擎投影里的标记同字（command_tree_sync.xml_sensitive_literal_replace）
_XML_ENCODING = re.compile(rb"""^\s*<\?xml[^>]*?\bencoding\s*=\s*["']([A-Za-z0-9._-]+)["']""")
# 注释、CDATA、处理指令、声明、结束标签；开始/空标签单独取标签名与属性串（属性值里可以有 >）
_MARKUP = re.compile(
    r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<![^>]*>|</[^>]*>"
    r"|<([^\s!?/>]+)((?:\s+[^\s=/>]+\s*=\s*(?:\"[^\"]*\"|'[^']*'))*)\s*/?>", re.S)
_ATTR = re.compile(r"(\s+)([^\s=/>]+)(\s*=\s*)(?:\"([^\"]*)\"|'([^']*)')")
_ENTITY = re.compile(r"&(#[0-9]+|#[xX][0-9A-Fa-f]+|amp|lt|gt|quot|apos);")
_NAMED_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
_COMMAND_TAGS = frozenset({"scope", "menu", "item"})
# 投影会读的非凭据参数属性（build_vendor_stdlib.parse_vendor_xml 经 _safe_xml_text 现场脱敏的那几个）
_PROJECTED_ARG_ATTRS = frozenset({"name", "length", "limit", "help_string"})


class RederiveError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _literal_pattern(literal: str, *, ignore_case: bool) -> re.Pattern | None:
    """与引擎 command_tree_sync._xml_sensitive_literal_pattern 同一条规则：纯字母数字按词边界。"""
    text = str(literal or "").casefold()
    if not text:
        return None
    flags = re.IGNORECASE if ignore_case else 0
    if re.fullmatch("[a-z0-9]+", text):
        return re.compile(f"(?<![a-z0-9]){re.escape(text)}(?![a-z0-9])", flags)
    return re.compile(re.escape(text), flags)


def literal_count(text: str, values) -> int:
    """缺省实现，同 command_tree_sync.xml_sensitive_literal_count（run() 传引擎自己的那个）。"""
    folded = str(text or "").casefold()
    return sum(1 for value in values
               if (pattern := _literal_pattern(value, ignore_case=False)) is not None
               and pattern.search(folded) is not None)


def literal_replace(text: str, values) -> str:
    """缺省实现，同 command_tree_sync.xml_sensitive_literal_replace。"""
    out = str(text or "")
    for value in values:
        pattern = _literal_pattern(value, ignore_case=True)
        if pattern is not None:
            out = pattern.sub(REDACTED, out)
    return out


def _unescape(text: str) -> str:
    def one(match: re.Match) -> str:
        ref = match.group(1)
        if ref[:2] in ("#x", "#X"):
            return chr(int(ref[2:], 16))
        if ref[0] == "#":
            return chr(int(ref[1:]))
        return _NAMED_ENTITIES[ref]

    return _ENTITY.sub(one, text)


def _attribute_value(raw: str) -> str:
    """解析器看到的属性值：行尾规范化、属性值空白规范化，再展开实体。"""
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    return _unescape(raw.replace("\t", " ").replace("\n", " "))


def _text_value(raw: str) -> str:
    return _unescape(raw.replace("\r\n", "\n").replace("\r", "\n"))


def _escape_attribute(value: str, quote: str) -> str:
    out = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out = out.replace("\t", "&#9;").replace("\n", "&#10;").replace("\r", "&#13;")
    return out.replace('"', "&quot;") if quote == '"' else out.replace("'", "&apos;")


def _escape_text(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\r", "&#13;"))


def _written_forms(literal: str) -> frozenset[str]:
    """一个值在 XML 原文里可能的写法（原文、各种实体转义、URL 编码）。"""
    xml = literal.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    forms = {literal, xml, urllib.parse.quote(literal, safe="")}
    for quot in ('"', "&quot;", "&#34;"):
        for apos in ("'", "&apos;", "&#39;"):
            forms.add(xml.replace('"', quot).replace("'", apos))
    return frozenset(form for form in forms if form)


def sanitize_xml(raw: bytes, is_credential_argument, default_literal_closure, *,
                 literal_count=literal_count, literal_replace=literal_replace
                 ) -> tuple[bytes, dict[str, Any]]:
    """去掉原始 XML 里凭据默认值闭包的每一处出现（按解析后的值比对），别的字节不变。"""
    import xml.etree.ElementTree as ET

    literals = frozenset(default_literal_closure(raw))
    declared = _XML_ENCODING.match(raw)
    encoding = declared.group(1).decode("ascii") if declared else "utf-8"
    try:
        text = raw.decode(encoding)
    except (LookupError, UnicodeDecodeError) as exc:
        raise RederiveError(f"the command tree XML does not decode as its declared encoding "
                            f"{encoding}") from exc
    tally: dict[str, int] = {"blanked_default_values": 0, "blanked_credential_defaults": 0,
                             "blanked_other_defaults": 0, "redacted_text_nodes": 0,
                             "projected_fields_redacted": 0}
    attributes: dict[str, int] = {}
    changed: set[tuple[int, str]] = set()

    def carries(value: str) -> bool:
        return bool(literals) and literal_count(value, literals) > 0

    def written(chunk: str) -> bool:
        return any(literal_count(chunk, _written_forms(literal)) for literal in literals)

    def text_node(raw_text: str) -> str:
        if "<" in raw_text:
            raise RederiveError("the command tree XML has markup the sanitizer does not recognize")
        value = _text_value(raw_text)
        if not carries(value):
            return raw_text
        tally["redacted_text_nodes"] += 1
        return _escape_text(literal_replace(value, literals))

    out: list[str] = []
    position = 0
    ordinal = -1
    for match in _MARKUP.finditer(text):
        out.append(text_node(text[position:match.start()]))
        position = match.end()
        token = match.group(0)
        tag = match.group(1)
        if tag is None:
            if token.startswith(("<!", "<?")) and literals and written(token):
                raise RederiveError("a credential default literal occurs inside an XML comment, "
                                    "CDATA section or declaration")
            out.append(token)
            continue
        ordinal += 1
        raw_attrs = match.group(2)
        values = {item.group(2): _attribute_value(item.group(4) if item.group(4) is not None
                                                  else item.group(5))
                  for item in _ATTR.finditer(raw_attrs)}
        credential = tag == "arg" and bool(is_credential_argument(
            name=values.get("name"), arg_type=values.get("type"),
            help_string=values.get("help_string")))

        def attribute(item: re.Match, tag=tag, credential=credential, ordinal=ordinal,
                      values=values) -> str:
            name = item.group(2)
            # 凭据参数的默认值不论是不是闭包里的值（占位字面也算）都置空；别处只动带闭包值的
            blank = name == "default_value" and (carries(values[name])
                                                 or (credential and values[name].strip() != ""))
            if not blank and not carries(values[name]):
                return item.group(0)
            if blank:
                new = ""
                tally["blanked_default_values"] += 1
                tally["blanked_credential_defaults" if credential else "blanked_other_defaults"] += 1
            elif tag in _COMMAND_TAGS and name == "name":
                raise RederiveError(f"a credential default literal is part of a command token "
                                    f"(<{tag} name>); sanitizing it would change the command tree")
            else:
                new = literal_replace(values[name], literals)
                attributes[name] = attributes.get(name, 0) + 1
                if tag == "arg" and not credential and name in _PROJECTED_ARG_ATTRS:
                    tally["projected_fields_redacted"] += 1
            changed.add((ordinal, name))
            quote = '"' if item.group(4) is not None else "'"
            return f"{item.group(1)}{name}{item.group(3)}{quote}{_escape_attribute(new, quote)}{quote}"

        sanitized_attrs = _ATTR.sub(attribute, raw_attrs)
        if sanitized_attrs != raw_attrs:
            head = 1 + len(tag)
            token = token[:head] + sanitized_attrs + token[head + len(raw_attrs):]
        out.append(token)
    out.append(text_node(text[position:]))
    sanitized_text = "".join(out)
    sanitized = sanitized_text.encode(encoding)

    try:
        before = list(ET.fromstring(raw).iter())
        after = list(ET.fromstring(sanitized).iter())
    except ET.ParseError as exc:
        raise RederiveError("the sanitized command tree XML does not parse") from exc
    if len(before) != len(after):
        raise RederiveError("sanitization changed the XML element structure")
    left = 0
    for index, (old, new) in enumerate(zip(before, after, strict=True)):
        if old.tag != new.tag or set(old.attrib) != set(new.attrib):
            raise RederiveError("sanitization changed the XML element structure")
        for key, value in new.attrib.items():
            if value != old.attrib[key] and (index, key) not in changed:
                raise RederiveError("sanitization changed an attribute it did not mean to change")
            left += carries(value)
        for old_text, new_text in ((old.text or "", new.text or ""), (old.tail or "", new.tail or "")):
            if old_text != new_text and not carries(old_text):
                raise RederiveError("sanitization changed text that carries no credential default "
                                    "literal")
            left += carries(new_text)
    if left:
        raise RederiveError(f"{left} parsed attribute or text value(s) of the sanitized XML still "
                            "carry credential default literals")
    if default_literal_closure(sanitized):
        raise RederiveError("the sanitized XML still carries credential default values")
    if literals and written(sanitized_text):
        raise RederiveError("the sanitized XML still carries a credential default literal in "
                            "escaped or encoded form")
    return sanitized, {**tally, "redacted_attributes": dict(sorted(attributes.items())),
                       "distinct_literals_removed": len(literals),
                       "rule": "command_tree_sync._xml_default_literal_closure(original XML); "
                               "every occurrence in any attribute or text",
                       "replacement": {"default_value": "", "other": REDACTED}}


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
# 计数（足迹语料随 InfoTest 收敛增长；省略的默认值、现场脱敏的字段各少了脱敏收据里那几个——
# 这两个差在 run() 里按收据逐一核对，不是放过）。命令头一条都不许变
_PROJECTION_IDENTITY = [("source", "sha256"), ("stats", "default_values_omitted"),
                        ("stats", "credential_fields_redacted"),
                        ("stats", "value_domain", "footprint_nodes_read"),
                        ("stats", "value_domain", "footprint_commands_read")]
_ATLAS_IDENTITY = [("identity",), ("auxiliary_sources",)]
_GRAMMAR_IDENTITY = [("framework_cleanup_rules", "source_identity")]


def same_but_identity(original: Any, derived: Any, paths: list[tuple[str, ...]]) -> bool:
    return _without(original, paths) == _without(derived, paths)


def counter_deltas(before: dict[str, Any], after: dict[str, Any],
                   receipt: dict[str, Any]) -> dict[str, bool]:
    """投影里放过的两个计数，差必须正好等于脱敏收据（原投影 stats − 重推导投影 stats）。"""
    return {
        "omitted_defaults_delta": (before["default_values_omitted"] - after["default_values_omitted"]
                                   == receipt["blanked_default_values"]),
        "redacted_fields_delta": (
            before["credential_fields_redacted"] - after["credential_fields_redacted"]
            == receipt["projected_fields_redacted"]),
    }


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
        xml_sensitive_literal_count,
        xml_sensitive_literal_replace,
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
    sanitized, receipt = sanitize_xml(raw_xml, is_credential_argument, _xml_default_literal_closure,
                                      literal_count=xml_sensitive_literal_count,
                                      literal_replace=xml_sensitive_literal_replace)
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
    checks.update(counter_deltas(json.loads(original.projection_path.read_text("utf-8"))["stats"],
                                 json.loads(derived.projection_path.read_text("utf-8"))["stats"],
                                 receipt))
    if not all(checks.values()):
        raise RederiveError("re-derived artifacts differ beyond their XML identity: "
                            + ", ".join(name for name, ok in checks.items() if not ok))
    generation = derived.generation_root
    return {
        "ok": True, "checks": checks,
        "sanitization": {**receipt, "original_xml_sha256": original.source_sha256,
                         "sanitized_xml_sha256": derived.source_sha256,
                         "original_generation_id": original.generation_id},
        # 发布端要在原始 XML 上现算默认值闭包（出包前扫描用）；只给路径，值不经过 stdout
        "original_xml": {"path": str(original.xml_path), "sha256": original.source_sha256},
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
