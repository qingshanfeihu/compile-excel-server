"""命令树 XML 脱敏（tools/cmdtree_rederive.py 的 sanitize_xml）：凭据默认值在哪儿出现都要去掉。

引擎的默认值闭包给的是**解析后**的值；XML 原文里它是转义后的写法（& 写成 &amp;）。同一个值还会
出现在非凭据参数的默认值、帮助文本、元素文本里。脱敏按解析后的值逐个属性、逐段文本比对：
default_value 置空，别处换成 [redacted]（引擎投影里的同一个标记），别的字节一个不动；
注释、命令名里出现就拒绝；脱敏后重新解析，任何属性/文本里还有就拒绝。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import cmdtree_rederive as rd  # noqa: E402

VALUE = "ex&mple-c0mm/unity"  # 文档用的假 community：带 &，XML 里写成 &amp;
ESCAPED = VALUE.replace("&", "&amp;").encode()

XML = (b'<?xml version="1.0" encoding="ISO-8859-1"?><commands><scope type="global">'
       b'<menu name="sdns"><menu name="monitor"><item name="collector" user_level="CLI_LEVEL_CONFIG">'
       b'<arguments>'
       b'<arg name="" type="STRING" help_string="community(a string of 1 to 32 characters). '
       b'Optional. Default value is ' + ESCAPED + b'." default_value="' + ESCAPED + b'"/>'
       b'<arg name="port" type="U16" help_string="port" default_value="161"/>'
       b'</arguments><results><result>ok</result></results></item></menu></menu>'
       b'<menu name="health"><item name="snmp" user_level="CLI_LEVEL_CONFIG"><arguments>'
       b'<arg name="" type="STRING" help_string="The maximum string length of the snmp '
       b'community is 32 (optional, default = public)" default_value="' + ESCAPED + b'"/>'
       b'<arg name="token" type="STRING" help_string="api token" default_value="none"/>'
       b'</arguments><results><result>seen ' + ESCAPED + b' twice</result></results></item>'
       b'</menu></scope></commands>')


def _is_credential(*, name, arg_type, help_string):
    """测试用分类器：帮助文本的第一个短语以 community 结尾，或参数名是 token。"""
    head = (help_string or "").split("(", 1)[0].strip().lower()
    return name == "token" or head.endswith("community")


def _closure(raw: bytes) -> frozenset[str]:
    """同引擎 _xml_default_literal_closure：凭据参数的非占位默认值（解析后的值）。"""
    return frozenset(
        arg.get("default_value").strip() for arg in ET.fromstring(raw).iter("arg")
        if _is_credential(name=arg.get("name"), arg_type=arg.get("type"),
                          help_string=arg.get("help_string"))
        and (arg.get("default_value") or "").strip()
        and arg.get("default_value").strip().lower() not in {"none", "null", "nil", "n/a", "na"})


def _values(raw: bytes) -> list[str]:
    root = ET.fromstring(raw)
    return [v for el in root.iter() for v in (*el.attrib.values(), el.text or "", el.tail or "")]


def test_closure_value_is_removed_everywhere_it_occurs_in_escaped_form():
    assert _closure(XML) == {VALUE}, "the credential arg carries the value; the other arg repeats it"
    assert XML.count(ESCAPED) == 4 and VALUE.encode() not in XML
    sanitized, receipt = rd.sanitize_xml(XML, _is_credential, _closure)
    assert ESCAPED not in sanitized and VALUE.encode() not in sanitized
    assert not any(VALUE in value for value in _values(sanitized))
    assert b"Default value is [redacted]." in sanitized
    assert b"seen [redacted] twice" in sanitized
    health = [arg for arg in ET.fromstring(sanitized).iter("arg")
              if (arg.get("help_string") or "").startswith("The maximum")][0]
    assert health.get("default_value") == "", "the repeat in a non-credential arg is blanked too"
    token = [arg for arg in ET.fromstring(sanitized).iter("arg") if arg.get("name") == "token"][0]
    assert token.get("default_value") == "", "credential defaults are blanked even when a placeholder"
    assert b'default_value="161"' in sanitized, "non-credential defaults stay"
    assert receipt["blanked_default_values"] == 3
    assert receipt["blanked_credential_defaults"] == 2 and receipt["blanked_other_defaults"] == 1
    assert receipt["redacted_attributes"] == {"help_string": 1}
    assert receipt["redacted_text_nodes"] == 1
    assert receipt["projected_fields_redacted"] == 0, "the help belongs to a credential arg"
    assert _closure(sanitized) == frozenset()


def test_sanitize_touches_only_the_credential_occurrences():
    sanitized, _receipt = rd.sanitize_xml(XML, _is_credential, _closure)
    expected = (XML.replace(b'Default value is ' + ESCAPED + b'."', b'Default value is [redacted]."')
                .replace(b'default_value="' + ESCAPED + b'"', b'default_value=""')
                .replace(b'default_value="none"', b'default_value=""')
                .replace(b'seen ' + ESCAPED + b' twice', b'seen [redacted] twice'))
    assert sanitized == expected


def test_literal_in_a_projected_help_string_is_redacted_and_counted():
    xml = (b'<commands><scope type="global"><menu name="snmp"><item name="community">'
           b'<arguments>'
           b'<arg name="community" type="STRING" help_string="community string" '
           b'default_value="s3cr3t-word"/>'
           b'<arg name="port" type="U16" help_string="like s3cr3t-word" default_value="161"/>'
           b'</arguments></item></menu></scope></commands>')

    def credential(*, name, arg_type, help_string):
        return name == "community"

    def closure(raw):
        return frozenset(a.get("default_value") for a in ET.fromstring(raw).iter("arg")
                         if a.get("name") == "community" and a.get("default_value"))

    sanitized, receipt = rd.sanitize_xml(xml, credential, closure)
    assert b"s3cr3t-word" not in sanitized
    assert b'help_string="like [redacted]"' in sanitized
    assert receipt["projected_fields_redacted"] == 1, "the engine projects this help; count it"


def test_alnum_literal_matches_on_word_boundaries_like_the_engine():
    xml = (b'<commands><scope type="global"><item name="x"><arguments>'
           b'<arg name="password" type="STRING" help_string="secret" default_value="Admin1"/>'
           b'<arg name="n" type="STRING" help_string="admin1 or Admin12 or xadmin1" default_value=""/>'
           b'</arguments></item></scope></commands>')

    def credential(*, name, arg_type, help_string):
        return name == "password"

    sanitized, _receipt = rd.sanitize_xml(xml, credential, lambda raw: frozenset(
        a.get("default_value") for a in ET.fromstring(raw).iter("arg")
        if a.get("name") == "password" and a.get("default_value")))
    assert b'help_string="[redacted] or Admin12 or xadmin1"' in sanitized


@pytest.mark.parametrize("where", ["comment", "command name"])
def test_sanitize_refuses_what_it_cannot_redact_in_place(where):
    extra = (b"<!-- default " + ESCAPED + b" -->" if where == "comment"
             else b'<item name="' + ESCAPED + b'" user_level="CLI_LEVEL_CONFIG"/>')
    xml = XML.replace(b"</scope></commands>", extra + b"</scope></commands>")
    with pytest.raises(rd.RederiveError, match="comment|command token"):
        rd.sanitize_xml(xml, _is_credential, _closure)


def test_projection_counters_must_move_by_exactly_the_receipt():
    receipt = {"blanked_default_values": 30, "projected_fields_redacted": 1}
    before = {"default_values_omitted": 1200, "credential_fields_redacted": 40}
    assert rd.counter_deltas(before, {"default_values_omitted": 1170,
                                      "credential_fields_redacted": 39}, receipt) == {
        "omitted_defaults_delta": True, "redacted_fields_delta": True}
    checks = rd.counter_deltas(before, {"default_values_omitted": 1171,
                                        "credential_fields_redacted": 40}, receipt)
    assert checks == {"omitted_defaults_delta": False, "redacted_fields_delta": False}


def test_local_rule_is_the_engine_rule():
    """缺省比对/替换与引擎 command_tree_sync 的同名函数逐字一致（有 skills 检出时核）。

    在子进程里导入引擎：不把另一份 cex_core 留在本进程的 sys.modules 里。"""
    skills = Path(os.environ.get("CEX_SKILLS_ROOT") or REPO_ROOT.parent / "compile-excel-skills")
    if not (skills / "cex_core" / "engine" / "sync" / "command_tree_sync.py").is_file():
        pytest.skip("no compile-excel-skills checkout (set CEX_SKILLS_ROOT)")
    script = f"""
import json, sys
sys.path.insert(0, {str(skills)!r}); sys.path.insert(0, {str(REPO_ROOT / "tools")!r})
from cex_core.engine.sync import command_tree_sync as cts
import cmdtree_rederive as rd
values = frozenset({{"ex&mple-c0mm", "Admin1", "p@ss w0rd"}})
bad = [t for t in ("x ex&MPLE-c0mm y", "admin1", "Admin12", "xadmin1 ADMIN1.", "P@SS W0RD!", "")
       if rd.literal_count(t, values) != cts.xml_sensitive_literal_count(t, values)
       or rd.literal_replace(t, values) != cts.xml_sensitive_literal_replace(t, values)]
print(json.dumps(bad))
"""
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          timeout=120, env={**os.environ, "CEX_ENGINE_DATA_ROOT": ""})
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == []
