"""命令存在性与参数契约判定：读命令树投影（vendor_stdlib JSON），不读原始 XML。

本文件由 InfoTest `main/case_compiler/vendor_stdlib.py` 的判定函数逐字抽出生成
（norm_command_tokens … resolve_vendor_command 与所需常量），唯一改动是
`resolve_vendor_command` 的投影由调用方传入，而不是按版本从本机命令树仓加载。
与 InfoTest 的一致性由 Phase 3 对拍守住；改判据先改 InfoTest 源再重新抽取，不在这里手改。
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from pathlib import Path

_MAX_HEAD_TOKENS = 8
_EXECUTABLE_ARGUMENT_TYPES = frozenset({
    "STRING", "XSTRING", "U16", "U32", "IPADDR", "DOTTEDIP", "IPMASK",
})
_REDACTED_ARGUMENT_TYPE = "REDACTED_SENSITIVE"
_VALUE_DOMAIN_KINDS = frozenset({"enum", "union", "range", "length", "default"})
_VALUE_DOMAIN_SOURCES = frozenset({
    "xml_limit", "xml_help", "manual_table", "footprint",
})
_CLOSED_SET_ENUM_SOURCES = frozenset({"xml_limit", "manual_table", "footprint"})

#: 「查了命令树、这个命令头不在里面」的 reason_code。与
#: `xml_absent_catalog_unavailable`（catalog 取不到，措辞不放宽）是姊妹码，
#: 由本模块与 `main/ist_core/tools/device/emit_xlsx_tool.py` 两个签发点共用——
#: 两边各写一份裸串就会在改码时漂开（INV-28 式②：事件名单源）。
XML_COMMAND_NOT_FOUND = "command_not_found"


def norm_command_tokens(cmd: str) -> list[str]:
    return _norm_tokens(cmd)


def strip_token_quotes(token: str) -> str:
    # 引号归一只有这一份实现：命令侧（shlex 主路径已剥，回退路径补剥）与
    # 条件值侧（stated_value_tokens）共用，否则带引号字面在两侧得到不同归一，
    # 同一条命令里的值会被比对器误报 absent（yzg #05/#06 三条假冲突）。
    text = str(token or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def match_command_head(tokens: list[str], heads: dict) -> tuple[str, dict] | None:
    return _try_match(tokens, heads)


def _norm_tokens(cmd: str) -> list[str]:
    value = (cmd or "").strip()
    if not value:
        return []
    try:
        return [token.lower() for token in shlex.split(value, posix=True)]
    except ValueError:
        return [
            strip_token_quotes(part).lower()
            for part in re.sub(r"\s+", " ", value.lower()).split(" ")
            if part
        ]


def _head_candidate(tokens: list[str], heads: dict) -> tuple[str, dict, list[str]] | None:
    for k in range(min(len(tokens), _MAX_HEAD_TOKENS), 0, -1):
        head = " ".join(tokens[:k])
        entry = heads.get(head)
        if isinstance(entry, dict):
            return head, entry, tokens[k:]
    return None


def _value_matches_type(value: str, arg_type: str) -> bool:
    if arg_type == "STRING":
        return True
    if arg_type == "XSTRING":
        return bool(value)
    if arg_type in {"U16", "U32"}:
        if not re.fullmatch(r"\d+", value):
            return False
        number = int(value)
        return number <= (65535 if arg_type == "U16" else 4294967295)
    if arg_type in {"IPADDR", "DOTTEDIP"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return False
        return arg_type == "IPADDR" or parsed.version == 4
    if arg_type == "IPMASK":
        if re.fullmatch(r"\d+", value):
            return 0 <= int(value) <= 128
        try:
            ipaddress.IPv4Network(f"0.0.0.0/{value}")
        except ValueError:
            return False
        return True
    return False


def _value_domain_error(value: str, arg: dict, index: int) -> dict | None:
    domain = arg.get("value_domain")
    if not isinstance(domain, dict):
        return None
    folded = value.casefold()
    for claim in domain.get("default") or []:
        if folded == str(claim.get("value") or "").casefold():
            return None
    all_enum_claims = [
        claim for claim in domain.get("enum") or [] if isinstance(claim, dict)
    ]
    enum_claims = [
        claim for claim in all_enum_claims
        if str(claim.get("source")) in _CLOSED_SET_ENUM_SOURCES
    ]
    range_claims = [
        claim for claim in domain.get("range") or [] if isinstance(claim, dict)
    ]
    if not enum_claims and not range_claims:
        return None
    all_members = {
        str(item).casefold()
        for claim in all_enum_claims
        for item in claim.get("values") or []
    }
    if folded in all_members:
        return None
    union_separators = sorted({
        str(claim.get("separator") or "")
        for claim in domain.get("union") or []
        if isinstance(claim, dict) and str(claim.get("separator") or "")
    })
    for separator in union_separators:
        parts = folded.split(separator)
        if len(parts) >= 2 and all(part and part in all_members for part in parts):
            return None
    number: int | None
    try:
        number = int(value)
    except ValueError:
        number = None
    if range_claims and number is None:
        if not enum_claims:
            return None
    for claim in range_claims:
        if number is not None and int(claim["min"]) <= number <= int(claim["max"]):
            return None
    if enum_claims:
        error = {
            "code": "enum_mismatch",
            "argument_index": index,
            "allowed_enums": sorted({
                str(item)
                for claim in all_enum_claims
                for item in claim.get("values") or []
            }),
            "value_domain_sources": sorted({
                str(claim.get("source")) for claim in all_enum_claims
            }),
        }
        if union_separators:
            error["union_separators"] = union_separators
        return error
    return {
        "code": "range_mismatch",
        "argument_index": index,
        "allowed_ranges": [
            {"min": int(claim["min"]), "max": int(claim["max"])}
            for claim in range_claims
        ],
        "value_domain_sources": sorted({
            str(claim.get("source")) for claim in range_claims
        }),
    }


def _argument_variants(entry: dict) -> list[list[dict]]:
    variants: list[list[dict]] = []
    primary = entry.get("args")
    if isinstance(primary, list):
        variants.append(primary)
    for candidate in entry.get("arg_variants") or []:
        if isinstance(candidate, list) and candidate not in variants:
            variants.append(candidate)
    return variants


def _parameter_contract_error(rem: list[str], entry: dict) -> dict | None:
    variants = _argument_variants(entry)
    if not variants:
        pmax = int(entry.get("pmax") or 0)
        if len(rem) > pmax:
            return {"code": "arity_too_many", "actual_count": len(rem), "pmax": pmax}
        return None

    failures: list[dict] = []
    accepted = False
    for args in variants:
        required = sum(not bool(arg.get("optional")) for arg in args)
        maximum = len(args)
        if len(rem) < required:
            failures.append({
                "code": "arity_too_few", "actual_count": len(rem),
                "required_min": required, "pmax": maximum,
            })
            continue
        if len(rem) > maximum:
            failures.append({
                "code": "arity_too_many", "actual_count": len(rem),
                "required_min": required, "pmax": maximum,
            })
            continue
        mismatch = None
        for index, (value, arg) in enumerate(zip(rem, args), start=1):
            arg_type = str(arg.get("type") or "")
            if (
                arg_type == _REDACTED_ARGUMENT_TYPE
                and arg.get("executable") is False
            ):
                mismatch = {
                    "code": "sensitive_parameter_unexecutable",
                    "argument_index": index,
                }
                break
            if not _value_matches_type(value, arg_type):
                mismatch = {
                    "code": "type_mismatch", "argument_index": index,
                    "expected_type": arg_type,
                }
                break
            domain_error = _value_domain_error(value, arg, index)
            if domain_error is not None:
                mismatch = domain_error
                break
        if mismatch is None:
            accepted = True
        else:
            failures.append(mismatch)
    sensitive = next(
        (
            item for item in failures
            if item["code"] == "sensitive_parameter_unexecutable"
        ),
        None,
    )
    if sensitive is not None:
        return sensitive
    if accepted:
        return None
    for code in ("type_mismatch", "enum_mismatch", "range_mismatch"):
        preferred = next(
            (item for item in failures if item["code"] == code), None
        )
        if preferred is not None:
            return preferred
    return failures[0]


def _try_match(tokens: list[str], heads: dict) -> tuple[str, dict] | None:
    candidate = _head_candidate(tokens, heads)
    if candidate is None:
        return None
    head, entry, rem = candidate
    if "manual_pmax" in entry and "vendor_pmax" in entry:
        manual_pmax = int(entry.get("manual_pmax") or 0)
        vendor_pmax = int(entry.get("vendor_pmax") or 0)
        if min(manual_pmax, vendor_pmax) < len(rem) <= max(manual_pmax, vendor_pmax):
            return head, entry
        return None
    return None if _parameter_contract_error(rem, entry) else (head, entry)


def resolve_vendor_command(cmd: str, inv: dict | None) -> dict:
    """InfoTest 同名函数的逐字副本，只把「按版本加载投影」换成由调用方传入投影。"""
    if inv is None:
        return {
            "decided": False, "hit": False, "head": "", "src": "",
            "version": "", "device_build": "", "origin": "",
        }
    heads = inv["heads"]
    tokens = _norm_tokens(cmd)
    if not tokens or not re.match(r"^[a-z\[]", tokens[0]):
        return {
            "decided": False, "hit": False, "head": "", "src": "",
            "version": inv.get("version", ""),
            "device_build": inv.get("device_os_build", ""),
            "origin": "",
        }
    candidate = _head_candidate(tokens, heads)
    if candidate is None:
        return {
            "decided": True, "hit": False, "head": "", "src": "",
            "version": inv.get("version", ""),
            "device_build": inv.get("device_os_build", ""),
            "origin": "", "reason_code": XML_COMMAND_NOT_FOUND,
        }
    head, entry, rem = candidate
    parameter_error = _parameter_contract_error(rem, entry)
    if parameter_error is not None:
        return {
            "decided": True, "hit": False, "head": head,
            "src": str(entry.get("src", "")),
            "version": inv.get("version", ""),
            "device_build": inv.get("device_os_build", ""),
            "origin": str(entry.get("origin") or ""),
            "reason_code": "parameter_contract_violation",
            "parameter_error": parameter_error,
        }
    return {"decided": True, "hit": True, "head": head,
            "src": str(entry.get("src", "")), "version": inv.get("version", ""),
            "device_build": inv.get("device_os_build", ""),
            "origin": str(entry.get("origin") or "")}


def load_projection(path: str | Path) -> dict:
    """读投影 JSON；形态不对（没有 heads 映射）就报错，不把“读不到”当成“命令不存在”。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("heads"), dict):
        raise ValueError(f"{path} 不是命令树投影（缺 heads 映射）")
    return data
