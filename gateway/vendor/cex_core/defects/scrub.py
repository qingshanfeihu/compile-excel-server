"""缺陷单文本脱敏与禁入判定。

逐字抽自 InfoTest main/defect_spec_source.py（scrub_declaration_text、contains_prohibited_declaration
及其依赖的正则与归一函数）。改判据先改 InfoTest 源再重新抽取，不在这里手改。
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>]+", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"(?<!\w)[A-Za-z]:\\(?:[^\s\\]+\\)*[^\s\\]+")
_UNIX_PATH_RE = re.compile(r"(?<![\w:])/(?:[^\s/]+/)+[^\s/]+")
_REPO_PATH_RE = re.compile(
    r"\b(?:workspace|knowledge|runtime|main|tests)/(?:[^\s/]+/)*[^\s/]+"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_ENV_KEY_BODY = (
    r"[A-Za-z][A-Za-z0-9_]*"
    r"(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|ACCESS_KEY|LICENSE_KEY)"
)
_GENERIC_CREDENTIAL_KEY_BODY = (
    rf"(?:{_ENV_KEY_BODY}|password|passwd|pwd|secret|api[_ -]?key|"
    r"access[_ -]?token|authorization|cookie|license[_ -]?key)"
)
_CREDENTIAL_RE = re.compile(
    r"(?im)\b(?:password|passwd|pwd|secret|api[_ -]?key|access[_ -]?token|"
    r"authorization|cookie|license[_ -]?key)\b\s*[:=]\s*[^\r\n]+"
)
_ENV_CREDENTIAL_RE = re.compile(
    rf"(?im)(?<![A-Za-z0-9_])[\"']?{_ENV_KEY_BODY}"
    r"[\"']?\s*[:=]\s*(?:[\"'][^\"'\r\n]*[\"']|[^\r\n]+)"
)
_HTML_TAG_RE = re.compile(r"</?[A-Za-z][^>\r\n]*>")
_HTML_BLOCK_TAG_RE = re.compile(
    r"</?(?:h[1-6]|p|div|li|br|tr|td|th|section|article)[^>\r\n]*>",
    re.IGNORECASE,
)
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]\r\n]+)\]\([^\)\r\n]*\)")
_DECORATED_CREDENTIAL_KEY_RE = re.compile(
    rf"(?im)(?<![A-Za-z0-9_])(?:\*\*|__|`{{1,3}})?[\"']?"
    rf"(?P<key>{_GENERIC_CREDENTIAL_KEY_BODY})[\"']?"
    r"(?:\*\*|__|`{1,3})?\s*(?P<sep>[:=])"
)
_YAML_CREDENTIAL_BLOCK_RE = re.compile(
    rf"(?im)^[ \t]*[\"']?{_GENERIC_CREDENTIAL_KEY_BODY}[\"']?\s*[:=]"
    r"\s*[|>][+-]?[ \t]*(?:\r?\n[ \t]+[^\r\n]*)+"
)
_MARKDOWN_TABLE_CREDENTIAL_RE = re.compile(
    rf"(?im)^[ \t]*\|[ \t]*(?:\*\*|__|`{{1,3}})?[\"']?"
    rf"{_GENERIC_CREDENTIAL_KEY_BODY}[\"']?(?:\*\*|__|`{{1,3}})?"
    r"[ \t]*\|[ \t]*[^|\r\n]+(?:\|[^\r\n]*)?$"
)
_ADJACENT_CREDENTIAL_VALUE_RE = re.compile(
    rf"(?im)^[ \t|]*(?:\*\*|__|`{{1,3}})?[\"']?"
    rf"{_GENERIC_CREDENTIAL_KEY_BODY}[\"']?(?:\*\*|__|`{{1,3}})?"
    r"(?:[ \t]*\|[ \t]*[^|\r\n]+|\r?\n[ \t]*[^\r\n]+|"
    r"[ \t]+[^|\r\n]+)(?:\|[^\r\n]*)?$"
)
_AUTH_SCHEME_CREDENTIAL_RE = re.compile(
    r"(?im)(?<![A-Za-z0-9_])authorization\s+(?:bearer|basic)\s+\S+"
)
_CLI_CREDENTIAL_RE = re.compile(
    rf"(?im)(?<![A-Za-z0-9_])--(?:{_GENERIC_CREDENTIAL_KEY_BODY})"
    r"(?:\s*=\s*|\s+)(?:[\"'][^\"'\r\n]*[\"']|\S+)"
)
_SENSITIVE_CREDENTIAL_KEY_RE = re.compile(
    rf"^(?:{_GENERIC_CREDENTIAL_KEY_BODY})$",
    re.IGNORECASE,
)
_PROHIBITED_HEADING_RE = re.compile(
    r"(?:actual\s+(?:results?|behaviors?|outputs?)|"
    r"observed\s+(?:results?|behaviors?|outputs?)|actual|"
    r"log\s+(?:outputs?|entries?|history)|logs?|"
    r"steps?\s+to\s+reproduce|reproduction(?:\s+steps?)?|"
    r"repro(?:duction)?(?:\s+steps?)?|comment\s+history|comments?|"
    r"how\s+to\s+reproduce|cli\s+output|notes?|remarks?|show\s+version|"
    r"detail\s+information|实际结果|"
    r"实际现象|当前结果|实际输出|复现步骤|复现过程|评论|备注|日志|"
    r"复现|设备回显)",
    re.IGNORECASE,
)
_PROHIBITED_LABEL_RE = re.compile(
    rf"(?<![A-Za-z0-9_])(?:{_PROHIBITED_HEADING_RE.pattern})"
    r"(?:\s*(?:for|on|/|[-–—]|[\[(（【])[^:：\r\n]*)?\s*(?:[:：]|$)",
    re.IGNORECASE,
)
_MARKDOWN_DECORATION_RE = re.compile(r"^[*_~`\s]+|[*_~`\s]+$")
_ATX_OPEN_RE = re.compile(r"^#{1,6}\s+")
_ATX_CLOSE_RE = re.compile(r"\s+#{1,6}\s*$")
_BLOCKQUOTE_RE = re.compile(r"^>\s*")
_UNORDERED_LIST_RE = re.compile(r"^[-+*]\s+")
_ORDERED_LIST_RE = re.compile(r"^\d+[.)、．]\s*")
_CHINESE_ORDER_RE = re.compile(
    r"^(?:[（(][一二三四五六七八九十百千]+[）)]|"
    r"[一二三四五六七八九十百千]+[、.)）．])\s*"
)
_TASK_LIST_RE = re.compile(r"^\[(?: |x|X)\]\s*")


def _normalize_security_markup(value: Any, *, preserve_blocks: bool) -> str:
    text = _ANSI_ESCAPE_RE.sub("", html.unescape(str(value or "")))
    text = "".join(
        char for char in text if unicodedata.category(char) != "Cf"
    )
    if preserve_blocks:
        text = _HTML_BLOCK_TAG_RE.sub("\n", text)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _MARKDOWN_LINK_RE.sub(lambda match: match.group(1), text)
    return text


def _normalize_credential_markup(value: Any) -> str:
    text = _normalize_security_markup(value, preserve_blocks=False)
    return _DECORATED_CREDENTIAL_KEY_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}",
        text,
    )


def is_sensitive_credential_key(value: Any) -> bool:
    normalized = _normalize_credential_markup(value).strip()
    normalized = _MARKDOWN_DECORATION_RE.sub("", normalized).strip()
    normalized = normalized.strip("|[](){}<>\"' ")
    normalized = normalized.removeprefix("--")
    return bool(_SENSITIVE_CREDENTIAL_KEY_RE.fullmatch(normalized))


def _contains_credential_material(value: Any) -> bool:
    normalized = _normalize_credential_markup(value)
    from ..security_scrub import scrub_text

    return bool(
        scrub_text(normalized, scrub_paths=False) != normalized
        or _PRIVATE_KEY_RE.search(normalized)
        or _YAML_CREDENTIAL_BLOCK_RE.search(normalized)
        or _MARKDOWN_TABLE_CREDENTIAL_RE.search(normalized)
        or _ADJACENT_CREDENTIAL_VALUE_RE.search(normalized)
        or _AUTH_SCHEME_CREDENTIAL_RE.search(normalized)
        or _CLI_CREDENTIAL_RE.search(normalized)
        or _ENV_CREDENTIAL_RE.search(normalized)
        or _CREDENTIAL_RE.search(normalized)
    )


def contains_credential_material(value: Any) -> bool:
    return _contains_credential_material(value)


def _coverage(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left)


def _dice(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return 2 * len(left & right) / (len(left) + len(right))


def scrub_declaration_text(value: Any, *, limit: int = 8000) -> str:
    text = _CONTROL_RE.sub("", _normalize_credential_markup(value))
    if _contains_credential_material(text):
        return "[redacted-credential-field]"[:limit]
    text = _PRIVATE_KEY_RE.sub("[redacted-private-key]", text)
    text = _YAML_CREDENTIAL_BLOCK_RE.sub("[redacted-credential]", text)
    text = _ENV_CREDENTIAL_RE.sub("[redacted-credential]", text)
    text = _CREDENTIAL_RE.sub("[redacted-credential]", text)
    text = _URL_RE.sub("[redacted-url]", text)
    text = _WINDOWS_PATH_RE.sub("[redacted-path]", text)
    text = _UNIX_PATH_RE.sub("[redacted-path]", text)
    text = _REPO_PATH_RE.sub("[redacted-path]", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:limit]


def contains_prohibited_declaration(value: Any) -> bool:
    normalized = _normalize_security_markup(value, preserve_blocks=True)
    for raw_line in normalized.splitlines():
        line = raw_line.strip()
        for _ in range(12):
            previous = line
            for pattern in (
                _BLOCKQUOTE_RE,
                _ATX_OPEN_RE,
                _UNORDERED_LIST_RE,
                _ORDERED_LIST_RE,
                _CHINESE_ORDER_RE,
                _TASK_LIST_RE,
            ):
                line = pattern.sub("", line, count=1).strip()
            if line == previous:
                break
        line = _ATX_CLOSE_RE.sub("", line).strip()
        line = _MARKDOWN_DECORATION_RE.sub("", line).strip()
        if not line:
            continue
        if _PROHIBITED_LABEL_RE.search(line):
            return True
        if line.startswith("[") and "]" in line:
            heading = line[1 : line.index("]")]
        else:
            heading = re.split(r"[:：]", line, maxsplit=1)[0]
        heading = _ATX_CLOSE_RE.sub("", heading).strip()
        heading = _MARKDOWN_DECORATION_RE.sub("", heading).strip()
        match = _PROHIBITED_HEADING_RE.match(heading)
        qualifier = heading[match.end():] if match is not None else ""
        if match is not None and (
            not qualifier
            or re.fullmatch(
                r"\s*(?:[\[(（【].*[\])）】]|[-–—]\s*.+)",
                qualifier,
            )
        ):
            return True
    return False


