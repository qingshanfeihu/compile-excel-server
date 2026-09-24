"""缺陷页 HTML → 已校验、已脱敏的缺陷单。

单号归一与校验（_RAW_ID_RE、_CLEAN_*、_backend_dir、_canonical_requested_ticket、
_validate_extracted_ticket）逐字抽自 InfoTest main/ingest/defect_parse.py；
文本脱敏用 scrub.scrub_declaration_text（逐字抽自 InfoTest defect_spec_source）。
与 InfoTest 不同的只有落盘：这里不写任何文件，只返回结果，由调用方决定放哪。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .html_extractors import get_extractor
from .scrub import scrub_declaration_text

_BACKEND_DIRS = {
    "bugzilla": "bugzilla",
    "zentao": "zentao",
    "zentao_story": "zentao",
}
_RAW_ID_RE = re.compile(r"(?:(BUG|BZ|PLM|ZT|STORY|REQ)-)?(\d+)", re.IGNORECASE)
_CLEAN_BUG_ID_RE = re.compile(r"BUG-[1-9]\d*")
_CLEAN_STORY_ID_RE = re.compile(r"STORY-[1-9]\d*")
MAX_HTML_BYTES = 32 * 1024 * 1024

# 自由文本字段一律过脱敏；单号、状态这类闭集字段不动
_FREE_TEXT_FIELDS = ("title", "description", "steps_to_reproduce", "fix_summary", "module",
                     "product", "resolution")
# 人名、附件链接、源文件路径不出客户端
_DROPPED_FIELDS = ("reported_by", "resolved_by", "attachments", "source_html_path")


class DefectParseError(ValueError):
    pass


def _backend_dir(backend: str) -> str:
    key = (backend or "").strip().lower()
    try:
        return _BACKEND_DIRS[key]
    except KeyError as exc:
        raise ValueError("unsupported defect backend") from exc


def _canonical_requested_ticket(backend_dir: str, raw_stem: str) -> str:
    match = _RAW_ID_RE.fullmatch(raw_stem)
    if match is None:
        raise ValueError("raw defect filename has an invalid ticket id")
    prefix = (match.group(1) or "").upper()
    number_value = int(match.group(2))
    if number_value < 1:
        raise ValueError("raw defect filename has an invalid ticket id")
    number = str(number_value)
    if backend_dir == "bugzilla":
        if prefix not in {"", "BUG", "BZ"}:
            raise ValueError("raw defect filename does not match backend")
        return f"BUG-{number}"
    if prefix in {"STORY", "REQ"}:
        return f"STORY-{number}"
    if prefix in {"", "BUG", "PLM", "ZT"}:
        return f"BUG-{number}"
    raise ValueError("raw defect filename does not match backend")


def _validate_extracted_ticket(
    backend_dir: str,
    raw_stem: str,
    ticket_id: object,
) -> str:
    value = str(ticket_id or "").strip().upper()
    allowed = (
        _CLEAN_BUG_ID_RE.fullmatch(value) is not None
        if backend_dir == "bugzilla"
        else (
            _CLEAN_BUG_ID_RE.fullmatch(value) is not None
            or _CLEAN_STORY_ID_RE.fullmatch(value) is not None
        )
    )
    if not allowed:
        raise ValueError("extracted defect ticket id is outside the closed set")
    if value != _canonical_requested_ticket(backend_dir, raw_stem):
        raise ValueError("extracted defect ticket id does not match raw request")
    return value


def canonical_ticket(backend: str, requested: str) -> str:
    """把用户给的单号（`12345`、`BUG-12345`、`STORY-7`…）归一；不合法就抛 DefectParseError。"""
    try:
        return _canonical_requested_ticket(_backend_dir(backend), str(requested or "").strip())
    except ValueError as exc:
        raise DefectParseError(str(exc)) from None


def parse_ticket_html(backend: str, requested: str, html: bytes | str) -> dict[str, Any]:
    """解析一张缺陷页。单号必须与请求的一致，页面必须是有效详情页；自由文本已脱敏。"""
    raw = html.encode("utf-8") if isinstance(html, str) else bytes(html)
    if not raw or len(raw) > MAX_HTML_BYTES:
        raise DefectParseError("defect HTML is empty or too large")
    try:
        backend_dir = _backend_dir(backend)
        ticket = get_extractor(backend).extract(raw.decode("utf-8", errors="ignore"))
        ticket_id = _validate_extracted_ticket(backend_dir, str(requested or "").strip(),
                                               ticket.ticket_id)
    except ValueError as exc:
        raise DefectParseError(str(exc)) from None
    if not ticket.is_valid_detail():
        raise DefectParseError(ticket.invalid_reason or "page is not a valid ticket detail")
    data = ticket.to_dict()
    data["ticket_id"] = ticket_id
    for key in _FREE_TEXT_FIELDS:
        data[key] = scrub_declaration_text(data.get(key) or "")
    for key in _DROPPED_FIELDS:
        data.pop(key, None)
    data["backend"] = (backend or "").strip().lower()
    data["html_sha256"] = hashlib.sha256(raw).hexdigest()
    return data
