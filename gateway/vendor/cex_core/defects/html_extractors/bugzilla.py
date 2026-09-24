# ruff: noqa: F401, F601
# 移植自 InfoTest main/ingest/html_extractors/bugzilla.py：逐字复制，只把包内导入改成相对导入。

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from ._common import (
    extract_ticket_id,
    load_selectors,
    make_soup,
    normalize_resolution,
    normalize_severity,
    normalize_status,
    parse_int,
    select_attrs,
    select_text,
    select_texts,
)
from .schema import Attachment, DefectTicket

logger = logging.getLogger(__name__)

_DESCRIPTION_MIN_CHARS = 40
_DESCRIPTION_COMMENT_LIMIT = 3


_VERSION_LINE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "affected": ("Affected Release", "Affected Version", "Affected in", "影响版本", "影响范围"),
    "fixed": ("Fixed in", "Fixed Release", "Fixed Version", "修复版本", "已修复版本"),
}


def _extract_versions_from_text(text: str, keys: tuple[str, ...]) -> list[str]:
    if not text:
        return []
    for kw in keys:
        m = re.search(rf"{re.escape(kw)}\s*[:：]\s*([^\n\r]+)", text, re.IGNORECASE)
        if m:
            parts = re.split(r"[\s,;、，；]+", m.group(1).strip())
            return [p for p in parts if p and len(p) <= 40]
    return []


_INVALID_BUGZILLA_SIGNALS = [
    "you are not authorized to access bug",
    "there is no bug with the id",
    "bug not found",
    "invalid bug id",
    "access denied",
]


def _detect_bugzilla_invalid(soup) -> str:
    body_text = soup.get_text(" ", strip=True).lower()
    for sig in _INVALID_BUGZILLA_SIGNALS:
        if sig in body_text:
            return f"bugzilla_signal:{sig}"
    title_el = soup.find("title")
    if title_el is not None:
        title = title_el.get_text(strip=True).lower()
        if any(t in title for t in ("not found", "invalid", "access denied")):
            return f"bugzilla_title:{title[:60]}"
    return ""


def _bugzilla_description_fallback(soup, sel: dict) -> str:
    primary = select_text(soup, sel.get("description", []))
    if primary and len(primary) >= _DESCRIPTION_MIN_CHARS:
        return primary
    comment_selectors = sel.get("description_comments", []) or ["pre.bz_comment_text"]
    comments: list[str] = []
    for css in comment_selectors:
        for el in soup.select(css):
            text = el.get_text(" ", strip=True)
            if text and text not in comments:
                comments.append(text)
            if len(comments) >= _DESCRIPTION_COMMENT_LIMIT:
                break
        if len(comments) >= _DESCRIPTION_COMMENT_LIMIT:
            break
    merged = "\n\n".join(comments)
    if primary and len(merged) > len(primary):
        return merged
    return primary or merged


_FIX_TEMPLATE_KEY_GROUPS: list[tuple[str, ...]] = [
    ("fixed details:", "fix details:", "修复详情", "修复方案", "solution:"),
    ("root cause:", "根本原因", "根因:", "根因："),
    ("condition of occurrence", "发生条件", "复现条件"),
    ("affected release", "affected version", "影响版本", "影响范围"),
    ("testing suggestions", "测试建议", "验证建议"),
]
_FIX_TEMPLATE_MIN_SCORE = 2


def _score_fix_template(text: str) -> int:
    lower = text.lower()
    score = 0
    for group in _FIX_TEMPLATE_KEY_GROUPS:
        if any(variant in lower for variant in group):
            score += 1
    return score


def _bugzilla_fix_summary_fallback(soup, sel: dict) -> str:
    
    primary = select_text(soup, sel.get("fix_summary", []))
    if primary:
        return primary

    
    candidates: list[tuple[int, int, str]] = []
    for el in soup.select("pre.bz_comment_text, div.bz_comment_text"):
        text = el.get_text(" ", strip=True)
        if not text:
            continue
        score = _score_fix_template(text)
        if score >= _FIX_TEMPLATE_MIN_SCORE:
            candidates.append((score, len(text), text))
    if candidates:
        
        candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
        return candidates[0][2]

    
    keywords = [k.lower() for k in (sel.get("fix_summary_keywords") or [])]
    if not keywords:
        return primary or ""
    for el in soup.select("pre.bz_comment_text, div.bz_comment_text"):
        text = el.get_text(" ", strip=True)
        lower = text.lower()
        if any(kw in lower for kw in keywords):
            return text
    return primary or ""


_RELATED_BUG_RE = re.compile(r"(?:bug|show_bug\.cgi\?id=)\s*#?(\d{3,6})", re.IGNORECASE)


def _bugzilla_related_bug_ids(soup, sel: dict) -> list[str]:
    texts = select_texts(soup, sel.get("related_bug_ids", []))
    ids: list[str] = []
    seen: set[str] = set()
    for t in texts:
        m = _RELATED_BUG_RE.search(t)
        if m:
            val = f"BUG-{m.group(1)}"
            if val not in seen:
                seen.add(val)
                ids.append(val)
    
    for link_sel in sel.get("related_bug_ids", []):
        for el in soup.select(link_sel):
            href = el.get("href") or ""
            m = _RELATED_BUG_RE.search(href)
            if m:
                val = f"BUG-{m.group(1)}"
                if val not in seen:
                    seen.add(val)
                    ids.append(val)
    return ids


def _bugzilla_comments_count(soup) -> int:
    return len(soup.select("pre.bz_comment_text")) or len(soup.select("div.bz_comment_text"))


class BugzillaExtractor:
    backend = "bugzilla"
    version = "v3"

    def extract(self, html: str) -> DefectTicket:
        if not html:
            return DefectTicket(ticket_id="UNKNOWN", backend=self.backend)

        sel = (load_selectors().get("bugzilla") or {})
        self.version = sel.get("version") or self.version
        soup = make_soup(html)

        
        invalid_reason = _detect_bugzilla_invalid(soup)

        raw_id = select_text(soup, sel.get("ticket_id", []))
        ticket_id = extract_ticket_id(raw_id) or raw_id or "UNKNOWN"

        title = select_text(soup, sel.get("title", []))
        product = select_text(soup, sel.get("product", []))
        module = select_text(soup, sel.get("module", []))
        severity = normalize_severity(select_text(soup, sel.get("severity", [])))
        priority = select_text(soup, sel.get("priority", []))
        status = normalize_status(select_text(soup, sel.get("status", [])))
        resolution = normalize_resolution(select_text(soup, sel.get("resolution", [])))

        reported_by = select_text(soup, sel.get("reported_by", []))
        reported_at = select_text(soup, sel.get("reported_at", []))
        resolved_by = select_text(soup, sel.get("resolved_by", []))
        resolved_at = select_text(soup, sel.get("resolved_at", []))

        description = _bugzilla_description_fallback(soup, sel)
        steps = select_text(soup, sel.get("steps_to_reproduce", []))
        fix_summary = _bugzilla_fix_summary_fallback(soup, sel)

        affected = select_texts(soup, sel.get("affected_versions", []))
        fixed_versions = select_texts(soup, sel.get("fixed_versions", []))
        fixed_commit = select_text(soup, sel.get("fixed_commit", []))

        
        if not affected:
            affected = _extract_versions_from_text(
                f"{description}\n{fix_summary}", _VERSION_LINE_KEYWORDS["affected"]
            )
        if not fixed_versions:
            fixed_versions = _extract_versions_from_text(
                f"{description}\n{fix_summary}", _VERSION_LINE_KEYWORDS["fixed"]
            )

        related_bugs = _bugzilla_related_bug_ids(soup, sel)

        attachment_urls = select_attrs(soup, sel.get("attachments", []), "href")
        attachment_names = select_texts(soup, sel.get("attachments", []))
        attachments = [
            Attachment(url=url, filename=attachment_names[i] if i < len(attachment_names) else "")
            for i, url in enumerate(attachment_urls)
        ]

        html_sha = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()[:16]

        return DefectTicket(
            ticket_id=ticket_id,
            title=title,
            product=product,
            module=module,
            severity=severity,
            priority=priority,
            status=status,
            resolution=resolution,
            reported_by=reported_by,
            reported_at=reported_at,
            resolved_by=resolved_by,
            resolved_at=resolved_at,
            description=description,
            steps_to_reproduce=steps,
            fix_summary=fix_summary,
            affected_versions=affected,
            fixed_versions=fixed_versions,
            fixed_commit=fixed_commit,
            related_bug_ids=related_bugs,
            comments_count=_bugzilla_comments_count(soup),
            attachments=attachments,
            backend=self.backend,
            doc_type="bug",
            html_sha256=html_sha,
            invalid_reason=invalid_reason,
        )
