# ruff: noqa: F401, F601
# 移植自 InfoTest main/ingest/html_extractors/zentao.py：逐字复制，只把包内导入改成相对导入。

from __future__ import annotations

import hashlib
import re
from typing import Any

from bs4 import BeautifulSoup

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
from ._zh_fold import fold_zh_label
from .schema import Attachment, DefectTicket


def _resolve_zentao_cfg() -> dict[str, Any]:
    cfg = load_selectors() or {}
    return cfg.get("zentao") or {}


def select_by_th_label(soup: BeautifulSoup, labels: list[str]) -> str:
    if not labels:
        return ""
    label_set = {fold_zh_label(label.strip()) for label in labels if label}
    for sel in ("th", "td.w-80px", "label", "strong"):
        for el in soup.select(sel):
            text = fold_zh_label(el.get_text(" ", strip=True).rstrip("：:"))
            if text and text in label_set:
                sib = el.find_next_sibling("td")
                if sib is not None:
                    val = sib.get_text(" ", strip=True)
                    if val:
                        return val
                nxt = el.find_next("td")
                if nxt is not None and nxt is not el:
                    val = nxt.get_text(" ", strip=True)
                    if val:
                        return val
    return ""


def select_all_by_th_label(soup: BeautifulSoup, labels: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    if not labels:
        return out
    label_set = {fold_zh_label(label.strip()) for label in labels if label}
    for el in soup.select("th, td.w-80px, label, strong"):
        text = fold_zh_label(el.get_text(" ", strip=True).rstrip("：:"))
        if text and text in label_set:
            sib = el.find_next_sibling("td")
            if sib is None:
                continue
            items = [li.get_text(" ", strip=True) for li in sib.find_all("li")]
            if not items:
                raw = sib.get_text(" ", strip=True)
                items = [s.strip() for s in re.split(r"[\s,，、;；/]+", raw) if s.strip()]
            for it in items:
                if it and it not in seen:
                    seen.add(it)
                    out.append(it)
    return out


def _zentao_severity_map(raw: str) -> str:
    if not raw:
        return "low"
    s = str(raw).strip()
    m = re.match(r"^(\d)", s)
    if m:
        n = int(m.group(1))
        return {1: "low", 2: "mid", 3: "high", 4: "critical"}.get(n, "low")
    return normalize_severity(s)


def _zentao_status_map(raw: str) -> str:
    s = fold_zh_label((raw or "").strip()).lower()
    if not s:
        # Do not invent "open": that default hid Traditional-label misses
        # (status always looked present, only product was empty).
        return ""
    if any(k in s for k in ("已解决", "已关闭", "已修复", "closed", "resolved", "fixed")):
        return "fixed"
    if any(k in s for k in ("激活", "新建", "new", "active", "triage")):
        return "triage"
    return normalize_status(s)


_NUM_RE = re.compile(r"#?(\d{2,6})")


_INVALID_ZENTAO_SIGNALS = [
    "没有匹配的结果",
    "无搜索结果",
    "未找到匹配",
    "no results",
    "您没有访问权限",
    "无访问权限",
    "您无权",
    "page not found",
    "404 - 找不到页面",
    "bug 不存在",
    "需求不存在",
    "story not exist",
]


def _detect_zentao_invalid(soup) -> str:
    body_text = soup.get_text(" ", strip=True).lower()
    for sig in _INVALID_ZENTAO_SIGNALS:
        if sig in body_text:
            return f"zentao_signal:{sig}"
    title_el = soup.find("title")
    if title_el is not None:
        title = title_el.get_text(strip=True).lower()
        if any(t in title for t in ("404", "not found", "无权", "无搜索结果")):
            return f"zentao_title:{title[:60]}"
    
    
    return ""


def _extract_id_list(text: str, prefix: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in _NUM_RE.finditer(text):
        key = f"{prefix}-{m.group(1)}"
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


class ZentaoExtractor:

    backend = "zentao"
    version = "v2"

    def __init__(self, *, doc_type: str = "bug") -> None:
        self.doc_type_hint = doc_type

    def extract(self, html: str) -> DefectTicket:
        if not html:
            return DefectTicket(ticket_id="UNKNOWN", backend=self.backend)

        cfg = _resolve_zentao_cfg()
        self.version = cfg.get("version") or self.version
        soup = make_soup(html)

        invalid_reason = _detect_zentao_invalid(soup)

        th_labels = cfg.get("th_labels") or {}

        raw_id = select_text(soup, cfg.get("ticket_id", []))
        ticket_id = extract_ticket_id(raw_id) or raw_id or "UNKNOWN"

        
        title = select_by_th_label(soup, th_labels.get("title", []))
        if not title and raw_id:
            title = re.sub(r"^Bug\s*#?\d+[\s:：]*", "", raw_id).strip() or raw_id

        
        
        
        if not invalid_reason and ticket_id == "UNKNOWN" and not title:
            invalid_reason = "zentao_no_detail_data"

        product = select_by_th_label(soup, th_labels.get("product", []))
        module = select_by_th_label(soup, th_labels.get("module", []))
        severity_raw = select_by_th_label(soup, th_labels.get("severity", []))
        severity = _zentao_severity_map(severity_raw)
        priority = select_by_th_label(soup, th_labels.get("priority", []))
        status_raw = select_by_th_label(soup, th_labels.get("status", []))
        status = _zentao_status_map(status_raw)
        resolution = normalize_resolution(select_by_th_label(soup, th_labels.get("resolution", [])))

        description = select_by_th_label(soup, th_labels.get("description", []))
        if not description:
            description = select_text(soup, cfg.get("description_blocks", []))
        steps = select_by_th_label(soup, th_labels.get("steps_to_reproduce", []))
        fix_summary = select_by_th_label(soup, th_labels.get("fix_summary", []))

        
        reported_by = select_by_th_label(soup, th_labels.get("reported_by", []))
        reported_at = select_by_th_label(soup, th_labels.get("reported_at", []))
        resolved_by = select_by_th_label(soup, th_labels.get("resolved_by", []))
        resolved_at = select_by_th_label(soup, th_labels.get("resolved_at", []))

        
        affected = [
            fold_zh_label(item)
            for item in select_all_by_th_label(soup, th_labels.get("affected_versions", []))
        ]
        fixed_versions = [
            fold_zh_label(item)
            for item in select_all_by_th_label(soup, th_labels.get("fixed_versions", []))
        ]
        fixed_commit = select_by_th_label(soup, th_labels.get("fixed_commit", []))

        
        related_story = select_by_th_label(soup, th_labels.get("related_story", []))
        related_case = select_by_th_label(soup, th_labels.get("related_case_ids", []))
        related_task = select_by_th_label(soup, th_labels.get("related_task_ids", []))
        related_bug = select_by_th_label(soup, th_labels.get("related_bug_ids", []))

        related_story_ids = _extract_id_list(related_story, "STORY")
        related_case_ids = _extract_id_list(related_case, "TC")
        related_task_ids = _extract_id_list(related_task, "TASK")
        related_bug_ids = _extract_id_list(related_bug, "ZT")

        
        related_feature_ids: list[str] = []
        for sid in related_story_ids:
            m = _NUM_RE.search(sid)
            if m:
                related_feature_ids.append(m.group(1))

        
        activated_raw = select_by_th_label(soup, th_labels.get("activated_count", []))
        activated_count = parse_int(activated_raw, 0)

        
        attachment_urls = select_attrs(soup, cfg.get("attachments", []), "href")
        attachment_names = select_texts(soup, cfg.get("attachments", []))
        attachments = [
            Attachment(url=url, filename=attachment_names[i] if i < len(attachment_names) else "")
            for i, url in enumerate(attachment_urls)
        ]

        
        doc_type = self.doc_type_hint or "bug"
        if ticket_id.upper().startswith(("STORY", "REQ", "PLM")):
            doc_type = "plm_ticket"

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
            description=description,
            steps_to_reproduce=steps,
            fix_summary=fix_summary,
            reported_by=reported_by,
            reported_at=reported_at,
            resolved_by=resolved_by,
            resolved_at=resolved_at,
            affected_versions=affected,
            fixed_versions=fixed_versions,
            fixed_commit=fixed_commit,
            related_feature_ids=related_feature_ids,
            related_case_ids=related_case_ids,
            related_story_ids=related_story_ids,
            related_task_ids=related_task_ids,
            related_bug_ids=related_bug_ids,
            activated_count=activated_count,
            attachments=attachments,
            backend=self.backend,
            doc_type=doc_type,
            html_sha256=html_sha,
            invalid_reason=invalid_reason,
        )


class ZentaoStoryExtractor(ZentaoExtractor):

    def __init__(self) -> None:
        super().__init__(doc_type="plm_ticket")
