# 移植自 InfoTest main/ingest/html_extractors/schema.py：字段、默认值与方法逐字保留；
# 客户端不依赖 pydantic，所以换成 dataclass（extra="allow" 的额外字段不保留）。
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Attachment:
    url: str
    filename: str = ""


@dataclass
class DefectTicket:
    """HTML 解析后的统一缺陷/需求模型。"""

    ticket_id: str
    invalid_reason: str = ""

    
    title: str = ""
    module: str = ""
    product: str = ""
    severity: str = "low"
    priority: str = ""
    status: str = "open"
    resolution: str = ""
    description: str = ""
    steps_to_reproduce: str = ""
    fix_summary: str = ""

    
    reported_by: str = ""
    reported_at: str = ""
    resolved_by: str = ""
    resolved_at: str = ""

    
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    fixed_commit: str = ""

    
    related_feature_ids: list[str] = field(default_factory=list)
    related_case_ids: list[str] = field(default_factory=list)
    related_story_ids: list[str] = field(default_factory=list)
    related_task_ids: list[str] = field(default_factory=list)
    related_bug_ids: list[str] = field(default_factory=list)

    
    activated_count: int = 0
    comments_count: int = 0

    attachments: list[Attachment] = field(default_factory=list)

    
    backend: str = ""
    doc_type: str = "bug"
    source_html_path: str = ""
    html_sha256: str = ""
    captured_at: str = ""

    def is_valid_detail(self) -> bool:
        if self.invalid_reason:
            return False
        tid = (self.ticket_id or "").strip().upper()
        if not tid or tid == "UNKNOWN":
            return False
        if not (self.title or "").strip() and not (self.description or "").strip():
            return False
        return True

    def identity_metadata_complete(self) -> bool:
        return bool((self.product or "").strip()) and bool((self.status or "").strip())

    def to_index_dict(self) -> dict:
        pc_parts = [
            f"[{self.ticket_id}][{self.module}][Sev={self.severity}]"
            f"{('[Pri=' + self.priority + ']') if self.priority else ''}"
            f" {self.title}",
        ]
        if self.product and self.product != self.module:
            pc_parts.append(f"产品: {self.product}")
        if self.description:
            pc_parts.append(self.description)
        if self.steps_to_reproduce:
            pc_parts.append("复现:\n" + self.steps_to_reproduce)
        if self.fix_summary:
            pc_parts.append("修复: " + self.fix_summary)
        if self.resolution:
            pc_parts.append(f"解决方案类型: {self.resolution}")
        timeline_parts: list[str] = []
        if self.reported_by or self.reported_at:
            timeline_parts.append(f"由 {self.reported_by} 提交于 {self.reported_at}".strip())
        if self.resolved_by or self.resolved_at:
            timeline_parts.append(f"由 {self.resolved_by} 解决于 {self.resolved_at}".strip())
        if timeline_parts:
            pc_parts.append(" / ".join(p for p in timeline_parts if p))
        relation_parts: list[str] = []
        if self.related_case_ids:
            relation_parts.append(f"相关用例: {', '.join(self.related_case_ids)}")
        if self.related_story_ids:
            relation_parts.append(f"相关需求: {', '.join(self.related_story_ids)}")
        if self.related_task_ids:
            relation_parts.append(f"相关任务: {', '.join(self.related_task_ids)}")
        if self.related_bug_ids:
            relation_parts.append(f"相关 Bug: {', '.join(self.related_bug_ids)}")
        if relation_parts:
            pc_parts.append("\n".join(relation_parts))
        page_content = "\n\n".join(p for p in pc_parts if p)

        return {
            "ticket_id": self.ticket_id,
            "page_content": page_content,
            "title": self.title,
            "description": self.description,
            "steps_to_reproduce": self.steps_to_reproduce,
            "fix_summary": self.fix_summary,
            "metadata": {
                "doc_type": self.doc_type,
                "module": self.module,
                "product": self.product,
                "severity": self.severity,
                "priority": self.priority,
                "status": self.status,
                "resolution": self.resolution,
                "reported_by": self.reported_by,
                "reported_at": self.reported_at,
                "resolved_by": self.resolved_by,
                "resolved_at": self.resolved_at,
                "affected_versions": self.affected_versions,
                "fixed_versions": self.fixed_versions,
                "fixed_commit": self.fixed_commit,
                "related_feature_ids": self.related_feature_ids,
                "related_case_ids": self.related_case_ids,
                "related_story_ids": self.related_story_ids,
                "related_task_ids": self.related_task_ids,
                "related_bug_ids": self.related_bug_ids,
                "activated_count": self.activated_count,
                "comments_count": self.comments_count,
                "backend": self.backend,
                "source_html_path": self.source_html_path,
                "html_sha256": self.html_sha256,
                "captured_at": self.captured_at,
            },
        }

    def to_dict(self) -> dict:
        return asdict(self)
