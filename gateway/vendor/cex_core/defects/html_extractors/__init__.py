# ruff: noqa: F401, F601
# 移植自 InfoTest main/ingest/html_extractors/__init__.py：逐字复制，只把包内导入改成相对导入。

from __future__ import annotations

from typing import Protocol

from .schema import DefectTicket

__all__ = ["DefectExtractor", "DefectTicket", "get_extractor", "canonical_backend"]


class DefectExtractor(Protocol):
    backend: str
    version: str

    def extract(self, html: str) -> DefectTicket: ...


def canonical_backend(backend: str) -> str:
    return (backend or "").strip().lower()


def get_extractor(backend: str) -> DefectExtractor:
    b = (backend or "").strip().lower()
    if b == "bugzilla":
        from .bugzilla import BugzillaExtractor

        return BugzillaExtractor()
    if b == "zentao":
        from .zentao import ZentaoExtractor

        return ZentaoExtractor()
    if b == "zentao_story":
        from .zentao import ZentaoStoryExtractor

        return ZentaoStoryExtractor()
    raise ValueError(f"未知 backend: {backend}")
