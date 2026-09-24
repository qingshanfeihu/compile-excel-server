"""用例 IR（skill 剪切版）。

上游来源：InfoTest_Engine main/case_compiler/case_ir.py。
只保留 FileIR / CaseIR / Step / Row 四个数据结构；
上游的契约白名单与 G/I 语法校验（validate_row / validate_case）不随包分发
——G 列内容合法性归 agent，InfoTest lint 复核兜底。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Row:

    test_object: str = ""
    method: str = ""
    data: str = ""
    save_as: Optional[str] = None
    input_var: Optional[str] = None
    provenance: Optional[str] = None

    def is_check_point(self) -> bool:
        return self.test_object == "check_point"


@dataclass
class Step:

    stmt_type: int
    description: str
    rows: list[Row] = field(default_factory=list)


@dataclass
class CaseIR:

    autoid: str
    priority: str = "P1"
    title: str = ""
    steps: list[Step] = field(default_factory=list)
    source_module: str = ""
    source_text: str = ""
    expected: list[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: list[str] = field(default_factory=list)
    is_passthrough: bool = False

    def check_point_count(self) -> int:
        return sum(1 for st in self.steps for r in st.rows if r.is_check_point())


@dataclass
class FileIR:

    feature: str
    author: str = "IST-Core"
    init_rows: list[Row] = field(default_factory=list)
    cases: list[CaseIR] = field(default_factory=list)
    module: str = ""
    rejected: list[dict] = field(default_factory=list)
    questions: list[dict] = field(default_factory=list)


__all__ = ["Row", "Step", "CaseIR", "FileIR"]
