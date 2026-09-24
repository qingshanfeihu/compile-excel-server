"""ist_emit：InfoTest emit_xlsx 的最小剪切（skill 分发版）。

模块清单与上游对应关系（剪切声明详见 reference/excel-contract.md）：
- _sealed_io.py      ← main/case_compiler/_sealed_io.py（全量；run_governance 钩子置空）
- config.py          ← main/case_compiler/config.py（全量；配置路径参数化）
- schema_identity.py ← main/common/schema_identity.py（全量）
- excel_contract.py  ← excel_contract.py 的 resolve_execution_sheet 子集（身份钉死）
- case_ir.py         ← case_ir.py 的 FileIR/CaseIR/Step/Row
- credential_literals.py ← 字面量源改为本地可选 deny 文件
- xlsx_emit.py       ← xlsx_emit.py（fd 级原子写盘；模板=内置冻结快照+SHA 钉死）

依赖：python3 标准库 + openpyxl。注意：openpyxl 只被 xlsx_emit 需要——
导出按需解析（PEP 562），login/fetch 等客户端只 import _sealed_io 时
不需要装 openpyxl。

出口名（按需导入）：CaseIR/FileIR/Row/Step、CONTRACT_MARKER/
EXECUTION_HEADERS/EXECUTION_SHEET_MARKER/PINNED_CONTRACT_SHA256/
TEMPLATE_SHA256、ExcelContractError、resolve_execution_sheet、
emit_xlsx、select_runtime_template。
"""

from typing import Any

_LAZY = {
    "CaseIR": ("ist_emit.case_ir", "CaseIR"),
    "FileIR": ("ist_emit.case_ir", "FileIR"),
    "Row": ("ist_emit.case_ir", "Row"),
    "Step": ("ist_emit.case_ir", "Step"),
    "CONTRACT_MARKER": ("ist_emit.excel_contract", "CONTRACT_MARKER"),
    "EXECUTION_HEADERS": ("ist_emit.excel_contract", "EXECUTION_HEADERS"),
    "EXECUTION_SHEET_MARKER": ("ist_emit.excel_contract", "EXECUTION_SHEET_MARKER"),
    "PINNED_CONTRACT_SHA256": ("ist_emit.excel_contract", "PINNED_CONTRACT_SHA256"),
    "TEMPLATE_SHA256": ("ist_emit.excel_contract", "TEMPLATE_SHA256"),
    "ExcelContractError": ("ist_emit.excel_contract", "ExcelContractError"),
    "resolve_execution_sheet": ("ist_emit.excel_contract", "resolve_execution_sheet"),
    "emit_xlsx": ("ist_emit.xlsx_emit", "emit_xlsx"),
    "select_runtime_template": ("ist_emit.xlsx_emit", "select_runtime_template"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(target[0])
    return getattr(module, target[1])


def __dir__() -> list[str]:
    return sorted(_LAZY)
