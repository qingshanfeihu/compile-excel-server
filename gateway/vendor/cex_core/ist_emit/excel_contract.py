"""执行页解析契约（skill 剪切版）。

上游来源：InfoTest_Engine main/case_compiler/excel_contract.py 的
`resolve_execution_sheet` 及其表头归一化 / defined-name / marker 校验。
剪切声明（与 InfoTest 的行为差异）：
- 不带 excel_contract.json 数据驱动校验（1.1MB 契约数据不随 skill 分发）；
  G 列内容合法性归 agent，InfoTest lint 复核兜底。
- 工作簿身份用钉死常量校验（模板 SHA + marker 契约 SHA），模板是冻结快照
  而非晋升链产物。详见 reference/excel-contract.md。
"""

from __future__ import annotations

from typing import Any

from .config import XlsxLayout
from .schema_identity import accepts_schema

SCHEMA = "ist.excel.function-contract"
RUNTIME_SCHEMA = "ist.excel.runtime"

EXECUTION_HEADERS = (
    "自动化ID",
    "优先级",
    "语句类型",
    "描述",
    "测试对象",
    "方法",
    "数据",
    "临时保存期望结果",
    "输入变量",
)
EXECUTION_SHEET_MARKER = "IST_EXECUTION_SHEET"
CONTRACT_MARKER = "IST_EXCEL_CONTRACT"

# ── 钉死的模板身份（冻结快照，见 reference/excel-contract.md）─────────
# 模板：knowledge/data/compile_ref/excel_runtime_template.xlsx
TEMPLATE_SHA256 = "46aa14dfffbe767ec486dc6b186d582458d666de8a8f6aec2294f920077a45f9"
# 晋升回执：runtime/excel_release/promotion_receipt.json（status=promoted，
# device_build=InfosecOS_Beta_APV_HG_K_10_5_0_585）的 final_contract_sha256；
# 与模板 A1 marker 行 C 列逐字一致。
PINNED_CONTRACT_SHA256 = "ca32544f34bbd8662e14320e1cec7ca7892df63a3852a24f496ae2e2eb1fdf6c"


class ExcelContractError(ValueError):
    pass


def _normalized_header(row: tuple[Any, ...]) -> tuple[str, ...]:
    return tuple("" if value is None else str(value).strip() for value in row)


def _defined_name_destinations(workbook: Any) -> list[tuple[str, str]] | None:
    names = getattr(workbook, "defined_names", None)
    if names is None:
        return None
    try:
        marker = names.get(EXECUTION_SHEET_MARKER)
    except (AttributeError, KeyError):
        marker = None
    if marker is None:
        return None
    try:
        return list(marker.destinations)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ExcelContractError("execution-sheet marker is malformed") from exc


def _unquote_sheet_name(name: str) -> str:
    if len(name) >= 2 and name[0] == name[-1] == "'":
        return name[1:-1].replace("''", "'")
    return name


def resolve_execution_sheet(
    workbook: Any,
    *,
    allow_legacy: bool = False,
) -> tuple[Any, XlsxLayout]:
    """全 sheet 扫描唯一 A-I 表头行，核验 defined-name 与契约 marker。

    与上游语义一致：表头不在第 1 行（真模板在第 29 行）；
    `IST_EXECUTION_SHEET` 必须精确指向该表头行；`IST_EXCEL_CONTRACT`
    必须在表头之前且唯一；marker 版本/SHA 与钉死身份一致。
    skill 版默认 `allow_legacy=False`（禁止 legacy 回退）。
    """
    matches: list[tuple[Any, int]] = []
    for worksheet in getattr(workbook, "worksheets", ()):
        for row_no, row in enumerate(
            worksheet.iter_rows(min_col=1, max_col=len(EXECUTION_HEADERS), values_only=True),
            start=1,
        ):
            if _normalized_header(row) == EXECUTION_HEADERS:
                matches.append((worksheet, row_no))
    if len(matches) != 1:
        raise ExcelContractError(
            f"expected exactly one complete A-I execution header, found {len(matches)}"
        )

    worksheet, header_row = matches[0]
    destinations = _defined_name_destinations(workbook)
    markers: list[tuple[Any, int, tuple[Any, ...]]] = []
    for candidate in getattr(workbook, "worksheets", ()):
        for row_no, row in enumerate(
            candidate.iter_rows(min_col=1, max_col=3, values_only=True),
            start=1,
        ):
            if row and str(row[0] or "").strip() == CONTRACT_MARKER:
                markers.append((candidate, row_no, tuple(row)))

    if destinations is None and not markers:
        if not allow_legacy:
            raise ExcelContractError(
                f"current workbook is missing {EXECUTION_SHEET_MARKER!r} and "
                f"{CONTRACT_MARKER!r} markers"
            )
    else:
        if destinations is None:
            raise ExcelContractError(
                f"current workbook is missing {EXECUTION_SHEET_MARKER!r} marker"
            )
        expected_ref = f"$A${header_row}:$I${header_row}"
        normalized = [(_unquote_sheet_name(sheet), ref.upper()) for sheet, ref in destinations]
        if normalized != [(worksheet.title, expected_ref)]:
            raise ExcelContractError(
                f"{EXECUTION_SHEET_MARKER!r} does not target the unique A-I header"
            )
        if len(markers) != 1:
            raise ExcelContractError(
                f"expected exactly one {CONTRACT_MARKER!r} identity marker, "
                f"found {len(markers)}"
            )
        marker_sheet, marker_row, marker_values = markers[0]
        if marker_sheet is not worksheet or marker_row >= header_row:
            raise ExcelContractError(
                f"{CONTRACT_MARKER!r} must precede the unique A-I header"
            )
        marker_version = str(marker_values[1] or "").strip()
        marker_sha = str(marker_values[2] or "").strip()
        if not accepts_schema(marker_version, RUNTIME_SCHEMA):
            raise ExcelContractError(
                "workbook runtime identity does not match the pinned contract "
                f"(workbook {marker_version!r} vs pinned {RUNTIME_SCHEMA!r})"
            )
        if marker_sha != PINNED_CONTRACT_SHA256 and not allow_legacy:
            raise ExcelContractError(
                "workbook contract identity does not match the pinned contract "
                f"(workbook sha {marker_sha[:12]}… vs pinned "
                f"{PINNED_CONTRACT_SHA256[:12]}…)"
            )

    return worksheet, XlsxLayout(
        header_row=header_row,
        data_start=header_row + 1,
        header_anchor=EXECUTION_HEADERS[0],
        n_cols=len(EXECUTION_HEADERS),
    )


__all__ = [
    "SCHEMA", "RUNTIME_SCHEMA", "EXECUTION_HEADERS", "EXECUTION_SHEET_MARKER",
    "CONTRACT_MARKER", "TEMPLATE_SHA256", "PINNED_CONTRACT_SHA256",
    "ExcelContractError", "resolve_execution_sheet",
]
