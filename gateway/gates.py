"""上机前闸：上传的工作簿先在内存里冻结，再逐项检查；任何一项不过就拒绝，不改写文件。

对应 InfoTest dev_run_batch 身份链的“冻结 + 派生”几步（批次工具第 2–4 步）：
- zip 结构与体积（成员数、单成员/总大小、压缩比、路径穿越、重复成员）；
- openpyxl 能在行列上限内打开，执行页唯一（契约 marker 与表头行）；
- 执行页 autoid 从冻结字节里读，不信调用方给的列表；
另加两道 InfoTest 上机路径上没有的闸：
- 自毁命令（规则来自服务端数据包的 domain_grammar.json，读不到就拒绝）；
- 凭据字面量（从跳板机上真实框架源码 AST 提取，任何单元格命中就拒绝；报告只给单元格位置）。
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .vendor.cex_core.ist_emit._sealed_io import validate_xlsx_zip_budget
from .vendor.cex_core.ist_emit.excel_contract import resolve_execution_sheet
from .vendor.cex_core.scan_destructive import (
    DestructiveRulesUnavailable,
    load_patterns,
    scan_lines,
)

MAX_XLSX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 20000
MAX_COLUMNS = 64
SENTINEL_AUTOID = "999999999999999"
_AUTOID_RE = re.compile(r"^\d{12,24}$")
_MIN_LITERAL_LEN = 4


class GateError(ValueError):
    """工作簿被拒；problems 是逐项原因（英文，给模型看）。"""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class FrozenCase:
    data: bytes
    sha256: str
    size: int
    autoids: tuple[str, ...]
    command_lines: tuple[tuple[str, str], ...]
    cells: tuple[tuple[str, str], ...]


def freeze(data: bytes) -> FrozenCase:
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise GateError(["workbook is empty"])
    data = bytes(data)
    if len(data) > MAX_XLSX_BYTES:
        raise GateError([f"workbook exceeds {MAX_XLSX_BYTES} bytes"])
    try:
        validate_xlsx_zip_budget(data, error_type=GateError, message="workbook zip is malformed")
    except GateError:
        raise GateError(["workbook zip is malformed or exceeds size/ratio limits"]) from None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [info.filename for info in archive.infolist()]
        if len(names) != len(set(names)):
            raise GateError(["workbook zip has duplicate members"])
        for info in archive.infolist():
            name = info.filename
            if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                raise GateError(["workbook zip has a member path outside the archive"])
            if info.flag_bits & 0x1:
                raise GateError(["workbook zip has encrypted members"])
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise GateError(["workbook zip has symlink members"])
    from openpyxl import load_workbook

    try:
        wb = load_workbook(io.BytesIO(data), read_only=False, data_only=False)
    except Exception as exc:  # noqa: BLE001 — 任何解析失败都是拒收理由
        raise GateError([f"workbook does not open: {type(exc).__name__}"]) from None
    try:
        for ws in wb.worksheets:
            if ws.max_row > MAX_ROWS or ws.max_column > MAX_COLUMNS:
                raise GateError([f"sheet {ws.title!r} exceeds {MAX_ROWS} rows or "
                                 f"{MAX_COLUMNS} columns"])
        try:
            ws, _ = resolve_execution_sheet(wb, allow_legacy=False)
        except Exception as exc:  # noqa: BLE001
            raise GateError([f"execution sheet does not satisfy the Excel contract: {exc}"]) \
                from None
        autoids: list[str] = []
        commands: list[tuple[str, str]] = []
        for row_no, row in enumerate(ws.iter_rows(values_only=True), start=1):
            first = str(row[0]).strip() if row and row[0] is not None else ""
            if first == SENTINEL_AUTOID:
                break
            if _AUTOID_RE.match(first) and first not in autoids:
                autoids.append(first)
            device = str(row[4] or "").strip() if len(row) > 4 else ""
            command = str(row[6] or "") if len(row) > 6 else ""
            if device.startswith("APV") and command.strip():
                for line in command.splitlines():
                    if line.strip():
                        commands.append((f"{ws.title}!G{row_no}", line))
        cells = []
        for sheet in wb.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    if isinstance(cell.value, str) and cell.value.strip():
                        cells.append((f"{sheet.title}!{cell.coordinate}", cell.value))
    finally:
        wb.close()
    if not autoids:
        raise GateError(["execution sheet has no case autoids"])
    return FrozenCase(data=data, sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                      autoids=tuple(autoids), command_lines=tuple(commands), cells=tuple(cells))


def check(frozen: FrozenCase, *, grammar: dict[str, Any] | Path | None,
          credential_literals: frozenset[str]) -> None:
    problems: list[str] = []
    try:
        patterns = load_patterns(grammar if grammar is not None else {})
    except DestructiveRulesUnavailable as exc:
        raise GateError([f"destructive-command rules unavailable, refusing to run: {exc}"]) \
            from None
    for finding in scan_lines(frozen.command_lines, patterns):
        problems.append(f"{finding['where']}: {finding['command']!r} matches destructive rule "
                        f"{finding['rule']!r}; clean up only what the case created")
    literals = [value for value in credential_literals if len(value) >= _MIN_LITERAL_LEN]
    for where, text in frozen.cells:
        folded = text.casefold()
        if any(value.casefold() in folded for value in literals):
            problems.append(f"{where}: contains a framework credential literal; "
                            "remove it (credentials come from the framework conf at run time)")
    if problems:
        raise GateError(problems)
