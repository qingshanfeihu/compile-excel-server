"""自毁命令扫描：整机清配置、恢复出厂、重启/关机这类命令不许出现在用例里。

规则只有一个来源：数据包 projections 里的 `domain_grammar.json` 的
`destructive_commands.patterns`（与 InfoTest structural_gate 读同一份）。这里不写任何命令。

与 InfoTest 的对应：
- 辖区同 InfoTest `is_apv_command_step(methods=None)`：E 列以 APV 开头的每一步都查，
  不按 F 列分辖区（按 F 分等于留一个“换个方法名就能绕过”的口子）；
- 逐行查 G 列（不剥执行器关键字，比 InfoTest 多查不少查）；
- 与 InfoTest 不同：规则读不到、为空或编译失败时**拒绝**（抛 DestructiveRulesUnavailable），
  而不是记一笔“本次未检查”后放行——这里是上机前的最后一道闸。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


class DestructiveRulesUnavailable(RuntimeError):
    pass


def load_patterns(grammar: dict[str, Any] | str | Path) -> list[re.Pattern[str]]:
    if not isinstance(grammar, dict):
        try:
            grammar = json.loads(Path(grammar).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise DestructiveRulesUnavailable(f"domain grammar unreadable: {exc}") from None
    raw = ((grammar or {}).get("destructive_commands") or {}).get("patterns") or []
    if not isinstance(raw, list) or not raw:
        raise DestructiveRulesUnavailable("domain grammar carries no destructive_commands.patterns")
    try:
        return [re.compile(str(pattern), re.IGNORECASE) for pattern in raw]
    except re.error as exc:
        raise DestructiveRulesUnavailable(f"destructive pattern does not compile: {exc}") from None


def scan_lines(lines: Iterable[tuple[str, str]],
               patterns: list[re.Pattern[str]]) -> list[dict[str, str]]:
    """lines 是 (位置, 命令行)；返回每个命中：位置、命令、命中的规则。"""
    findings = []
    for where, line in lines:
        text = (line or "").strip()
        if not text:
            continue
        hit = next((p for p in patterns if p.search(text)), None)
        if hit is not None:
            findings.append({"where": where, "command": text, "rule": hit.pattern})
    return findings


def workbook_command_lines(xlsx: str | Path) -> list[tuple[str, str]]:
    """执行页里每个 APV 步的 G 列逐行拆开。"""
    from openpyxl import load_workbook

    from .ist_emit.excel_contract import resolve_execution_sheet

    wb = load_workbook(Path(xlsx), read_only=True, data_only=True)
    try:
        ws, _ = resolve_execution_sheet(wb, allow_legacy=False)
        out = []
        for row_no, row in enumerate(ws.iter_rows(values_only=True), start=1):
            device = str(row[4] or "").strip() if len(row) > 4 else ""
            command = str(row[6] or "") if len(row) > 6 else ""
            if not device.startswith("APV") or not command.strip():
                continue
            for line in command.splitlines():
                if line.strip():
                    out.append((f"{ws.title}!G{row_no}", line))
        return out
    finally:
        wb.close()


def scan_workbook(xlsx: str | Path, grammar: dict[str, Any] | str | Path) -> list[dict[str, str]]:
    return scan_lines(workbook_command_lines(xlsx), load_patterns(grammar))
