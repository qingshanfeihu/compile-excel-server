
from __future__ import annotations

import re
from typing import Any

_LEGACY_SUFFIX_RE = re.compile(r"^(.+)\.v\d+$")


def canonical_schema(name: str) -> str:
    if not isinstance(name, str) or not name:
        return str(name or "")
    match = _LEGACY_SUFFIX_RE.match(name.strip())
    if match:
        return match.group(1)
    return name.strip()


def accepts_schema(actual: Any, expected: str) -> bool:
    if not isinstance(actual, str) or not actual.strip():
        return False
    if not isinstance(expected, str) or not expected.strip():
        return False
    return canonical_schema(actual) == canonical_schema(expected)


def write_schema(expected: str) -> str:
    return canonical_schema(expected)


def reject_unless_schema(payload: dict[str, Any], expected: str, *, field: str = "schema") -> None:
    actual = payload.get(field)
    if not accepts_schema(actual, expected):
        raise ValueError(
            f"unsupported schema: expected {write_schema(expected)!r}, got {actual!r}"
        )
