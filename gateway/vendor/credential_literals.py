# 同步自 InfoTest main/case_compiler/credential_literals.py（tools/sync_gateway_vendor.py），不在这里手改。

from __future__ import annotations

import ast
import hashlib
import re
import threading
import warnings
from pathlib import Path
from typing import Mapping

# 网关总是显式传框架根目录；InfoTest 的默认镜像路径在跳板机上不存在
KNOWLEDGE_FRAMEWORK_MIRROR = None

__all__ = [
    "MirrorCredentialLiteralError",
    "clear_credential_literal_cache",
    "mirror_credential_literals",
    "mirror_credential_literals_with_overlays",
    "matching_credential_literal_count",
    "credential_declaration_head",
    "credential_declaration_heads",
    "is_credential_argument",
    "is_placeholder_default_literal",
]

_CACHE_LOCK = threading.Lock()
_LITERAL_CACHE: dict[tuple[str, str], frozenset[str]] = {}


class MirrorCredentialLiteralError(RuntimeError):
    pass


_CREDENTIAL_SLOT_SEGMENTS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "passphrase",
})


def _is_credential_slot(name: str | None) -> bool:
    if not name:
        return False
    return bool(_CREDENTIAL_SLOT_SEGMENTS & set(re.split(r"[_\W]+", name.casefold())))


def _static_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
        return node.value
    return None


def _target_slot_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Attribute):
        return [target.attr]
    if isinstance(target, ast.Subscript):
        key = _static_string(target.slice)
        return [key] if key else []
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for elt in target.elts for name in _target_slot_names(elt)]
    return []


def _is_os_environ_get(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "environ"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "os"
    )


def _is_os_getenv(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "getenv"
        and isinstance(func.value, ast.Name)
        and func.value.id == "os"
    )


class _CredentialLiteralVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.values: set[str] = set()

    def _add_if_slot(self, name: str | None, value: ast.AST | None) -> None:
        literal = _static_string(value)
        if literal is not None and _is_credential_slot(name):
            self.values.add(literal)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            for name in _target_slot_names(target):
                self._add_if_slot(name, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        for name in _target_slot_names(node.target):
            self._add_if_slot(name, node.value)
        self.generic_visit(node)

    def _visit_function_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults = node.args.defaults
        if defaults:
            for arg, default in zip(positional[-len(defaults):], defaults):
                self._add_if_slot(arg.arg, default)
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            self._add_if_slot(arg.arg, default)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_defaults(node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            self._add_if_slot(_static_string(key), value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            self._add_if_slot(keyword.arg, keyword.value)
        if _is_os_environ_get(node) or _is_os_getenv(node):
            env_name = _static_string(node.args[0]) if node.args else None
            fallback = node.args[1] if len(node.args) > 1 else None
            if fallback is None:
                fallback = next((kw.value for kw in node.keywords if kw.arg == "default"), None)
            self._add_if_slot(env_name, fallback)
        self.generic_visit(node)


def clear_credential_literal_cache() -> None:
    """测试与换代入口用；生产 emit 靠当前 ``*.py`` 字节身份自动失效。"""
    with _CACHE_LOCK:
        _LITERAL_CACHE.clear()


def _load_python_sources(
    root: Path,
    overlays: Mapping[str, bytes | bytearray],
) -> list[tuple[str, bytes]]:
    """读出完整 ``*.py`` 闭包的相对路径与原字节；不解析、不缓存。"""
    paths = sorted(root.rglob("*.py"))
    if not paths:
        raise MirrorCredentialLiteralError("framework mirror contains no Python sources")
    python_relatives = {path.relative_to(root).as_posix() for path in paths}
    unknown = set(overlays) - python_relatives
    if unknown:
        raise MirrorCredentialLiteralError(
            f"credential overlay contains unknown Python sources (count={len(unknown)})"
        )
    if any(not isinstance(value, (bytes, bytearray)) for value in overlays.values()):
        raise MirrorCredentialLiteralError("credential overlays must be sealed bytes")

    entries: list[tuple[str, bytes]] = []
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            raw = bytes(overlays[relative]) if relative in overlays else path.read_bytes()
        except OSError as exc:
            raise MirrorCredentialLiteralError(
                f"cannot read mirror source: {relative} ({type(exc).__name__})"
            ) from exc
        entries.append((relative, raw))
    return entries


def _python_source_identity(entries: list[tuple[str, bytes]]) -> str:
    """当前提取闭包的内容身份：相对路径 + 源码字节，不含 ``.sync_meta.json``。"""
    digest = hashlib.sha256()
    for relative, raw in entries:
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _parse_credential_literals(entries: list[tuple[str, bytes]]) -> frozenset[str]:
    visitor = _CredentialLiteralVisitor()
    for relative, raw in entries:
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MirrorCredentialLiteralError(
                f"cannot read mirror source: {relative} ({type(exc).__name__})"
            ) from exc
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                warnings.simplefilter("ignore", DeprecationWarning)
                tree = ast.parse(source, filename="<framework-mirror-source>")
        except SyntaxError as exc:
            raise MirrorCredentialLiteralError(
                f"cannot parse mirror source: {relative} ({type(exc).__name__})"
            ) from exc
        visitor.visit(tree)
    return frozenset(visitor.values)


def _extract_credential_literals(
    root: Path,
    overlays: Mapping[str, bytes | bytearray],
) -> frozenset[str]:
    return _parse_credential_literals(_load_python_sources(root, overlays))


def mirror_credential_literals_with_overlays(
    source_overlays: Mapping[str, bytes | bytearray] | None = None,
    mirror_root: Path | None = None,
) -> frozenset[str]:
    """从完整 mirror 闭包提取凭据，并以已密封源码字节替换对应文件。

    读取或语法解析不完整时拒绝返回部分集合，避免生成器把“没有发现”误当成
    “没有凭据”。异常只带路径和错误类型，不携带源文或字面量。

    无 overlay 时按当前 ``*.py`` 源码字节身份缓存；``.sync_meta.json`` 只是
    同步加速索引，不进入缓存键。overlay 路径不缓存。源码变动、不可读或
    语法失败都不得静默返回过时闭集。不用 env 开关。
    """
    root = (mirror_root or KNOWLEDGE_FRAMEWORK_MIRROR).resolve()
    if not root.is_dir():
        raise MirrorCredentialLiteralError("framework mirror directory is unavailable")
    overlays = dict(source_overlays or {})
    if overlays:
        return _extract_credential_literals(root, overlays)
    entries = _load_python_sources(root, overlays)
    key = (str(root), _python_source_identity(entries))
    with _CACHE_LOCK:
        hit = _LITERAL_CACHE.get(key)
        if hit is not None:
            return hit
    values = _parse_credential_literals(entries)
    with _CACHE_LOCK:
        _LITERAL_CACHE[key] = values
    return values


def mirror_credential_literals(mirror_root: Path | None = None) -> frozenset[str]:
    return mirror_credential_literals_with_overlays({}, mirror_root)


def matching_credential_literal_count(text: str, values: frozenset[str] | set[str]) -> int:
    folded = (text or "").casefold()
    return sum(value.casefold() in folded for value in values if value)


_CREDENTIAL_HEAD_NOUNS = frozenset({
    "password", "passwords", "passwd", "passwds", "pwd", "pwds",
    "passphrase", "passphrases", "secret", "secrets",
    "key", "keys", "credential", "credentials", "token", "tokens",
    "community", "communities", "pin", "pins",
})

_TRANSPARENT_HEAD_NOUNS = frozenset({
    "value", "values", "string", "strings", "literal", "literals",
    "content", "contents", "text", "data",
})
_HEAD_TAIL_MODIFIER_RE = re.compile(
    r"\b(?:for|of|in|on|to|with|from|by|used|use|which|that|who|whose|when|"
    r"where|ranging|range|enclosed|required|optional|containing|contains|"
    r"specified|generated|imported|exported|associated|about|as|per|via)\b.*$",
    re.IGNORECASE,
)
_COORDINATOR_SPLIT_RE = re.compile(r"\b(?:and|or)\b", re.IGNORECASE)
_HEAD_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_HEAD_SUBWORD_SPLIT_RE = re.compile(r"[-_]+")
_XML_ENTITIES = (
    ("&quot;", '"'), ("&apos;", "'"), ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"),
)
_STRUCTURAL_NON_CREDENTIAL_TYPES = frozenset({
    "U16", "U32", "IPADDR", "DOTTEDIP", "IPMASK",
})
_PLACEHOLDER_DEFAULT_LITERALS = frozenset({"null", "none", "nil", "n/a", "na"})


def _unescape_xml_text(value: str) -> str:
    text = str(value or "")
    for entity, char in _XML_ENTITIES:
        text = text.replace(entity, char)
    return text


def _branch_head(branch: str) -> str:
    segment = _HEAD_TAIL_MODIFIER_RE.sub("", branch)
    segment = segment.replace("'s", " ").replace("’s", " ")
    words = [
        subword.casefold()
        for word in _HEAD_WORD_RE.findall(segment)
        for subword in _HEAD_SUBWORD_SPLIT_RE.split(word)
        if subword
    ]
    while words and words[-1] in _TRANSPARENT_HEAD_NOUNS:
        words.pop()
    return words[-1] if words else ""


def credential_declaration_heads(help_string: str | None) -> list[str]:
    text = _unescape_xml_text(help_string)
    for token, char in (("\\n", "\n"), ("\\t", "\t"), ("\\r", "\n")):
        text = text.replace(token, char)
    segment = re.split(r"[.;:,\n\r()\[\]]", text, maxsplit=1)[0]
    heads = [_branch_head(branch) for branch in _COORDINATOR_SPLIT_RE.split(segment)]
    return [head for head in heads if head]


def credential_declaration_head(help_string: str | None) -> str:
    heads = credential_declaration_heads(help_string)
    return heads[0] if heads else ""


def is_credential_argument(
    *,
    name: str | None = "",
    arg_type: str | None = "",
    help_string: str | None = "",
) -> bool:
    if str(arg_type or "").strip().upper() in _STRUCTURAL_NON_CREDENTIAL_TYPES:
        return False
    if _is_credential_slot(name):
        return True
    return any(
        head in _CREDENTIAL_HEAD_NOUNS
        for head in credential_declaration_heads(help_string)
    )


def is_placeholder_default_literal(value: str | None) -> bool:
    text = _unescape_xml_text(value).strip().strip("\"'").strip()
    if not text:
        return True
    return text.casefold() in _PLACEHOLDER_DEFAULT_LITERALS
