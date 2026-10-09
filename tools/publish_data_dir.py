#!/usr/bin/env python3
"""publish_data_dir：把已收敛的编译数据（InfoTest 仓根布局的数据目录）发布成服务端数据包。

与 tools/import_infotest.py 的区别：不导入任何 InfoTest 代码，每一类只按数据文件自己的身份
核对（代际清单、镜像锚点、契约来源、晋升回执、规格书清单、同步回执、手册 catalog 状态、足迹
回填收据）。命令树从 InfoTest 的活动代际出发，经 tools/cmdtree_rederive.py 去掉凭据字面、用引擎
自己的函数重推导代际、投影、拆卸图谱与领域文法；SSL 生命周期证据的图谱身份随之改绑。另发两份
编写阶段要的数据：判据台账（runtime/criterion_author_rules.jsonl，客户端当种子）与 SSL 生命周期
证据。上传走 import_infotest 里与 InfoTest 无关的 Publisher。

数据包不带凭据。凭据值 = 引擎在**原始**数据上的闭包：框架镜像源码里的凭据字面
（credential_literals.mirror_credential_literals）+ 命令树 XML 凭据参数的默认值
（command_tree_sync._xml_default_literal_closure）。除命令树外，发之前这样处理：
- 框架树：带凭据值（或带口令的 URL userinfo）的成员把它换成占位 CEX-REDACTED（.py 逐字替换后
  必须还能解析；xlsx 解开替换里面的 XML 再按原成员信息重新打包），.sync_meta.json 的 by_path、
  mirror_manifest.json 的锚点随之改成脱敏后的哈希（这两份描述的就是发出去的文件）。Excel 契约
  source_hashes 钉住的文件**不动**：客户端按契约逐字节核它们，契约身份又被客户端代码钉死，改了
  客户端就认不出契约——这类文件带凭据只能在上游修掉再重新认证契约，出包前扫描会点名拒绝。
- 规格书：文档里的凭据值与 URL userinfo（带口令的）换成占位；索引里受影响的条目用引擎自己的
  build_spec_index 在脱敏前后各推一遍、只把推出来的差异写回（sha256/size，以及口令被当成缺陷号、
  关键词时的那几项）；代际清单的文档与索引哈希改成新值，代际号按内容派生一个新的（时间前缀不变）。
- 手册与其 catalog 不改写：catalog 内嵌的 md 身份客户端要核，catalog 在这里又推不出来（生成器
  不在引擎里）。手册里带凭据，出包前扫描就点名拒绝。
另有些派生投影记着生成时读过的源文件哈希（方法参考/能力图谱的框架源身份、节奏用法的工作簿
清单）：它们如实描述自己是从哪份源生成的，客户端不拿它们核镜像，这里不改写。

最后对每个条目、每个 tar/zip 成员做出包前扫描（原文、XML 转义、URL 编码、JSON 转义的写法都查），
有一处就拒绝发布，只报位置与次数、不带值。

  python3 tools/publish_data_dir.py --data-root <InfoTest 布局根> --raw-build "<show version>" \\
      --manual-version 10.5.0 --server https://<服务端> --client-secret-file <0600 文件> \\
      [--promote] [--insecure-lan] [--dry-run | --out-dir <目录>]

模板与契约的固定身份、凭据闭包与规格书索引的函数都取自 gateway/vendor 里同步来的 cex_core
（客户端用的是同一份），所以先跑 tools/sync_gateway_vendor.py --only cex_core。
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
from import_infotest import (  # noqa: E402 — 与 InfoTest 无关的打包上传层
    KINDS,
    SUBSTRING,
    TOKEN,
    CredentialScanError,
    CredentialScanner,
    Entry,
    Publisher,
    PublishError,
    Resolution,
    check_publish_server,
    describe_credential_hits,
    deterministic_tar_gz,
    media_type_for,
    read_secret_file,
    tar_gz_bytes,
)

VENDOR = REPO_ROOT / "gateway" / "vendor"
PROJECTION_EXCLUDE_NAMES = {"excel_runtime_template.xlsx", "excel_workbook_manifest.json"}
PROJECTION_EXCLUDE_PREFIXES = ("vendor_stdlib_", "source_reconciliation_", "cmdtree_")
# 由命令树重推导产出、替换数据目录里原件的投影
REDERIVED_PROJECTIONS = ("command_teardown_atlas.json", "domain_grammar.json")
SSL_LIFECYCLE_ASSET = "scripts/maintenance/assets/ssl_lifecycle_contract.json"
CRITERION_LEDGER = "runtime/criterion_author_rules.jsonl"
# 脱敏占位：URL、Python 字符串、XML、JSON 里都不用转义，也不会是正常内容的子串
PLACEHOLDER = "CEX-REDACTED"
# 带口令的 URL userinfo（scheme://user:pass@）；userinfo 取到 host 前最后一个 @
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15}://)([^\s/?#\"'<>\\`]+)@")
_TEMPLATE_MARKS = set("{}%$<>")  # 口令位是模板占位（{pwd}、%s、$PASS、<password>）的不算凭据
_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
FOOTPRINT_RECEIPT_SCHEMA = "ist.footprint-backfill-receipt"
FOOTPRINT_RECEIPT_ALGO = "catalog-anchored-slice-per-family"
_PINNED_NOTE = ("pinned by excel_contract.json source_hashes: remove the credential upstream, "
                "then re-certify the contract")
_MANUAL_NOTE = ("manual text is not rewritten here (the client verifies the catalog's md identity "
                "and the catalog cannot be re-derived); redact upstream")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execution_build(raw: str) -> str:
    """show version 的完整版本 → 执行侧构建名（结果库表名同一规则）。"""
    text = re.sub(r"[^0-9A-Za-z_]+", "_", raw).strip("_")
    return "b_" + text if text and text[0].isdigit() else text


def _canonical_schema(name: Any) -> str:
    """与引擎 common.schema_identity.canonical_schema 同一条规则：去掉结尾的 .vN。"""
    text = str(name or "").strip()
    match = re.match(r"^(.+)\.v\d+$", text)
    return match.group(1) if match else text


_JSON_STYLES = (
    {"ensure_ascii": False, "indent": 2},
    {"ensure_ascii": False, "indent": 1},
    {"ensure_ascii": False, "sort_keys": True, "separators": (",", ":")},
    {"ensure_ascii": False, "separators": (",", ":")},
    {"ensure_ascii": False, "indent": 2, "sort_keys": True},
    {"ensure_ascii": True, "indent": 2},
    {"ensure_ascii": True, "sort_keys": True, "separators": (",", ":")},
    {"ensure_ascii": False},
)


def dump_like(original: bytes, obj: Any) -> bytes:
    """按原文件的 JSON 写法（缩进、键序、转义、结尾换行）写改过的对象；认不出写法用缺省写法。"""
    parsed = json.loads(original)
    for style in _JSON_STYLES:
        text = json.dumps(parsed, **style)
        for tail in ("", "\n"):
            if (text + tail).encode("utf-8") == original:
                return (json.dumps(obj, **style) + tail).encode("utf-8")
    return (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


class EngineHooks:
    """发布进程里用到的引擎函数，取自 gateway/vendor 同步来的 cex_core（客户端跑的同一份）。

    这些函数都按参数给的路径/字节工作，不读数据根；测试注入替身。"""

    def __init__(self) -> None:
        if str(VENDOR) not in sys.path:
            sys.path.insert(0, str(VENDOR))
        try:
            from cex_core.engine.case_compiler import credential_literals
            from cex_core.engine.kms import manual_catalog_store, spec_index
            from cex_core.engine.sync import command_tree_sync
        except ImportError as exc:
            raise RuntimeError("gateway/vendor/cex_core is missing; run "
                               "tools/sync_gateway_vendor.py --only cex_core first") from exc
        self.mirror_literals = lambda root: credential_literals.mirror_credential_literals(
            mirror_root=root)
        self.parse_literals = credential_literals._parse_credential_literals
        self.xml_literals = command_tree_sync._xml_default_literal_closure
        self.build_spec_index = spec_index.build_spec_index
        self.catalog_status = manual_catalog_store.load_catalog_status


class Unredactable(ValueError):
    """这个文件带凭据，但没法安全地原位脱敏（不是 UTF-8 文本、脱敏后解析不了……）。"""


def _redact_userinfo(text: str) -> tuple[str, int]:
    count = 0

    def one(match: re.Match) -> str:
        nonlocal count
        userinfo = match.group(2)
        _user, sep, password = userinfo.partition(":")
        if (not sep or not password or userinfo == PLACEHOLDER
                or _TEMPLATE_MARKS & set(password)):
            return match.group(0)
        count += 1
        return f"{match.group(1)}{PLACEHOLDER}@"

    return _URL_USERINFO.sub(one, text), count


def redact_text(scanner: CredentialScanner, text: str) -> tuple[str, int, int]:
    """凭据值换成占位，再把带口令的 URL userinfo 换成占位。返回 (新文本, 值处数, userinfo 处数)。"""
    text, values = scanner.replace(text, PLACEHOLDER)
    text, userinfo = _redact_userinfo(text)
    return text, values, userinfo


def _findings(scanner: CredentialScanner, data: bytes) -> tuple[int, int]:
    """(凭据值处数, 可脱敏的 userinfo 处数)；zip（xlsx）逐个成员看。"""
    if data[:4] == _ZIP_MAGIC:
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            values = userinfo = 0
            for info in archive.infolist():
                if not info.is_dir():
                    inner = _findings(scanner, archive.read(info))
                    values += inner[0]
                    userinfo += inner[1]
            return values, userinfo
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError):
            pass
    text = data.decode("utf-8", "replace")
    return scanner.count_blob(data), _redact_userinfo(text)[1]


def redact_member(scanner: CredentialScanner, rel: str, data: bytes) -> tuple[bytes, int, int]:
    """把一个框架树成员（文本或 zip/xlsx）里的凭据值与带口令 userinfo 换成占位。"""
    if data[:4] == _ZIP_MAGIC:
        return _redact_zip(scanner, rel, data)
    if data[:2] == _GZIP_MAGIC:
        raise Unredactable(f"{rel}: a gzip member carries credential values")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Unredactable(f"{rel}: carries credential values but is not UTF-8 text") from exc
    new, values, userinfo = redact_text(scanner, text)
    if rel.endswith(".py"):
        try:
            ast.parse(new, filename="<redacted-mirror-source>")
        except SyntaxError as exc:
            raise Unredactable(f"{rel}: no longer parses after redaction") from exc
    blob = new.encode("utf-8")
    if scanner.count_blob(blob):
        raise Unredactable(f"{rel}: still carries credential values after redaction")
    return blob, values, userinfo


def _parses_as_xml(data: bytes) -> bool:
    try:
        ET.fromstring(data)
    except ET.ParseError:
        return False
    return True


def _redact_zip(scanner: CredentialScanner, rel: str, data: bytes) -> tuple[bytes, int, int]:
    try:
        source = zipfile.ZipFile(io.BytesIO(data))
        members = source.infolist()
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError) as exc:
        raise Unredactable(f"{rel}: carries credential values but is not a readable zip") from exc
    out = io.BytesIO()
    values = userinfo = 0
    with zipfile.ZipFile(out, "w") as target:
        for info in members:
            content = source.read(info)
            if not info.is_dir() and any(_findings(scanner, content)):
                if content[:4] == _ZIP_MAGIC or content[:2] == _GZIP_MAGIC:
                    raise Unredactable(f"{rel}!{info.filename}: nested archive carries "
                                       "credential values")
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise Unredactable(f"{rel}!{info.filename}: carries credential values but "
                                       "is not UTF-8 text") from exc
                new, found, links = redact_text(scanner, text)
                values += found
                userinfo += links
                if _parses_as_xml(content) and not _parses_as_xml(new.encode("utf-8")):
                    raise Unredactable(f"{rel}!{info.filename}: no longer parses after redaction")
                content = new.encode("utf-8")
            copy = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            copy.compress_type = info.compress_type
            copy.external_attr = info.external_attr
            copy.create_system = info.create_system
            copy.comment = info.comment
            target.writestr(copy, content)
        target.comment = source.comment
    blob = out.getvalue()
    if scanner.scan(rel, blob):
        raise Unredactable(f"{rel}: still carries credential values after redaction (a value "
                           "split across rich-text runs?)")
    return blob, values, userinfo


def derived_generation_id(original: str, documents: dict[str, Any],
                          artifacts: dict[str, Any]) -> str:
    """脱敏后的规格书代际号：保留原代际的时间前缀（代龄照旧），随机段换成内容派生。"""
    prefix = original.split("-", 1)[0]
    digest = sha(json.dumps({"from": original, "documents": documents, "artifacts": artifacts},
                            sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    return f"{prefix}-{digest[:16]}"


def footprint_receipt_problems(receipt: Any, *, md_pins: dict[str, str],
                               catalog_pins: dict[str, str], nodes: Path) -> list[str]:
    """足迹回填收据：与 InfoTest footprint_update.backfill_receipt_status 同一组条件。"""
    if not isinstance(receipt, dict):
        return ["receipt is not a JSON object"]
    problems = []
    if _canonical_schema(receipt.get("schema")) != FOOTPRINT_RECEIPT_SCHEMA:
        problems.append(f"schema {receipt.get('schema')!r}")
    if receipt.get("algo") != FOOTPRINT_RECEIPT_ALGO:
        problems.append(f"algo {receipt.get('algo')!r}")
    if "status" in receipt and receipt.get("status") != "complete":
        problems.append(f"status {receipt.get('status')!r}")
    if receipt.get("complete") is not True:
        problems.append("complete is not true (the backfill did not finish)")
    if receipt.get("manual_sha256") != md_pins:
        problems.append("manual_sha256 pins differ from the manual being shipped")
    if receipt.get("catalog_sha256") != catalog_pins:
        problems.append("catalog_sha256 pins differ from the catalogs being shipped")
    try:
        has_nodes = nodes.is_dir() and any(path.name.endswith(".json")
                                           and not path.name.startswith(".")
                                           for path in nodes.iterdir())
    except OSError:
        has_nodes = False
    if not has_nodes:
        problems.append(f"{nodes.name}/ has no node files")
    return problems


@dataclass
class FrameworkView:
    """框架树的出包视图：脱敏后替换的成员、新的同步回执、没法动的带凭据成员。"""
    by_path: dict[str, str]
    meta_bytes: bytes
    original_meta_bytes: bytes
    redacted: dict[str, bytes] = field(default_factory=dict)
    pinned_with_credentials: dict[str, int] = field(default_factory=dict)
    values: int = 0
    userinfo: int = 0


def client_pins() -> tuple[str, str]:
    """(模板 SHA, 契约 SHA)：客户端 cex_core 固定校验的那一对。"""
    if str(VENDOR) not in sys.path:
        sys.path.insert(0, str(VENDOR))
    try:
        from cex_core.ist_emit.excel_contract import (
            PINNED_CONTRACT_SHA256,
            TEMPLATE_SHA256,
        )
    except ImportError as exc:
        raise SystemExit("gateway/vendor/cex_core is missing; run "
                         "tools/sync_gateway_vendor.py --only cex_core first") from exc
    return TEMPLATE_SHA256, PINNED_CONTRACT_SHA256


def rederive_command_tree(data_root: Path, raw_build: str, manual_version: str,
                          work: Path) -> dict[str, Any]:
    """子进程跑 cmdtree_rederive.py（引擎在导入时按数据根定路径，不能与发布进程共用）。"""
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "cmdtree_rederive.py"),
         "--data-root", str(data_root), "--raw-build", raw_build,
         "--manual-version", manual_version, "--work", str(work)],
        capture_output=True, text=True, timeout=1800, check=False)
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    try:
        result = json.loads(lines[-1])
    except (IndexError, ValueError):
        result = {"ok": False, "error": (proc.stderr or proc.stdout)[-800:]}
    return result


class Refused(RuntimeError):
    pass


class DataDirResolver:
    def __init__(self, root: Path, raw_build: str, manual_version: str, *,
                 rederive: Callable[..., dict[str, Any]] = rederive_command_tree,
                 pins: tuple[str, str] | None = None, work: Path | None = None,
                 engine: Any = None):
        self.root = root.resolve()
        self.raw = raw_build.strip()
        self.build = execution_build(self.raw)
        self.manual_ver = manual_version
        self.rederive = rederive
        self.pins = pins
        self.work = work
        self._engine_hooks = engine
        self.entries: list[Entry] = []
        self.checks: list[dict[str, Any]] = []
        self.failures: list[dict[str, Any]] = []
        self.rederived: dict[str, Any] = {}
        self.scanner: CredentialScanner | None = None
        self._framework_view: FrameworkView | Exception | None = None
        self.source: dict[str, Any] = {"importer": "publish_data_dir", "raw_build": self.raw,
                                       "execution_build": self.build,
                                       "manual_version": self.manual_ver}

    def engine(self) -> Any:
        if self._engine_hooks is None:
            self._engine_hooks = EngineHooks()
        return self._engine_hooks

    def ok(self, key: str, evidence: str = "") -> None:
        self.checks.append({"key": key, "status": "ok", "evidence": evidence[:300]})

    def fail(self, key: str, evidence: str, **extra: Any) -> None:
        item = {"key": key, "status": "fail", "evidence": evidence[:500], **extra}
        self.checks.append(item)
        self.failures.append(item)

    def add(self, kind: str, rel: str, path: Path, **meta: Any) -> None:
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(f"{path} missing")
        self.add_bytes(kind, rel, path.read_bytes(), media_type_for(path.name), **meta)

    def add_bytes(self, kind: str, rel: str, data: bytes, media_type: str, **meta: Any) -> None:
        self.entries.append(Entry(kind, f"{kind}/{rel}", data, media_type, dict(meta)))

    def step(self, key: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — 逐类收集，最后一起拒绝
            self.fail(key, f"{type(exc).__name__}: {exc}")

    def _scratch(self, prefix: str) -> tempfile.TemporaryDirectory:
        if self.work is not None:
            self.work.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(prefix=prefix,
                                           dir=str(self.work) if self.work is not None else None)

    # ── 各类 ───────────────────────────────────────────────────────────

    def cmdtree(self) -> None:
        work = self.work or Path(tempfile.mkdtemp(prefix="cex-cmdtree-"))
        result = self.rederive(self.root, self.raw, self.manual_ver, work)
        if not result.get("ok"):
            return self.fail("cmdtree", str(result.get("error") or "re-derivation failed"))
        self.rederived = result
        files = {name: Path(path) for name, path in result["files"].items()}
        gen = result["generation"]
        for name in ("generation_manifest.json", f"cmdtree_{gen['device_build']}.xml"):
            self.add("cmdtree", name, files[name])
        projection = next(name for name in files if name.startswith("vendor_stdlib_"))
        self.add("cmdtree", projection, files[projection], legacy_name=projection,
                 version=gen["generation_id"], projection_sha256=gen["projection_sha256"])
        summary = {"schema": "cex.cmdtree-source/v2", **{k: gen[k] for k in (
            "full_version", "generation_id", "manifest_sha256", "source_url", "source_sha256",
            "projection_sha256", "product", "platform", "version", "device_build",
            "results_total", "results_nonempty", "item_count")},
            "raw_xml_shipped": "sanitized", "sanitization": result["sanitization"],
            "rederivation_checks": result["checks"]}
        self.add_bytes("cmdtree", "source.json",
                       json.dumps(summary, ensure_ascii=False, indent=1).encode(),
                       "application/json")
        self.source["cmdtree_generation"] = gen["generation_id"]
        self.ok("cmdtree", f"{gen['generation_id']} (sanitized: "
                           f"{result['sanitization']['blanked_default_values']} default values "
                           "blanked)")

    def credentials(self) -> None:
        """凭据值：引擎在原始框架镜像与原始命令树 XML 上的闭包（只在内存里，不记值）。"""
        if not self.rederived:
            return self.fail("credentials", "the command tree was not re-derived, so the original "
                                            "XML's default-value closure is unavailable")
        original = self.rederived.get("original_xml") or {}
        xml_path = Path(str(original.get("path") or "")).resolve()
        store = self.root / "runtime/command_tree"
        if store not in xml_path.parents or not xml_path.is_file():
            return self.fail("credentials", "the re-derivation reported no original command tree "
                                            "XML inside the data root")
        raw_xml = xml_path.read_bytes()
        if sha(raw_xml) != original.get("sha256") \
                or sha(raw_xml) != self.rederived["sanitization"].get("original_xml_sha256"):
            return self.fail("credentials", "the original command tree XML changed during publish")
        engine = self.engine()
        framework = frozenset(engine.mirror_literals(self.root / "knowledge/framework/mirror"))
        tree = frozenset(engine.xml_literals(raw_xml))
        values = {value: SUBSTRING for value in framework}
        for value in tree:
            values.setdefault(value, TOKEN)
        self.scanner = CredentialScanner(values)
        self.source["credential_values"] = {"framework_mirror": len(framework),
                                            "command_tree_defaults": len(tree)}
        self.ok("credentials", f"{len(framework)} framework literal(s), {len(tree)} command-tree "
                               "default literal(s) (values are never recorded)")

    def _require_scanner(self) -> CredentialScanner:
        if self.scanner is None:
            raise RuntimeError("credential values are unavailable (see the credentials check)")
        return self.scanner

    def framework_view(self) -> FrameworkView:
        """框架树出包视图（算一次）：钉在契约里的文件不动，别的带凭据成员脱敏。"""
        if isinstance(self._framework_view, Exception):
            raise self._framework_view
        if self._framework_view is None:
            try:
                self._framework_view = self._build_framework_view()
            except Exception as exc:  # noqa: BLE001 — 记下原因，projections/framework 都报
                self._framework_view = exc
                raise
        return self._framework_view

    def _build_framework_view(self) -> FrameworkView:
        scanner = self._require_scanner()
        mirror = self.root / "knowledge/framework/mirror"
        meta_bytes = (mirror / ".sync_meta.json").read_bytes()
        meta = json.loads(meta_bytes)
        by_path = dict(meta["by_path"])
        bad = [rel for rel, h in by_path.items()
               if not (mirror / rel).is_file() or sha((mirror / rel).read_bytes()) != h]
        if bad:
            raise ValueError(f"{len(bad)} mirror files differ from .sync_meta: {bad[:3]}")
        contract = json.loads((self.root / "knowledge/data/compile_ref/excel_contract.json")
                              .read_text(encoding="utf-8"))
        pinned = set(contract.get("source_hashes") or {})
        view = FrameworkView(by_path=by_path, meta_bytes=meta_bytes, original_meta_bytes=meta_bytes)
        problems = []
        for rel in sorted(by_path):
            data = (mirror / rel).read_bytes()
            values, userinfo = _findings(scanner, data)
            if not values and not userinfo:
                continue
            if rel in pinned:
                if values:
                    view.pinned_with_credentials[rel] = values
                continue
            try:
                blob, found, links = redact_member(scanner, rel, data)
            except Unredactable as exc:
                problems.append(str(exc))
                continue
            view.redacted[rel] = blob
            view.values += found
            view.userinfo += links
        if problems:
            raise Unredactable(f"{len(problems)} framework file(s) carry credentials that cannot "
                               f"be redacted in place: {'; '.join(problems[:5])}")
        if view.redacted:
            # 客户端引擎要对整棵树解析凭据字面（mirror_credential_literals）：脱敏后每个 .py 都还得能解析
            sources = [(rel, view.redacted.get(rel) or (mirror / rel).read_bytes())
                       for rel in sorted(by_path) if rel.endswith(".py")]
            self.engine().parse_literals(sources)
            view.by_path = {rel: sha(view.redacted[rel]) if rel in view.redacted else digest
                            for rel, digest in by_path.items()}
            view.meta_bytes = dump_like(meta_bytes, {**meta, "by_path": view.by_path})
        return view

    def projections(self) -> None:
        ref = self.root / "knowledge/data/compile_ref"
        mirror = self.root / "knowledge/framework/mirror"
        anchors_bytes = (ref / "mirror_manifest.json").read_bytes()
        anchors_doc = json.loads(anchors_bytes)
        anchors = anchors_doc["files"]
        drift = [rel for rel, h in anchors.items()
                 if not (mirror / rel).is_file() or sha((mirror / rel).read_bytes()) != h]
        if drift:
            return self.fail("projections", f"mirror drifted from mirror_manifest anchors: {drift[:5]}")
        _template, contract_pin = self.pins or client_pins()
        contract = json.loads((ref / "excel_contract.json").read_text())
        if contract.get("contract_sha256") != contract_pin:
            return self.fail("projections", "excel_contract differs from the client's pinned contract")
        bad = [rel for rel, h in contract["source_hashes"].items()
               if not (mirror / rel).is_file() or sha((mirror / rel).read_bytes()) != h]
        if bad:
            return self.fail("projections", f"contract sources differ from the mirror: {bad}")
        if not self.rederived:
            return self.fail("projections", "the command tree was not re-derived; the teardown "
                                            "atlas and domain grammar cannot be bound")
        view = self.framework_view()
        # 锚点描述的是发出去的镜像文件：脱敏过的锚点文件改记脱敏后的哈希
        rebound = {rel: sha(view.redacted[rel]) for rel in anchors if rel in view.redacted}
        rederived = {name: Path(self.rederived["files"][name]) for name in REDERIVED_PROJECTIONS}
        count = 0
        for path in sorted(ref.rglob("*")):
            rel = path.relative_to(ref)
            if (not path.is_file() or path.is_symlink() or any(p.startswith(".") for p in rel.parts)
                    or rel.name in PROJECTION_EXCLUDE_NAMES
                    or rel.name.startswith(PROJECTION_EXCLUDE_PREFIXES)
                    or "__pycache__" in rel.parts):
                continue
            if rel.as_posix() == "mirror_manifest.json" and rebound:
                self.add_bytes("projections", "mirror_manifest.json",
                               dump_like(anchors_bytes, {**anchors_doc,
                                                         "files": {**anchors, **rebound}}),
                               "application/json")
            else:
                self.add("projections", rel.as_posix(), rederived.get(rel.as_posix(), path))
            count += 1
        self.add_bytes("projections", "ssl_lifecycle_contract.json", self._ssl_lifecycle(),
                       "application/json")
        ledger = self.root / CRITERION_LEDGER
        self.add("projections", "criterion_author_rules.jsonl", ledger)
        records = sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip())
        self.ok("projections", f"{count} files; {len(anchors)} anchors match"
                               f"{f' ({len(rebound)} rebound to redacted files)' if rebound else ''}; "
                               f"atlas and grammar re-derived; {records} criterion rules")

    def _ssl_lifecycle(self) -> bytes:
        """SSL 生命周期证据：拆卸图谱身份改绑到重推导的图谱，别的证据按文件逐个核对。"""
        payload = json.loads((self.root / SSL_LIFECYCLE_ASSET).read_text(encoding="utf-8"))
        ref = self.root / "knowledge/data/compile_ref"
        old_identity = json.loads((ref / "command_teardown_atlas.json").read_text())["identity"]["sha256"]
        new_atlas = json.loads(Path(self.rederived["files"]["command_teardown_atlas.json"]).read_text())
        mirror_prefix = "knowledge/framework/mirror/"
        redacted = self.framework_view().redacted
        for contract in payload.get("contracts") or []:
            reference = contract.get("reference_evidence") or {}
            for path_key, sha_key in (("clear_source", "clear_source_sha256"),
                                      ("start_manual_source", "start_manual_source_sha256")):
                source = str(reference.get(path_key) or "")
                target = self.root / source
                if not target.is_file() or sha(target.read_bytes()) != reference.get(sha_key):
                    raise ValueError(f"SSL lifecycle evidence {path_key} no longer matches the data")
                if source.startswith(mirror_prefix) and source[len(mirror_prefix):] in redacted:
                    raise ValueError(f"SSL lifecycle evidence {path_key} names a framework file "
                                     "that the publisher redacted")
            if reference.get("teardown_atlas_identity_sha256") != old_identity:
                raise ValueError("SSL lifecycle evidence is bound to another teardown atlas")
            reference["teardown_atlas_identity_sha256"] = new_atlas["identity"]["sha256"]
        return (json.dumps(payload, ensure_ascii=False, indent=1) + "\n").encode("utf-8")

    def template(self) -> None:
        ref = self.root / "knowledge/data/compile_ref"
        tpl = ref / "excel_runtime_template.xlsx"
        template_pin, contract_pin = self.pins or client_pins()
        if sha(tpl.read_bytes()) != template_pin:
            return self.fail("template", "runtime template differs from the client's pinned template")
        receipt_path = self.root / "runtime/excel_release/promotion_receipt.json"
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("status") != "promoted" or receipt.get("device_build") != self.build \
                or receipt.get("final_contract_sha256") != contract_pin:
            return self.fail("template", f"promotion receipt is for {receipt.get('device_build')}, "
                                         f"status {receipt.get('status')}")
        released_in = receipt.get("environment")  # 晋升回执记的 Excel 晋升环境
        self.add("template", tpl.name, tpl, legacy_name=tpl.name, version=self.build,
                 contract_sha256=contract_pin, environment=released_in)
        for name in ("excel_contract.json", "excel_workbook_manifest.json"):
            self.add("template", name, ref / name)
        self.add("template", "promotion_receipt.json", receipt_path)
        self.source["excel_environment"] = released_in
        self.ok("template", f"promoted for {self.build}")

    def manual(self) -> None:
        """手册：与引擎客户端同一条 catalog 生效规则（load_catalog_status 为 ok 才发）。"""
        base = self.root / "knowledge/data/manual"
        shipped, problems = [], []
        for fam in ("cli", "app"):
            verdict = self.engine().catalog_status(self.manual_ver, fam, root=base)
            status = str(verdict.get("status") or "")
            if status == "md_missing" and fam != "cli":
                continue
            if status != "ok":
                problems.append(f"{fam}: catalog status {status or '?'}")
                continue
            self.add("manual", f"{self.manual_ver}/{fam}_cn.md", base / self.manual_ver / f"{fam}_cn.md")
            self.add("manual", f"{self.manual_ver}/{fam}_cn.catalog.json",
                     base / self.manual_ver / f"{fam}_cn.catalog.json")
            shipped.append(fam)
        if problems:
            return self.fail("manual", f"{self.manual_ver}: " + "; ".join(problems))
        state = json.loads((base / ".sync_state.json").read_text())
        picked = {k: v for k, v in state.items() if k.endswith(f":{self.manual_ver}")}
        self.add_bytes("manual", f"{self.manual_ver}/sync_state.json",
                       json.dumps(picked, ensure_ascii=False, sort_keys=True, indent=1).encode(),
                       "application/json")
        self.ok("manual", f"{self.manual_ver}: {', '.join(shipped)}")

    def spec(self) -> None:
        base = self.root / "knowledge/data/spec"
        active = json.loads((base / "active.json").read_text())
        gen = base / "generations" / active["generation_id"]
        mbytes = (gen / "manifest.json").read_bytes()
        if sha(mbytes) != active["manifest_sha256"]:
            return self.fail("spec", "active.json manifest_sha256 mismatch")
        manifest = json.loads(mbytes)
        docs: dict[str, bytes] = {}
        bad = []
        for name, info in sorted(manifest["documents"].items()):
            path = gen / "docs" / name
            if not path.is_file() or sha(path.read_bytes()) != info["sha256"]:
                bad.append(name)
                continue
            docs[name] = path.read_bytes()
        if bad:
            return self.fail("spec", f"{len(bad)} documents missing or altered: {bad[:3]}")
        scanner = self._require_scanner()
        redacted: dict[str, bytes] = {}
        values = userinfo = 0
        for name, data in docs.items():
            if not any(_findings(scanner, data)):
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                return self.fail("spec", f"docs/{name} carries credentials but is not UTF-8 text")
            new, found, links = redact_text(scanner, text)
            redacted[name] = new.encode("utf-8")
            values += found
            userinfo += links
        index_bytes = (gen / "index.json").read_bytes()
        generation_id = active["generation_id"]
        if redacted:
            index_bytes = dump_like(index_bytes, self._rederive_spec_index(gen, docs, redacted,
                                                                           json.loads(index_bytes)))
            documents = {name: ({**info, "size": len(redacted[name]),
                                 "sha256": sha(redacted[name])} if name in redacted else info)
                         for name, info in manifest["documents"].items()}
            artifacts = {**manifest["artifacts"],
                         "index.json": {**manifest["artifacts"]["index.json"],
                                        "size": len(index_bytes), "sha256": sha(index_bytes)}}
            generation_id = derived_generation_id(active["generation_id"], documents, artifacts)
            mbytes = dump_like(mbytes, {**manifest, "generation_id": generation_id,
                                        "documents": documents, "artifacts": artifacts})
            self.source["spec_redaction"] = {"original_generation_id": active["generation_id"],
                                             "documents": len(redacted), "credential_values": values,
                                             "url_userinfo": userinfo, "placeholder": PLACEHOLDER}
        self.add_bytes("spec", "manifest.json", mbytes, "application/json",
                       generation_id=generation_id, manifest_sha256=sha(mbytes))
        self.add_bytes("spec", "index.json", index_bytes, "application/json")
        self.add("spec", "state.tsv", gen / "state.tsv")
        for name, data in docs.items():
            self.add_bytes("spec", f"docs/{name}", redacted.get(name, data), media_type_for(name))
        self.source["spec_generation"] = generation_id
        self.ok("spec", f"{generation_id}: {len(docs)} documents"
                        + (f" ({len(redacted)} redacted from {active['generation_id']})"
                           if redacted else ""))

    def _rederive_spec_index(self, gen: Path, docs: dict[str, bytes], redacted: dict[str, bytes],
                             index: dict[str, Any]) -> dict[str, Any]:
        """用引擎的 build_spec_index 在脱敏前后各推一遍，只把推出来的差异写回原索引。"""
        with self._scratch("cex-spec-") as scratch:
            folder = Path(scratch) / "docs"
            folder.mkdir()
            for name, data in docs.items():
                target = folder / name
                target.write_bytes(redacted.get(name, data))
                times = (gen / "docs" / name).stat()
                os.utime(target, ns=(times.st_atime_ns, times.st_mtime_ns))  # 缺台账时代龄按 mtime
            before = self.engine().build_spec_index(gen / "docs", state_path=gen / "state.tsv")
            after = self.engine().build_spec_index(folder, state_path=gen / "state.tsv")
        entries = index.get("entries")
        if not isinstance(entries, dict) or set(before["entries"]) != set(after["entries"]):
            raise ValueError("redaction changed which spec documents the index covers")
        updated = json.loads(json.dumps(index))
        for name, old in before["entries"].items():
            new = after["entries"][name]
            if old == new:
                continue
            if name not in updated["entries"]:
                raise ValueError(f"spec index has no entry for {name}")
            for key in set(old) | set(new):
                if old.get(key) != new.get(key):
                    if key in new:
                        updated["entries"][name][key] = new[key]
                    else:
                        updated["entries"][name].pop(key, None)
        for key, value in after.get("coverage", {}).items():
            if before.get("coverage", {}).get(key) != value:
                updated.setdefault("coverage", {})[key] = value
        for name, data in redacted.items():
            entry = updated["entries"].get(name) or {}
            if entry.get("sha256") != sha(data) or entry.get("size") != len(data):
                raise ValueError(f"the re-derived spec index does not bind docs/{name}")
        return updated

    def framework(self) -> None:
        mirror = self.root / "knowledge/framework/mirror"
        view = self.framework_view()
        keep = sorted(view.by_path)
        tar = tar_gz_bytes((rel, view.redacted.get(rel) or (mirror / rel).read_bytes())
                           for rel in keep)
        meta = json.loads(view.meta_bytes)
        self.add_bytes("framework", "framework_tree.tar.gz", tar, "application/gzip",
                       legacy_name="framework_tree.tar.gz", files=len(keep),
                       sync_receipt_sha256=sha(view.meta_bytes), synced_at=meta.get("synced_at"),
                       source_host=meta.get("source"), redacted_files=len(view.redacted),
                       **({"original_sync_receipt_sha256": sha(view.original_meta_bytes)}
                          if view.redacted else {}))
        self.add_bytes("framework", "sync_meta.json", view.meta_bytes, "application/json")
        self.source["framework_synced_at"] = meta.get("synced_at")
        if view.redacted:
            self.source["framework_redaction"] = {
                "files": len(view.redacted), "credential_values": view.values,
                "url_userinfo": view.userinfo, "placeholder": PLACEHOLDER,
                "pinned_files_with_credentials": sorted(view.pinned_with_credentials),
                # 方法参考/能力图谱记的框架源身份覆盖 lib/ 与 smoke_test/conftest.py：这些文件脱敏后，
                # 那份身份如实描述的是脱敏前的源（客户端不拿它核镜像），在这里点名
                "projection_identity_sources": sorted(
                    rel for rel in view.redacted
                    if rel.startswith("lib/") or rel == "smoke_test/conftest.py")}
        self.ok("framework", f"{len(keep)} files verified against .sync_meta"
                             + (f"; {len(view.redacted)} redacted" if view.redacted else ""))

    def footprints(self) -> None:
        fp = self.root / "knowledge/footprints"
        receipt = fp / f".receipt_nodes_{self.manual_ver}.json"
        info = json.loads(receipt.read_text())
        nodes = fp / f"nodes_{self.manual_ver}"
        manual = self.root / "knowledge/data/manual"
        md_pins, catalog_pins = {}, {}
        for fam in ("cli", "app"):
            md = manual / self.manual_ver / f"{fam}_cn.md"
            if not md.is_file():
                continue
            md_pins[md.name] = sha(md.read_bytes())
            verdict = self.engine().catalog_status(self.manual_ver, fam, root=manual)
            catalog_pins[f"{fam}_cn.catalog.json"] = str(verdict.get("catalog_sha256") or "")
        problems = footprint_receipt_problems(info, md_pins=md_pins, catalog_pins=catalog_pins,
                                              nodes=nodes)
        if problems:
            return self.fail("footprints", f"{receipt.name}: " + "; ".join(problems))
        self.add_bytes("footprints", f"nodes_{self.manual_ver}.tar.gz",
                       deterministic_tar_gz(nodes, include=lambda rel: rel.suffix == ".json"),
                       "application/gzip", manual_version=self.manual_ver)
        self.add("footprints", f"receipt_nodes_{self.manual_ver}.json", receipt)
        self.ok("footprints", f"{self.manual_ver} backfill receipt complete")

    def credential_scan(self) -> None:
        """出包前扫描：每个条目、每个 tar/zip 成员都不许再带凭据值。"""
        scanner = self._require_scanner()
        try:
            hits = scanner.scan_entries(self.entries)
        except CredentialScanError as exc:
            return self.fail("credential_scan", f"the bundle could not be scanned: {exc}")
        if hits:
            pinned = (self._framework_view.pinned_with_credentials
                      if isinstance(self._framework_view, FrameworkView) else {})
            notes = {}
            for name, _count in hits:
                parts = name.split("!")
                if parts[0] == "framework/framework_tree.tar.gz" and len(parts) > 1 \
                        and parts[1] in pinned:
                    notes[name] = _PINNED_NOTE
                elif parts[0].startswith("manual/"):
                    notes[name] = _MANUAL_NOTE
            return self.fail("credential_scan",
                             f"{len(hits)} bundle entries/members still carry credential values "
                             f"({sum(n for _, n in hits)} occurrences; locations and counts only)",
                             locations=describe_credential_hits(hits, notes))
        self.source["credential_scan"] = {"status": "clean", "values": scanner.value_count,
                                          "entries": len(self.entries)}
        self.ok("credential_scan", f"{len(self.entries)} entries and their members carry none of "
                                   f"{scanner.value_count} credential value(s)")

    def resolve(self) -> Resolution:
        # cmdtree 先跑：credentials 要它报的原始 XML，projections 要它重推导的图谱与文法；
        # 出包前扫描最后跑，扫的就是要发的全部条目
        order = ("cmdtree", "credentials", *[kind for kind in KINDS if kind != "cmdtree"],
                 "credential_scan")
        for key in order:
            self.step(key, getattr(self, key))
        if self.failures:
            raise Refused(json.dumps(self.failures, ensure_ascii=False, indent=1))
        return Resolution(self.build, self.entries, self.source, self.checks)


def write_out_dir(resolution: Resolution, out: Path) -> dict[str, Any]:
    """把条目按包布局写到本地目录（与客户端同步下来的目录同形），供检查与离线测试。

    本地目录也可能被拿去 ces registry import-dir：同样只写扫描过且干净的解析结果。"""
    Publisher.preflight(resolution, promote=False)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for entry in resolution.entries:
        target = out / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry.data)
        rows.append({"kind": entry.kind, "path": entry.path, "sha256": entry.sha256,
                     "bytes": len(entry.data), "media_type": entry.media_type,
                     "meta": entry.meta})
    manifest = {"build": resolution.build, "entries": rows, "source": resolution.source,
                "bundle_id": sha(json.dumps(sorted((r["path"], r["sha256"]) for r in rows))
                                 .encode())}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    return {"out_dir": str(out), "entries": len(rows), "bundle_id": manifest["bundle_id"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-root", required=True)
    ap.add_argument("--raw-build", required=True)
    ap.add_argument("--manual-version", required=True)
    ap.add_argument("--server", default="",
                    help="server URL, or the connection string printed by `ces link` "
                         "(with #ca= the CA is fetched and checked against the fingerprint)")
    ap.add_argument("--client-id", default="publisher")
    ap.add_argument("--client-secret-file", default="")
    ap.add_argument("--promote", action="store_true")
    ap.add_argument("--insecure-lan", action="store_true",
                    help="allow plain http to a non-loopback server (trusted lab network only)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out-dir", default="", help="write the bundle to this directory instead of uploading")
    args = ap.parse_args(argv)
    uploading = not args.dry_run and not args.out_dir
    if uploading:
        # 先核地址再花几分钟解析：明文 http 发往非回环地址直接拒绝
        if not args.server or not args.client_secret_file:
            print(json.dumps({"ok": False, "error": "--server and --client-secret-file are required "
                                                    "(or --dry-run / --out-dir)"}))
            return 64
        try:
            check_publish_server(args.server, insecure_lan=args.insecure_lan)
        except PublishError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
            return 1
    resolver = DataDirResolver(Path(args.data_root), args.raw_build, args.manual_version)
    try:
        res = resolver.resolve()
    except Refused as exc:
        print(json.dumps({"ok": False, "refused": json.loads(str(exc))}, ensure_ascii=False, indent=1))
        return 3
    summary = {"ok": True, "build": res.build,
               "entries": {k: sum(1 for e in res.entries if e.kind == k) for k in KINDS},
               "bytes": sum(len(e.data) for e in res.entries), "checks": res.checks}
    if args.dry_run:
        print(json.dumps({**summary, "dry_run": True}, ensure_ascii=False, indent=1))
        return 0
    if args.out_dir:
        print(json.dumps({**summary, **write_out_dir(res, Path(args.out_dir))}, ensure_ascii=False,
                         indent=1))
        return 0
    try:
        pub = Publisher(args.server, args.client_id,
                        read_secret_file(Path(args.client_secret_file).expanduser()),
                        insecure_lan=args.insecure_lan)
        result = pub.publish(res, promote=args.promote, required_kinds=KINDS)
    except (PublishError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    summary.pop("checks")
    print(json.dumps({**summary, **result}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
