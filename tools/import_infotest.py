#!/usr/bin/env python3
"""import_infotest：把工作站上 InfoTest 已收敛的编译数据发布成服务端数据包（过渡期发布通道）。

在跑过 InfoTest 批入口（收敛链）的工作站上，用 InfoTest 自己的 venv 运行：

  <InfoTest venv>/bin/python tools/import_infotest.py \\
      --infotest-root <InfoTest 仓根> --device-build "<show version 的完整版本>" \\
      --server https://ces.example --client-id publisher --client-secret-file <0600 文件> \\
      [--promote] [--dry-run]

做法：
- 只调 InfoTest 自己的解析与校验函数；收敛函数（ensure_compile_environment、
  refresh_compile_projections、converge_*）一律不调——它们会写文件、部署跳板机、上设备。
- InfoTest 没有“收敛链已跑完”的回执，所以闸是：InfoTest 编译预检里与数据有关的各项 +
  逐类的校验。任何一项不过就拒绝导入，并指出 InfoTest 里修复它的入口。
- spec：先调 InfoTest 自己的 spec 同步（有时限），同步失败就拒绝；generation 的代龄只记录。
- 命令树只发投影（vendor_stdlib JSON），不发原始 XML：原始 XML 带参数默认值（含凭据默认值）；
  compile_ref 里的 cmdtree_*.xml 也不进 projections。
- 出包前扫描：每个条目、每个 tar/zip 成员里都不许出现凭据值（框架镜像源码的凭据字面 +
  命令树 XML 凭据参数的默认值，取 InfoTest 自己的闭包函数，查原文、XML 转义、URL 编码等写法）。
  本通道不脱敏：框架树、规格书里带凭据就拒绝，改用 tools/publish_data_dir.py（它脱敏并重推导）。
- 发布：client_credentials 取令牌 → 逐个 PUT blob → POST 清单进 candidate →
  服务端自检通过且给了 --promote 才切 stable。内容没变时 bundle_id 相同，是空操作。
  服务端地址必须是 https（回环地址除外；可信实验网显式 --insecure-lan），客户端密钥不明文过网。

分两层：InfoTestResolver 只负责从 InfoTest 取条目和检查结果；Publisher 只负责打包上传，
与 InfoTest 无关（测试用假 resolver 驱动它）。出包前扫描（CredentialScanner）也在与 InfoTest
无关的这一层，两个发布通道共用；Publisher 只上传扫描过且干净的解析结果。
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

KINDS = ("cmdtree", "manual", "spec", "projections", "template", "framework", "footprints")

# InfoTest 编译预检里与发布数据有关的检查项；跳板机、设备、串口、Web 终端、结果通道这些
# 连接面检查属于上机侧，交给网关，不拦发布
DATA_CHECKS = (
    "framework_mirror", "framework_projection", "excel_template", "excel_contract",
    "command_tree", "projection_catalog_freshness", "criterion_manual_anchors",
    "spec_active", "footprints", "manual_cli", "manual_sync_state", "manual_catalog",
    "manual_backfill_receipt",
)

# compile_ref 下不进包的：扁平 vendor_stdlib 的有效副本在命令树 generation 里；
# source_reconciliation 没有消费方；Excel 候选文件归 template 类；cmdtree_*.xml 是带凭据默认值的
# 原始命令树（脱敏重推导的那份由 publish_data_dir 发）
_PROJECTION_EXCLUDE_PREFIXES = ("vendor_stdlib_", "source_reconciliation_", "cmdtree_")
_PROJECTION_EXCLUDE_NAMES = {
    "excel_contract.json", "excel_runtime_template.xlsx", "excel_workbook_manifest.json",
}
_MEDIA = {
    ".json": "application/json", ".md": "text/markdown", ".xlsx":
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".gz": "application/gzip", ".tsv": "text/tab-separated-values",
}


class ImportRefused(RuntimeError):
    """导入被闸拒绝；failures 里是逐项原因。"""

    def __init__(self, failures: list[dict[str, str]]):
        super().__init__(f"{len(failures)} 项检查未通过")
        self.failures = failures


@dataclass
class Entry:
    kind: str
    path: str
    data: bytes
    media_type: str = "application/octet-stream"
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class Resolution:
    build: str
    entries: list[Entry]
    source: dict[str, Any]
    checks: list[dict[str, str]]


def media_type_for(name: str) -> str:
    return _MEDIA.get(Path(name).suffix.lower(), "application/octet-stream")


def deterministic_tar_gz(root: Path, *, include: Callable[[Path], bool] | None = None) -> bytes:
    """同样的文件内容永远打出同样的字节：按路径排序，mtime/uid/gid 清零，gzip 头不带时间。"""
    root = Path(root)
    files = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if path.is_symlink() or not path.is_file():
            continue
        if include is not None and not include(rel):
            continue
        files.append((rel.as_posix(), path.read_bytes()))
    return tar_gz_bytes(files)


def tar_gz_bytes(files: Iterable[tuple[str, bytes]]) -> bytes:
    """内存里的 (相对路径, 内容) 打成确定性 tar.gz（与 deterministic_tar_gz 同一套规则）。

    按路径分段排序（与 Path 排序一致），同样的内容打出与按目录打包同样的字节。"""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel, data in sorted(files, key=lambda item: item[0].split("/")):
            info = tarfile.TarInfo(rel)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


# ── 出包前的凭据扫描（与 InfoTest 无关；两个发布通道共用）────────────────────
# 值由调用方用引擎在**原始**数据上的闭包算出（框架镜像源码里的凭据字面、命令树 XML 凭据参数的
# 默认值），这里只认值。匹配与引擎同一套规则：
#   SUBSTRING：忽略大小写的子串（credential_literals.matching_credential_literal_count，框架闭包）
#   TOKEN：纯字母数字的值按词边界、其余按子串，忽略大小写
#          （command_tree_sync.xml_sensitive_literal_count，命令树默认值闭包）
# 每个值还查它在包里可能的别的写法：XML 转义、URL 编码、JSON 转义。gzip/tar/zip（含 xlsx）逐层
# 解开查；xlsx 的共享串按富文本分段存时，把同一个串的各段拼起来再查一遍。
# 报告只有位置与次数，从不带值。
SUBSTRING = "substring"
TOKEN = "token"
_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
_SCAN_MAX_DEPTH = 4
_SCAN_MAX_EXPANDED = 4 * 1024 ** 3
_XML_RUN_GROUP = re.compile(r"<(si|is)\b[^>]*>(.*?)</\1>", re.S)
_XML_RUN_TEXT = re.compile(r"<t\b[^>]*>(.*?)</t>", re.S)


class CredentialScanError(RuntimeError):
    """包没法扫完（嵌套过深、解开后过大）：当成没扫过，拒绝发布。"""


def credential_forms(value: str) -> frozenset[str]:
    """一个凭据值在包里可能的写法：原文、XML 转义（&amp; &lt; &gt; &quot; &#39; …）、URL 编码、JSON 转义。"""
    xml = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    forms = {value, xml, value.replace("&", "&#38;"),
             urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value, safe=""),
             urllib.parse.quote(value), json.dumps(value)[1:-1],
             json.dumps(value, ensure_ascii=False)[1:-1]}
    for quot in ('"', "&quot;", "&#34;"):
        for apos in ("'", "&#39;", "&apos;"):
            forms.add(xml.replace('"', quot).replace("'", apos))
    return frozenset(form for form in forms if form)


def _joined_runs(text: str) -> str:
    return "\n".join("".join(_XML_RUN_TEXT.findall(group.group(2)))
                     for group in _XML_RUN_GROUP.finditer(text))


class CredentialScanner:
    def __init__(self, values: Mapping[str, str]):
        plain: set[str] = set()
        token: set[str] = set()
        for value, rule in values.items():
            if rule not in (SUBSTRING, TOKEN):
                raise ValueError(f"unknown credential match rule {rule!r}")
            for form in credential_forms(str(value)):
                folded = form.casefold()
                if rule == TOKEN and re.fullmatch("[a-z0-9]+", folded):
                    token.add(folded)
                elif folded:
                    plain.add(folded)
        parts = [re.escape(form) for form in sorted(plain, key=lambda f: (-len(f), f))]
        parts += [rf"(?<![a-z0-9]){re.escape(form)}(?![a-z0-9])"
                  for form in sorted(token, key=lambda f: (-len(f), f))]
        self.value_count = len(values)
        self._folded = re.compile("|".join(parts)) if parts else None
        # 原文上定位（脱敏替换用）：同一组写法，忽略大小写
        self._original = re.compile("|".join(parts), re.IGNORECASE) if parts else None

    def count(self, text: str) -> int:
        if self._folded is None or not text:
            return 0
        return sum(1 for _ in self._folded.finditer(text.casefold()))

    def replace(self, text: str, placeholder: str) -> tuple[str, int]:
        if self._original is None or not text:
            return text, 0
        return self._original.subn(placeholder, text)

    def count_blob(self, data: bytes) -> int:
        """一段不再往下解的内容：按 UTF-8 读（读不了的字节换掉），XML 里再拼富文本分段查。"""
        text = data.decode("utf-8", "replace")
        found = self.count(text)
        if "<t" in text:
            found = max(found, self.count(_joined_runs(text)))
        return found

    def scan(self, name: str, data: bytes) -> list[tuple[str, int]]:
        """name 下（含层层解开的成员）还带凭据值的位置与次数。"""
        hits: list[tuple[str, int]] = []
        self._scan(name, data, hits, 0, [_SCAN_MAX_EXPANDED])
        return hits

    def scan_entries(self, entries: Iterable[Entry]) -> list[tuple[str, int]]:
        hits: list[tuple[str, int]] = []
        for entry in entries:
            hits.extend(self.scan(entry.path, entry.data))
        return hits

    def _scan(self, name: str, data: bytes, hits: list, depth: int, budget: list[int]) -> None:
        if depth > _SCAN_MAX_DEPTH:
            raise CredentialScanError(f"{name}: containers nested too deep to scan")
        if data[:4] == _ZIP_MAGIC:
            try:
                archive = zipfile.ZipFile(io.BytesIO(data))
                members = [info for info in archive.infolist() if not info.is_dir()]
                for info in members:
                    budget[0] -= info.file_size
                    if budget[0] < 0:
                        raise CredentialScanError(f"{name}: expands beyond the scan budget")
                    self._scan(f"{name}!{info.filename}", archive.read(info), hits, depth + 1,
                               budget)
                return
            except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError,
                    RuntimeError) as exc:
                if isinstance(exc, CredentialScanError):
                    raise
                # 不是能解开的 zip：当普通字节查
        elif data[:2] == _GZIP_MAGIC:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    inner = stream.read(budget[0] + 1)
            except (OSError, EOFError):
                inner = None
            if inner is not None:
                if len(inner) > budget[0]:
                    raise CredentialScanError(f"{name}: expands beyond the scan budget")
                budget[0] -= len(inner)
                try:
                    with tarfile.open(fileobj=io.BytesIO(inner), mode="r:") as tar:
                        for member in tar.getmembers():
                            if member.isfile():
                                blob = tar.extractfile(member)
                                self._scan(f"{name}!{member.name}",
                                           blob.read() if blob is not None else b"", hits,
                                           depth + 1, budget)
                    return
                except tarfile.TarError:
                    self._scan(f"{name}!gunzip", inner, hits, depth + 1, budget)
                    return
        found = self.count_blob(data)
        if found:
            hits.append((name, found))


def describe_credential_hits(hits: list[tuple[str, int]],
                             notes: Mapping[str, str] | None = None,
                             limit: int = 60) -> list[str]:
    rows = [f"{name}: {count}" + (f" ({notes[name]})" if notes and name in notes else "")
            for name, count in hits[:limit]]
    if len(hits) > limit:
        rows.append(f"... and {len(hits) - limit} more")
    return rows


# ── InfoTest 一侧 ──────────────────────────────────────────────────────
def compile_ref_files(compile_ref: Path) -> list[tuple[str, Path]]:
    """compile_ref 下进 projections 的文件（排除规则见 _PROJECTION_EXCLUDE_*）。"""
    picked = []
    for path in sorted(compile_ref.rglob("*")):
        rel = path.relative_to(compile_ref)
        if (not path.is_file() or path.is_symlink()
                or any(part.startswith(".") for part in rel.parts)
                or rel.name in _PROJECTION_EXCLUDE_NAMES
                or rel.name.startswith(_PROJECTION_EXCLUDE_PREFIXES)):
            continue
        picked.append((rel.as_posix(), path))
    return picked


class InfoTestResolver:
    def __init__(self, root: Path, raw_build: str, *, spec_sync_timeout_s: int = 180):
        self.root = Path(root).resolve()
        self.raw_build = raw_build.strip()
        self.spec_sync_timeout_s = spec_sync_timeout_s
        self.failures: list[dict[str, str]] = []
        self.checks: list[dict[str, str]] = []
        self.entries: list[Entry] = []
        self.source: dict[str, Any] = {"importer": "import_infotest", "raw_build": self.raw_build}
        self._raw_xml: bytes | None = None  # 活动代际的原始命令树 XML（只用来算默认值闭包，不进包）

    def _fail(self, key: str, evidence: str, repair: str = "", **extra: Any) -> None:
        item = {"key": key, "status": "fail", "evidence": evidence[:500], "repair": repair, **extra}
        self.failures.append(item)
        self.checks.append(item)

    def _ok(self, key: str, evidence: str = "") -> None:
        self.checks.append({"key": key, "status": "ok", "evidence": evidence[:500]})

    def _step(self, key: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except ImportRefused:
            raise
        except Exception as exc:  # noqa: BLE001 — 任何异常都按该项不过处理，继续收集其余项
            self._fail(key, f"{type(exc).__name__}: {exc}")

    def _add_file(self, kind: str, rel: str, path: Path, **meta: Any) -> None:
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(f"{path.name} 缺失或不是普通文件")
        self.entries.append(Entry(kind, f"{kind}/{rel}", path.read_bytes(),
                                  media_type_for(path.name), dict(meta)))

    def resolve(self) -> Resolution:
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        self._step("identity", self._identity)
        if self.failures:
            raise ImportRefused(self.failures)
        self._step("spec_sync", self._spec_sync)
        self._step("preflight", self._preflight)
        self._step("template", self._template)
        self._step("cmdtree", self._cmdtree)
        self._step("manual", self._manual)
        self._step("spec", self._spec)
        self._step("projections", self._projections)
        self._step("framework", self._framework)
        self._step("footprints", self._footprints)
        self._step("credential_scan", self._credential_scan)
        if self.failures:
            raise ImportRefused(self.failures)
        return Resolution(self.execution_build, self.entries, self.source, self.checks)

    def _identity(self) -> None:
        from main.ist_core.compile_engine.bed import mysql_safe_build
        from main.sync.command_tree_sync import parse_build_identity

        ident = parse_build_identity(self.raw_build)
        self.identity = ident
        self.execution_build = mysql_safe_build(self.raw_build)
        self.inventory_version = ident.inventory_version
        self.manual_version = ident.release
        self.source.update({"execution_build": self.execution_build,
                            "inventory_version": self.inventory_version,
                            "manual_version": self.manual_version})
        self._ok("identity", self.execution_build)

    def _spec_sync(self) -> None:
        from main.ist_core.compile_engine import engine_tool

        if not engine_tool._spec_sync_source_ready():
            self._fail("spec_sync", "spec 同步源未配置或地址不合法",
                       "按 InfoTest environment.example 配好 spec 桶的 WebDAV 源")
            return
        result = engine_tool._run_spec_sync_subprocess(
            project_root=self.root, timeout_sec=self.spec_sync_timeout_s)
        if result.get("killed") or result.get("returncode") != 0:
            self._fail("spec_sync",
                       f"spec 同步未完成（killed={result.get('killed')}, "
                       f"rc={result.get('returncode')}），日志 {result.get('log_path')}",
                       "engine_tool._governing_spec_entry_preflight")
            return
        self._ok("spec_sync", "spec 同步完成")

    def _preflight(self) -> None:
        from main.ist_core.compile_engine import env_preflight

        items = env_preflight.run_compile_env_preflight(
            product_version=self.inventory_version, device_build=self.raw_build,
            result_channel_probe=lambda: (True, "importer does not probe the result channel"))
        for item in items:
            if item.key not in DATA_CHECKS:
                continue
            if item.status == "fail":
                self._fail(f"preflight:{item.key}", item.evidence,
                           env_preflight.ENTRY_REPAIR_SITES.get(item.key, ""))
            else:
                self.checks.append({"key": f"preflight:{item.key}", "status": item.status,
                                    "evidence": str(item.evidence)[:300]})

    def _template(self) -> None:
        from main.case_compiler import excel_release, excel_release_bundle

        selected = excel_release.select_promoted_runtime_template()
        if selected.device_build != self.execution_build:
            self._fail("template", f"晋升回执的构建 {selected.device_build!r} 与 "
                       f"{self.execution_build!r} 不一致",
                       "environment_prepare 晋升步（跑一次该床的批入口）")
            return
        candidate = excel_release.validate_candidate_artifact_set()
        paths = candidate.paths
        meta = {"contract_sha256": selected.contract_sha256,
                "promotion_receipt_sha256": selected.promotion_receipt_sha256,
                "environment": selected.environment}
        self._add_file("template", paths.runtime_template.name, paths.runtime_template,
                       legacy_name=paths.runtime_template.name, version=self.execution_build,
                       **meta)
        for path in (paths.contract, paths.ide_workbook, paths.manifest):
            self._add_file("template", path.name, path)
        bundle = excel_release_bundle.build_release_bundle()
        self.entries.append(Entry("template", "template/release_bundle.json", bundle,
                                  "application/json", meta))
        self.source["excel_environment"] = selected.environment
        self._ok("template", "promoted")

    def _cmdtree(self) -> None:
        from main.case_compiler import vendor_stdlib
        from main.ist_core.compile_engine.environment_prepare import (
            DeviceReleaseIdentity,
            active_projection_rebuild_verdict,
        )
        from main.sync.command_tree_sync import resolve_active_command_tree

        scope = vendor_stdlib._command_tree_scope(self.inventory_version, self.raw_build)
        if scope is None:
            self._fail("cmdtree", "推不出唯一的命令树分区", "environment_prepare._converge_device_command_tree")
            return
        product, platform, version, build = scope
        active = resolve_active_command_tree(
            product=product, platform=platform, version=version, device_build=build,
            store_root=vendor_stdlib._command_tree_store_root())
        if active is None or active.full_version != self.raw_build:
            self._fail("cmdtree", "没有与该构建一致的命令树活动代际",
                       "environment_prepare._converge_device_command_tree")
            return
        verdict = active_projection_rebuild_verdict(
            DeviceReleaseIdentity(self.raw_build, self.execution_build, ""),
            product_version=version)
        if verdict.get("rebuild") != "no":
            self._fail("cmdtree", f"命令树投影需要重铸（{verdict.get('reason')}）",
                       "environment_prepare._converge_device_command_tree")
            return
        raw_xml = active.xml_path.read_bytes()
        if hashlib.sha256(raw_xml).hexdigest() != active.source_sha256:
            self._fail("cmdtree", "命令树活动代际的 XML 与代际清单不一致",
                       "environment_prepare._converge_device_command_tree")
            return
        self._raw_xml = raw_xml
        self._add_file("cmdtree", active.projection_path.name, active.projection_path,
                       legacy_name=active.projection_path.name, version=active.generation_id,
                       projection_sha256=active.projection_sha256)
        summary = {
            "schema": "cex.cmdtree-source/v1", "full_version": active.full_version,
            "generation_id": active.generation_id, "manifest_sha256": active.manifest_sha256,
            "source_url": active.source_url, "source_sha256": active.source_sha256,
            "projection_sha256": active.projection_sha256,
            "results_total": active.results_total, "results_nonempty": active.results_nonempty,
            "item_count": active.item_count, "raw_xml_shipped": False,
        }
        self.entries.append(Entry("cmdtree", "cmdtree/source.json",
                                  json.dumps(summary, ensure_ascii=False, indent=1).encode(),
                                  "application/json"))
        self.source["cmdtree_generation"] = active.generation_id
        self._ok("cmdtree", active.generation_id)

    def _manual(self) -> None:
        from main.kms import manual_catalog_store as store

        version = self.manual_version
        shipped = []
        for family in ("cli", "app"):
            status = store.load_catalog_status(version, family)
            state = str(status.get("status") or "")
            if state == "md_missing" and family != "cli":
                continue
            if state != "ok":
                self._fail("manual", f"{family} 手册 catalog 状态 {state}",
                           "engine_tool._manual_freshness_entry_gate")
                continue
            self._add_file("manual", f"{version}/{family}_cn.md", store.md_path(version, family))
            self._add_file("manual", f"{version}/{family}_cn.catalog.json",
                           store.catalog_path(version, family))
            shipped.append(family)
        sync_state_path = store.md_path(version, "cli").parent.parent / ".sync_state.json"
        if sync_state_path.is_file():
            state = json.loads(sync_state_path.read_text(encoding="utf-8"))
            picked = {k: v for k, v in state.items()
                      if isinstance(k, str) and k.endswith(f":{version}")}
            self.entries.append(Entry(
                "manual", f"manual/{version}/sync_state.json",
                json.dumps(picked, ensure_ascii=False, sort_keys=True, indent=1).encode(),
                "application/json"))
        if shipped:
            self._ok("manual", f"{version}: {', '.join(shipped)}")

    def _spec(self) -> None:
        from main.knowledge_paths import (
            resolve_active_spec_generation,
            spec_generation_age_seconds,
        )

        active = resolve_active_spec_generation(self.root)
        parseable, age_s = spec_generation_age_seconds(active.generation_id)
        self.source["spec_generation"] = active.generation_id
        self.source["spec_age_s"] = int(age_s) if parseable else None
        self._add_file("spec", "manifest.json", active.manifest,
                       generation_id=active.generation_id,
                       manifest_sha256=active.manifest_sha256)
        self._add_file("spec", "index.json", active.index)
        # 同步台账：代际清单登记了它的 sha256，客户端重建代际目录时要逐字节核对
        self._add_file("spec", "state.tsv", active.state)
        docs_root = Path(active.docs)
        for path in sorted(docs_root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                self._add_file("spec", "docs/" + path.relative_to(docs_root).as_posix(), path)
        self._ok("spec", active.generation_id)

    def _projections(self) -> None:
        from main.case_compiler.excel_contract import load_excel_contract
        from main.ist_core.compile_engine.mirror_anchor import check_manifest_drift
        from main.knowledge_paths import KNOWLEDGE_DATA_ROOT
        from scripts import gen_command_teardown_atlas

        load_excel_contract()
        drift = check_manifest_drift()
        if drift.get("status") != "match":
            self._fail("projections", f"框架镜像与锚定清单不一致（{drift.get('status')}）",
                       "environment_prepare._sync_framework")
            return
        compile_ref = Path(KNOWLEDGE_DATA_ROOT) / "compile_ref"
        atlas = compile_ref / "command_teardown_atlas.json"
        gen_command_teardown_atlas.verify_atlas_source_identity(
            json.loads(atlas.read_text(encoding="utf-8")))
        count = 0
        for rel, path in compile_ref_files(compile_ref):
            self._add_file("projections", rel, path)
            count += 1
        self._ok("projections", f"{count} files")

    def _credential_values(self) -> dict[str, str]:
        """InfoTest 自己的闭包：框架镜像源码的凭据字面 + 原始命令树 XML 凭据参数的默认值。"""
        from main.case_compiler.credential_literals import mirror_credential_literals
        from main.knowledge_paths import KNOWLEDGE_FRAMEWORK_MIRROR
        from main.sync.command_tree_sync import _xml_default_literal_closure

        if self._raw_xml is None:
            raise RuntimeError("命令树活动代际没解析出来，取不到 XML 默认值闭包，没法做出包前扫描")
        values = {value: SUBSTRING
                  for value in mirror_credential_literals(Path(KNOWLEDGE_FRAMEWORK_MIRROR))}
        for value in _xml_default_literal_closure(self._raw_xml):
            values.setdefault(value, TOKEN)
        return values

    def _credential_scan(self) -> None:
        scanner = CredentialScanner(self._credential_values())
        hits = scanner.scan_entries(self.entries)
        if hits:
            self._fail("credential_scan",
                       f"{len(hits)} 个条目/成员仍带凭据值（共 {sum(n for _, n in hits)} 处；"
                       "只列位置与次数）",
                       "过渡通道不脱敏：改用 tools/publish_data_dir.py 发布（命令树脱敏后重推导、"
                       "框架树与规格书脱敏、出包前同样扫描）",
                       locations=describe_credential_hits(hits))
            return
        self.source["credential_scan"] = {"status": "clean", "values": scanner.value_count,
                                          "entries": len(self.entries)}
        self._ok("credential_scan", f"{len(self.entries)} entries clean "
                                    f"({scanner.value_count} credential values)")

    def _framework(self) -> None:
        from main.case_compiler.framework_projection_identity import (
            build_framework_source_identity,
        )
        from main.knowledge_paths import KNOWLEDGE_FRAMEWORK_MIRROR

        mirror = Path(KNOWLEDGE_FRAMEWORK_MIRROR)
        ident = build_framework_source_identity(mirror)
        tar = deterministic_tar_gz(
            mirror, include=lambda rel: not any(p.startswith(".") for p in rel.parts))
        meta = {k: ident.get(k) for k in ("snapshot_sha256", "sync_receipt_sha256", "synced_at")}
        self.entries.append(Entry("framework", "framework/framework_tree.tar.gz", tar,
                                  "application/gzip",
                                  {"legacy_name": "framework_tree.tar.gz",
                                   "version": str(ident.get("snapshot_sha256") or ""), **meta}))
        self._add_file("framework", "sync_meta.json", mirror / ".sync_meta.json")
        self.source["framework_synced_at"] = ident.get("synced_at")
        self._ok("framework", str(ident.get("snapshot_sha256") or ""))

    def _footprints(self) -> None:
        from main.kms.footprint_update import backfill_receipt_path, backfill_receipt_status
        from main.knowledge_paths import (
            KNOWLEDGE_FOOTPRINTS,
            KNOWLEDGE_MANUAL,
            footprint_nodes_dir,
        )

        version = self.manual_version
        status = backfill_receipt_status(version, manual_root=Path(KNOWLEDGE_MANUAL),
                                         footprint_root=Path(KNOWLEDGE_FOOTPRINTS))
        if status.get("status") != "complete":
            self._fail("footprints", f"footprint 回填收据状态 {status.get('status')}",
                       "engine_tool（footprint_backfill 子进程）")
            return
        nodes = Path(footprint_nodes_dir(version))
        self.entries.append(Entry(
            "footprints", f"footprints/nodes_{version}.tar.gz",
            deterministic_tar_gz(nodes, include=lambda rel: rel.suffix == ".json"),
            "application/gzip", {"manual_version": version}))
        receipt = backfill_receipt_path(Path(KNOWLEDGE_FOOTPRINTS), version)
        self._add_file("footprints", f"receipt_nodes_{version}.json", receipt)
        self._ok("footprints", version)


# ── 发布一侧（与 InfoTest 无关）─────────────────────────────────────────
class PublishError(RuntimeError):
    pass


# 进 stable 的服务端下限（registry.STABLE_REQUIRED_KINDS；服务端可用 CES_STABLE_REQUIRED_KINDS 改）。
# 发布方在上传之前按同一个变量核一遍：缺这些 kind 的包进不了 stable，早早拒绝，而不是传完才在
# 切 stable 时被服务端拒
STABLE_FLOOR_ENV = "CES_STABLE_REQUIRED_KINDS"
_STABLE_FLOOR = ("cmdtree", "projections")


def stable_floor(value: str | None = None) -> tuple[str, ...]:
    raw = os.environ.get(STABLE_FLOOR_ENV, "") if value is None else value
    items = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    if not items:
        return _STABLE_FLOOR
    if items == ["none"]:
        return ()
    unknown = [item for item in items if item not in KINDS]
    if unknown:
        raise PublishError(f"{STABLE_FLOOR_ENV} 含未知 kind：{', '.join(unknown)}")
    return tuple(dict.fromkeys(items))


def _is_loopback_host(host: str) -> bool:
    """与 deploy/tls_policy.is_loopback_host、客户端 check_server_url 同一条规则。"""
    host = (host or "").strip().strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def split_connection_string(value: str) -> tuple[str, str]:
    """连接串 https://主机:端口#ca=<指纹> 拆成（地址, 64 位小写十六进制指纹）；普通地址指纹为空。"""
    url, _, fragment = (value or "").strip().partition("#")
    pin = ""
    if fragment:
        key, _, raw = fragment.partition("=")
        pin = re.sub(r"[\s:]", "", raw.lower().removeprefix("sha256:"))
        if key != "ca" or not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise PublishError("--server 的连接串里 #ca= 后面应是 64 位十六进制的 CA 指纹"
                               "（原样复制服务端 ces link 的输出）")
    return url.strip(), pin


_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----")
MAX_CA_BYTES = 64 << 10


def single_cert_der(text: str) -> bytes:
    """严格解析：恰好一个证书块、base64 严格解码。ssl.PEM_cert_to_DER_cert 解码不严，拼接两张证书的
    PEM 会算出第一张的指纹，若再把整份 PEM 装进信任库，第二张（冒充者的 CA）也会被信任。"""
    if text.count("-----BEGIN ") != 1:
        raise ValueError("应当只有一张证书")
    match = _PEM_BLOCK.search(text)
    if match is None:
        raise ValueError("不是 PEM 证书")
    return base64.b64decode(re.sub(r"\s", "", match.group(1)), validate=True)


def pinned_ca(url: str, pin: str, *, timeout: float = 30.0) -> ssl.SSLContext:
    """先不校验证书取 /ca.pem，核对连接串里的指纹；对上了只把这一张 CA（加上系统证书库）用来校验服务端。"""
    loose = ssl.create_default_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url + "/ca.pem", timeout=timeout, context=loose) as resp:
            raw = resp.read(MAX_CA_BYTES + 1)
        if len(raw) > MAX_CA_BYTES:
            raise ValueError("回应太大，不是一张 CA 证书")
        der = single_cert_der(raw.decode("ascii"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PublishError(f"取不到服务端的 CA 证书（{url}/ca.pem）：{exc}") from None
    if hashlib.sha256(der).hexdigest() != pin:
        raise PublishError("服务端 CA 证书的指纹与连接串不一致：连接串抄错了，或者连到了别的机器")
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=der)  # 用解出的 DER，不用原文
    return context


def check_publish_server(url: str, *, insecure_lan: bool = False) -> str:
    """服务端地址：https 放行；http 只放行回环地址，或显式 --insecure-lan（可信实验网）。
    也接受连接串（https://主机:端口#ca=<指纹>），这里只核地址部分。

    发布方的 client secret 走 Basic 认证、令牌走 Bearer：明文 http 会让同网段的人直接拿到。"""
    url = split_connection_string(url)[0].rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise PublishError(f"--server 必须是 http(s) 地址：{url!r}")
    if parts.username or parts.password:
        raise PublishError("--server 里不许带凭据（用 --client-secret-file）")
    if parts.scheme == "http" and not insecure_lan and not _is_loopback_host(parts.hostname):
        raise PublishError("明文 http 发往非回环地址会把 client secret 与令牌明文过网；用 https，"
                           "或确认是可信实验网后加 --insecure-lan")
    return url


class Publisher:
    def __init__(self, server: str, client_id: str, client_secret: str, *,
                 timeout: float = 120.0, insecure_lan: bool = False):
        self.server = check_publish_server(server, insecure_lan=insecure_lan)
        self.client_id = client_id
        self._secret = client_secret
        self.timeout = timeout
        self._token = ""
        # 连接串带 #ca= 时：服务端用内置 CA，先核对指纹再信任它
        pin = split_connection_string(server)[1]
        self._ssl = pinned_ca(self.server, pin) if pin else None

    def _request(self, method: str, path: str, *, data: bytes | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        req = urllib.request.Request(self.server + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def login(self) -> None:
        basic = base64.b64encode(
            f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self._secret)}"
            .encode()).decode()
        status, raw = self._request(
            "POST", "/token", data=b"grant_type=client_credentials&scope=bundles%3Apublish",
            headers={"Authorization": f"Basic {basic}",
                     "Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            raise PublishError(f"取令牌失败（HTTP {status}）：检查 client id/secret 与 scope")
        self._token = json.loads(raw)["access_token"]

    def _auth(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", **(extra or {})}

    @staticmethod
    def preflight(resolution: Resolution, *, promote: bool,
                  required_kinds: tuple[str, ...] = KINDS) -> None:
        """上传之前就能判的拒绝：没做出包前扫描（或没过）；要切 stable 却缺 stable 下限的 kind。"""
        scan = resolution.source.get("credential_scan")
        if not isinstance(scan, dict) or scan.get("status") != "clean":
            raise PublishError("这份解析结果没有通过出包前的凭据扫描，拒绝上传"
                               "（由 InfoTestResolver / DataDirResolver 的 resolve() 产出）")
        if not promote:
            return  # 只进 candidate：缺哪类由服务端自检如实记下
        present = {entry.kind for entry in resolution.entries}
        missing = [kind for kind in dict.fromkeys((*required_kinds, *stable_floor()))
                   if kind not in present]
        if missing:
            raise PublishError(f"包里缺少 {', '.join(missing)}，进不了 stable（服务端自检与 stable "
                               f"下限，见 {STABLE_FLOOR_ENV}）；先补齐再发布")

    def publish(self, resolution: Resolution, *, promote: bool,
                required_kinds: tuple[str, ...] = KINDS) -> dict[str, Any]:
        self.preflight(resolution, promote=promote, required_kinds=required_kinds)
        if not self._token:
            self.login()
        uploaded = 0
        sent: set[str] = set()
        for entry in resolution.entries:
            # 同一次发布里内容相同的条目（例如同一份契约既是 projections 也是 template）只传一次
            if entry.sha256 in sent:
                continue
            sent.add(entry.sha256)
            status, raw = self._request(
                "PUT", f"/v1/blobs/{entry.sha256}", data=entry.data,
                headers=self._auth({"Content-Type": entry.media_type}))
            if status not in (200, 201):
                raise PublishError(f"上传 {entry.path} 失败（HTTP {status}）："
                                   f"{raw[:200].decode('utf-8', 'replace')}")
            uploaded += status == 201
        body = json.dumps({
            "build": resolution.build,
            "entries": [{"kind": e.kind, "path": e.path, "sha256": e.sha256,
                         "media_type": e.media_type, "meta": e.meta}
                        for e in resolution.entries],
            "source": {**resolution.source, "checks": resolution.checks},
            "required_kinds": list(required_kinds),
        }, ensure_ascii=False).encode("utf-8")
        status, raw = self._request("POST", "/v1/bundles", data=body,
                                    headers=self._auth({"Content-Type": "application/json"}))
        if status not in (200, 201):
            raise PublishError(f"登记数据包失败（HTTP {status}）："
                               f"{raw[:300].decode('utf-8', 'replace')}")
        result = json.loads(raw)
        result["uploaded_blobs"] = uploaded
        result["promoted"] = False
        if promote:
            result["promotion"] = self._promote(resolution.build, result)
            result["promoted"] = result["promotion"]["status"] == "promoted"
        return result

    def _promote(self, build: str, result: dict[str, Any]) -> dict[str, Any]:
        """切 stable，但不覆盖别人的决定：

        - 服务端自检没过 → PublishError（退出码非零）；
        - stable 已经指着这个包 → already_stable；
        - 内容没变（created 为 False）而 stable 指着别的包 → 不动（left_alone_unchanged）：
          多半是运维回滚过，同内容重发不该把它拨回来；
        - 新包 → 带 expect=<登记时看到的 stable 指针|none> 切；服务端回 409 说明这期间有人动过
          stable（并发发布或回滚）→ 不动（left_alone_conflict），如实报当前指针。
        这三种“不动”都按成功退出（每天由 cron 重跑也不报错）；其余被拒（自检、缺 kind、权限…）
        抛 PublishError。旧版服务端的回应里没有 channels：只在新包时切，不带 expect。"""
        bundle_id = result["bundle_id"]
        if not result["checks"]["ok"]:
            raise PublishError("服务端自检未通过，不切 stable：" +
                               "; ".join(result["checks"]["problems"]))
        channels = result.get("channels")
        stable = channels.get("stable") if isinstance(channels, dict) else None
        if stable == bundle_id:
            return {"status": "already_stable", "stable": stable,
                    "message": "stable 已经指向这个包"}
        if not result.get("created"):
            return {"status": "left_alone_unchanged", "stable": stable,
                    "message": f"内容与已登记的包相同，stable 指针没动（现在指向 {stable or '（空）'}，"
                               "可能是运维回滚过）；确要切过去：ces registry promote "
                               f"{build} {bundle_id} --expect {stable or 'none'}"}
        fields = {"bundle_id": bundle_id}
        if isinstance(channels, dict):
            fields["expect"] = stable or "none"
        status, raw = self._request(
            "POST", f"/v1/builds/{urllib.parse.quote(build)}/channels/stable",
            data=urllib.parse.urlencode(fields).encode(),
            headers=self._auth({"Content-Type": "application/x-www-form-urlencoded"}))
        if status == 409:
            try:
                current = json.loads(raw).get("current")
            except ValueError:
                current = None
            return {"status": "left_alone_conflict", "stable": current,
                    "message": f"登记后 stable 被别人动过（现在指向 {current or '（空）'}），没有覆盖；"
                               f"核对后确要切过去：ces registry promote {build} {bundle_id} "
                               f"--expect {current or 'none'}"}
        if status != 200:
            raise PublishError(f"切 stable 失败（HTTP {status}）："
                               f"{raw[:300].decode('utf-8', 'replace')}")
        try:
            changed = json.loads(raw).get("changed", True)
        except ValueError:
            changed = True
        return {"status": "promoted" if changed is not False else "already_stable",
                "stable": bundle_id, "message": "已切到 stable" if changed is not False
                else "stable 已经指向这个包"}


def read_secret_file(path: Path) -> str:
    info = os.stat(path)
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise PublishError(f"{path} 权限必须是 0600（现在 {oct(stat.S_IMODE(info.st_mode))}）")
    secret = path.read_text(encoding="utf-8").strip()
    if not secret:
        raise PublishError(f"{path} 是空的")
    return secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="把 InfoTest 已收敛的编译数据发布到服务端")
    parser.add_argument("--infotest-root", required=True)
    parser.add_argument("--device-build", required=True,
                        help="设备 show version 的完整版本串（与该床批入口用的一致）")
    parser.add_argument("--server", default="",
                        help="服务端地址，或服务端 ces link 显示的连接串（带 #ca= 时自动核对证书）")
    parser.add_argument("--client-id", default="publisher")
    parser.add_argument("--client-secret-file", default="")
    parser.add_argument("--spec-sync-timeout", type=int, default=180)
    parser.add_argument("--promote", action="store_true", help="自检通过后切到 stable")
    parser.add_argument("--dry-run", action="store_true", help="只解析与校验，不上传")
    parser.add_argument("--insecure-lan", action="store_true",
                        help="允许明文 http 发往非回环地址（仅限可信实验网）")
    args = parser.parse_args(argv)
    if not args.dry_run and args.server:
        try:  # 先核地址再解析：明文 http 发往非回环地址直接拒绝
            check_publish_server(args.server, insecure_lan=args.insecure_lan)
        except PublishError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
            return 1

    resolver = InfoTestResolver(Path(args.infotest_root), args.device_build,
                                spec_sync_timeout_s=args.spec_sync_timeout)
    try:
        resolution = resolver.resolve()
    except ImportRefused as exc:
        passed = [c for c in resolver.checks if c["status"] != "fail"]
        print(json.dumps({"ok": False, "refused": exc.failures, "passed": passed},
                         ensure_ascii=False, indent=1))
        return 3
    summary = {
        "ok": True, "build": resolution.build,
        "entries": {kind: sum(1 for e in resolution.entries if e.kind == kind) for kind in KINDS},
        "bytes": sum(len(e.data) for e in resolution.entries),
    }
    if args.dry_run:
        print(json.dumps({**summary, "dry_run": True}, ensure_ascii=False, indent=1))
        return 0
    if not args.server or not args.client_secret_file:
        print("需要 --server 与 --client-secret-file（或加 --dry-run 只做校验）", file=sys.stderr)
        return 64
    try:
        publisher = Publisher(args.server, args.client_id,
                              read_secret_file(Path(args.client_secret_file).expanduser()),
                              insecure_lan=args.insecure_lan)
        result = publisher.publish(resolution, promote=args.promote)
    except (PublishError, OSError) as exc:
        print(json.dumps({**summary, "ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({**summary, **result}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
