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
- 命令树只发投影（vendor_stdlib JSON），不发原始 XML：原始 XML 带参数默认值（含凭据默认值）。
- 发布：client_credentials 取令牌 → 逐个 PUT blob → POST 清单进 candidate →
  服务端自检通过且给了 --promote 才切 stable。内容没变时 bundle_id 相同，是空操作。

分两层：InfoTestResolver 只负责从 InfoTest 取条目和检查结果；Publisher 只负责打包上传，
与 InfoTest 无关（测试用假 resolver 驱动它）。
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
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
# source_reconciliation 没有消费方；Excel 候选文件归 template 类
_PROJECTION_EXCLUDE_PREFIXES = ("vendor_stdlib_", "source_reconciliation_")
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
        files.append((rel.as_posix(), path))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for rel, path in files:
            data = path.read_bytes()
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


# ── InfoTest 一侧 ──────────────────────────────────────────────────────
class InfoTestResolver:
    def __init__(self, root: Path, raw_build: str, *, spec_sync_timeout_s: int = 180):
        self.root = Path(root).resolve()
        self.raw_build = raw_build.strip()
        self.spec_sync_timeout_s = spec_sync_timeout_s
        self.failures: list[dict[str, str]] = []
        self.checks: list[dict[str, str]] = []
        self.entries: list[Entry] = []
        self.source: dict[str, Any] = {"importer": "import_infotest", "raw_build": self.raw_build}

    def _fail(self, key: str, evidence: str, repair: str = "") -> None:
        item = {"key": key, "status": "fail", "evidence": evidence[:500], "repair": repair}
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
        for path in sorted(compile_ref.rglob("*")):
            rel = path.relative_to(compile_ref)
            if (not path.is_file() or path.is_symlink()
                    or any(part.startswith(".") for part in rel.parts)
                    or rel.name in _PROJECTION_EXCLUDE_NAMES
                    or rel.name.startswith(_PROJECTION_EXCLUDE_PREFIXES)):
                continue
            self._add_file("projections", rel.as_posix(), path)
            count += 1
        self._ok("projections", f"{count} files")

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


class Publisher:
    def __init__(self, server: str, client_id: str, client_secret: str, *,
                 timeout: float = 120.0):
        self.server = server.rstrip("/")
        self.client_id = client_id
        self._secret = client_secret
        self.timeout = timeout
        self._token = ""

    def _request(self, method: str, path: str, *, data: bytes | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        req = urllib.request.Request(self.server + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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

    def publish(self, resolution: Resolution, *, promote: bool,
                required_kinds: tuple[str, ...] = KINDS) -> dict[str, Any]:
        if not self._token:
            self.login()
        uploaded = 0
        for entry in resolution.entries:
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
            if not result["checks"]["ok"]:
                raise PublishError("服务端自检未通过，不切 stable：" +
                                   "; ".join(result["checks"]["problems"]))
            form = urllib.parse.urlencode({"bundle_id": result["bundle_id"]}).encode()
            status, raw = self._request(
                "POST", f"/v1/builds/{urllib.parse.quote(resolution.build)}/channels/stable",
                data=form, headers=self._auth(
                    {"Content-Type": "application/x-www-form-urlencoded"}))
            if status != 200:
                raise PublishError(f"切 stable 失败（HTTP {status}）："
                                   f"{raw[:300].decode('utf-8', 'replace')}")
            result["promoted"] = True
        return result


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
    parser.add_argument("--server", default="")
    parser.add_argument("--client-id", default="publisher")
    parser.add_argument("--client-secret-file", default="")
    parser.add_argument("--spec-sync-timeout", type=int, default=180)
    parser.add_argument("--promote", action="store_true", help="自检通过后切到 stable")
    parser.add_argument("--dry-run", action="store_true", help="只解析与校验，不上传")
    args = parser.parse_args(argv)

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
                              read_secret_file(Path(args.client_secret_file).expanduser()))
        result = publisher.publish(resolution, promote=args.promote)
    except (PublishError, OSError) as exc:
        print(json.dumps({**summary, "ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({**summary, **result}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
