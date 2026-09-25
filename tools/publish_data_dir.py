#!/usr/bin/env python3
"""publish_data_dir：把已收敛的编译数据（InfoTest 仓根布局的数据目录）发布成服务端数据包。

与 tools/import_infotest.py 的区别：不导入任何 InfoTest 代码，每一类只按数据文件自己的身份
核对（代际清单、镜像锚点、契约来源、晋升回执、规格书清单、同步回执）。命令树从 InfoTest 的
活动代际出发，经 tools/cmdtree_rederive.py 去掉凭据默认值、用引擎自己的函数重推导代际、投影、
拆卸图谱与领域文法；SSL 生命周期证据的图谱身份随之改绑。另发两份编写阶段要的数据：判据台账
（runtime/criterion_author_rules.jsonl，客户端当种子）与 SSL 生命周期证据。上传走
import_infotest 里与 InfoTest 无关的 Publisher。

  python3 tools/publish_data_dir.py --data-root <InfoTest 布局根> --raw-build "<show version>" \\
      --manual-version 10.5.0 --server https://<服务端> --client-secret-file <0600 文件> \\
      [--promote] [--dry-run | --out-dir <目录>]

模板与契约的固定身份取自 gateway/vendor 里同步来的 cex_core（客户端校验的是同一份），
所以先跑 tools/sync_gateway_vendor.py --only cex_core。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
from import_infotest import (  # noqa: E402 — 与 InfoTest 无关的打包上传层
    KINDS,
    Entry,
    Publisher,
    PublishError,
    Resolution,
    deterministic_tar_gz,
    media_type_for,
    read_secret_file,
)

VENDOR = REPO_ROOT / "gateway" / "vendor"
PROJECTION_EXCLUDE_NAMES = {"excel_runtime_template.xlsx", "excel_workbook_manifest.json"}
PROJECTION_EXCLUDE_PREFIXES = ("vendor_stdlib_", "source_reconciliation_", "cmdtree_")
# 由命令树重推导产出、替换数据目录里原件的投影
REDERIVED_PROJECTIONS = ("command_teardown_atlas.json", "domain_grammar.json")
SSL_LIFECYCLE_ASSET = "scripts/maintenance/assets/ssl_lifecycle_contract.json"
CRITERION_LEDGER = "runtime/criterion_author_rules.jsonl"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def execution_build(raw: str) -> str:
    """show version 的完整版本 → 执行侧构建名（结果库表名同一规则）。"""
    text = re.sub(r"[^0-9A-Za-z_]+", "_", raw).strip("_")
    return "b_" + text if text and text[0].isdigit() else text


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
                 pins: tuple[str, str] | None = None, work: Path | None = None):
        self.root = root.resolve()
        self.raw = raw_build.strip()
        self.build = execution_build(self.raw)
        self.manual_ver = manual_version
        self.rederive = rederive
        self.pins = pins
        self.work = work
        self.entries: list[Entry] = []
        self.checks: list[dict[str, str]] = []
        self.failures: list[dict[str, str]] = []
        self.rederived: dict[str, Any] = {}
        self.source: dict[str, Any] = {"importer": "publish_data_dir", "raw_build": self.raw,
                                       "execution_build": self.build,
                                       "manual_version": self.manual_ver}

    def ok(self, key: str, evidence: str = "") -> None:
        self.checks.append({"key": key, "status": "ok", "evidence": evidence[:300]})

    def fail(self, key: str, evidence: str) -> None:
        item = {"key": key, "status": "fail", "evidence": evidence[:500]}
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
                           f"{result['sanitization']['blanked_default_values']} credential defaults)")

    def projections(self) -> None:
        ref = self.root / "knowledge/data/compile_ref"
        mirror = self.root / "knowledge/framework/mirror"
        anchors = json.loads((ref / "mirror_manifest.json").read_text())["files"]
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
        rederived = {name: Path(self.rederived["files"][name]) for name in REDERIVED_PROJECTIONS}
        count = 0
        for path in sorted(ref.rglob("*")):
            rel = path.relative_to(ref)
            if (not path.is_file() or path.is_symlink() or any(p.startswith(".") for p in rel.parts)
                    or rel.name in PROJECTION_EXCLUDE_NAMES
                    or rel.name.startswith(PROJECTION_EXCLUDE_PREFIXES)
                    or "__pycache__" in rel.parts):
                continue
            self.add("projections", rel.as_posix(), rederived.get(rel.as_posix(), path))
            count += 1
        self.add_bytes("projections", "ssl_lifecycle_contract.json", self._ssl_lifecycle(),
                       "application/json")
        ledger = self.root / CRITERION_LEDGER
        self.add("projections", "criterion_author_rules.jsonl", ledger)
        records = sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip())
        self.ok("projections", f"{count} files; {len(anchors)} anchors match; atlas and grammar "
                               f"re-derived; {records} criterion rules")

    def _ssl_lifecycle(self) -> bytes:
        """SSL 生命周期证据：拆卸图谱身份改绑到重推导的图谱，别的证据按文件逐个核对。"""
        payload = json.loads((self.root / SSL_LIFECYCLE_ASSET).read_text(encoding="utf-8"))
        ref = self.root / "knowledge/data/compile_ref"
        old_identity = json.loads((ref / "command_teardown_atlas.json").read_text())["identity"]["sha256"]
        new_atlas = json.loads(Path(self.rederived["files"]["command_teardown_atlas.json"]).read_text())
        for contract in payload.get("contracts") or []:
            reference = contract.get("reference_evidence") or {}
            for path_key, sha_key in (("clear_source", "clear_source_sha256"),
                                      ("start_manual_source", "start_manual_source_sha256")):
                target = self.root / str(reference.get(path_key) or "")
                if not target.is_file() or sha(target.read_bytes()) != reference.get(sha_key):
                    raise ValueError(f"SSL lifecycle evidence {path_key} no longer matches the data")
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
        base = self.root / "knowledge/data/manual"
        for fam in ("cli", "app"):
            self.add("manual", f"{self.manual_ver}/{fam}_cn.md", base / self.manual_ver / f"{fam}_cn.md")
            self.add("manual", f"{self.manual_ver}/{fam}_cn.catalog.json",
                     base / self.manual_ver / f"{fam}_cn.catalog.json")
        state = json.loads((base / ".sync_state.json").read_text())
        picked = {k: v for k, v in state.items() if k.endswith(f":{self.manual_ver}")}
        self.add_bytes("manual", f"{self.manual_ver}/sync_state.json",
                       json.dumps(picked, ensure_ascii=False, sort_keys=True, indent=1).encode(),
                       "application/json")
        self.ok("manual", f"{self.manual_ver}: cli, app")

    def spec(self) -> None:
        base = self.root / "knowledge/data/spec"
        active = json.loads((base / "active.json").read_text())
        gen = base / "generations" / active["generation_id"]
        mbytes = (gen / "manifest.json").read_bytes()
        if sha(mbytes) != active["manifest_sha256"]:
            return self.fail("spec", "active.json manifest_sha256 mismatch")
        manifest = json.loads(mbytes)
        self.add("spec", "manifest.json", gen / "manifest.json", generation_id=active["generation_id"],
                 manifest_sha256=active["manifest_sha256"])
        self.add("spec", "index.json", gen / "index.json")
        self.add("spec", "state.tsv", gen / "state.tsv")
        bad = []
        for name, info in sorted(manifest["documents"].items()):
            path = gen / "docs" / name
            if not path.is_file() or sha(path.read_bytes()) != info["sha256"]:
                bad.append(name)
                continue
            self.add("spec", f"docs/{name}", path)
        if bad:
            return self.fail("spec", f"{len(bad)} documents missing or altered: {bad[:3]}")
        self.source["spec_generation"] = active["generation_id"]
        self.ok("spec", f"{active['generation_id']}: {len(manifest['documents'])} documents")

    def framework(self) -> None:
        mirror = self.root / "knowledge/framework/mirror"
        meta_bytes = (mirror / ".sync_meta.json").read_bytes()
        meta = json.loads(meta_bytes)
        by_path = meta["by_path"]
        bad = [rel for rel, h in by_path.items()
               if not (mirror / rel).is_file() or sha((mirror / rel).read_bytes()) != h]
        if bad:
            return self.fail("framework", f"{len(bad)} mirror files differ from .sync_meta: {bad[:3]}")
        keep = set(by_path)
        tar = deterministic_tar_gz(mirror, include=lambda rel: rel.as_posix() in keep)
        self.add_bytes("framework", "framework_tree.tar.gz", tar, "application/gzip",
                       legacy_name="framework_tree.tar.gz", files=len(keep),
                       sync_receipt_sha256=sha(meta_bytes), synced_at=meta.get("synced_at"),
                       source_host=meta.get("source"))
        self.add_bytes("framework", "sync_meta.json", meta_bytes, "application/json")
        self.source["framework_synced_at"] = meta.get("synced_at")
        self.ok("framework", f"{len(keep)} files verified against .sync_meta")

    def footprints(self) -> None:
        fp = self.root / "knowledge/footprints"
        receipt = fp / f".receipt_nodes_{self.manual_ver}.json"
        info = json.loads(receipt.read_text())
        nodes = fp / f"nodes_{self.manual_ver}"
        self.add_bytes("footprints", f"nodes_{self.manual_ver}.tar.gz",
                       deterministic_tar_gz(nodes, include=lambda rel: rel.suffix == ".json"),
                       "application/gzip", manual_version=self.manual_ver)
        self.add("footprints", f"receipt_nodes_{self.manual_ver}.json", receipt)
        self.ok("footprints", f"{self.manual_ver} receipt status={info.get('status', '?')}")

    def resolve(self) -> Resolution:
        # cmdtree 先跑：projections 要用它重推导的图谱与文法
        for key in ("cmdtree", *[kind for kind in KINDS if kind != "cmdtree"]):
            self.step(key, getattr(self, key))
        if self.failures:
            raise Refused(json.dumps(self.failures, ensure_ascii=False, indent=1))
        return Resolution(self.build, self.entries, self.source, self.checks)


def write_out_dir(resolution: Resolution, out: Path) -> dict[str, Any]:
    """把条目按包布局写到本地目录（与客户端同步下来的目录同形），供检查与离线测试。"""
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
    ap.add_argument("--server", default="")
    ap.add_argument("--client-id", default="publisher")
    ap.add_argument("--client-secret-file", default="")
    ap.add_argument("--promote", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out-dir", default="", help="write the bundle to this directory instead of uploading")
    args = ap.parse_args(argv)
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
                        read_secret_file(Path(args.client_secret_file).expanduser()))
        result = pub.publish(res, promote=args.promote, required_kinds=KINDS)
    except (PublishError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    summary.pop("checks")
    print(json.dumps({**summary, **result}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
