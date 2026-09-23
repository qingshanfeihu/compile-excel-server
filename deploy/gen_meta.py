#!/usr/bin/env python3
"""gen_meta：扫描 data/artifacts 生成/合并 artifacts_meta.json。

规则：
- 只收录 data/artifacts 下实际存在的文件；SHA 由服务启动时对字节快照，meta 不存 SHA；
- media_type 按扩展名推断（xlsx/xml/tar.gz/json/md…），未知扩展按 octet-stream；
- version 取值顺序：version_map 指定 > 既有 meta > default_version > installed-YYYYMMDD；
- kms_addr 写入顶层（透出到 /healthz 与 manifest）；
- 已有 artifacts 条目的 receipt 等手写字段原样保留（按名合并）。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

MEDIA_TYPES = {
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
    ".xml": "application/xml",
    ".json": "application/json",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".tar.gz": "application/gzip",
    ".tgz": "application/gzip",
    ".gz": "application/gzip",
    ".zip": "application/zip",
}


def _media_type(name: str) -> str:
    lowered = name.lower()
    for suffix, media in sorted(MEDIA_TYPES.items(), key=lambda kv: -len(kv[0])):
        if lowered.endswith(suffix):
            return media
    return "application/octet-stream"


def generate_meta(
    data_dir: Path,
    *,
    device_build: str = "",
    kms: str = "",
    version_map: dict[str, str] | None = None,
    default_version: str = "",
) -> dict:
    data_dir = Path(data_dir).expanduser().resolve()
    artifacts_dir = data_dir / "artifacts"
    if not artifacts_dir.is_dir():
        print(f"工件目录不存在: {artifacts_dir}", file=sys.stderr)
        raise SystemExit(66)
    files = sorted(p for p in artifacts_dir.iterdir() if p.is_file())
    if not files:
        print(f"工件目录为空: {artifacts_dir}（先放文件再生成 meta）", file=sys.stderr)
        raise SystemExit(66)

    overrides = version_map or {}
    meta_path = data_dir / "artifacts_meta.json"
    existing: dict = {}
    if meta_path.is_file():
        try:
            loaded = json.loads(meta_path.read_text(encoding="utf-8"))
            existing = loaded if isinstance(loaded, dict) else {}
        except (OSError, json.JSONDecodeError):
            existing = {}
    existing_artifacts = existing.get("artifacts") if isinstance(
        existing.get("artifacts"), dict) else {}

    device_build = device_build or str(existing.get("device_build") or "")
    if not device_build:
        print("缺 device_build：传 --device-build 或在既有 meta 中提供", file=sys.stderr)
        raise SystemExit(64)
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", device_build):
        print(f"device_build 非法: {device_build!r}（限字母数字._-，≤64）", file=sys.stderr)
        raise SystemExit(64)

    installed_tag = "installed-" + time.strftime("%Y%m%d")
    artifacts: dict = {}
    for path in files:
        name = path.name
        old = existing_artifacts.get(name)
        old = old if isinstance(old, dict) else {}
        version = (overrides.get(name)
                   or str(old.get("version") or "")
                   or default_version
                   or installed_tag)
        entry = {
            "version": version,
            "media_type": str(old.get("media_type") or _media_type(name)),
        }
        if old.get("receipt"):
            entry["receipt"] = old["receipt"]
        else:
            entry["receipt"] = {
                "schema": "ist.excel.promotion-receipt",
                "status": "installed",
                "device_build": device_build,
            }
        artifacts[name] = entry

    meta = {
        "device_build": device_build,
        "artifacts": artifacts,
    }
    kms = kms or str(existing.get("kms_addr") or "")
    if kms:
        if not re.fullmatch(r"[A-Za-z0-9._\-]+:\d{1,5}", kms):
            print(f"kms 地址非法: {kms!r}（应为 host:port）", file=sys.stderr)
            raise SystemExit(64)
        meta["kms_addr"] = kms

    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n",
                         encoding="utf-8")
    meta_path.chmod(0o600)
    print(f"已生成 {meta_path}: device_build={device_build} "
          f"artifacts={len(artifacts)} kms={kms or '-'}")
    for name, entry in artifacts.items():
        print(f"  {name}: v={entry['version']} {entry['media_type']}")
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description="生成/合并 artifacts_meta.json")
    parser.add_argument("--data", required=True, help="数据目录")
    parser.add_argument("--device-build", default="", help="device_build 标识")
    parser.add_argument("--kms", default="", help="openkm/KMS 地址 host:port")
    parser.add_argument("--version", action="append", default=[],
                        help="指定工件版本 name=ver（可重复）")
    parser.add_argument("--default-version", default="", help="未指定版本的缺省值")
    args = parser.parse_args()

    version_map: dict[str, str] = {}
    for pair in args.version:
        name, sep, ver = pair.partition("=")
        if not sep or not name or not ver:
            print(f"--version 参数非法: {pair!r}（应为 name=ver）", file=sys.stderr)
            return 64
        version_map[name] = ver
    generate_meta(
        Path(args.data),
        device_build=args.device_build,
        kms=args.kms,
        version_map=version_map,
        default_version=args.default_version,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
