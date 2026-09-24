#!/usr/bin/env python3
"""cexg：跳板机网关入口。

  cexg serve  --config gateway.toml     前台运行（systemd 用）
  cexg check  --config gateway.toml     配置与框架自检（不碰设备）
  cexg sample-config                    打印配置样例

配置里的路径与口令文件都在跳板机本机；网关不读任何 environment 文件。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "gateway"

import gateway  # noqa: E402
from gateway.config import ConfigError, load  # noqa: E402

# 按包的位置找样例：源码运行与 PyInstaller 打包后（数据文件在 _internal/gateway/）都对
SAMPLE = Path(gateway.__file__).resolve().parent / "gateway.example.toml"


def cmd_check(config: Path) -> int:
    from gateway import framework
    from gateway.tools import Gateway

    try:
        cfg = load(config)
    except ConfigError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    gateway = Gateway(cfg)
    checks = []
    checks.append({"check": "py38", "ok": cfg.py38.is_file()})
    checks.append({"check": "test_xlsx", "ok": (cfg.apv_src / "lib" / "test_xlsx.py").is_file()})
    try:
        ips = framework.device_ips(framework.read_conf(cfg))
        checks.append({"check": "conf", "ok": bool(ips), "devices": len(ips)})
    except framework.FrameworkError as exc:
        checks.append({"check": "conf", "ok": False, "error": str(exc)})
    try:
        gateway.grammar()
        checks.append({"check": "bundle_grammar", "ok": True})
    except Exception as exc:  # noqa: BLE001
        checks.append({"check": "bundle_grammar", "ok": False, "error": str(exc)})
    ok = all(c["ok"] for c in checks)
    print(json.dumps({"ok": ok, "checks": checks}, ensure_ascii=False, indent=1))
    return 0 if ok else 1


def cmd_serve(config: Path) -> int:
    from gateway.service import build_server
    from gateway.tools import Gateway

    try:
        cfg = load(config)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    httpd = build_server(Gateway(cfg))
    scheme = "https" if cfg.tls_cert else "http"
    print(f"cexg 监听 {scheme}://{cfg.host}:{cfg.port}/mcp", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cexg", description="compile-excel 跳板机网关")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "check"):
        p = sub.add_parser(name)
        p.add_argument("--config", required=True)
    sub.add_parser("sample-config")
    args = parser.parse_args(argv)
    if args.command == "sample-config":
        print(SAMPLE.read_text(encoding="utf-8"))
        return 0
    config = Path(args.config).expanduser()
    return cmd_serve(config) if args.command == "serve" else cmd_check(config)


if __name__ == "__main__":
    sys.exit(main())
