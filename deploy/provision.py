#!/usr/bin/env python3
"""provision：部署时初始化数据目录并生成实例凭据。

用法：python3 deploy/provision.py [--data <目录>] [--sample]

做三件事（幂等，已存在的不动）：
1. 建目录骨架 data/{artifacts,docs}（700）；
2. 生成 data/audit_hmac_key（600，32 字节随机 hex）——审计日志的实例签名密钥；
   **凭据只在部署时生成，绝不入 git**；
3. 写 data/artifacts_meta.json 骨架（device_build 占位，部署侧按实际构建填写）。

--sample 额外调用 sample_data.py 生成合成工件与手册（用于自测/冒烟，
不含任何内部资产）。

手册与旧版工件装好后用管理菜单（ces → 手册与旧版工件）导入，或 ces docs add / ces artifacts add。
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

META_SKELETON = {
    "device_build": "DEVICE_BUILD_PLACEHOLDER",
    "artifacts": {
        "example_artifact.xlsx": {
            "version": "0.0.0-example",
            "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "receipt": {"schema": "ist.excel.promotion-receipt", "status": "example"},
        },
    },
}


def provision(data_dir: Path, *, sample: bool) -> int:
    data_dir = data_dir.expanduser().resolve()
    data_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    (data_dir / "artifacts").mkdir(exist_ok=True)
    (data_dir / "docs").mkdir(exist_ok=True)
    os.chmod(data_dir, 0o700)

    key_path = data_dir / "audit_hmac_key"
    if key_path.exists():
        print(f"审计签名密钥已存在，沿用：{key_path}")
    else:
        key_path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        print(f"已生成审计签名密钥：{key_path}（只有你能读，不要外传）")

    meta_path = data_dir / "artifacts_meta.json"
    if not meta_path.exists():  # 旧版工件清单的骨架；导入工件时（ces artifacts add）补全
        meta_path.write_text(
            json.dumps(META_SKELETON, ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        os.chmod(meta_path, 0o600)

    if sample:
        rc = os.system(f"{sys.executable} '{REPO_ROOT / 'deploy' / 'sample_data.py'}' "
                       f"--data '{data_dir}'")
        if rc != 0:
            print("样例数据生成失败", file=sys.stderr)
            return 1

    mode = stat.S_IMODE(os.stat(data_dir).st_mode)
    print(f"数据目录就绪：{data_dir}（权限 {oct(mode)[2:]}）")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="compile-excel-server 部署初始化")
    parser.add_argument("--data", default=str(REPO_ROOT / "data"),
                        help="数据目录（缺省 <仓库>/data）")
    parser.add_argument("--sample", action="store_true",
                        help="生成合成工件与手册（自测用，无内部资产）")
    args = parser.parse_args()
    return provision(Path(args.data), sample=args.sample)


if __name__ == "__main__":
    sys.exit(main())
