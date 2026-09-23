#!/usr/bin/env python3
"""sample_data：生成合成工件与知识库样例（自测/冒烟用，零内部资产）。

用法：python3 deploy/sample_data.py [--data <目录>] [--force]

产出（覆盖 data/artifacts_meta.json 中的 artifacts 定义）：
- artifacts/sample_runtime_template.xlsx：合成字节（非真实模板）；
- artifacts/framework_tree.tar.gz：tarfile 现打的合成框架子集；
- artifacts/cmdtree_sample.xml：合成命令树 xml；
- docs/ 两篇中性手册（通用检索引擎演示文案，与任何内部契约无关）。
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
from pathlib import Path

META_SAMPLE = {
    "device_build": "SAMPLE_BUILD_LOCAL",
    "artifacts": {
        "sample_runtime_template.xlsx": {
            "version": "0.1.0-sample",
            "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "receipt": {"schema": "ist.excel.promotion-receipt", "status": "sample"},
        },
        "framework_tree.tar.gz": {
            "version": "0.1.0-sample",
            "media_type": "application/gzip",
            "receipt": {"schema": "ist.excel.promotion-receipt", "status": "sample"},
        },
        "cmdtree_sample.xml": {
            "version": "0.1.0-sample",
            "media_type": "application/xml",
            "receipt": {"schema": "ist.excel.promotion-receipt", "status": "sample"},
        },
    },
}

DOC_A = """# 合成手册：工件与清单

本篇为知识库检索引擎的合成演示文档，不含任何内部资产。

- manifest 按 device_build 列出工件：名称、版本、SHA256、字节数、receipt。
- 工件下载走 Bearer 鉴权；客户端逐件校验 SHA256，不符即拒收。
- 服务器不可达时客户端可回退本地缓存，但必须明示缓存版本，禁止静默。

常见问题：token 过期由客户端用 refresh_token 自动换新；无效 token 一律 401。
"""

DOC_B = """# 合成手册：设备授权流

本篇为知识库检索引擎的合成演示文档，不含任何内部资产。

- 终端发起 device_authorize，得到 user_code 与 verification_uri；
- 用户在浏览器授权页确认设备码并提交账号名；
- 终端轮询 /token，授权完成后拿到 access_token 与 refresh_token；
- access token 有过期时间；refresh token 可换新 access token。
"""


def _tar_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("lib/placeholder.py")
        payload = b"# synthetic framework subset placeholder\n"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def generate(data_dir: Path, *, force: bool) -> int:
    data_dir = data_dir.expanduser().resolve()
    artifacts = data_dir / "artifacts"
    docs = data_dir / "docs"
    artifacts.mkdir(parents=True, exist_ok=True)
    docs.mkdir(parents=True, exist_ok=True)

    targets = {
        "sample_runtime_template.xlsx": b"PK\x03\x04synthetic-xlsx-placeholder" + os.urandom(256),
        "framework_tree.tar.gz": _tar_bytes(),
        "cmdtree_sample.xml": (
            "<cmdtree>\n  <!-- synthetic command tree -->\n"
            "  <cmd name=\"show version\"/>\n  <cmd name=\"show inventory\"/>\n</cmdtree>\n"
        ).encode("utf-8"),
    }
    for name, payload in targets.items():
        path = artifacts / name
        if path.exists() and not force:
            print(f"已存在（跳过）: {path}")
        else:
            path.write_bytes(payload)
            print(f"已生成: {path} ({len(payload)} B)")

    (docs / "sample-artifacts.md").write_text(DOC_A, encoding="utf-8")
    (docs / "sample-device-flow.md").write_text(DOC_B, encoding="utf-8")
    print(f"已写手册: {docs}/sample-artifacts.md, sample-device-flow.md")

    meta_path = data_dir / "artifacts_meta.json"
    meta = META_SAMPLE
    if meta_path.exists() and not force:
        existing = json.loads(meta_path.read_text(encoding="utf-8"))
        existing["device_build"] = meta["device_build"]
        existing["artifacts"] = {**existing.get("artifacts", {}), **meta["artifacts"]}
        meta = existing
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n",
                         encoding="utf-8")
    print(f"已更新元数据: {meta_path}（device_build={meta['device_build']}）")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="生成合成测试数据（零内部资产）")
    parser.add_argument("--data", required=True, help="数据目录")
    parser.add_argument("--force", action="store_true", help="覆盖已存在的合成文件")
    args = parser.parse_args()
    return generate(Path(args.data), force=args.force)


if __name__ == "__main__":
    sys.exit(main())
