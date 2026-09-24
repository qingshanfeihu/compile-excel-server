"""子进程入口：在已设好的引擎数据根里跑一步生成链。

  CEX_ENGINE_DATA_ROOT=<工作根> PYTHONPATH=<cex_core 所在目录>:<本仓> \
      python -m generators._step <步骤名> '<参数 JSON>'

结果以一行 JSON 打到标准输出最后一行；失败时只给异常类型与引擎自带的稳定原因码，正文截短，
不回显可能带路径或端点的长文。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    from generators.chain import STEPS

    name, params = argv[0], json.loads(argv[1] if len(argv) > 1 else "{}")
    root = Path(params["root"])
    try:
        value = STEPS[name].call(root, params)
    except Exception as exc:  # noqa: BLE001 — 每一步的失败都要落进报告，不让子进程带栈崩掉
        code = getattr(exc, "code", None) or getattr(exc, "reason_code", None)
        print(json.dumps({"ok": False, "error": type(exc).__name__,
                          "code": str(code) if code else None,
                          "detail": str(exc)[:300]}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "value": value}, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
