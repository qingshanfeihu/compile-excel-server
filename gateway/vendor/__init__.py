"""网关引用的外部判据代码（同步而来，不手改）。

cex_core/ 不入库，由 tools/sync_gateway_vendor.py --only cex_core 从 compile-excel-skills 生成。
"""

from importlib.util import find_spec as _find_spec

# 按模块查找而不是看文件：PyInstaller 打包后 cex_core 在归档里，磁盘上没有 .py
if _find_spec(__name__ + ".cex_core") is None:
    raise ImportError("gateway/vendor/cex_core is generated and not in git; run "
                      "python3 tools/sync_gateway_vendor.py --only cex_core "
                      "--skills-root <compile-excel-skills checkout>")
