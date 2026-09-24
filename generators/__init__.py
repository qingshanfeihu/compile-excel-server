"""服务端生成链：在服务端按 InfoTest 的顺序重生编译数据包里的投影（Phase 5 / E11）。

生成逻辑一行不重写：生成器与编排函数都来自 compile-excel-skills 的 cex_core/engine（从 InfoTest
抽取、与 InfoTest 逐条对拍的生成副本），这里只负责

- 把输入目录摆成引擎数据根（InfoTest 仓根布局）的一份工作副本；
- 每一步起一个子进程（引擎在导入时就按数据根定常量），调 InfoTest 的同名函数；
- 每一步先核对自己声明的输入在不在，不在就明确失败、下游步骤跳过，不静默产出；
- 收集 compile_ref/ 下的产物和一份报告，交给 `ces registry import-dir` 发布。

上游同步（WebDAV 手册与规格书、跳板机框架镜像、设备命令树、构建站）不在这里：它们要连
本环境够不到的上游，仍由 tools/import_infotest.py 在跑过收敛链的工作站上导入。
"""
