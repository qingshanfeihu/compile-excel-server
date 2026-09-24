"""生成链的步骤表：每一步调哪个 InfoTest 函数、先要哪些输入、会写哪些投影。

两条链照 InfoTest 批入口的顺序：
- ``framework_projections``：`environment_prepare._converge_framework_projections`
  （归因投影绑定不当前就带结转重生 capability atlas → 确认提示投影 → 框架派生投影四件）；
- ``compile_projections``：`environment_prepare.refresh_compile_projections`
  （命令树代际要不要重铸 → 清场 atlas → 判据规则 → 节奏用法 → 语言目录）。

另有三份 InfoTest 入库投影的生成器（开发者手动跑、不在批入口里），默认不跑，按名字点：
``rule_registry``、``device_behavior_examples``、``device_characteristics``。

函数体只在子进程里执行（`generators._step`），这里的 import 都是延迟的。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

COMPILE_REF = "knowledge/data/compile_ref"
MIRROR = "knowledge/framework/mirror"


@dataclass(frozen=True)
class Step:
    name: str
    call: Callable[[Path, dict[str, Any]], Any]
    needs: tuple[str, ...] = ()          # 数据根下必须已存在的路径
    params: tuple[str, ...] = ()         # 必须给的参数
    after: tuple[str, ...] = ()          # 同一次运行里排在它前面、失败就跳过它的步骤
    note: str = ""
    default: bool = True
    meta: dict[str, Any] = field(default_factory=dict)


def _framework_projections(root: Path, params: dict[str, Any]) -> Any:
    from cex_core.engine.ist_core.compile_engine import environment_prepare as ep

    return ep._converge_framework_projections()  # noqa: SLF001 — 批入口同一函数


def _compile_projections(root: Path, params: dict[str, Any]) -> Any:
    from cex_core.engine.ist_core.compile_engine import environment_prepare as ep

    identity = ep.DeviceReleaseIdentity(params["raw_build"],
                                        params.get("execution_build") or params["raw_build"], "")
    return list(ep.refresh_compile_projections(identity, product_version=params["version"]))


def _rule_registry(root: Path, params: dict[str, Any]) -> Any:
    from cex_core.engine.scripts import gen_rule_registry

    os.chdir(root)  # 它按工作目录的相对路径写
    return gen_rule_registry.main()


def _device_behavior_examples(root: Path, params: dict[str, Any]) -> Any:
    from cex_core.engine.scripts import gen_device_behavior_examples

    code = gen_device_behavior_examples.main([])
    if code:
        raise RuntimeError(f"gen_device_behavior_examples exited {code}")
    return code


def _device_characteristics(root: Path, params: dict[str, Any]) -> Any:
    from cex_core.engine.scripts import gen_device_characteristics

    code = gen_device_characteristics.main([])
    if code:
        raise RuntimeError(f"gen_device_characteristics exited {code}")
    return code


STEPS: dict[str, Step] = {step.name: step for step in (
    Step("framework_projections", _framework_projections,
         needs=(f"{MIRROR}/lib",),
         note="capability atlas（按需结转重生）、确认提示、能力用法索引、先例建议、设备行为样例、"
              "语言目录"),
    Step("compile_projections", _compile_projections,
         needs=("runtime/command_tree", f"{MIRROR}/lib/apv/clear.py", "knowledge/data/manual",
                "scripts/data/criterion_rule_sources.json", f"{COMPILE_REF}/domain_grammar.json",
                f"{COMPILE_REF}/blocks_schema.json"),
         params=("raw_build", "version"), after=("framework_projections",),
         note="命令树代际、清场 atlas、判据规则、节奏用法、语言目录"),
    Step("rule_registry", _rule_registry, default=False,
         note="入库投影 rule_registry.json（数据写在生成器里）"),
    Step("device_behavior_examples", _device_behavior_examples, default=False,
         needs=("knowledge/data/device_behavior_corpus",),
         note="入库投影 device_behavior_examples.json（密封语料构建）"),
    Step("device_characteristics", _device_characteristics, default=False,
         needs=("scripts/data/device_characteristics_source.json", "knowledge/data/manual"),
         after=("compile_projections",),
         note="入库投影 device_characteristics.json（还要命令树投影）"),
)}

DEFAULT_STEPS = tuple(name for name, step in STEPS.items() if step.default)
