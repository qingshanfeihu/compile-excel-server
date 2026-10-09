# 发布编译数据

本篇写给负责把编译数据发给用户的人。先说清几个概念，再讲三种发布方式：管理菜单、两个批量发布工具、服务端生成链。

## 构建、包与通道

| 概念 | 说明 |
|---|---|
| 构建（构建号） | 设备 `show version` 里的执行构建名，只能含字母、数字和 `. _ -`。每个构建有自己的一串包 |
| 包 | 一组文件。每个文件有类别、包内路径和 SHA-256；包的编号由文件清单算出来，内容不变编号就不变 |
| 类别 | `cmdtree`（命令树）、`projections`（投影：规则与派生表）、`manual`（手册）、`spec`（规格书）、`template`（Excel 模板）、`framework`（测试框架）、`footprints`（回填记录） |
| 通道 | 每个构建有两个通道：`candidate`（待发布）和 `stable`（用户默认同步的）。新包先进 `candidate`，通过检查后才能切到 `stable` |

发布的规则：

- 新包进 `candidate` 时服务端会自检：文件齐全、落盘内容与哈希一致、发布方声明的必备类别齐全。自检不通过的包不能进 `stable`。
- 进 `stable` 另有服务端下限：包里必须有 `CES_STABLE_REQUIRED_KINDS` 列出的类别，默认是 `cmdtree projections`（客户端判断命令是否存在、网关上机前检查都要用到它们）。发布方声明不需要也放不宽这个下限；确实要放宽时，在服务端设这个环境变量（`none` 表示不设下限）。
- 内容和已有的包相同时不新建包，也不改通道指向。
- 切换通道可以带 `expect`（你以为的当前指向）：对不上就拒绝并告诉你当前是哪个包，不会覆盖别人刚做的发布或运维刚做的回滚。指向本来的包时什么也不做。
- 客户端先读 `stable` 的文件清单，再逐个下载文件，并按清单里的 SHA-256 校验。

## 用管理菜单发布

适合手上已经有整理好的目录。

| 步骤 | 菜单 | 对应命令 |
|---|---|---|
| 导入 | 4. 编译数据 → 导入目录 | `ces registry import-dir <构建号> <类别> <目录>` |
| 发布 | 4. 编译数据 → 发布到 stable | `ces registry promote <构建号> <包> --expect <当前 stable 的包或 none>` |
| 回滚 | 4. 编译数据 → 回滚 stable 到旧版本 | 同上，`<包>` 换成旧包 |
| 查看 | 4. 编译数据 → 查看构建与发布情况 / 查看某个构建的全部包 | `ces registry list` / `ces registry bundles <构建号>` |

导入的细节：

- 默认按路径叠加：目录里的文件替换 `candidate` 里同路径的文件，其余文件原样保留。
- 选“整类替换”（`--replace-kind`）时，先清掉 `candidate` 里这一类的全部文件，目录必须是这一类的完整集合。
- 导入完菜单会问要不要马上发布。

## 批量发布工具

两个工具都用“发布客户端”的身份上传。先在服务端建一个（菜单“3. 服务客户端 → 新建发布客户端”）：

```bash
ces clients add publisher --scopes "bundles:publish bundles:read" --out ~/.config/ces-publisher.secret
```

两个工具共同的规则：

- `--server` 直接填服务端 `ces link` 显示的连接串：带 `#ca=` 时，工具先下载服务端的 CA 证书、核对指纹，再用它校验服务端。也可以只填地址（服务端用正式证书时）。
- 服务端地址必须是 https（本机地址或显式 `--insecure-lan` 除外），地址里不能带用户名口令。
- 出包前扫描：包里每个文件（包括 tar、gzip、xlsx 里的成员）按原文、XML 转义、URL 编码和 JSON 编码查找凭据值，命中就拒绝发布，只报位置和次数。
- `--dry-run` 只做解析和校验，不上传。
- `--promote` 带着登记时看到的当前 `stable` 去切换：内容没变而 `stable` 指着别的包（运维回滚过）就不切；切的时候 `stable` 已经被别人改过也不覆盖，只报出当前指向和手动切换的命令，退出码 0。其他拒绝的退出码是 1。缺 `stable` 下限要求的类别时，在上传之前就拒绝。
- 内容没变时重跑，服务端不新建包、不改通道。

### 过渡期工具：`tools/import_infotest.py`

在跑过 InfoTest 批入口（收敛链）的工作站上，用 InfoTest 的虚拟环境运行：

```bash
<InfoTest 虚拟环境>/bin/python tools/import_infotest.py --infotest-root <InfoTest 仓库根目录> \
    --device-build "<show version 的完整版本>" --server "<连接串>" \
    --client-secret-file ~/.config/ces-publisher.secret --promote
```

- 只调用 InfoTest 自己的解析和校验函数，不调用任何会写文件、部署跳板机、上设备的收敛函数。
- 检查项：InfoTest 编译预检里与数据有关的各项，加上逐类校验（Excel 晋升回执、命令树活动代际与投影时新性、手册目录、回填收据、框架镜像身份、投影绑定）。任何一项不过就以退出码 3 退出，逐项列出原因和 InfoTest 里修复它的入口。
- 规格书：先跑 InfoTest 自己的规格书同步，同步失败就拒绝；代龄只记在包的来源信息里。
- 命令树只发投影，不发原始 XML：原始 XML 带着参数默认值，其中可能有凭据。
- 框架镜像里带着凭据字面量时，这个工具一定会拒绝，改用下面的数据目录工具。

### 数据目录工具：`tools/publish_data_dir.py`

对已经收敛好的数据目录（InfoTest 仓库的目录布局）只核对数据文件自身的身份，不导入 InfoTest 代码：

```bash
python3 tools/sync_gateway_vendor.py --skills-root ../compile-excel-skills --only cex_core
python3 tools/publish_data_dir.py --data-root <数据目录> --raw-build "<show version 的完整版本>" \
    --manual-version <手册版本> --server "<连接串>" \
    --client-secret-file ~/.config/ces-publisher.secret --promote   # 或 --dry-run / --out-dir <目录>
```

- 命令树：从活动代际取 XML，按引擎的凭据参数规则把默认值置空（`tools/cmdtree_rederive.py`），再用引擎自己的函数从这份 XML 重新推导代际、投影、拆卸图谱和领域文法。重推导结果与原件只允许身份字段不同，否则拒绝发布。包里发脱敏后的 XML、代际清单和投影，`cmdtree/source.json` 记脱敏收据。
- 命令树脱敏：引擎凭据闭包里的值在 XML 的任何属性、文本里都会去掉（默认值置空，其余换成引擎自己的 `[redacted]`）；脱敏后重新解析，仍有残留或结构变了就拒绝。收据里的 `credential_fields_redacted` 计数是重推导结果与原件之间唯一允许的差别。
- 另发编写阶段要用的两份：判据台账种子（`projections/criterion_author_rules.jsonl`）和 SSL 生命周期证据（`projections/ssl_lifecycle_contract.json`，图谱身份随重推导改绑）。
- 模板与契约的固定身份取自同步来的 `gateway/vendor/cex_core`，和客户端校验用的是同一份。
- 框架树与规格书：凭据值和 URL 里带口令的部分换成 `CEX-REDACTED`；镜像清单、规格书清单与索引随之改绑，规格书代际号由内容派生。Excel 契约钉住哈希的框架文件和手册不改写：它们带着凭据时，出包前扫描会点名拒绝，要先在源头去掉。
- `--out-dir` 也要先过出包前扫描。
- 同步判据代码：`sync_gateway_vendor.py` 只取 compile-excel-skills 仓库里已提交的内容（默认 HEAD，经 `git archive`）；工作区有未提交改动时拒绝（`--allow-dirty` 也只取已提交的内容）；写下 `gateway/vendor/cex_core/.vendor_stamp.json`（提交与日期）；永远不带 `cex_core/engine/_identities.json`。
- 客户端（compile-excel-skills 的 `cex_client/engine_env.py`）按 `cmdtree/generation_manifest.json` 逐个核对哈希后，摆成引擎的活动命令树代际；两份编写阶段数据摆到引擎读取的位置。只带投影的旧包仍按平铺布局摆放，引擎会如实报告命令树不可用。

## 服务端生成链

`ces generate`（代码在 `generators/`）把 InfoTest 批入口里纯本地的那几步搬到服务端执行：

1. 把输入目录（InfoTest 仓库的目录布局：框架镜像、手册、命令树代际、`scripts/data` 策展源、入库的几份 compile_ref）复制成工作副本；
2. 逐步起子进程，调用 InfoTest 的同名函数；
3. 产物目录里只有本次新写或改动的投影，直接用 `ces registry import-dir <构建号> projections <产物目录>` 发布（按路径叠加，没改的投影原样保留，不要加 `--replace-kind`）。

| 步骤 | 调用的 InfoTest 函数 | 默认 |
|---|---|---|
| `framework_projections` | `environment_prepare._converge_framework_projections`（按需重生能力图谱、确认提示、能力用法索引、先例建议、设备行为样例、语言目录） | 执行 |
| `compile_projections` | `environment_prepare.refresh_compile_projections`（命令树代际、清场图谱、判据规则、节奏用法、语言目录；需要 `--raw-build` 和 `--version`） | 执行 |
| `rule_registry` / `device_behavior_examples` / `device_characteristics` | 三份入库投影的生成器 | 点名才执行 |

- 生成逻辑一行不重写：函数来自 compile-excel-skills 的 `cex_core/engine`（从 InfoTest 抽取、逐条对拍），经 `tools/sync_gateway_vendor.py --only cex_core` 同步进 `gateway/vendor/`。
- 每一步先核对自己需要的输入和参数，缺了记为 `missing_inputs` / `missing_params`，依赖它的步骤记为 `skipped`，退出码 1；不会静默产出。
- 依赖（openpyxl、PyYAML、pydantic）见 `requirements-generators.txt`。每一步都要起 Python 子进程，所以只在源码安装里可用。
- 上游同步（WebDAV 上的手册与规格书、跳板机框架镜像、设备命令树、构建站）不在这里，仍走上面的批量发布工具。

## 旧版工件接口

`/v1/artifacts/*` 是早期的下载接口，现在由某个构建 `stable` 包里带旧文件名的条目派生：

- 清单与下载都按 `?device_build=` 选构建，默认是本实例的旧版构建号（`ces artifacts build` 设置）。
- 服务启动时，`artifacts/` 目录会被登记成一个包（发布者记为 `legacy-import`）。每个通道只在它为空、或本来就指着旧目录导入的包时才跟着变：不会覆盖批量工具发布的 `stable`，也不会把刚登记的 `candidate` 拨回去。
- 旧目录的包按它实际有的类别自检，不受 `stable` 下限约束（那是运维自己放进数据目录的文件；之后手工把 `stable` 切回它回滚也一样）。
- `legacy-import`、`ces-cli` 是保留的发布者名，不能用作账号或客户端名称。
- 下载的是登记时的不可变文件，运行中改动 `artifacts/` 不影响已登记的内容，重启后才会重新登记。
