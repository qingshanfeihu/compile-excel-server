# compile-excel-server

**身份 / 知识库 / 编译数据分发平台**：OAuth2 设备授权流（内置“管理员发放访问码”后端 `private-mock`，
令牌只存哈希、可撤销、按 scope 逐路由校验）+ 令牌内省（给跳板机网关）+ 组织下发的客户端常量 + 按构建发布的编译数据包
（blob 按内容寻址、candidate/stable 双通道、服务端自检）+ 旧版工件清单与下载（由 stable 包派生）
+ 知识库关键词检索。
单一 `ces` 入口：配置向导（断点续填）、安装部署、管理菜单、系统服务。

## 一键安装（与 circle 同款形态：Release 自包含二进制，不依赖本机 Python）

```bash
# 公开仓
curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash
# 私有仓（需 gh auth login 且有仓库权限）
bash <(gh api repos/qingshanfeihu/compile-excel-server/contents/install.sh --jq .content | base64 -d)
# 钉版本
… | CES_VERSION=0.1.0 bash
```

装到 `~/.local/share/compile-excel-server/current`，软链 `~/.local/bin/ces`（PATH 自动写 rc）。
支持 darwin-arm64 / darwin-x86_64 / linux-x86_64（打 tag `v*` 自动出 Release，见
`.github/workflows/release.yml`）。

```bash
# 源码/开发（隔离 venv，不污染系统环境）
./install.sh --from-source
# Windows：暂无二进制档——git clone 后 python deploy/setup.py（需 python3.9+）
```

## 装完三步

```bash
ces setup     # 配置向导：数据目录/device_build/openkm·KMS 地址/工件(xml·xlsx·tar)/手册/端口与监听地址
              #   监听地址默认 127.0.0.1（只本机可用）；局域网内其他机器要登录，填 0.0.0.0（或 --host 0.0.0.0）
              #   非本机监听必须给 TLS 证书（--tls-cert/--tls-key）；可信实验网暂无证书时显式 --insecure-lan
              #   逐项说明+示例；每答一题存草稿，中断重跑自动从断点继续
ces           # 管理菜单（状态/启停/日志/服务注册/重配/卸载）
ces service install   # 注册 systemd(Linux)/launchd(macOS)，开机自启（Linux 以数据目录属主运行，--user 可改）
ces users add alice   # 建账号；访问码只显示一次（或 --out 文件 写 0600 文件），交给本人
```

非交互（2.90/CI，向导产物复跑）：`ces setup --options-file <data>/install.options.json`

## ces 子命令

| 命令 | 作用 |
|---|---|
| （无参数） | 管理菜单 |
| `setup [...]` | 配置向导 / 非交互安装（同 deploy/setup.py 参数） |
| `serve --data D --port P [--host H] [--tls-cert C --tls-key K] [--insecure-lan]` | 前台运行（服务管理器/调试用）；非回环地址不配 TLS 就拒绝启动 |
| `status` / `start` / `stop` / `restart` / `log` | 进程管理（pidfile + healthz） |
| `service install\|remove\|print [--user 账号]` | systemd/launchd 服务（print 只看 unit 内容）；systemd 写 `User=`（缺省取数据目录属主），ExecStart 各参数加引号 |
| `uninstall [--purge]` | 卸载（--purge 连数据目录一起删） |
| `users add <名> [--scopes "…"] [--out F]` | 建账号，生成访问码（库里只存哈希）；给 `--out` 时先把访问码写进 0600 文件，写不了就不建账号 |
| `users list` / `disable` / `enable` / `reset-code` / `scopes <名> "…"` | 账号管理；停用、重置访问码、改 scope 都会撤销该账号已签发的令牌 |
| `clients add <id> --scopes "…" [--out F]` / `list` / `remove` | 服务客户端：网关（`introspect`）、发布导入器（`bundles:publish`） |
| `clients rotate-secret <id> [--out F]` | 换 client secret：旧 secret 立即失效，已签发的令牌照常用到过期（access 默认 15 分钟） |
| `tokens revoke --user <名>\|--client <id>` / `purge` | 撤销令牌、清理过期记录 |
| `config show\|set <键> <地址>\|unset <键>\|import-env <文件>` | 下发给客户端的门户/缺陷系统/网关地址 |
| `registry list\|show <build>` | 数据包注册表：查看构建、通道与包内条目 |
| `registry import-dir <build> <kind> <目录> [--replace-kind]` | 目录里的文件按路径叠加到 candidate 上（同路径替换、其余保留）；`--replace-kind` 先丢掉这一类的全部条目 |
| `registry promote <build> <bundle_id> [--channel c] [--expect <bundle_id>\|none]` | 切通道；`--expect` 给出你以为的当前指针，对不上就拒绝（防并发发布/回滚被静默覆盖） |
| `registry verify` / `gc [--grace-hours 24]` | 全量复核 blob；回收没有包引用、且宽限期内没再上传过的 blob |
| `audit verify` | 复核审计日志：逐段逐行哈希链 + 各段自己的密钥 hmac，报出第一处被改、被删或段与段接不上的地方 |
| `audit rotate [--new-key]` | 封存当前审计段（移到 `audit_archive/`，连同当时的密钥）并起新链；`--new-key` 同时换审计签名密钥 |
| `generate --inputs D --out D [--steps …] [--raw-build …] [--version …] [--report F]` / `generate --list` | 服务端生成链：按 InfoTest 批入口顺序重生投影（源码安装可用，见下文） |

管理命令默认作用于安装登记里的数据目录，也可以加 `--data <目录>`。改动账号、客户端、令牌、客户端
配置、注册表（导入/切通道/gc）的管理命令都会写进服务端审计链（事件名以 `admin_` 开头，带操作系统用户名，
不含任何凭据）。

## 传输与审计

- **TLS**：客户端带着 OAuth 令牌访问，监听非回环地址时 `ces serve` 要求 `--tls-cert/--tls-key`
  （`ces setup` 会问，写进安装登记），确认是可信实验网才可 `--insecure-lan`。规则在 `deploy/tls_policy.py`，
  网关用同一条。本机探活在开 TLS 时走 https，以部署自己的证书为信任锚校验证书链。
  这条规则出现前装好、监听非回环地址又没配 TLS 的实例照旧启动，但每次启动都提示；
  客户端对非回环地址默认也拒绝明文（工作区 `insecure_lan` 显式开启才放行）。
  客户端信任自签证书：让 Python 认得这张证书，例如设 `SSL_CERT_FILE` 指向证书文件。
- **审计**：服务端 `<data>/audit.log` 与网关 `<state>/audit.log` 都是哈希链（`gateway/audit_chain.py`）：
  每行带上一行的 SHA-256，改动或删除中间任何一行都会断链；服务端另有实例密钥 hmac。
  `ces audit verify` / `cexg audit-verify --config …` 复核。哈希链证明不了"末尾没被截掉"，
  需要的话把最新一行的哈希定期记到别处。
  服务进程与 `ces` 管理命令往同一条链里写：每次追加都在 `<data>/audit.log.lock` 上加文件锁、锁内重读末行
  再接链（`deploy/audit_log.py`）。**升级到这一版后先重启服务，再用会写审计的管理命令**——旧版服务进程
  把末行哈希缓存在内存里，别的进程插进来的行会让它接错。
- **审计轮换与换钥**：不要直接替换 `audit_hmac_key`（旧行会全部报 hmac mismatch）。用
  `ces audit rotate --new-key`：在当前 `audit.log` 末尾写一行 `audit_sealed`（旧钥签）封口，整份移到
  `<data>/audit_archive/audit-NNNN.log`，旧钥另存 `audit-NNNN.key`（0600，复核旧段要用，随归档一起保管）；
  新 `audit.log` 的第一行 `audit_rotated` 记下被封段的名字与最后一行的哈希。运行中的服务不用重启，下一行
  就写进新文件、用新钥签。`ces audit verify` 逐段用各自的密钥复核，并核对段与段首尾相接，归档段被删、
  被改或密钥文件丢了都会报出来。只想切分日志不换钥：`ces audit rotate`。
- **Release**：每个 tag 的 Release 附 `SHA256SUMS`，下载后 `sha256sum -c SHA256SUMS` 核对。

## 仓库边界

| 内容 | 在哪里 |
|---|---|
| 平台代码、打包发布、自包含测试 | **本仓库**（测试用合成数据，零内部资产） |
| 真实工件（晋升模板/框架子集/命令树 xml）、知识库手册、device_build 元数据 | 部署侧数据目录（`--data`，安装器只建骨架） |
| 实例凭据（审计签名密钥） | 部署时由 provision 生成 |
| 账号、服务客户端、令牌 | 数据目录 `auth.db`（SQLite，访问码/secret 存加盐 HMAC-SHA256，令牌存 SHA-256） |
| OAuth 客户端 | skill 仓（compile-excel-skills）的一部分 |
| 跳板机网关 | 本仓库 `gateway/`（发布为独立的 `cexg-linux-x86_64.tar.gz`） |

`tests/test_e2e.py::test_no_internal_assets_in_repo` 是防泄漏守卫：git 跟踪
内容一旦出现内部资产指纹（真实模板/契约 SHA、内部构建名）即测试失败。

## 数据目录布局（部署侧灌入）

```
<data>/artifacts/            # 工件：xml 命令树 / xlsx 模板 / tar.gz…
<data>/docs/                 # 知识库 markdown（可带子目录）
<data>/artifacts_meta.json   # device_build + 每工件 version/media_type/receipt（gen_meta 生成）
<data>/audit_hmac_key        # provision 生成的审计签名密钥（ces audit rotate --new-key 换）
<data>/audit_archive/        # ces audit rotate 封存的审计段 audit-NNNN.log 与各自的密钥 audit-NNNN.key
<data>/auth.db               # 账号、服务客户端、令牌（只存哈希，0600）
<data>/client_config.json    # 下发给客户端的地址常量（ces config 管理）
<data>/registry/registry.db  # 数据包注册表（构建、包、条目、通道）
<data>/registry/blobs/sha256/<前2位>/<sha>   # 按内容寻址的只读 blob
<data>/audit.log  audit.log.lock  server.log  server.pid  install.options.json
```

## 身份与权限

授权页（`/activate`）由认证后端决定收哪些字段。内置后端 `private-mock`（名字沿用早期的“私有模拟”，
实际就是**管理员发放访问码**的正式后端）：管理员 `ces users add <名>` 建账号并拿到访问码，用户在授权页填
用户名 + 访问码；同一账号 15 分钟内连续失败 5 次锁 15 分钟（只给真实存在的账号计数，随手填的用户名
不占内存）。企业身份以后作为新后端接入（`auth_backends.py` 的 `BACKENDS`），设备流对外协议不变，客户端零改动。

访问码（144 位）与 client secret（256 位）都是服务端生成的随机串，库里存加盐 HMAC-SHA256，校验是微秒级；
早期版本写入的 PBKDF2 哈希照认，下次校验通过时（用户登录、客户端取令牌或内省）自动换成新格式，不需要迁移
步骤。校验在有上限的线程池里做，不占事件循环。

令牌：access 默认 15 分钟，refresh 默认 7 天且每用一次就轮换；已轮换的 refresh 被再次出示时，
整族令牌一起撤销。`POST /revoke` 撤销自己的令牌。令牌能用的 scope 始终是签发时的 scope 与账号**当前**
scope 的交集：设备码在授权页批准之后、兑换令牌之前，账号被停用/删除、访问码被重置，兑换一律拒绝
（`access_denied`），scope 被收回的只签发剩下的；refresh 同样按账号当前 scope 续签，一项不剩就拒绝。

未认证可达的入口都有上限：表单请求体 8 KiB、`POST /v1/bundles` 清单 16 MiB、blob `CES_MAX_BLOB_BYTES`，
超了回 413（声明的长度超限直接拒，不声明的边读边数）；待处理设备码全局 1000 个、同一来源地址
`CES_MAX_PENDING_FLOWS_PER_IP` 个（缺省 20）。`/healthz` 不鉴权，只回 `{"ok": true, "service": …}`，
构建号、认证后端、KMS 地址不在这里透出（构建号与 KMS 地址登录后看工件清单 `/v1/artifacts/manifest`，
本机 `ces status` 也显示构建号）。

| scope | 用途 | 默认给用户 |
|---|---|---|
| `artifacts:read` | 旧版工件清单与下载 | 是 |
| `docs:query` | 知识库检索 | 是 |
| `bundles:read` | 读取数据包与 blob | 是 |
| `config:read` | 读取客户端常量 | 是 |
| `jumphost:run` | 经网关租床、部署、提交用例 | 是 |
| `jumphost:admin` | 经网关初始化设备 | 否 |
| `bundles:publish` | 发布数据包、切通道 | 否（给导入器客户端） |
| `introspect` | 令牌内省 | 否（给网关客户端） |

客户端申请的 scope 与账号拥有的 scope 取交集后签发。网关用自己的 client secret 调
`POST /v1/introspect`（HTTP Basic）确认用户令牌是否有效、有哪些 scope。

`/v1/config/client` 只下发非机密地址；键名像凭据、URL 带账号口令的一律拒收，
个人门户账号不保存（客户端扫码登录）。

## 数据包与发布

每个构建（`build`，用路径安全的 execution build）有一串数据包；包由条目组成，条目是
`kind`（cmdtree / manual / spec / projections / template / framework / footprints）+
相对路径 + blob SHA-256。`bundle_id` 是规范化条目清单的哈希，内容没变就是同一个包。

- 新包进 `candidate`；服务端自检（blob 齐全、落盘内容复核、发布方声明的必备 kind 齐全）通过后才能切 `stable`。
- 进 `stable` 另有服务端下限：包里必须有 `CES_STABLE_REQUIRED_KINDS` 列出的 kind（缺省 `cmdtree projections`——
  客户端判命令存在性读 `cmdtree/vendor_stdlib_*`，自毁扫描与网关上机前闸读 `projections/domain_grammar.json`），
  发布方声明 `required_kinds: []` 也放不宽它；部署侧确需放宽时显式设这个变量（`none` 表示不设下限）。
- 内容与已有包相同的重发不新建包，也**不动任何通道指针**（`created: false`）；登记结果里的 `channels`
  是两个通道当前指向的包。切通道（`POST /v1/builds/{b}/channels/{c}`）可带 `expect=<bundle_id>|none`：
  通道当前不是它就回 409 并给出 `current`，不静默覆盖别人刚切的、运维刚回滚的指针；指向本来的包是空操作
  （`changed: false`）。
- 客户端读 `GET /v1/builds/{b}/bundle`（默认 stable）再逐个 `GET /v1/blobs/{sha}`，按清单 SHA 校验。
- 旧版 `/v1/artifacts/*` 由该构建 stable 包里带 `legacy_name` 的条目派生（清单与下载都按 `?device_build=`，
  缺省是本实例的构建）；启动时 `artifacts/` 目录会被登记成一个包（`legacy-import`），每个通道只在它为空、
  或本来就指着旧目录导入的包时才跟着走：不覆盖导入器发布的 stable，也不把导入器刚登记的 candidate 拨回去。
  旧目录的包按它实际有的类自检，不受 stable 下限约束（那是运维放进数据目录的文件；之后手工把 stable 切回它
  回滚也一样）。`legacy-import`、`ces-cli` 是注册表的保留发布者名，不能建成账号或客户端。下载发的是登记时的
  不可变 blob，运行中改 `artifacts/` 不影响已登记的内容，重启后才会重新登记。
- `ces registry gc` 只回收没有包引用、且最近一次上传早于宽限期（缺省 24 小时，`--grace-hours`）的 blob：
  发布进行中（blob 已 PUT、清单还没 POST）的不会被删；已有的 blob 再被 PUT 一次也会刷新这个时间。

### 过渡期发布通道：`tools/import_infotest.py`

在跑过 InfoTest 批入口（收敛链）的工作站上，用 InfoTest 的 venv 运行：

```bash
ces clients add publisher --scopes "bundles:publish bundles:read" --out ~/.config/ces-publisher.secret
<InfoTest venv>/bin/python tools/import_infotest.py --infotest-root <InfoTest 仓根> \
    --device-build "<show version 的完整版本>" --server https://<服务端> \
    --client-secret-file ~/.config/ces-publisher.secret --promote
```

- 只调 InfoTest 自己的解析与校验函数，不调任何会写文件、部署跳板机、上设备的收敛函数。
- 闸：InfoTest 编译预检里与数据有关的各项 + 逐类校验（Excel 晋升回执、命令树活动代际与投影
  时新性、手册 catalog、footprint 回填收据、框架镜像身份、投影绑定）。任何一项不过就退出码 3，
  逐项列出原因和 InfoTest 里修复它的入口。
- spec：先跑 InfoTest 自己的 spec 同步，同步失败就拒绝；代龄只记录在包的 `source` 里。
- 命令树只发投影 JSON，不发原始 XML（`cmdtree_*` 一律不进包：原始 XML 带参数默认值，含凭据默认值）。
- 出包前扫描：包里每个条目（含 tar、gzip、xlsx 里的成员）按原文、XML 转义、URL 与 JSON 编码查凭据值，
  命中就拒绝发布，只报位置与次数。框架镜像里带着凭据字面量时本通道必然拒绝，改用下面的数据目录发布通道。
- `--dry-run` 只做解析与校验。内容没变时重跑，服务端不新建包、不动通道指针。`--promote` 带 expect
  （登记时看到的当前 stable）：内容没变而 stable 指着别的包（运维回滚过）就不切；切的时候 stable 已被
  别人改过（409）也不覆盖，只报当前指针与手工切换命令，退出码 0；别的拒绝退出码 1。缺 stable 下限要求
  的 kind（`CES_STABLE_REQUIRED_KINDS`）在上传之前就拒绝。
- 服务端地址必须是 https（回环地址或显式 `--insecure-lan` 除外），URL 里带用户名口令的拒绝。

### 数据目录发布通道：`tools/publish_data_dir.py`（不导入 InfoTest 代码）

对已收敛的数据目录（InfoTest 仓根布局）只做数据文件自己的身份核对，再用同一个 Publisher 上传：

```bash
python3 tools/sync_gateway_vendor.py --skills-root ../compile-excel-skills --only cex_core
python3 tools/publish_data_dir.py --data-root <数据目录> --raw-build "<show version 的完整版本>" \
    --manual-version <手册版本> --server https://<服务端> \
    --client-secret-file ~/.config/ces-publisher.secret --promote   # 或 --dry-run / --out-dir <目录>
```

- 命令树：从活动代际取 XML，按引擎的凭据参数规则把 `default_value` 置空（`tools/cmdtree_rederive.py`），
  再用引擎自己的函数从这份 XML 重推导代际、投影、拆卸图谱与领域文法；重推导结果与原件只许
  身份字段不同，否则拒绝发布。包里发脱敏 XML、代际清单与投影，`cmdtree/source.json` 记脱敏收据。
- 另发编写阶段要的两份：判据台账种子（`projections/criterion_author_rules.jsonl`）与 SSL 生命周期
  证据（`projections/ssl_lifecycle_contract.json`，图谱身份随重推导改绑）。
- 模板与契约的固定身份取自同步来的 `gateway/vendor/cex_core`（客户端校验的同一份）。
- 命令树脱敏：引擎凭据闭包里的值在 XML 的任何属性、文本里都去掉（`default_value` 置空，其余换成引擎
  自己的 `[redacted]`）；脱敏后重新解析，仍有残留或结构变了就拒绝。收据里的 `credential_fields_redacted`
  计数是重推导结果与原件之间唯一允许的差别。
- 框架树与规格书：凭据值与 URL 里带口令的 userinfo 换成 `CEX-REDACTED`；`.sync_meta`、`mirror_manifest`、
  规格书清单与索引随之改绑，规格书代际号由内容派生。Excel 契约 `source_hashes` 钉住的框架文件与手册
  （catalog 记着 md 的哈希）不改写：它们带着凭据时出包前扫描点名拒绝（只报位置与次数），要先在源头去掉。
- 出包前扫描、https 要求与 `--promote` 的 expect 行为同上面的过渡期通道；`--out-dir` 也要先过扫描。
- vendor：`sync_gateway_vendor.py` 只取 skills 仓的提交（缺省 HEAD，经 `git archive`），工作区有未提交
  改动时拒绝（`--allow-dirty` 仍只取提交内容），写 `gateway/vendor/cex_core/.vendor_stamp.json`
  （提交与日期），永不带 `cex_core/engine/_identities.json`。
- 客户端（compile-excel-skills 的 `cex_client/engine_env.py`）按 `cmdtree/generation_manifest.json`
  逐文件核哈希后摆成引擎的活动命令树代际，两份编写阶段数据摆到引擎读的位置；只带投影的旧包仍按
  平面布局摆，引擎如实报命令树不可用。

### 服务端生成链：`ces generate`（`generators/`）

把 InfoTest 批入口里纯本地的那几段搬到服务端：输入目录（InfoTest 仓根布局：框架镜像、手册、
命令树代际、`scripts/data` 策展源、入库的那几份 compile_ref）复制成工作副本，逐步起子进程调
InfoTest 的同名函数，产物目录可直接 `ces registry import-dir <build> projections <out>` 发布：产物目录里只有
本次新写或改动的投影，import-dir 按路径叠加到 candidate 上，没改的投影原样保留（不要加 `--replace-kind`）。

| 步骤 | 调的 InfoTest 函数 | 缺省 |
|---|---|---|
| `framework_projections` | `environment_prepare._converge_framework_projections`（按需结转重生 capability atlas、确认提示、能力用法索引、先例建议、设备行为样例、语言目录） | 跑 |
| `compile_projections` | `environment_prepare.refresh_compile_projections`（命令树代际、清场 atlas、判据规则、节奏用法、语言目录；要 `--raw-build`、`--version`） | 跑 |
| `rule_registry` / `device_behavior_examples` / `device_characteristics` | 三份入库投影的生成器 | 点名才跑 |

- 生成逻辑一行不重写：函数来自 compile-excel-skills 的 `cex_core/engine`（从 InfoTest 抽取、逐条对拍），
  经 `tools/sync_gateway_vendor.py --only cex_core` 同步进 `gateway/vendor/`；
- 每一步先核对自己要的输入与参数，缺了记 `missing_inputs` / `missing_params`，依赖它的步骤记
  `skipped`，退出码 1；不静默产出；
- 生成器依赖（openpyxl、PyYAML、pydantic）见 `requirements-generators.txt`；每一步要起 Python 子进程，
  所以只在源码安装里可用；
- 上游同步（WebDAV 手册与规格书、跳板机框架镜像、设备命令树、构建站）不在这里，仍走上面的导入器。

## 跳板机网关（cexg，`gateway/`）

装在跳板机上，以框架用户身份运行，把"上机"变成几个带鉴权的 MCP 工具（streamable HTTP，`POST /mcp`）。
跳板机与设备口令只在这里（读框架 conf）；客户端文件夹里只有 OAuth 令牌。

```bash
cexg sample-config > ~/.config/cexg/gateway.toml     # 按跳板机实际情况填写
ces clients add gateway --scopes "introspect bundles:read" --out ~/.config/cexg/client.secret   # 在服务端执行
cexg check --config ~/.config/cexg/gateway.toml      # 配置与框架自检（不碰设备）
cexg serve --config ~/.config/cexg/gateway.toml      # systemd 样例见 gateway/cexg.service.example
```

| 工具 | scope | 说明 |
|---|---|---|
| `lease_acquire` / `lease_heartbeat` / `lease_release` / `lease_status` | `jumphost:run` | 单床租约，带 fencing token；碰设备的工具都要带当前租约 |
| `env_prepare` | `jumphost:run` | 框架文件、conf、设备可达、设备自述构建与网关构建一致、规则与凭据字面量可用；客户端带 `device_build`（用例按哪个构建编的），与本床构建不符直接拒绝；不带时照查，结果里 `build_checked: false` |
| `case_submit` | `jumphost:run` | 冻结工作簿 → 上机前闸（zip/体积、Excel 契约、自毁命令、框架凭据字面量）→ 只读落位、sha 对账 → 起跑 |
| `case_status` / `case_results` | `jumphost:run` | 状态；结果来自框架结果库，只认本次运行报告目录下的行（同一构建表里别的床、上一轮留下的行不算，条数记在 `ignored_rows`）；早于投递时间的日志标 stale；输出经脱敏；runner 没写完成状态就死了（网关重启、OOM、人工 kill）报 `lost`，`case_results` 回 `channel: runner_lost`（没有判定，重投）；回给客户端的一切另把网关知道的口令字面值（conf 口令项、结果库口令、框架凭据字面量）换成 `***` |
| `probe_show` | `jumphost:run` | 单条 show/get，只读：一行至多 200 字符，参数只许字母数字空格与 `_ . , : / @ % + = * " ' -`；等不到设备提示符回 `truncated: true` |
| `bed_topology` | `jumphost:run` | 本床拓扑事实（`network_topology.json`）：跳板机网卡与邻居、conf 里各台主机的接口地址（用框架自己的字面凭据登录，主机密钥首见即钉）、可达被测设备的 `show ip address`，按 InfoTest 拓扑生成器同一套纯函数合成；要租约，缓存到下次 `refresh`。客户端编写阶段的判据（VIP 选取、触发机配对、后端地址）读它；另带 `services`：`gateway.toml` 里 `[[bed.services]]` 的常驻服务清单（host/ip/proto/port/note），没配为空列表 |
| `init_device` | `jumphost:admin` | 串口重置，两步：`prepare` 给出计划与一次性确认码，`confirm` 带码执行；每步核对配置模式提示符；确认码只把 confirm 绑定到那份计划，人的批准靠客户端对该工具的权限确认；显式 `device_count` 须 ≥ 1 |

- 互斥：`<state>/bed.lock` 用 `flock`，锁随 pytest 进程组继承，进程结束内核自动释放；不写 pid、不删锁文件。
- runner 进程组另继承 `<state>/tasks/<task>.alive` 锁，pid/pgid 记在 `<task>.runner.json`；systemd 单元须
  `KillMode=process`（样例已带），否则重启网关会连带杀掉正在跑的用例。TLS 握手在连接线程里做（10 秒超时），
  空闲连接 60 秒断开。
- `cexg gc --config … [--days 30] [--apply]`：列出（`--apply` 才删，要床空闲）N 天前已结束任务的
  `<state>/tasks/*` 与 state.db 记录、`<staging_parent>/ist_staging_*/<autoid>/`，以及框架报告里的
  `report/*/*/ist_staging_*`（空了的上层一并删，别的报告不碰）；N 须长过 `run_max_s` 加一小时。
- 床拓扑缓存在 `<state>/bed_topology.json`，登录床内主机时见过的主机密钥钉在 `<state>/bed_host_key_pins.json`：
  之后对不上的主机不再递口令，只在结果的观察项里报出来。
- 设备初始化的命令全部来自 `gateway.toml` 的 `init_device.commands`，代码里不写设备命令。
- 规则文件（`projections/domain_grammar.json`）从服务端该构建的 stable 包取并缓存；取不到且没有缓存就拒绝上机。
- 判据代码 `gateway/vendor/` 由 `tools/sync_gateway_vendor.py` 从 compile-excel-skills 的 `cex_core`
  与 InfoTest 的凭据字面量提取器同步，`--check` 查漂移，不在 vendor 里手改。
  `gateway/vendor/cex_core/` **不入库**（它带真实模板/契约身份，本仓守零内部资产）：
  测试对仓库只读、从不改写它：网关测试用手动生成的这份（没生成过就不收集），生成链测试用 skills 仓
  `cex_core` 的临时副本；与 skills 仓（或 `CEX_SKILLS_ROOT`）不一致由 `tests/gateway/test_vendor_readonly.py`
  用 `--check` 报出；
  发版时 release 流程用只读令牌检出 skills 仓再生成（仓库 secret `CEX_SKILLS_READ_TOKEN`）。
  本地打包前、第一次跑网关测试前（以及 skills 仓的 `cex_core` 改过之后）手动跑
  `python3 tools/sync_gateway_vendor.py --only cex_core --skills-root <skills 检出>`。
- 测试用假框架目录（真 pytest 跑假 `test_xlsx`、假结果库）与假串口控制台；真跳板机与设备上的验收另做。

## 环境变量

| 变量 | 缺省 | 说明 |
|---|---|---|
| `CES_DATA_DIR` | `--data` 参数 | 数据目录 |
| `CES_PORT` / `--port` | 8900 | 监听端口 |
| `CES_ACCESS_TTL` | 900 | access token 有效期（秒） |
| `CES_REFRESH_TTL` | 7d | refresh token 有效期（秒） |
| `CES_DEVICE_TTL` | 600 | 设备码有效期（秒） |
| `CES_AUTH_BACKEND` | `private-mock` | 认证后端 |
| `CES_MAX_BLOB_BYTES` | 2 GiB | 单个 blob 上传上限（超了 413） |
| `CES_MAX_PENDING_FLOWS_PER_IP` | 20 | 同一来源地址同时挂着的设备码上限（全局另有 1000）；放在反向代理后面时所有请求同一来源，要按并发登录量调大 |
| `CES_STABLE_REQUIRED_KINDS` | `cmdtree projections` | 进 stable 必须有的 kind（空格或逗号分隔，`none` 不设下限）；服务进程与 `ces registry promote` 各自读，两边要设成一样 |
| `CES_CONFIG_ROOT` | 平台惯例目录 | 安装登记/向导草稿位置（测试用） |

## 测试

```bash
python -m pytest tests/ -v     # 需 fastapi/uvicorn/pytest；客户端脚本默认取同级 ../compile-excel-skills，
                               # 也可用 SKILL_SCRIPTS_DIR 指定；找不到时相关用例跳过
```
