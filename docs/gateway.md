# 跳板机网关（cexg）

网关装在跳板机上，以测试框架所在的用户身份运行。它把“上机”变成几个工具（circle-hub 的 worker 通过 `POST /mcp` 调用）：租床、准备环境、提交用例、取结果、只读探测、初始化设备。跳板机和设备的口令只存在跳板机上（网关读框架的 conf）。网关只有一个调用方——hub 的 worker，它拿一把静态密钥来调用，网关本地比对密钥的 SHA-256，不回调任何服务端；谁能用 hub、能做什么，由 hub 自己决定。

## 安装

**0.4.0 安装前置条件**：仅在床空闲、没有进行中任务时升级。集成者须先只读核对真实框架收集器，
确认它在报告目录及结果库 URL 中完整保留 `<task_id>/ist_staging_<module>/<首案编号>`，并核对结果库覆盖/保留规则。
这一步在安装之前完成，不只是认证版本之前。本仓仅用假框架验证，尚未完成真实收集器核对。
新目录对所有调用方生效（含不传 request_id 的旧调用方）；若 task_id 层被丢掉，所有调用方均会缺结果或无法证明归属，
不能安装后靠重读恢复，也不能回退借用另一派发的结果。

网关只有 Linux x86_64 的安装包，能在 Ubuntu 20.04（glibc 2.31）及更新的系统上运行。

实验室的跳板机通常上不了外网，所以用离线安装：

1. 在能上网的电脑上，从 [发布页](https://github.com/qingshanfeihu/compile-excel-server/releases) 下载三个文件：`install.sh`、`cexg-linux-x86_64.tar.gz`、`SHA256SUMS`（0.3.0 起网关不再回调服务端；0.3.0 之前的版本发布页里没有 `install.sh`，从仓库根目录取）。
2. 把三个文件拷到跳板机的同一个目录，例如 `~/cexg-install/`。
3. 在跳板机上运行：

```bash
cd ~/cexg-install && CES_ASSET_DIR=. CES_VERSION=<版本号> bash install.sh --gateway
```

跳板机能上外网时，也可以直接运行：

```bash
curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash -s -- --gateway
```

- 安装脚本会核对 SHA256，先试运行新版本再切换。程序装在 `~/.local/share/cexg/versions/<版本>/`，`current` 指向当前版本，命令是 `cexg`。
- 以后更新时按同样的步骤再装一次，然后重启网关（`sudo systemctl restart cexg`），配置不受影响。
- 如果 `~/.local/share/cexg` 里已经有别的方式部署的网关（例如 `current` 指向按提交号部署的 `releases/<提交>`、由系统服务用自带的 Python 启动），安装脚本会拒绝覆盖，免得正在运行的服务重启后起不来。这时用 `CES_PREFIX=<新目录>` 装到别处，确认无误后再改系统服务。

## 配置

### 第一步：准备三样东西

| 要准备的 | 怎么做 |
|---|---|
| 密钥 | `openssl rand -hex 32`。明文登记到 hub 的执行资源（凭据模式 `static-secret`）；跳板机上只放它的 SHA-256：`printf '%s' '<明文>' \| sha256sum \| cut -d' ' -f1 > ~/.config/cexg/hub.secret.sha256`，权限 600。换密钥就是换这个文件的内容，不用重启网关。要开 `init_device`，再生成一把管理密钥，同样放摘要到 `admin_secret_sha256_file` |
| 网关证书 | 由实验室 CA 签发 `gateway.crt` / `gateway.key`，放在 `~/.config/cexg/tls/`，权限 600；hub 的执行 profile 里信任那张 CA |
| 规则文件 | hub 的规则资产 `domain_grammar.json` 放到 `hub.grammar_file`（不配就是状态目录里的那份）；由运维随 hub 更新 |

### 第二步：在跳板机上写配置

```bash
mkdir -p ~/.config/cexg
cexg sample-config > ~/.config/cexg/gateway.toml
```

按样例里的注释填写，至少要改这些：

| 配置项 | 填什么 |
|---|---|
| `[hub] secret_sha256_file` | hub 密钥的 SHA-256 摘要文件（600） |
| `[hub] admin_secret_sha256_file` | 可选，管理密钥的摘要文件；配了 `init_device` 才可用 |
| `[hub] build` | 这张床对应的执行构建名 |
| `[hub] grammar_file` | 可选，规则文件路径；留空用 `<state.dir>/domain_grammar.json` |
| `[listen] host` / `port` | 给其他电脑用填 `0.0.0.0`，端口默认 8910 |
| `[listen] tls_cert` / `tls_key` | `gateway.pem` / `gateway.key` |
| `[framework]` 各项 | 测试框架的路径、Python 3.8 解释器、conf 文件名、落位目录 |

### 第三步：自检并启动

```bash
cexg check --config ~/.config/cexg/gateway.toml     # 检查配置与框架，不碰设备
cexg serve --config ~/.config/cexg/gateway.toml     # 前台运行
```

开机自启用 systemd：把 `gateway/cexg.service.example` 复制到 `/etc/systemd/system/cexg.service`，按实际情况改 `User` 和 `ExecStart` 里的路径，然后：

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now cexg
```

服务单元必须保留 `KillMode=process`（样例里已经写了），否则重启网关会连带杀掉正在跑的用例。

## 网关提供的工具

| 工具 | 需要的权限 | 说明 |
|---|---|---|
| `lease_acquire` / `lease_heartbeat` / `lease_release` / `lease_status` | `jumphost:run` | 单床租约，带防并发令牌；会碰设备的工具都要带着当前租约 |
| `env_prepare` | `jumphost:run` | 检查框架文件、conf、设备可达、设备自述的构建与网关构建一致、规则与凭据字面量可用。客户端带上用例编译时的构建号，与本床不符直接拒绝；不带时照常检查，结果里 `build_checked: false`。`device_count` 是 conf `[comm] ssh_ips` 列出的设备台数（用例只能用 `APV_0` 到 `APV_<台数-1>`）。结果另带 `conf.device_ips`：这些设备的管理地址，按 conf `[comm] ssh_ips` 的原顺序（hub 结果解析按它把 runner 日志行归到 `APV_<序号>`）；conf `[comm] marks` 给了设备名时另有同序的 `conf.device_names`。conf 读不到时没有 `conf` 字段（不拿空数组冒充），`framework_conf` 检查 `ok=false` |
| `case_submit` | `jumphost:run` | 冻结工作簿 → 上机前检查（压缩包与体积、Excel 契约、自毁命令、框架凭据字面量、床上没有的设备：E 列 `APV_k` / `Segk_tmp` 的 k 不小于设备台数就拒收；框架连不上第 k 台时整卷一个案都不跑）→ 只读落位、哈希对账 → 开始运行。回执带 `task_id`、`request_id`（传入时）、`submit_autoid`（最后一级落位目录名，即卷里第一个案）和 `module`；0.4.0 起可同时传 `request_id`、`not_after`，在租约检查前记账并去重 |
| `case_request` | `jumphost:run` | 按 `request_id` 只读查询，无需租约、不碰设备，`readOnlyHint: true`。只有本调用主体能看到自己的记录；不存在和别人的记录回答同形 |
| `case_status` / `case_results` | `jumphost:run` | 状态与结果。结果来自框架结果库，只认本次运行报告目录下的行（同一构建表里别的床、上一轮留下的行不算，条数记在 `ignored_rows`）；0.4.0 起新投递按带 `task_id` 的完整落位目录取结果、日志和会话，不再靠时间窗；目录外的同名报告不算。没过的案另带 `sessions`：本次运行里该案每个设备的命令行会话（`apv_<ip>.txt`）与触发机会话的尾部（每份最多 12000 字符、最多 8 份）。回执带 `rc`（框架进程退出码）、`run_dir`、`report_dir`、`submit_autoid`、`module`。运行进程没写完成状态就消失了（网关重启、内存不足、被人杀掉）时报 `lost`，`case_results` 回 `channel: runner_lost`（没有判定，需要重投） |
| `probe_show` | `jumphost:run` | 单条只读命令：一行最多 200 字符，参数只许字母、数字、空格和 `_ . , : / @ % + = * " ' -`；等不到设备提示符时回 `truncated: true` |
| `bed_topology` | `jumphost:run` | 本床拓扑（`network_topology.json`）：跳板机网卡与邻居、conf 里各台主机的接口地址（用框架自己的凭据登录，主机密钥首次见到即钉住）、可达被测设备的 `show ip address`。要租约，缓存到下次 `refresh`。另带 `services`：`gateway.toml` 里 `[[bed.services]]` 列的常驻服务（没配就是空列表） |
| `init_device` | `jumphost:admin` | 串口重置，分两步：`prepare` 给出计划和一次性确认码，`confirm` 带着确认码执行；每一步都核对配置模式提示符。显式给 `device_count` 时必须 ≥ 1 |

所有回给客户端的内容都经过脱敏：网关知道的口令字面值（conf 口令项、结果库口令、框架凭据字面量）一律换成 `***`。

## 运维要点

- **请求协议（0.4.0 起）**：`case_submit` 的 `request_id` 只收 ASCII 字母、数字、`:._-`，长度 1–128；`not_after` 为带 UTC 时区的 ISO 8601（`Z` 或 `+00:00`），两者必须同时给或同时省略。省略时仍可运行，但 `request_record: none`，没有按请求 id 去重或查账的保证。有效的一对参数在核租约前记下主体（含 `X-Circle-Hub-Actor`）、工作簿 SHA-256、截止时间和收到时刻；查重、截止判断和插入共享同一 `BEGIN IMMEDIATE`，时钟在拿到写锁后读取。坏 base64 仍记拒收，查询的 `xlsx_sha256: null` 明确表示没有可算摘要的工作簿；id 或截止参数本身不合法时只回受理阶段拒绝和审计，没有有效的请求记录。
- **去重**：同 id、同主体和同工作簿摘要返回保存的原回答，即使租约已过期也不重查、不重跑；主体或摘要不符只回冲突，不泄露、修改原记录。调用方不能为原 id 改换内容或在清理后复用它，新的尝试使用新的 id。不同 id 即使字节相同也是不同派发。请求处理用固定 256 个 `flock` 条带串行化，内核在网关退出时释放，不按请求数永久积累锁文件。
- **请求状态**：`received` → `rejected`（带阶段），或 `received` → `starting` → `started`；中断且确认没启动的为 `not_started`。任务与请求的 `starting/task_id` 在同一事务里先记，之后才起 runner。runner 的第一步写 `<task_id>.started`，之后才进入 pytest；父进程在 fork 前持有并传递 `.alive` 锁。查询和重复提交会对账：开始标记存在就是 `started/reached_device: true`；没有标记、请求处理锁和存活锁都已释放才记 `not_started`。正在处理或正在起进程时保持过渡状态，给出继续 `case_request` 的动作；原来的处理/runner 会继续，查询不会重发提交。状态变化在同一 SQLite 事务里留审计事件，随后追加到审计链；重启补写未追加的事件。写链后、确认前中断可能重复追加同一个 `event_id`，但不会漏掉已提交的状态变化。
- **拒绝阶段**：回答和 `tool_refused` 审计带 `stage`、`reached_device`。提交依次为 `admission`、`lease`、`precheck`、`bed_busy`、`staging`、`launch`，拒绝一律 `false`；runner 已起以后回任务状态，不伪装成拒绝。探测用 `probe`，初始化用 `initialization`；代理在 SSH 登录后明确回传标记，响应丢失时用本地登录标记补回事实；初始化也保留登录状态，登录后失败不会报成未上机。
- **查账与保留边界**：`case_request` 找到时给 `request_id/state/stage/reached_device/xlsx_sha256/received_at/not_after`，确认 runner 已启动时再给 `task_id`。找不到仍给 `found: false/gateway_time/gc_before/journal_id/journal_since/subject`（外加工具通用 `ok`）；所有时间字段均是 UTC Unix 秒。只有 journal_id、subject 与投递前冻结身份相同，且 `gateway_time > 调用方原 not_after > gc_before >= journal_since` 才能用缺记录证明未执行。查询的快照和当前时刻也在 SQLite 写锁里取，晚到提交不能穿过该截止保证。`gc_before` 为已删记录的最大截止时间，持久、只增；尚未过截止或仍在恢复的请求不清理，相关任务和目录也保留。初始值为日志创建时刻，不能据此推断旧版不支持此协议的调用；先核对发送投递的会话 `initialize.serverInfo.version`。
- **派发目录与兼容边界**：0.4.0 新目录是 `<staging_parent>/<task_id>/ist_staging_<module>/<首案编号>`，紧邻父目录仍给模块、最后一级仍给首案编号。假框架按这两级取名字，并在报告路径中保留 task_id；查询只认完整路径，结果库旧行被覆盖时保留“该派发缺结果行”的发现，不借新派发的行。若没有或出现多份对应报告，不选择最新一份冒充；返回明确缺失原因及检查本次日志、恢复归属证据的动作。回执回显请求 id，结果各通道回显请求 id、task_id，确认唯一目录时回 `ownership: staging_directory`，否则回 `ownership: none`。**真实框架对此目录布局尚未核对**：本次只跑合成夹具；集成者须在安装之前只读核对真实收集路径、报告 URL 和结果库保留规则（不是仅在版本认证之前核对）。升级前任务不具有新目录归属保证。
- **清理**：`cexg gc --config … [--days 30] [--apply]` 列出（加 `--apply` 才删，要求床空闲）N 天前已结束任务的记录、落位目录，以及框架报告里网关落位跑出来的目录。N 必须比 `run_max_s` 多一小时以上。新落位和报告按带 task_id 的目录形状清理，保留无对应网关落位的旧形状报告；请求删除数为 `requests_deleted`，删后查账仍带持久保留边界。
- **审计**：`cexg audit-verify --config …` 复核网关的审计日志哈希链。
- **互斥**：床锁 `<状态目录>/bed.lock` 用 `flock`，锁随测试进程组继承，进程结束时内核自动释放；不写进程号、不删锁文件。运行进程另继承 `<状态目录>/tasks/<任务>.alive` 锁，进程号记在 `<任务>.runner.json`。
- **连接**：证书握手在连接线程里做（10 秒超时），空闲连接 60 秒后断开。
- **拓扑缓存**：床拓扑缓存在 `<状态目录>/bed_topology.json`；登录床内主机时见过的主机密钥钉在 `<状态目录>/bed_host_key_pins.json`，之后对不上的主机不再递口令，只在结果里报出来。
- **设备命令**：设备初始化的命令全部来自 `gateway.toml` 的 `init_device.commands`，代码里不写设备命令。
- **规则文件**：`hub.grammar_file`（默认 `<状态目录>/domain_grammar.json`）是跳板机本地文件，按修改时间重读；文件不在或不是 JSON 时拒绝上机。
- **鉴权报错**：`cexg check` 的 `hub_secret` 不通过，或请求回 503 “gateway auth is misconfigured”，说明密钥摘要文件缺失、权限不是 600 或内容不是 64 位十六进制；401 则是 hub 用的密钥与摘要对不上。

## 判据代码

网关的上机前检查用的判据代码在 `gateway/vendor/`，由 `tools/sync_gateway_vendor.py` 从 compile-excel-skills 的 `cex_core` 和 InfoTest 的凭据字面量提取器同步过来，不要在 vendor 里手改。同步与发版的细节见 [开发与发版](development.md#同步判据代码)。

请求查询的 `subject` 是网关解析后的完整调用主体（含 actor），无论找到与否都会回传。
缺记录仅在查询 subject 与原投递 subject 完全一致时才可能证明未执行；主体变更不能作为未执行证据。

### 请求日志身份和未执行证明

`case_request`（找到或未找到）与 `case_submit` 回答均增加：

- `journal_id`：第一次创建请求日志时生成并持久化的随机身份；重启保持，重建/迁移到新日志时改变。
- `journal_since`：日志开始可靠记账的 UTC Unix 秒边界，和建表在同一事务持久化。
- `subject`：网关解析后的完整调用主体，含 actor。

`gc_before` 为垃圾清理边界与 journal_since 的较大值。Hub 必须在投递前同租约下查询并冻结日志身份及主体，
确认发送投递的会话版本支持请求协议。未找到仅在查询 journal_id 与投递前冻结值相同、subject 与投递主体相同，
且 gateway_time > 原 not_after > gc_before >= journal_since 时能证明未执行。只核对查询会话的版本不够。
旧库升级时从升级时刻建立新边界，不能据此证明边界以前的调用；库重置或身份改变均须保留未决，人工核对原投递事实。

请求处于 received/starting 且尚无 runner 开始标记时，reached_device 为 null（尚未确定），不可当 false。
即使请求处理锁忙，存在开始标记仍确认为 started/true 并给 task_id。

过期与 base64 拒绝在首次请求登记事务中直接持久化为 rejected/admission；处理阶段每次变化也持久化。
中断且证实未启动时，查询和重复投递均回 not_started/interrupted；重复投递为非拒绝状态回答，
含 interrupted_stage 记录最后处理阶段，不再捏造 launch 拒绝。

旧共享目录任务不回退到时间窗口猜归属。找不到唯一归属报告时回 `ownership: none`，
`ownership_reason` 区分 legacy_layout、no_report、ambiguous_reports（及越界路径）；须检查派发日志、
收集器目录和保留证据，由运维恢复或明确报能力缺口，重复读取本身不能修复。升级仅在床空闲时进行。
