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
| `env_prepare` | `jumphost:run` | 检查框架文件、conf、设备可达、设备自述的构建、规则与凭据字面量可用。床上装的构建以设备自述为准（`build_install` 之后就变了），回在 `device_build`；配置的 `[hub] build` 只定框架用 conf 哪一段凭据登录设备，设备自述的构建落在另一段凭据里时不 ready。客户端带上用例编译时的构建号，与设备自述不符就不 ready（写不成构建名的在受理时拒绝）；不带时照常检查，结果里 `build_checked: false`。同一租约里随后的 `case_submit`、`build_install` 以这次看到的构建起 runner（`--build`，结果库的构建表跟着它），没跑过 `env_prepare` 的租约用配置的构建。`device_count` 是 conf `[comm] ssh_ips` 列出的设备台数（用例只能用 `APV_0` 到 `APV_<台数-1>`）。结果另带 `conf.device_ips`：这些设备的管理地址，按 conf `[comm] ssh_ips` 的原顺序（hub 结果解析按它把 runner 日志行归到 `APV_<序号>`）；conf `[comm] marks` 给了设备名时另有同序的 `conf.device_names`。conf 读不到时没有 `conf` 字段（不拿空数组冒充），`framework_conf` 检查 `ok=false` |
| `case_submit` | `jumphost:run` | 冻结工作簿 → 上机前检查（压缩包与体积、Excel 契约、自毁命令、框架凭据字面量、床上没有的设备：E 列 `APV_k` / `Segk_tmp` 的 k 不小于设备台数就拒收；框架连不上第 k 台时整卷一个案都不跑）→ 只读落位、哈希对账 → 开始运行。回执带 `task_id`、`request_id`（传入时）、`submit_autoid`（最后一级落位目录名，即卷里第一个案）和 `module`；序号协议传 `request_id`、`dispatch_sequence`、`sequence_scope`，在租约检查前记账并去重 |
| `build_install` | `jumphost:run` | 装构建，照 InfoTest：用框架自己的升级用例 `smoke_test/system/upgrade/99999999{0,1,2}.py`（conf 里第 i 台设备一个，`[upgrade] cases` 可改），带 `test_build=<镜像名>` 跑。设备已是目标版本就跳过；否则用例在床内文件服务器上缺镜像时先下载，再 `system update`、等重启、升级后 `show version` 核对。请求 `install_b64` 是 `{schema: "bed-install@1", build, image}` 的 JSON：镜像名只许字母、数字和 `. _ -`，以 `.click` 或 `.array` 结尾，并且按升级用例的读法（第一个 `-` 之后到最后一个 `.` 之前，`_` 读作 `.`）正好是 `build`，否则在上机前拒收。用例文件逐字节复制到 `<staging_parent>/<task_id>/ist_install/` 再跑，报告目录因此带 task_id，归属与工作簿一样唯一。请求协议、拒绝阶段、去重和恢复与 `case_submit` 相同；回执另带 `build`、`image`、`target_version` 和每个用例文件的摘要。之后同样用 `case_status`、`case_results` 读，每台设备的升级用例是一个案。配了 `[upgrade] image_source`（构建库里镜像所在目录的 http 地址）时，runner 先把镜像放到 `[upgrade] stage_host`（conf `[env]` 里的主机，缺省 server231）的 `stage_dir`（缺省 /var/www/html）：已在且非空就不动，否则在跳板机上从构建库下载、经框架的主机登录写临时名再换名；回执的 `image_staging` 写明从哪里放到哪里 |
| `case_request` | `jumphost:run` | 按 `request_id` 只读查询，无需租约、不碰设备，`readOnlyHint: true`。只有本调用主体能看到自己的记录；不存在和别人的记录回答同形 |
| `case_status` / `case_results` | `jumphost:run` | 状态与结果。结果来自框架结果库，只认本次运行报告目录下的行（同一构建表里别的床、上一轮留下的行不算，条数记在 `ignored_rows`）；0.4.0 起新投递按带 `task_id` 的完整落位目录取结果、日志和会话，不再靠时间窗；目录外的同名报告不算。没过的案另带 `sessions`：本次运行里该案每个设备的命令行会话（`apv_<ip>.txt`）与触发机会话的尾部（每份最多 12000 字符、最多 8 份）。回执带 `rc`（框架进程退出码）、`run_dir`、`report_dir`、`submit_autoid`、`module`。运行进程没写完成状态就消失了（网关重启、内存不足、被人杀掉）时报 `lost`，`case_results` 回 `channel: runner_lost`（没有判定，需要重投） |
| `probe_show` | `jumphost:run` | 单条只读命令：一行最多 200 字符，参数只许字母、数字、空格和 `_ . , : / @ % + = * " ' -`；等不到设备提示符时回 `truncated: true` |
| `bed_topology` | `jumphost:run` | 本床拓扑（`network_topology.json`）：跳板机网卡与邻居、conf 里各台主机的接口地址（用框架自己的凭据登录，主机密钥首次见到即钉住）、可达被测设备的 `show ip address`。要租约，缓存到下次 `refresh`。另带 `services`：`gateway.toml` 里 `[[bed.services]]` 列的常驻服务（没配就是空列表） |
| `init_device` | `jumphost:admin` | 串口重置，分两步：`prepare` 给出计划和一次性确认码，`confirm` 带着确认码执行；每一步都核对配置模式提示符。显式给 `device_count` 时必须 ≥ 1 |

所有回给客户端的内容都经过脱敏：网关知道的口令字面值（conf 口令项、结果库口令、框架凭据字面量）一律换成 `***`。

## 运维要点

- **请求协议（序号修订）**：`case_submit` 使用 `request_id`、正安全整数 `dispatch_sequence`、`sequence_scope`（执行器身份）。主体和序号流共同隔离回收线；签发方须持久分配严格递增序号，把它与请求一起纳入签名/冻结摘要。网关不要求 `not_after`，旧字段收到时原样记录并回 `not_after_ignored: true`，不比较任何外部截止与本机墙钟。截止由 Hub 在发送前按自己的时钟判定。旧式不带请求身份的调用仍标 `request_record: none`，不具有请求账本保证。
- **去重**：核租约前原子记账。已有 request_id 的再次提交拒绝（`replayed: true`、`stage: duplicate`），不再调用 runner；查原记录用 `case_request`。重复调用的拒绝不等于原派发未触达设备，设备接触字段来自原记录；主体、摘要或模块不符仍为冲突。最小请求 id 墓碑永久保留，避免回收后用新序号重用同一 id。条带 flock 和独立日志恢复机制不变。
- **请求状态**：`received` → `rejected`（带阶段），或 `received` → `starting` → `started`；中断且确认没启动的为 `not_started`。任务与请求的 `starting/task_id` 在同一事务里先记，之后才起 runner。runner 的第一步写 `<task_id>.started`，之后才进入 pytest；父进程在 fork 前持有并传递 `.alive` 锁。查询和重复提交会对账：开始标记存在就是 `started/reached_device: true`；没有标记、请求处理锁和存活锁都已释放才记 `not_started`。正在处理或正在起进程时保持过渡状态，给出继续 `case_request` 的动作；原来的处理/runner 会继续，查询不会重发提交。状态变化在同一 SQLite 事务里留审计事件，随后追加到审计链；重启补写未追加的事件。写链后、确认前中断可能重复追加同一个 `event_id`，但不会漏掉已提交的状态变化。
- **拒绝阶段**：回答和 `tool_refused` 审计带 `stage`、`reached_device`。提交依次为 `admission`、`lease`、`precheck`、`bed_busy`、`staging`、`launch`，拒绝一律 `false`；runner 已起以后回任务状态，不伪装成拒绝。探测用 `probe`，初始化用 `initialization`；代理在 SSH 登录后明确回传标记，响应丢失时用本地登录标记补回事实；初始化也保留登录状态，登录后失败不会报成未上机。
- **查账与保留边界**：`case_request` 接受 `sequence_scope`，返回该主体/序号流的 `sequence_floor`。不大于回收线的序号一律拒绝，已用序号也不能搭配新 id。已回收/序号拒绝回 stage: collected、reached_device: null：只证明本次没有再执行，不能把原派发的历史效果说成未触达。`received_at/not_after/gateway_time/gc_before/journal_since` 只作记录，不参与受理、回收或未执行判定；查空不证明未执行。明确拒收/未启动事实仍须绑定原请求身份、摘要和可靠日志身份；不能凭两机器时间次序推断。
- **派发目录与兼容边界**：0.4.0 新目录是 `<staging_parent>/<task_id>/ist_staging_<module>/<首案编号>`，紧邻父目录仍给模块、最后一级仍给首案编号。假框架按这两级取名字，并在报告路径中保留 task_id；查询只认完整路径，结果库旧行被覆盖时保留“该派发缺结果行”的发现，不借新派发的行。若没有或出现多份对应报告，不选择最新一份冒充；返回明确缺失原因及检查本次日志、恢复归属证据的动作。回执回显请求 id，结果各通道回显请求 id、task_id，确认唯一目录时回 `ownership: staging_directory`，否则回 `ownership: none`。**真实框架对此目录布局尚未核对**：本次只跑合成夹具；集成者须在安装之前只读核对真实收集路径、报告 URL 和结果库保留规则（不是仅在版本认证之前核对）。升级前任务不具有新目录归属保证。
- **清理**：`cexg journal-gc --config … --holder <主体> --sequence-scope <执行器> --through-sequence <整数> [--apply]` 按序号回收请求详情，回收线只增并持久化；待处理请求阻止回收，床忙时拒绝。先停住该序号范围的新签发和在途派发并完成对账，再回收；旧无序号记录永久保留。原 `cexg gc --days` 只清任务文件及目录，不清请求账本；关联请求详情未回收时保留任务目录。
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

- `journal_id`：第一次创建请求日志时生成并持久化的随机身份；重启保持，重建、迁移到新日志或日志内容可能回退时改变。
- `journal_since`：日志开始可靠记账的 UTC Unix 秒边界，和建表在同一事务持久化。
- `subject`：网关解析后的完整调用主体，含 actor。

`gc_before` 为垃圾清理边界与 journal_since 的较大值。Hub 必须在投递前同租约下查询并冻结日志身份及主体，
确认发送投递的会话版本支持请求协议。未找到仅在查询 journal_id 与投递前冻结值相同、subject 与投递主体相同，
且 gateway_time > 原 not_after > gc_before >= journal_since 时能证明未执行。只核对查询会话的版本不够。
旧库升级时从升级时刻建立新边界，不能据此证明边界以前的调用；库重置或身份改变均须保留未决，人工核对原投递事实。

请求事实（含启动前任务快照）、待投审计事件、日志身份和持久时钟下限放在独立 SQLite 日志中：
`<state.dir 的同级目录>/<state.dir 末段名>.request-journal/requests.db`，例如配置为 `state` 时使用
同级 `state.request-journal/requests.db`。`state.db` 仍保存租约和任务列表，但不再作为请求日志的副本。
恢复旧 `state.db` 不会抹掉已登记的投递，也不会改变请求日志身份；启动前的快照支持主库任务行丢失后的查询和去重。
旧库首次升级会迁移原有请求并换日志身份和起点，须在服务停止、床空闲时执行。
主库记录独立日志的存储身份，独立日志丢失或与该身份不符时拒绝启动，管理员须恢复可信的当前日志。
备份和灾备必须单独保护请求日志；不得只恢复旧主库后删除请求日志来“修复”启动失败。

本机无法检测独立日志及其身份一起回退（例如从旧备份恢复两个目录或切换到旧副本）。
发生这种恢复时，管理员必须先停止网关、核对床和未决 runner，再在离线且床空闲时运行
`cexg journal-reset --config gateway.toml --reason "Restore reconciled backup"`，然后再启动服务。
命令改变公开 `journal_id`，将 `journal_since` 抬到持久时钟下限与当前时间的较大值，保留请求行、清理边界和永久墓碑；
不会把旧请求变成新的投递。命令不负责停服，运行中的服务不得并行执行此维护动作。
旧身份下的未决投递必须人工核实，不得因查空结项；Hub 冻结身份不匹配时须继续保持未决。
日志完整性或备份新旧无法核实时也不能采信查空。正常重启不需要换身份。

清理请求详情时，在同一独立日志事务内先留永久 `request_tombstones(request_id, not_after)` 再删详情。
墓碑命中即拒绝重交，回答 admission / request_record:collected / reached_device:false，
与新提交的截止时间、主体或内容无关；墓碑不随常规 GC 删除，也不随 journal-reset 清空。
查询仍给 found:false，原截止时间不大于 gc_before，因此不能证明该旧投递未执行。
永久墓碑只保存 id 和原截止时间，需计入长期日志容量；不能通过删除墓碑释放容量后继续沿用同一日志身份。
此保证覆盖升级时仍保留及升级后登记的请求；升级前已被旧版本删除的 id 无法凭空恢复，调用方仍须永久禁止旧 id 复用。
新尝试使用新 id，相同工作簿字节本身不阻止新尝试。

请求处于 received/starting 且尚无 runner 开始标记时，reached_device 为 null（尚未确定），不可当 false。
即使请求处理锁忙，存在开始标记仍确认为 started/true 并给 task_id。

过期与 base64 拒绝在首次请求登记事务中直接持久化为 rejected/admission；处理阶段每次变化也持久化。
中断且证实未启动时，查询和重复投递均回 not_started/interrupted；重复投递为非拒绝状态回答，
含 interrupted_stage 记录最后处理阶段，不再捏造 launch 拒绝。

旧共享目录任务不回退到时间窗口猜归属。找不到唯一归属报告时回 `ownership: none`，
`ownership_reason` 区分 legacy_layout、no_report、ambiguous_reports（及越界路径）。
尚未跑完或 runner 丢失时未核验归属，分别为 not_determined_not_completed、not_determined_runner_lost；
前者按 next_action 查询 case_status 后再读结果，后者由管理员恢复本任务 runner 和派发证据再核验。须检查派发日志、
收集器目录和保留证据，由运维恢复或明确报能力缺口，重复读取本身不能修复。升级仅在床空闲时进行。

凭据字面量刷新失败时保留上次成功集合和旧时间戳，下一次读取继续尝试刷新；不把失败缓存成空集合。
若尚无成功扫描，设备文本整份扣留，回答 ok:false、stage:redaction 与修复框架源码后重读的动作。


## 0.4.1：运行钥匙重叠与 Hub 结果字段

`[hub].previous_secret_sha256_file` 可配置上一把运行钥匙的摘要文件路径。
与 `secret_sha256_file` 一样只放一行 SHA-256、权限 0600；不存在表示已撤下。
先配置该路径并部署版本（第一次配置需重新加载网关）；后续轮换不重启：

1. 将当前旧摘要原子写入 previous 路径，保持服务账号可读、权限 0600。
2. 原子替换 current 摘要为新值；两把钥匙都只给 `jumphost:run`，主体不变。
3. Hub 的执行器引用 `${secret:GATEWAY_RUN_KEY}`；集成者经标准输入执行
   `circle-hub secret set --name GATEWAY_RUN_KEY --reason '轮换网关运行密钥'`。
4. 验证新钥匙、等待旧会话/请求不再使用旧值，再删除 previous 文件。
   删除下一次鉴权即生效；旧钥匙 401，新钥匙 200。不存在的可选槽不阻断当前钥匙；
   已存在但格式/权限坏的摘要会导致 503，不能当成撤销成功。

每次鉴权对 current、previous、admin 的固定长度摘要都做 `hmac.compare_digest`，
不因 current 已匹配而跳过其他槽；日志不打印钥匙或摘要。previous 不借用 admin 槽。
运维必须显式删除 previous，不能把重叠当成自动过期；清理动作和时间由集成者负责。

`case_results` 的已归属任务回答新增：

| 字段 | 类型 | 含义 / Hub 执行器定义 |
|---|---|---|
| `complete` | JSON boolean | 指向 `result.complete: "/complete"`；只有 runner 已完成、唯一归属报告存在、预期案全部有 PASS/FAIL 结果及非空且未过期日志、查询未报错时为 true。FAIL 本身不使结果不完整。运行中、lost、缺行/报告/日志、查询错误及未知判词为 false。`ok` 只是工具调用成功，不能代替它 |
| `submitted_at` | 带 UTC 时区 ISO 8601 字符串 | 指向 `result.submitted_at: "/submitted_at"`；从 task 原始 `deliver_epoch` 转换，保留微秒，不取结果查询时刻；不配置 `submitted_at_scale_ms` |
| `xlsx_sha256` | SHA-256 字符串 | 所有已归属任务通道（含 lost/运行中）均带原投递摘要；指向 `result.sha256: "/xlsx_sha256"` |

其余身份不改：提交回执摘要 `/sha256`、条目 `/case_ids`；结果 `/request_id`、`/task_id`、
`/cases`，逐案 `/case_id`、`/result`、`/log`、`/log_stale`、`/sessions`；
结果归属 `/ownership` 的唯一肯定值为 `staging_directory`，`/ownership_reason` 无冲突。
Hub 已有这些指针声明及消费逻辑，网关不需要修改 Hub 源码。部署侧需把这两个新增指针登记到
完整执行器定义，协议/前提认证版本改为 **0.4.1** 并补真实证据，不能沿用 0.4.0 认证。

`complete` 不是设备判决：Hub 仍独立核请求号、任务号、摘要、认证版本、每案收尾标记、
同租约的设备身份和连续性。日志是否收尾由执行器声明的标记校验；网关不把工具成功冒充设备通过。
真实收集器完整路径和保留规则仍须在安装前只读核对，假框架测试不替代实机证据。

### 0.4.2：提交回执与结果使用同一微秒精度

`case_submit.deliver_epoch`（含恢复/去重回执）从原 task 的 REAL 值取数，
舍入到六位小数，仍是 Unix 秒的 JSON number，不再截断成秒级整数。
`case_results.submitted_at` 从同一个舍入值转为 UTC ISO 8601，固定六位小数。
原 task.deliver_epoch 不改，查询不重新取时间；这是展示精度的统一，不是更改投递时刻。

手工核对新回执与结果时：把回执的十进制秒转换为整数微秒，与 UTC ISO 时间的整数微秒比较，
不要把 Unix 秒数字与 ISO 字符串直接比较，也不要要求二进制浮点跨语言的逐位相等。
Hub 将结果 `/submitted_at` 和旧 clock_skew_ms 仅作记录，不再比较跨机器时间窗；
不把回执的 Unix 秒套到 `/submitted_at`，不配置 submitted_at_scale_ms。

升级前已经保存的 0.4.0/0.4.1 回执不会改写，可能仍只有秒级 `deliver_epoch`。
对这些历史回执，只能核对 `旧回执秒 <= 结果时间 < 旧回执秒 + 1`，不能声称从旧回执恢复了微秒；
旧回执时间精度只影响记录展示，不作为受理、结果或有效性判据；结果身份不足时保留未知，由集成者按原请求/任务核对，不能重新派发。

仓库外的 `preflight.sh` 会在 0700 临时目录捕获 stderr（文件 0600），
只输出首条可识别诊断对应的固定类别及原退出码；未知原文只记 unclassified_stderr，
不转发任何原始文本、主机、账号、配置或口令，分类后立即删除临时文本，异常退出也清理。
主机钥变更与认证拒绝不自动重试，不降低 StrictHostKeyChecking。
sshpass 标准退出码 5 是密码拒绝，6 是未知主机钥，7 是主机钥变更；255 只作连接/认证未成功的线索，
不能单靠它断言根因。退出码依据见上游源码的 program_return_codes：
https://github.com/kevinburke/sshpass/blob/master/main.c 。诊断类别是排障提示，不是远端状态认证。

### 租约与时间记录

租约 TTL 从收到/续约起只按网关本机单调时钟计算。持久单调截止绑定操作系统启动身份；同一次启动内可跨服务重启恢复，系统重启或旧墙钟租约一律失效并重新取围栏。回执 expires_at 和结果 submitted_at 等时刻仅为记录；跨机器墙钟不作有效性证据，expires_in_s 是本机单调时钟算出的相对剩余时长。
