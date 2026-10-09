# 跳板机网关（cexg）

网关装在跳板机上，以测试框架所在的用户身份运行。它把“上机”变成几个需要登录的工具（编译助手通过 `POST /mcp` 调用）：租床、准备环境、提交用例、取结果、只读探测、初始化设备。跳板机和设备的口令只存在跳板机上（网关读框架的 conf），用户电脑上只有自己的登录令牌。

## 安装

在跳板机上（只有 Linux x86_64 的安装包）：

```bash
curl -fsSL https://raw.githubusercontent.com/qingshanfeihu/compile-excel-server/main/install.sh | bash -s -- --gateway
```

程序装在 `~/.local/share/cexg/versions/<版本>/`，`current` 指向当前版本，命令是 `cexg`。以后更新时重新运行这条命令，再重启网关（`sudo systemctl restart cexg`）即可，配置不受影响。

## 配置

### 第一步：在服务端准备三样东西

在服务端运行 `ces` 进入管理菜单：

| 要准备的 | 菜单 | 对应命令 |
|---|---|---|
| 网关客户端密钥 | 3. 服务客户端 → 新建网关客户端 | `ces clients add gateway --scopes "introspect bundles:read" --out ~/cexg-client.secret` |
| 网关证书（服务端用内置 CA 时） | 6. 连接与证书 → 为跳板机网关签发证书 | `ces tls gateway <跳板机 IP 或主机名> --out ~/cexg-tls` |
| 把网关地址告诉用户 | 7. 客户端配置 → 设置一项 → `gateway.url` | `ces config set gateway.url https://<跳板机>:8910/mcp` |

把密钥文件和 `~/cexg-tls` 里的三个文件（`gateway.pem`、`gateway.key`、`ca.pem`）拷到跳板机，例如 `~/.config/cexg/`，权限保持 600。

### 第二步：在跳板机上写配置

```bash
mkdir -p ~/.config/cexg
cexg sample-config > ~/.config/cexg/gateway.toml
```

按样例里的注释填写，至少要改这些：

| 配置项 | 填什么 |
|---|---|
| `[server] url` | 服务端地址，例如 `https://192.168.1.20:8900`（不要带连接串里 `#` 后面的部分，带了会报错） |
| `[server] client_secret_file` | 网关客户端密钥文件 |
| `[server] ca_file` | 服务端的 CA 证书 `ca.pem`；服务端用正式证书时留空 |
| `[server] build` | 这张床对应的执行构建名 |
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
| `env_prepare` | `jumphost:run` | 检查框架文件、conf、设备可达、设备自述的构建与网关构建一致、规则与凭据字面量可用。客户端带上用例编译时的构建号，与本床不符直接拒绝；不带时照常检查，结果里 `build_checked: false`。`device_count` 是 conf `[comm] ssh_ips` 列出的设备台数（用例只能用 `APV_0` 到 `APV_<台数-1>`） |
| `case_submit` | `jumphost:run` | 冻结工作簿 → 上机前检查（压缩包与体积、Excel 契约、自毁命令、框架凭据字面量、床上没有的设备：E 列 `APV_k` / `Segk_tmp` 的 k 不小于设备台数就拒收；框架连不上第 k 台时整卷一个案都不跑）→ 只读落位、哈希对账 → 开始运行。回执带 `submit_autoid`（落位目录名，即卷里第一个案）和 `module` |
| `case_status` / `case_results` | `jumphost:run` | 状态与结果。结果来自框架结果库，只认本次运行报告目录下的行（同一构建表里别的床、上一轮留下的行不算，条数记在 `ignored_rows`）；早于投递时间的日志标为过期。没过的案另带 `sessions`：本次运行里该案每个设备的命令行会话（`apv_<ip>.txt`）与触发机会话的尾部（每份最多 12000 字符、最多 8 份）。回执带 `rc`（框架进程退出码）、`run_dir`、`report_dir`、`submit_autoid`、`module`。运行进程没写完成状态就消失了（网关重启、内存不足、被人杀掉）时报 `lost`，`case_results` 回 `channel: runner_lost`（没有判定，需要重投） |
| `probe_show` | `jumphost:run` | 单条只读命令：一行最多 200 字符，参数只许字母、数字、空格和 `_ . , : / @ % + = * " ' -`；等不到设备提示符时回 `truncated: true` |
| `bed_topology` | `jumphost:run` | 本床拓扑（`network_topology.json`）：跳板机网卡与邻居、conf 里各台主机的接口地址（用框架自己的凭据登录，主机密钥首次见到即钉住）、可达被测设备的 `show ip address`。要租约，缓存到下次 `refresh`。另带 `services`：`gateway.toml` 里 `[[bed.services]]` 列的常驻服务（没配就是空列表） |
| `init_device` | `jumphost:admin` | 串口重置，分两步：`prepare` 给出计划和一次性确认码，`confirm` 带着确认码执行；每一步都核对配置模式提示符。显式给 `device_count` 时必须 ≥ 1 |

所有回给客户端的内容都经过脱敏：网关知道的口令字面值（conf 口令项、结果库口令、框架凭据字面量）一律换成 `***`。

## 运维要点

- **清理**：`cexg gc --config … [--days 30] [--apply]` 列出（加 `--apply` 才删，要求床空闲）N 天前已结束任务的记录、落位目录，以及框架报告里网关落位跑出来的目录。N 必须比 `run_max_s` 多一小时以上。
- **审计**：`cexg audit-verify --config …` 复核网关的审计日志哈希链。
- **互斥**：床锁 `<状态目录>/bed.lock` 用 `flock`，锁随测试进程组继承，进程结束时内核自动释放；不写进程号、不删锁文件。运行进程另继承 `<状态目录>/tasks/<任务>.alive` 锁，进程号记在 `<任务>.runner.json`。
- **连接**：证书握手在连接线程里做（10 秒超时），空闲连接 60 秒后断开。
- **拓扑缓存**：床拓扑缓存在 `<状态目录>/bed_topology.json`；登录床内主机时见过的主机密钥钉在 `<状态目录>/bed_host_key_pins.json`，之后对不上的主机不再递口令，只在结果里报出来。
- **设备命令**：设备初始化的命令全部来自 `gateway.toml` 的 `init_device.commands`，代码里不写设备命令。
- **规则文件**：`projections/domain_grammar.json` 从服务端该构建的 `stable` 包里取并缓存；取不到又没有缓存时拒绝上机。
- **证书报错**：日志或 `cexg check` 里出现“服务端证书不受信任”，说明 `[server] ca_file` 没填或填错了。

## 判据代码

网关的上机前检查用的判据代码在 `gateway/vendor/`，由 `tools/sync_gateway_vendor.py` 从 compile-excel-skills 的 `cex_core` 和 InfoTest 的凭据字面量提取器同步过来，不要在 vendor 里手改。同步与发版的细节见 [开发与发版](development.md#同步判据代码)。
