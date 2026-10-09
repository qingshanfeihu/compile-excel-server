# 服务端运维

本篇写给维护 compile-excel-server 的管理员。日常操作都可以在管理菜单（运行 `ces`）里完成，这里列出菜单背后的命令和各项细节，方便查阅和写脚本。

## 命令一览

管理命令默认作用于安装时登记的数据目录，也可以加 `--data <目录>` 指定。

### 安装与运行

| 命令 | 作用 |
|---|---|
| `ces` | 管理菜单（没有终端时打印命令说明） |
| `ces setup` | 配置向导；重新运行会以上次的答案作默认值，数据目录里的内容都保留 |
| `ces setup --data D [--host 0.0.0.0] [--port 8900] [--tls-auto] [--start]` | 不提问，按参数安装（脚本、CI 用）；其他参数见 `ces setup --help` |
| `ces setup --options-file <数据目录>/install.options.json` | 按向导存下的答案重装 |
| `ces status` | 运行状态、连接串、证书、开机自启 |
| `ces link [--host 地址\|auto]` | 显示发给用户的连接串和证书指纹；`--host` 指定连接串里写的地址（多网卡、跨网段、经端口映射访问时用），`auto` 改回自动选择 |
| `ces version` | 版本号 |
| `ces start` / `stop` / `restart` | 启动、停止、重启；开启了开机自启时交给 systemd / launchd 处理 |
| `ces log` | 看最后 40 行日志 |
| `ces service install` / `remove` / `print` `[--user 账号]` | 开启、关闭开机自启，或只打印服务单元内容；Linux 上要用 `sudo ~/.local/bin/ces service install`，服务以数据目录的属主运行，`--user` 可改 |
| `ces update [--version 版本]` | 更新到最新版或指定版本；数据目录和配置不动，原来在运行的服务会自动重启 |
| `ces uninstall [--purge]` | 卸载程序；`--purge` 连数据目录一起删除 |
| `ces serve --data D --port P [--host H] [--tls-cert C --tls-key K] [--insecure-lan]` | 前台运行，给服务管理器或调试用 |

### 账号与客户端

| 命令 | 作用 |
|---|---|
| `ces users add <用户名> [--scopes "权限…"] [--out 文件]` | 建账号，生成访问码；给了 `--out` 就先写进权限 600 的文件，写不了就不建账号 |
| `ces users list` | 列出账号和权限 |
| `ces users disable` / `enable <用户名>` | 停用、启用账号；停用会让他已登录的会话全部失效 |
| `ces users reset-code <用户名> [--out 文件]` | 重置访问码，旧访问码和已登录的会话一起失效 |
| `ces users scopes <用户名> "权限…"` | 改权限，已登录的会话需要重新登录 |
| `ces clients add <名称> --scopes "权限…" [--out 文件]` | 建服务客户端：网关用 `"introspect bundles:read"`，发布器用 `"bundles:publish bundles:read"` |
| `ces clients list` / `remove <名称>` | 列出、删除服务客户端 |
| `ces clients rotate-secret <名称> [--out 文件]` | 换客户端密钥：旧密钥立即失效，已签发的令牌用到过期（默认 15 分钟） |
| `ces tokens revoke --user <用户名>` / `--client <名称>` | 让某个账号或客户端的所有会话下线 |
| `ces tokens purge` | 清理过期超过一天的令牌记录 |

权限的含义见 [安全设计](security.md#权限)。

### 证书与客户端配置

| 命令 | 作用 |
|---|---|
| `ces tls show` | 证书方式、包含的地址、到期时间、CA 指纹 |
| `ces tls renew [--name 地址]... [--remove 地址]...` | 用内置 CA 重新签发服务器证书：以前加过的地址都保留，`--name` 加上、`--remove` 去掉；重启服务后生效 |
| `ces tls gateway <跳板机地址>... --out <目录>` | 为跳板机网关签发证书，输出 `gateway.pem`、`gateway.key`、`ca.pem` |
| `ces config show` | 查看下发给客户端的地址 |
| `ces config set <项> <地址>` / `unset <项>` | 设置、删除一项；可设置的项运行 `ces config` 查看 |
| `ces config import-env <文件>` | 从 `KEY=value` 文件导入门户与缺陷系统地址（账号口令不导入） |

### 编译数据、手册与旧版工件

| 命令 | 作用 |
|---|---|
| `ces registry list` | 各构建的包数量和通道指向 |
| `ces registry bundles <构建号>` | 某个构建的全部包，新的在前（回滚时从这里挑） |
| `ces registry show <构建号> [--channel stable\|candidate]` | 通道上那个包的文件清单 |
| `ces registry import-dir <构建号> <类别> <目录> [--replace-kind]` | 把目录里的文件按路径叠加到 `candidate`；`--replace-kind` 先清掉这一类的全部文件 |
| `ces registry promote <构建号> <包> [--channel c] [--expect <包>\|none]` | 切换通道；`--expect` 写你以为的当前指向，对不上就拒绝，防止覆盖别人刚做的发布或回滚 |
| `ces registry verify` | 逐个复核已存文件的哈希 |
| `ces registry gc [--grace-hours 24]` | 删除没有包引用、且宽限期内没有再上传过的文件 |
| `ces docs list` / `add <目录或 .md 文件>... [--force]` | 查看、导入知识库手册；重启服务后生效 |
| `ces artifacts list` / `add <文件>[:版本]... [--force]` | 查看、导入旧版工件；重启服务后生效 |
| `ces artifacts build <构建号>` / `kms <主机:端口\|none>` | 设置旧版接口的构建号、KMS 地址；重启服务后生效 |
| `ces generate --inputs D --out D [...]` | 服务端生成链，见 [发布编译数据](publishing.md#服务端生成链) |

### 审计日志

| 命令 | 作用 |
|---|---|
| `ces audit verify` | 逐段复核审计日志，报出第一处被改、被删或段与段接不上的地方 |
| `ces audit rotate [--new-key]` | 封存当前段，从新文件接着记；`--new-key` 同时换签名密钥 |

改动账号、客户端、令牌、证书、客户端配置、编译数据、手册、旧版工件的命令都会写进审计日志，事件名以 `admin_` 开头，记着操作系统用户名，不含任何访问码、密钥或令牌。

## 证书与连接串

服务只给本机用（监听 `127.0.0.1`）时不需要证书。给局域网用时，用户的登录令牌要经过网络，必须用 https。三种方式：

| 方式 | 适合 | 怎么配 |
|---|---|---|
| 内置 CA 自动签发（推荐） | 没有现成证书的内网 | 向导里选“自动生成证书”，或 `ces setup --tls-auto` |
| 自备证书 | 组织有正式 CA | 向导里选“使用已有证书”，或 `--tls-cert` / `--tls-key` |
| 不用证书 | 可信实验网临时使用 | 向导里选“不用证书”，或 `--insecure-lan`；用户初始化时也要说明允许明文 |

内置 CA 的做法：

- 第一次配置时在 `<数据目录>/tls/` 生成本服务专用的 CA（十年有效）和服务器证书（两年有效）。服务器证书里写着本机主机名、全部网卡地址和 `127.0.0.1`。
- 连接串里的地址默认取默认路由那块网卡；没有默认路由时取第一块网卡，都没有时会提示。多网卡、用户在别的网段或经端口映射访问时，用 `ces link --host <地址>` 指定，证书里没有这个地址会自动补上。
- 服务端在 `/ca.pem` 公开 CA 证书。证书本身不是机密，私钥 `ca.key` 只在数据目录里（权限 600）。
- 连接串是 `https://<地址>:<端口>#ca=<CA 证书的 SHA-256 指纹>`。编译助手先下载 CA 证书、核对指纹，对上了才信任它；下载途中被调包，指纹就对不上。
- 用户用了证书里没有的地址（域名、映射出去的 IP），运行 `ces tls renew --name <地址>` 再重启服务。CA 不变，用户不用重新初始化。
- `ca.pem` 和 `ca.key` 只剩一个时，`ces` 会报错而不是悄悄换一个新 CA（换 CA 会让所有用户都要重新初始化）。确实要换 CA，删掉整个 `tls/` 目录再运行 `ces setup`，把新的连接串发给所有用户。
- 浏览器不认识内置 CA，用户打开授权页时会看到证书警告。编译助手会给出服务器证书的指纹供用户在浏览器里核对，也会给出把 CA 加入系统信任的命令。
- 服务器证书到期前 30 天内重新运行 `ces setup` 或 `ces tls renew` 会自动续签。
- 跳板机网关的证书用同一个 CA 签发（`ces tls gateway`），编译助手、网关、服务端只认这一份 CA。

监听规则（`deploy/tls_policy.py`，网关用同一条）：

- 监听非本机地址又没配证书时，`ces serve` 拒绝启动，除非显式 `--insecure-lan`。
- 这条规则出现之前装好、监听局域网又没配证书的实例照旧启动，但每次启动都会提示。
- 本机探活在开了 https 时也走 https，以部署自己的证书为信任锚校验。

## 开机自启

| 系统 | 方式 | 说明 |
|---|---|---|
| Linux | systemd | `sudo ~/.local/bin/ces service install`；服务以数据目录的属主运行（不是 root），`--user` 可改；`ExecStart` 每个参数都加了引号，指向 `current` 链接（更新后自动用上新版本）；日志照旧写进 `<数据目录>/server.log` |
| macOS | launchd | `ces service install`，装在当前用户的 LaunchAgents 里 |
| Windows | 不支持自动注册 | 可以用 NSSM 把 `ces serve ...` 注册成服务 |

开启开机自启以后，`ces start` / `stop` / `restart` 会交给 systemd 或 launchd 执行。重新运行 `ces setup` 改了配置时，向导会同时更新服务单元并重启。

## 数据目录

| 路径 | 内容 |
|---|---|
| `auth.db` | 账号、服务客户端、令牌（只存哈希，权限 600） |
| `registry/registry.db` | 编译数据的构建、包、文件条目和通道 |
| `registry/blobs/sha256/<前两位>/<哈希>` | 按内容存放的只读文件 |
| `tls/ca.pem`、`tls/ca.key` | 内置 CA（私钥权限 600） |
| `tls/server.pem`、`tls/server.key` | 内置 CA 签发的服务器证书 |
| `docs/` | 知识库手册（markdown，可以有子目录） |
| `artifacts/`、`artifacts_meta.json` | 旧版工件和它们的版本、构建号、KMS 地址 |
| `client_config.json` | 下发给客户端的地址 |
| `audit.log`、`audit.log.lock`、`audit_hmac_key` | 审计日志、写日志用的文件锁、签名密钥 |
| `audit_archive/` | 封存的审计段 `audit-NNNN.log` 和各自的密钥 `audit-NNNN.key` |
| `server.log`、`server.pid` | 服务日志、进程号 |
| `install.options.json` | 向导这次的答案（可以用 `--options-file` 复用） |

安装登记（数据目录在哪、端口、证书路径、连接串里的地址）在 `~/.config/compile-excel-server/install.json`。用 sudo 运行 `ces` 时，仍然读发起 sudo 的那个用户的这份登记。

## 程序目录

安装脚本把每个版本放在 `~/.local/share/compile-excel-server/versions/<版本>/`，`current` 是指向当前版本的链接，`~/.local/bin/ces` 指向 `current` 里的程序。更新时只切换链接：正在运行的旧进程继续用它自己那份文件，不会读到被替换的文件；保留上一个版本，更早的删掉。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `CES_DATA_DIR` | `--data` 参数 | 数据目录 |
| `CES_PORT` | 8900 | 监听端口（`server.py` 直接运行时用） |
| `CES_ACCESS_TTL` | 900 | 访问令牌有效期（秒） |
| `CES_REFRESH_TTL` | 7 天 | 刷新令牌有效期（秒） |
| `CES_DEVICE_TTL` | 600 | 设备码有效期（秒） |
| `CES_AUTH_BACKEND` | `private-mock` | 登录方式（内置的是“管理员发放访问码”） |
| `CES_MAX_BLOB_BYTES` | 2 GiB | 单个上传文件的上限，超了回 413 |
| `CES_MAX_PENDING_FLOWS_PER_IP` | 20 | 同一来源地址同时挂着的设备码上限（全局另有 1000）；放在反向代理后面时所有请求同一来源，要按并发登录量调大 |
| `CES_STABLE_REQUIRED_KINDS` | `cmdtree projections` | 进 `stable` 必须有的数据类别（空格或逗号分隔，`none` 表示不设下限）；服务进程和 `ces registry promote` 各自读，两边要设成一样 |
| `CES_CONFIG_ROOT` | `~/.config/compile-excel-server` | 安装登记和向导草稿放在哪里（测试用） |
| `CES_REPO` | `qingshanfeihu/compile-excel-server` | `ces update` 和安装脚本从哪个仓库下载 |

## 审计日志

- 服务端的 `audit.log` 和网关的 `<状态目录>/audit.log` 都是哈希链：每行带着上一行的 SHA-256，改动或删除中间任何一行都会断链。服务端另用实例密钥签名。
- 服务进程和 `ces` 管理命令往同一条链里写：每次追加都先在 `audit.log.lock` 上加文件锁，在锁里重读末行再接链。从很早的版本升级时，先重启服务，再用会写审计的管理命令。
- 哈希链证明不了“末尾没有被截掉”。需要的话，定期把最新一行的哈希记到别处。
- 不要直接替换 `audit_hmac_key`，否则旧的行会全部报签名不符。要换密钥，用 `ces audit rotate --new-key`：
  1. 在当前 `audit.log` 末尾用旧密钥写一行封口记录；
  2. 整份移到 `audit_archive/audit-NNNN.log`，旧密钥另存为 `audit-NNNN.key`（权限 600，复核旧段要用）；
  3. 新的 `audit.log` 第一行记下被封存的段名和它最后一行的哈希。
- 轮换时服务不用重启，下一行就写进新文件、用新密钥签名。`ces audit verify` 逐段用各自的密钥复核，并核对段与段首尾相接；归档段被删、被改或密钥文件丢了都会报出来。
