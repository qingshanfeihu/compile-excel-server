# compile-excel-server

**身份 / 知识库 / 编译数据分发平台**：OAuth2 设备授权流（私有模拟后端，令牌只存哈希、可撤销、按 scope
逐路由校验）+ 令牌内省（给跳板机网关）+ 组织下发的客户端常量 + 按构建发布的编译数据包
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
              #   逐项说明+示例；每答一题存草稿，中断重跑自动从断点继续
ces           # 管理菜单（状态/启停/日志/服务注册/重配/卸载）
ces service install   # 注册 systemd(Linux)/launchd(macOS)，开机自启
ces users add alice   # 建账号；访问码只显示一次（或 --out 文件 写 0600 文件），交给本人
```

非交互（2.90/CI，向导产物复跑）：`ces setup --options-file <data>/install.options.json`

## ces 子命令

| 命令 | 作用 |
|---|---|
| （无参数） | 管理菜单 |
| `setup [...]` | 配置向导 / 非交互安装（同 deploy/setup.py 参数） |
| `serve --data D --port P` | 前台运行（服务管理器/调试用） |
| `status` / `start` / `stop` / `restart` / `log` | 进程管理（pidfile + healthz） |
| `service install\|remove\|print` | systemd/launchd 服务（print 只看 unit 内容） |
| `uninstall [--purge]` | 卸载（--purge 连数据目录一起删） |
| `users add <名> [--scopes "…"] [--out F]` | 建账号，生成访问码（库里只存哈希） |
| `users list` / `disable` / `enable` / `reset-code` / `scopes <名> "…"` | 账号管理；停用、重置访问码、改 scope 都会撤销该账号已签发的令牌 |
| `clients add <id> --scopes "…" [--out F]` / `list` / `remove` | 服务客户端：网关（`introspect`）、发布导入器（`bundles:publish`） |
| `tokens revoke --user <名>\|--client <id>` / `purge` | 撤销令牌、清理过期记录 |
| `config show\|set <键> <地址>\|unset <键>\|import-env <文件>` | 下发给客户端的门户/缺陷系统/网关地址 |
| `registry list\|show <build>\|import-dir <build> <kind> <目录>\|promote <build> <bundle_id>\|verify\|gc` | 数据包注册表：查看、手工导入一类数据、切通道、全量复核 blob、回收无引用 blob |

管理命令默认作用于安装登记里的数据目录，也可以加 `--data <目录>`。

## 仓库边界

| 内容 | 在哪里 |
|---|---|
| 平台代码、打包发布、自包含测试 | **本仓库**（测试用合成数据，零内部资产） |
| 真实工件（晋升模板/框架子集/命令树 xml）、知识库手册、device_build 元数据 | 部署侧数据目录（`--data`，安装器只建骨架） |
| 实例凭据（审计签名密钥） | 部署时由 provision 生成 |
| 账号、服务客户端、令牌 | 数据目录 `auth.db`（SQLite，访问码/secret 存 PBKDF2 哈希，令牌存 SHA-256） |
| OAuth 客户端 | skill 仓（compile-excel-skills）的一部分 |
| 跳板机网关 | 本仓库 `gateway/`（发布为独立的 `cexg-linux-x86_64.tar.gz`） |

`tests/test_e2e.py::test_no_internal_assets_in_repo` 是防泄漏守卫：git 跟踪
内容一旦出现内部资产指纹（真实模板/契约 SHA、内部构建名）即测试失败。

## 数据目录布局（部署侧灌入）

```
<data>/artifacts/            # 工件：xml 命令树 / xlsx 模板 / tar.gz…
<data>/docs/                 # 知识库 markdown（可带子目录）
<data>/artifacts_meta.json   # device_build + 每工件 version/media_type/receipt（gen_meta 生成）
<data>/audit_hmac_key        # provision 生成的审计签名密钥
<data>/auth.db               # 账号、服务客户端、令牌（只存哈希，0600）
<data>/client_config.json    # 下发给客户端的地址常量（ces config 管理）
<data>/registry/registry.db  # 数据包注册表（构建、包、条目、通道）
<data>/registry/blobs/sha256/<前2位>/<sha>   # 按内容寻址的只读 blob
<data>/audit.log  server.log  server.pid  install.options.json
```

## 身份与权限

授权页（`/activate`）由认证后端决定收哪些字段。现有后端 `private-mock`：管理员
`ces users add <名>` 建账号并拿到访问码，用户在授权页填用户名 + 访问码；同一用户名连续失败
5 次锁 15 分钟。企业身份以后作为新后端接入（`auth_backends.py` 的 `BACKENDS`），
设备流对外协议不变，客户端零改动。

令牌：access 默认 15 分钟，refresh 默认 7 天且每用一次就轮换；已轮换的 refresh 被再次出示时，
整族令牌一起撤销。`POST /revoke` 撤销自己的令牌。

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

- 新包进 `candidate`；服务端自检（blob 齐全、落盘内容复核、必备 kind 齐全）通过后才能切 `stable`。
- 客户端读 `GET /v1/builds/{b}/bundle`（默认 stable）再逐个 `GET /v1/blobs/{sha}`，按清单 SHA 校验。
- 旧版 `/v1/artifacts/*` 由该构建 stable 包里带 `legacy_name` 的条目派生；启动时 `artifacts/`
  目录会被登记成一个包（`legacy-import`），但不会覆盖导入器发布的 stable。下载发的是登记时的
  不可变 blob，运行中改 `artifacts/` 不影响已登记的内容，重启后才会重新登记。

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
- 命令树只发投影 JSON，不发原始 XML（原始 XML 带参数默认值，含凭据默认值）。
- `--dry-run` 只做解析与校验。内容没变时重跑是空操作，适合每天由 cron 跑一次。

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
| `env_prepare` | `jumphost:run` | 框架文件、conf、设备可达、设备自述构建与网关构建一致、规则与凭据字面量可用 |
| `case_submit` | `jumphost:run` | 冻结工作簿 → 上机前闸（zip/体积、Excel 契约、自毁命令、框架凭据字面量）→ 只读落位、sha 对账 → 起跑 |
| `case_status` / `case_results` | `jumphost:run` | 状态；结果来自框架结果库，早于投递时间的日志标 stale；输出经脱敏 |
| `probe_show` | `jumphost:run` | 单条 show/get，只读 |
| `init_device` | `jumphost:admin` | 串口重置，两步：`prepare` 给出计划与一次性确认码，`confirm` 带码执行；每步核对配置模式提示符 |

- 互斥：`<state>/bed.lock` 用 `flock`，锁随 pytest 进程组继承，进程结束内核自动释放；不写 pid、不删锁文件。
- 设备初始化的命令全部来自 `gateway.toml` 的 `init_device.commands`，代码里不写设备命令。
- 规则文件（`projections/domain_grammar.json`）从服务端该构建的 stable 包取并缓存；取不到且没有缓存就拒绝上机。
- 判据代码 `gateway/vendor/` 由 `tools/sync_gateway_vendor.py` 从 compile-excel-skills 的 `cex_core`
  与 InfoTest 的凭据字面量提取器同步，`--check` 查漂移，不在 vendor 里手改。
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
| `CES_MAX_BLOB_BYTES` | 2 GiB | 单个 blob 上传上限 |
| `CES_CONFIG_ROOT` | 平台惯例目录 | 安装登记/向导草稿位置（测试用） |

## 测试

```bash
python -m pytest tests/ -v     # 需 fastapi/uvicorn/pytest；客户端脚本默认取同级 ../compile-excel-skills，
                               # 也可用 SKILL_SCRIPTS_DIR 指定；找不到时相关用例跳过
```
