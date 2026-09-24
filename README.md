# compile-excel-server

**身份 / 知识库 / 编译数据分发平台**：OAuth2 设备授权流（私有模拟后端，令牌只存哈希、可撤销、按 scope
逐路由校验）+ 令牌内省（给跳板机网关）+ 组织下发的客户端常量 + 按构建（device_build）的
工件清单与鉴权下载（xlsx / xml / tar.gz…，逐件 SHA256）+ 知识库关键词检索。
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

管理命令默认作用于安装登记里的数据目录，也可以加 `--data <目录>`。

## 仓库边界

| 内容 | 在哪里 |
|---|---|
| 平台代码、打包发布、自包含测试 | **本仓库**（测试用合成数据，零内部资产） |
| 真实工件（晋升模板/框架子集/命令树 xml）、知识库手册、device_build 元数据 | 部署侧数据目录（`--data`，安装器只建骨架） |
| 实例凭据（审计签名密钥） | 部署时由 provision 生成 |
| 账号、服务客户端、令牌 | 数据目录 `auth.db`（SQLite，访问码/secret 存 PBKDF2 哈希，令牌存 SHA-256） |
| OAuth 客户端 | skill 仓（compile-excel-skills）的一部分 |

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

## 环境变量

| 变量 | 缺省 | 说明 |
|---|---|---|
| `CES_DATA_DIR` | `--data` 参数 | 数据目录 |
| `CES_PORT` / `--port` | 8900 | 监听端口 |
| `CES_ACCESS_TTL` | 900 | access token 有效期（秒） |
| `CES_REFRESH_TTL` | 7d | refresh token 有效期（秒） |
| `CES_DEVICE_TTL` | 600 | 设备码有效期（秒） |
| `CES_AUTH_BACKEND` | `private-mock` | 认证后端 |
| `CES_CONFIG_ROOT` | 平台惯例目录 | 安装登记/向导草稿位置（测试用） |

## 测试

```bash
python -m pytest tests/ -v     # 需 fastapi/uvicorn/pytest；客户端脚本默认取同级 ../compile-excel-skills，
                               # 也可用 SKILL_SCRIPTS_DIR 指定；找不到时相关用例跳过
```
