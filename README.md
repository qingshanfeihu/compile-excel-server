# compile-excel-server

**KMS / 知识库 / 工件分发平台**：OAuth2 设备授权流 + 按构建（device_build）的
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

## 仓库边界

| 内容 | 在哪里 |
|---|---|
| 平台代码、打包发布、自包含测试 | **本仓库**（测试用合成数据，零内部资产） |
| 真实工件（晋升模板/框架子集/命令树 xml）、知识库手册、device_build 元数据 | 部署侧数据目录（`--data`，安装器只建骨架） |
| 实例凭据（审计签名密钥） | 部署时由 provision 生成 |
| 用户 token | 运行时签发（内存态） |
| OAuth 客户端 | skill 仓（compile-excel-skills）的一部分 |

`tests/test_e2e.py::test_no_internal_assets_in_repo` 是防泄漏守卫：git 跟踪
内容一旦出现内部资产指纹（真实模板/契约 SHA、内部构建名）即测试失败。

## 数据目录布局（部署侧灌入）

```
<data>/artifacts/            # 工件：xml 命令树 / xlsx 模板 / tar.gz…
<data>/docs/                 # 知识库 markdown（可带子目录）
<data>/artifacts_meta.json   # device_build + 每工件 version/media_type/receipt（gen_meta 生成）
<data>/audit_hmac_key        # provision 生成的审计签名密钥
<data>/audit.log  server.log  server.pid  install.options.json
```

## 对接真实 OAuth

内置授权后端是 `local`（/activate 任意账号名放行，适合内网小规模与自测）。
对接真实 OAuth 提供方时替换 `/device_authorize` `/activate` `/token` 三端点的
签发逻辑（设备流对外协议不变，客户端零改动）。

## 环境变量

| 变量 | 缺省 | 说明 |
|---|---|---|
| `CES_DATA_DIR` | `--data` 参数 | 数据目录 |
| `CES_PORT` / `--port` | 8900 | 监听端口 |
| `CES_ACCESS_TTL` | 900 | access token 有效期（秒） |
| `CES_REFRESH_TTL` | 7d | refresh token 有效期（秒） |
| `CES_DEVICE_TTL` | 600 | 设备码有效期（秒） |
| `CES_CONFIG_ROOT` | 平台惯例目录 | 安装登记/向导草稿位置（测试用） |

## 测试

```bash
python -m pytest tests/ -v     # 需 fastapi/uvicorn/pytest；客户端脚本默认取同级 ../compile-excel-skills，
                               # 也可用 SKILL_SCRIPTS_DIR 指定；找不到时相关用例跳过
```
