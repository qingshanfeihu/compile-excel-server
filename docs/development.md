# 开发与发版

本篇写给改代码、跑测试、发新版本的人。

## 源码安装

| 场景 | 做法 |
|---|---|
| macOS / Linux 开发 | `git clone` 后在代码目录运行 `./install.sh --from-source`：建独立的 Python 虚拟环境（`~/.local/share/compile-excel-server/venv`），`ces` 命令指向代码目录，改了代码立即生效 |
| 没有安装包的平台（例如 Linux arm64） | 同上 |
| Windows | 暂时没有安装包。装 Python 3.11 以上，`pip install -r requirements.txt`，然后用 `python ces_main.py` 代替 `ces`，例如 `python ces_main.py setup` |

`ces generate`（服务端生成链）每一步都要起 Python 子进程，只能在源码安装里用，依赖另见 `requirements-generators.txt`。

## 仓库边界

| 内容 | 在哪里 |
|---|---|
| 平台代码、打包脚本、用合成数据写的测试 | 本仓库 |
| 真实工件、知识库手册、构建元数据 | 部署侧的数据目录（`--data`），安装器只建空骨架 |
| 实例凭据（审计签名密钥、证书私钥） | 部署时生成，只在数据目录里 |
| 账号、服务客户端、令牌 | 数据目录的 `auth.db` |
| 编译助手（OAuth 客户端、`cex_*` 工具） | compile-excel-skills 仓库 |
| 跳板机网关 | 本仓库 `gateway/`，单独发布为 `cexg-linux-x86_64.tar.gz` |

## 代码地图

| 文件 | 作用 |
|---|---|
| `ces_main.py` | `ces` 命令的全部子命令 |
| `ces_menu.py` | 管理菜单：只收集参数，执行时调用 `ces_main.dispatch`，与子命令同一套代码 |
| `ces_version.py` | 版本号（唯一定义处） |
| `server.py` | 服务端接口（FastAPI） |
| `auth_store.py` / `auth_backends.py` | 账号、客户端、令牌；登录方式 |
| `registry.py` | 编译数据的构建、包、通道 |
| `client_config.py` | 下发给客户端的地址 |
| `deploy/setup.py` | 配置向导与非交互安装 |
| `deploy/certs.py` | 内置 CA 与证书签发 |
| `deploy/tls_policy.py` | 监听与证书规则（服务端和网关共用） |
| `deploy/audit_log.py` | 审计日志的追加、复核与轮换 |
| `gateway/` | 跳板机网关 |
| `tools/` | 批量发布工具、判据代码同步 |
| `generators/` | 服务端生成链 |

## 测试

```bash
python -m pytest tests/ -v
```

- 需要 fastapi、uvicorn、httpx、pytest、cryptography（见 `requirements.txt`）。
- 客户端相关的用例默认去同级目录 `../compile-excel-skills` 找客户端脚本，也可以用 `SKILL_SCRIPTS_DIR` 指定；找不到时这些用例跳过。
- 网关的运行类用例要用 GNU `timeout` 命令；macOS 上没有时这几个用例会失败，可以装 coreutils（`brew install coreutils` 后把 `gtimeout` 链接成 `timeout`）。
- 网关测试用假的测试框架目录（真 pytest 跑假的 `test_xlsx`、假结果库）和假的串口控制台；真跳板机和设备上的验收另外做。

## 同步判据代码

网关的判据代码 `gateway/vendor/` 由 `tools/sync_gateway_vendor.py` 从 compile-excel-skills 的 `cex_core` 和 InfoTest 的凭据字面量提取器同步而来：

- 只取 skills 仓库里已提交的内容（默认 HEAD，经 `git archive`）；工作区有未提交改动时拒绝，`--allow-dirty` 也只取已提交的内容。
- 写下 `gateway/vendor/cex_core/.vendor_stamp.json`（提交与日期），永远不带 `cex_core/engine/_identities.json`。
- `--check` 查漂移。不要在 vendor 里手改。
- `gateway/vendor/cex_core/` **不入库**：它带着真实模板和契约的身份，本仓库坚持不放内部资产。测试对仓库只读：网关测试用手动生成的这份（没生成过就不收集），生成链测试用 skills 仓库 `cex_core` 的临时副本；与 skills 仓库（或 `CEX_SKILLS_ROOT`）不一致时由 `tests/gateway/test_vendor_readonly.py` 用 `--check` 报出来。
- 本地打包前、第一次跑网关测试前，以及 skills 仓库的 `cex_core` 改过之后，手动运行：

```bash
python3 tools/sync_gateway_vendor.py --only cex_core --skills-root <skills 仓库的检出>
```

## 发版

1. 改 `ces_version.py` 的 `__version__`，同时改 `gateway/service.py` 里 `SERVER_INFO` 的版本号（`tests/test_onboarding.py` 会检查两处一致）。
2. 提交后打 tag：`git tag v<版本号> && git push origin v<版本号>`。
3. `.github/workflows/release.yml` 自动执行：
   - 先检查 tag 与 `ces_version.py` 一致、网关版本号已同步，不一致就停止；
   - 在 macOS（Apple 芯片与 Intel）上用 PyInstaller 打包 `compile-excel-server-<平台>.tar.gz`；
   - Linux 包在 Ubuntu 20.04 容器里打（打包机的 glibc 就是包能运行的最低版本：在 22.04 上打的包，到 20.04 的跳板机上会报 `GLIBC_2.35 not found`）。另外检出 skills 仓库、同步判据代码，打包网关 `cexg-linux-x86_64.tar.gz`。skills 仓库公开时用工作流自带的令牌；转为私有后要配只读令牌（仓库机密 `CEX_SKILLS_READ_TOKEN`）；
   - 全部平台到齐后统一计算 `SHA256SUMS`，和安装包一起发布。
4. 推送代码不会发布新版本，只有推送 `v*` tag 才会。
5. 想先拿到安装包试一试（例如拷到跳板机上验收）：在 GitHub 的 Actions 页面手动运行 `release` 工作流（或 `gh workflow run release.yml`），它只打包、算 `SHA256SUMS`，结果在这次运行的 `packages` 构建产物里，不发版。
