# compile-excel-server

**KMS / 知识库 / 工件分发平台**：OAuth2 设备授权流 + 按构建（device_build）的
工件清单与鉴权下载（xlsx / xml / tar.gz…，逐件 SHA256）+ 知识库关键词检索。

## 仓库边界（重要）

本仓库**只含平台代码**，可公开/私有托管（如 GitHub）：

| 内容 | 在哪里 |
|---|---|
| 平台代码、部署脚本、自包含测试 | **本仓库**（测试用合成数据，零内部资产） |
| 真实工件（晋升模板/框架子集/命令树 xml）、知识库手册、device_build 元数据 | 部署侧数据目录（`$CES_DATA_DIR`，`.gitignore` 排除） |
| 实例凭据（审计签名密钥等） | 部署时由 `deploy/provision.py` **生成**，不预置、不入库 |
| 用户 token | 运行时签发（内存态），绝不落仓库 |
| OAuth 客户端 | skill 仓（compile-excel-skills）的一部分 |

`tests/test_e2e.py::test_no_internal_assets_in_repo` 是防泄漏守卫：git 跟踪
内容一旦出现内部资产指纹（真实模板/契约 SHA、内部构建名）即测试失败。

## 部署（内网/2.90）

```bash
git clone <本仓库> && cd compile-excel-server
pip install -r requirements.txt
python3 deploy/provision.py --data /opt/ces/data      # 建骨架 + 生成实例凭据(600)
# 灌入真实资产：
#   /opt/ces/data/artifacts/  <- excel 模板、框架 tar、cmdtree xml…
#   /opt/ces/data/docs/       <- 知识库 markdown
#   /opt/ces/data/artifacts_meta.json <- device_build + 每工件 version/media_type/receipt
python3 server.py --data /opt/ces/data --port 8900    # 或 uvicorn
```

自测/冒烟（不需要任何内部资产）：`python3 deploy/provision.py --data <目录> --sample`

## 对接真实 OAuth

内置授权后端是 `local`（/activate 任意账号名放行，适合内网小规模与自测）。
对接真实 OAuth 提供方时替换 `/activate` + `/token` 的签发逻辑
（设备流对外协议不变，客户端零改动）；接入点集中在 `device_authorize` /
`activate_submit` / `token` 三个端点。

## 环境变量

| 变量 | 缺省 | 说明 |
|---|---|---|
| `CES_DATA_DIR` | `./data` | 数据目录（工件/手册/元数据/审计） |
| `CES_PORT` / `--port` | 8900 | 监听端口 |
| `CES_ACCESS_TTL` | 900 | access token 有效期（秒） |
| `CES_REFRESH_TTL` | 7d | refresh token 有效期（秒） |
| `CES_DEVICE_TTL` | 600 | 设备码有效期（秒） |
| `CES_POLL_INTERVAL` | 1 | 轮询间隔（秒） |

## 测试

```bash
python -m pytest tests/ -v     # 需 fastapi/uvicorn/pytest；SKILL_SCRIPTS_DIR 指向 skill 仓
```
