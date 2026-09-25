#!/usr/bin/env python3
"""compile-excel-server：身份、知识检索与编译数据分发。

本仓库**只含平台代码**，不含任何内部资产：
- 工件（xlsx/xml/tar.gz…）、知识库手册、device_build 元数据全部从数据目录加载
  （$CES_DATA_DIR，缺省 ./data；由部署侧灌入，见 deploy/provision.py）；
- 账号与密钥不预置：审计签名密钥在部署时由 provision 生成；用户与服务客户端由
  `ces users add` / `ces clients add` 创建，库里只存哈希；
- 认证后端可插拔（auth_backends.py）。现有 private-mock：用户名 + 管理员发放的访问码。

接口：
  POST /device_authorize           设备授权发起（RFC 8628）
  GET|POST /activate               授权页（按认证后端收字段）
  POST /token                      设备流 / refresh（轮换）/ client_credentials
  POST /revoke                     撤销令牌（RFC 7009）
  POST /v1/introspect              令牌内省（RFC 7662；服务客户端 Basic 认证，需 introspect）
  GET  /v1/whoami                  当前令牌的主体与 scope
  GET  /v1/config/client           组织下发的客户端常量（config:read）
  GET  /v1/builds                  构建列表与各通道指针（bundles:read）
  GET  /v1/builds/{b}/bundle       数据包清单（?channel=stable|candidate 或 ?bundle_id=）
  GET  /v1/blobs/{sha}             按内容寻址下载（bundles:read）
  PUT  /v1/blobs/{sha}             上传 blob，服务端重算哈希（bundles:publish）
  POST /v1/bundles                 登记数据包并进 candidate（bundles:publish）
  POST /v1/builds/{b}/channels/{c} 切通道；自检没过的包进不了 stable（bundles:publish）
  GET  /v1/artifacts/manifest      旧版工件清单：由该构建 stable 包派生（artifacts:read）
  GET  /v1/artifacts/{name}        旧版工件下载：发不可变 blob（artifacts:read）
  POST /v1/docs/query              知识库关键词检索（docs:query）
  GET  /healthz                    探活

跑法：python3 server.py [--port 8900] [--data <数据目录>]
依赖：fastapi + uvicorn。
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

import auth_backends
import client_config
from gateway.audit_chain import AuditChain
from auth_store import SCOPES, AuthStore
from registry import CHANNELS, Registry, RegistryError, valid_build, valid_sha

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"


def _resolve_data_dir_from_argv() -> str:
    """提前解析 --data（argv 扫描）：模块初始化就要读数据目录，
    不能等 main()；环境变量 CES_DATA_DIR 优先级更高。"""
    import sys as _sys

    if os.environ.get("CES_DATA_DIR"):
        return ""
    argv = _sys.argv[1:]
    for index, arg in enumerate(argv):
        if arg == "--data" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--data="):
            return arg.split("=", 1)[1]
    return ""

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
ACCESS_TTL = int(os.environ.get("CES_ACCESS_TTL", "900"))
REFRESH_TTL = int(os.environ.get("CES_REFRESH_TTL", str(7 * 24 * 3600)))
DEVICE_TTL = int(os.environ.get("CES_DEVICE_TTL", "600"))
POLL_INTERVAL = int(os.environ.get("CES_POLL_INTERVAL", "1"))
MAX_PENDING_FLOWS = 1000
DEFAULT_REQUEST_SCOPE = "artifacts:read docs:query"
MAX_BLOB_BYTES = int(os.environ.get("CES_MAX_BLOB_BYTES", str(2 << 30)))
MAX_MANIFEST_BYTES = 16 << 20

MANIFEST_SCHEMA = "ist.excel.artifact-manifest"
RECEIPT_SCHEMA = "ist.excel.promotion-receipt"

app = FastAPI(title="compile-excel-server")


# ── 数据目录（部署侧灌入；仓库内 .gitignore 排除）───────────────────────
def _load_meta(meta_path: Path) -> dict[str, Any]:
    """工件元数据：device_build + 每工件版本/media_type/receipt（部署配置）。"""
    if not meta_path.is_file():
        raise RuntimeError(
            f"数据目录未初始化：{meta_path} 不存在。"
            "先运行 deploy/provision.py（或部署侧灌入数据），见 README。")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or "device_build" not in meta:
        raise RuntimeError(f"{meta_path} 结构非法：需要 device_build 与 artifacts")
    return meta


def _init_data(data_dir: Path) -> None:
    """按数据目录装载全部状态；模块导入时调用一次，`--data` 覆盖时再调用一次。"""
    global DATA_DIR, ARTIFACTS_DIR, DOCS_DIR, META_PATH, AUDIT_PATH, AUDIT_KEY_PATH
    global META, DEVICE_BUILD, ARTIFACT_META, DOCS
    global AUTH_STORE, AUTH_BACKEND, REGISTRY, AUDIT
    DATA_DIR = Path(data_dir)
    ARTIFACTS_DIR = DATA_DIR / "artifacts"
    DOCS_DIR = DATA_DIR / "docs"
    META_PATH = DATA_DIR / "artifacts_meta.json"
    AUDIT_PATH = DATA_DIR / "audit.log"
    AUDIT_KEY_PATH = DATA_DIR / "audit_hmac_key"
    AUDIT = AuditChain(AUDIT_PATH, key=_audit_key)
    META = _load_meta(META_PATH)
    DEVICE_BUILD = str(META["device_build"])
    ARTIFACT_META = dict(META.get("artifacts") or {})
    DOCS = _load_docs()
    REGISTRY = Registry(DATA_DIR / "registry")
    # 旧 artifacts 目录登记成该构建的包；之后旧接口只从包里读，下载发的是不可变 blob
    REGISTRY.import_legacy_dir(DEVICE_BUILD, ARTIFACTS_DIR, ARTIFACT_META)
    AUTH_STORE = AuthStore(DATA_DIR / "auth.db")
    AUTH_BACKEND = auth_backends.make_backend(
        os.environ.get("CES_AUTH_BACKEND", ""), AUTH_STORE)


def _audit_key() -> bytes | None:
    """部署时生成的审计签名密钥（provision 产出，600）；缺省则审计不带 hmac。"""
    try:
        return bytes.fromhex(AUDIT_KEY_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


# ── 设备流状态（短命，进程内存；令牌本身在 auth.db）──────────────────────
_device_flows: dict[str, dict[str, Any]] = {}


def _audit(event: str, **fields: Any) -> None:
    """JSONL 审计，哈希链（audit_chain.py）；有实例密钥时附 hmac。
    调用方保证不含任何 token、访问码、client secret。"""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update(fields)
    AUDIT.append(record)


async def _parse_payload(request: Request) -> dict[str, str]:
    """兼容 form-encoded 与 JSON 的手动解析（不引入 python-multipart）。"""
    raw = await request.body()
    if not raw:
        return {}
    text = raw.decode("utf-8", "replace")
    if "application/json" in (request.headers.get("content-type") or ""):
        try:
            data = json.loads(text)
            return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {key: values[-1] for key, values in parse_qs(text).items()}


# ── 鉴权 ──────────────────────────────────────────────────────────────
def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        return ""
    return header[7:].strip()


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        {"detail": "missing, invalid or expired bearer token"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def _forbidden(scope: str) -> JSONResponse:
    return JSONResponse(
        {"detail": f"token lacks required scope {scope!r}"},
        status_code=403,
        headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'},
    )


def _require(request: Request, scope: str | None) -> dict[str, Any] | JSONResponse:
    """校验 Bearer 与 scope。通过时返回令牌元数据，否则返回 401/403 响应。"""
    record = AUTH_STORE.lookup_access(_bearer_token(request))
    if record is None:
        return _unauthorized()
    if scope is not None and scope not in record["scope"]:
        return _forbidden(scope)
    return record


def _client_credentials(request: Request, payload: dict[str, str]) -> tuple[str, str]:
    """服务客户端凭据：优先 HTTP Basic，其次表单 client_id/client_secret。"""
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        except (ValueError, UnicodeError):
            return "", ""
        client_id, _, secret = decoded.partition(":")
        return unquote(client_id), unquote(secret)
    return payload.get("client_id") or "", payload.get("client_secret") or ""


def _requested_scopes(raw: str) -> list[str] | None:
    items = raw.split()
    if any(item not in SCOPES for item in items):
        return None
    return sorted(set(items))


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    payload = {"ok": True, "service": "compile-excel-server",
               "device_build": DEVICE_BUILD, "auth_backend": AUTH_BACKEND.name}
    if META.get("kms_addr"):
        payload["kms_addr"] = str(META["kms_addr"])
    return payload


def _prune_flows() -> None:
    now = time.time()
    for code in [c for c, f in _device_flows.items() if f["exp"] < now]:
        _device_flows.pop(code, None)


@app.post("/device_authorize")
async def device_authorize(request: Request) -> JSONResponse:
    payload = await _parse_payload(request)
    client_id = (payload.get("client_id") or "compile-excel-skill")[:64]
    scopes = _requested_scopes(payload.get("scope") or DEFAULT_REQUEST_SCOPE)
    if not scopes:
        return JSONResponse({"error": "invalid_scope",
                             "error_description": f"known scopes: {' '.join(SCOPES)}"},
                            status_code=400)
    _prune_flows()
    if len(_device_flows) >= MAX_PENDING_FLOWS:
        return JSONResponse({"error": "slow_down"}, status_code=429)
    device_code = secrets.token_urlsafe(32)
    user_code = "".join(secrets.choice("BCDFGHJKLMNPQRSTVWXZ") for _ in range(8))
    host = request.headers.get("host") or "127.0.0.1"
    verification_uri = f"{request.url.scheme}://{host}/activate"
    _device_flows[device_code] = {
        "client_id": client_id,
        "scope": scopes,
        "user_code": user_code,
        "status": "pending",
        "username": "",
        "granted": [],
        "exp": time.time() + DEVICE_TTL,
    }
    return JSONResponse({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": f"{verification_uri}?user_code={user_code}",
        "expires_in": DEVICE_TTL,
        "interval": POLL_INTERVAL,
    })


_PAGE_STYLE = ("body{font-family:sans-serif;max-width:32em;margin:4em auto;line-height:1.6}"
               "code{background:#f4f4f4;padding:.2em .5em;font-size:1.2em}"
               "label{display:block;margin:.6em 0}")


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f'<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        f"<title>{html.escape(title)}</title><style>{_PAGE_STYLE}</style></head>"
        f"<body>{body}</body></html>", status_code=status,
        headers={"X-Frame-Options": "DENY", "Cache-Control": "no-store"})


def _find_flow(user_code: str) -> dict[str, Any] | None:
    now = time.time()
    return next((f for f in _device_flows.values()
                 if f["user_code"] == user_code and f["exp"] > now), None)


@app.get("/activate", response_class=HTMLResponse)
async def activate_page(user_code: str = "") -> HTMLResponse:
    flow = _find_flow(user_code.strip().upper()) if user_code else None
    fields = "".join(
        f'<label>{html.escape(field.label)}：<input name="{html.escape(field.name)}" '
        f'type="{html.escape(field.input_type)}" required autocomplete="off"></label>'
        for field in AUTH_BACKEND.fields)
    request_line = ""
    if flow is not None:
        request_line = (f"<p>客户端 <code>{html.escape(flow['client_id'])}</code> 申请："
                        f"<code>{html.escape(' '.join(flow['scope']))}</code></p>")
    body = (
        "<h2>设备授权请求</h2>"
        f"<p>确认设备码：<code>{html.escape(user_code or '________')}</code></p>"
        f"{request_line}"
        '<form method="post" action="/activate">'
        f'<label>设备码：<input name="user_code" required value="{html.escape(user_code)}"></label>'
        f"{fields}<button type=\"submit\">授权</button></form>")
    return _page("compile-excel-server 设备授权", body)


@app.post("/activate")
async def activate_submit(request: Request) -> HTMLResponse:
    payload = await _parse_payload(request)
    user_code = (payload.get("user_code") or "").strip().upper()
    flow = _find_flow(user_code)
    if flow is None:
        return _page("授权失败", "<h2>设备码无效或已过期</h2>", 400)
    if flow["status"] != "pending":
        return _page("授权失败", "<h2>这个设备码已经处理过</h2>", 400)
    principal = AUTH_BACKEND.authenticate(payload)
    attempted = (payload.get("username") or "").strip()[:64]
    if principal is None:
        _audit("activate_rejected", username=attempted, client_id=flow["client_id"])
        return _page("授权失败", "<h2>用户名或访问码不对，或账号已停用/暂时锁定</h2>", 403)
    granted = sorted(set(flow["scope"]) & set(principal.scopes))
    if not granted:
        flow["status"] = "denied"
        _audit("activate_denied_scope", username=principal.username,
               client_id=flow["client_id"], requested=flow["scope"])
        return _page("授权失败", "<h2>账号没有客户端申请的任何权限</h2>", 403)
    flow["status"] = "approved"
    flow["username"] = principal.username
    flow["granted"] = granted
    _audit("device_authorized", username=principal.username, client_id=flow["client_id"],
           scope=granted)
    return _page("已授权", f"<h2>已授权（{html.escape(principal.username)}）</h2>"
                           "<p>回到终端继续；登录完成后可关闭本页。</p>")


def _token_error(error: str, description: str = "", status: int = 400) -> JSONResponse:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def _token_ok(issued: dict[str, Any]) -> JSONResponse:
    return JSONResponse(issued, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.post("/token")
async def token(request: Request) -> JSONResponse:
    payload = await _parse_payload(request)
    grant_type = payload.get("grant_type") or ""

    if grant_type == DEVICE_GRANT:
        device_code = payload.get("device_code") or ""
        flow = _device_flows.get(device_code)
        if flow is None or flow["exp"] < time.time():
            _device_flows.pop(device_code, None)
            return _token_error("expired_token", "device code unknown or expired")
        if flow["status"] == "pending":
            return _token_error("authorization_pending")
        _device_flows.pop(device_code, None)
        if flow["status"] == "denied":
            return _token_error("access_denied")
        issued = AUTH_STORE.issue(
            subject=flow["username"], subject_kind="user", client_id=flow["client_id"],
            scope=flow["granted"], access_ttl=ACCESS_TTL, refresh_ttl=REFRESH_TTL)
        _audit("token_issued", username=flow["username"], client_id=flow["client_id"],
               scope=flow["granted"], grant="device_code", access_ttl=ACCESS_TTL)
        return _token_ok(issued)

    if grant_type == "refresh_token":
        state, record = AUTH_STORE.rotate_refresh(payload.get("refresh_token") or "")
        if state == "reused":
            _audit("refresh_reuse_family_revoked", subject=record["subject"],
                   client_id=record["client_id"])
            return _token_error("invalid_grant", "refresh token already used")
        if state != "ok":
            _audit("token_refresh_rejected")
            return _token_error("invalid_grant", "refresh token unknown, revoked or expired")
        issued = AUTH_STORE.issue(
            subject=record["subject"], subject_kind=record["subject_kind"],
            client_id=record["client_id"], scope=record["scope"].split(),
            access_ttl=ACCESS_TTL, refresh_ttl=REFRESH_TTL, family=record["family"])
        _audit("token_issued", username=record["subject"], client_id=record["client_id"],
               scope=record["scope"].split(), grant="refresh_token", access_ttl=ACCESS_TTL)
        return _token_ok(issued)

    if grant_type == "client_credentials":
        client_id, secret = _client_credentials(request, payload)
        client = AUTH_STORE.verify_client(client_id, secret)
        if client is None:
            _audit("client_auth_failed", client_id=client_id[:64])
            return _token_error("invalid_client", status=401)
        requested = _requested_scopes(payload.get("scope") or " ".join(client["scopes"]))
        if requested is None:
            return _token_error("invalid_scope")
        granted = sorted(set(requested) & set(client["scopes"]))
        if not granted:
            return _token_error("invalid_scope", "client holds none of the requested scopes")
        issued = AUTH_STORE.issue(
            subject=client_id, subject_kind="client", client_id=client_id,
            scope=granted, access_ttl=ACCESS_TTL, refresh_ttl=None)
        _audit("token_issued", client_id=client_id, scope=granted,
               grant="client_credentials", access_ttl=ACCESS_TTL)
        return _token_ok(issued)

    return _token_error("unsupported_grant_type")


@app.post("/revoke")
async def revoke(request: Request) -> JSONResponse:
    """RFC 7009：持有令牌即可撤销它；未知令牌同样返回 200。"""
    payload = await _parse_payload(request)
    if AUTH_STORE.revoke_token(payload.get("token") or ""):
        _audit("token_revoked", by="holder")
    return JSONResponse({}, headers={"Cache-Control": "no-store"})


@app.post("/v1/introspect")
async def introspect(request: Request) -> JSONResponse:
    """RFC 7662：只给带 introspect 权限的服务客户端（网关）用。"""
    payload = await _parse_payload(request)
    client_id, secret = _client_credentials(request, payload)
    client = AUTH_STORE.verify_client(client_id, secret)
    if client is None:
        _audit("client_auth_failed", client_id=client_id[:64], endpoint="introspect")
        return JSONResponse({"error": "invalid_client"}, status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="introspect"'})
    if "introspect" not in client["scopes"]:
        return JSONResponse({"error": "insufficient_scope"}, status_code=403)
    record = AUTH_STORE.lookup_access(payload.get("token") or "")
    _audit("introspect", client_id=client_id, active=record is not None,
           subject=record["subject"] if record else "")
    if record is None:
        return JSONResponse({"active": False}, headers={"Cache-Control": "no-store"})
    body = {
        "active": True,
        "scope": " ".join(record["scope"]),
        "client_id": record["client_id"],
        "sub": record["subject"],
        "token_type": "Bearer",
        "exp": int(record["expires_at"]),
        "iat": int(record["issued_at"]),
    }
    if record["subject_kind"] == "user":
        body["username"] = record["subject"]
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@app.get("/v1/whoami")
async def whoami(request: Request) -> JSONResponse:
    record = _require(request, None)
    if isinstance(record, JSONResponse):
        return record
    return JSONResponse({
        "sub": record["subject"], "kind": record["subject_kind"],
        "client_id": record["client_id"], "scope": " ".join(record["scope"]),
        "exp": int(record["expires_at"]),
    })


@app.get("/v1/config/client")
async def config_client(request: Request) -> JSONResponse:
    record = _require(request, "config:read")
    if isinstance(record, JSONResponse):
        return record
    try:
        document = client_config.document(DATA_DIR)
    except client_config.ConfigError as exc:
        _audit("client_config_invalid", reason=str(exc))
        return JSONResponse({"detail": "client config is invalid on the server; "
                                       "an administrator must fix it (ces config show)"},
                            status_code=503)
    _audit("client_config_served", subject=record["subject"])
    return JSONResponse(document)


# ── 数据包注册表 ────────────────────────────────────────────────────────
@app.get("/v1/builds")
async def list_builds(request: Request) -> JSONResponse:
    record = _require(request, "bundles:read")
    if isinstance(record, JSONResponse):
        return record
    return JSONResponse({"builds": REGISTRY.list_builds()})


@app.get("/v1/builds/{build}/bundle")
async def get_bundle(build: str, request: Request, channel: str = "stable",
                     bundle_id: str = "") -> JSONResponse:
    record = _require(request, "bundles:read")
    if isinstance(record, JSONResponse):
        return record
    if not valid_build(build):
        return JSONResponse({"detail": "invalid build"}, status_code=400)
    if bundle_id:
        if not valid_sha(bundle_id):
            return JSONResponse({"detail": "invalid bundle_id"}, status_code=400)
        target = bundle_id
    else:
        if channel not in CHANNELS:
            return JSONResponse({"detail": f"channel must be one of {CHANNELS}"},
                                status_code=400)
        target = REGISTRY.channel_bundle(build, channel)
    manifest = REGISTRY.bundle_manifest(target) if target else None
    if manifest is None or manifest["build"] != build:
        return JSONResponse({"detail": f"no bundle for build {build!r}"}, status_code=404)
    _audit("bundle_served", subject=record["subject"], build=build,
           bundle_id=manifest["bundle_id"], channel="" if bundle_id else channel)
    return JSONResponse(manifest)


@app.get("/v1/blobs/{sha}")
async def get_blob(sha: str, request: Request):
    record = _require(request, "bundles:read")
    if isinstance(record, JSONResponse):
        return record
    if not valid_sha(sha):
        return JSONResponse({"detail": "invalid sha256"}, status_code=400)
    info = REGISTRY.blob_info(sha)
    if info is None:
        return JSONResponse({"detail": "unknown blob"}, status_code=404)
    _audit("blob_download", subject=record["subject"], sha256=sha, bytes=info["bytes"])
    return FileResponse(REGISTRY.blob_path(sha), media_type=info["media_type"],
                        headers={"X-Content-SHA256": sha})


@app.put("/v1/blobs/{sha}")
async def put_blob(sha: str, request: Request) -> JSONResponse:
    record = _require(request, "bundles:publish")
    if isinstance(record, JSONResponse):
        return record
    if not valid_sha(sha):
        return JSONResponse({"detail": "invalid sha256"}, status_code=400)
    if REGISTRY.blob_info(sha) is not None:
        # 已有同一内容也要读完请求体再回：客户端还在发送时就回并关连接，大 blob 会断管（EPIPE）
        drained = 0
        async for chunk in request.stream():
            drained += len(chunk)
            if drained > MAX_BLOB_BYTES:
                break
        return JSONResponse({"sha256": sha, "created": False})
    writer = REGISTRY.begin_blob(request.headers.get("content-type") or "",
                                 MAX_BLOB_BYTES)
    try:
        async for chunk in request.stream():
            writer.write(chunk)
        stored = writer.finish(sha)
    except RegistryError as exc:
        writer.abort()
        _audit("blob_rejected", subject=record["subject"], sha256=sha, reason=str(exc))
        return JSONResponse({"detail": str(exc)}, status_code=422)
    except BaseException:
        writer.abort()
        raise
    _audit("blob_uploaded", subject=record["subject"], sha256=sha, bytes=stored["bytes"])
    return JSONResponse({**stored, "created": True}, status_code=201)


@app.post("/v1/bundles")
async def post_bundle(request: Request) -> JSONResponse:
    record = _require(request, "bundles:publish")
    if isinstance(record, JSONResponse):
        return record
    raw = await request.body()
    if len(raw) > MAX_MANIFEST_BYTES:
        return JSONResponse({"detail": "manifest too large"}, status_code=413)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return JSONResponse({"detail": "body must be JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"detail": "body must be a JSON object"}, status_code=400)
    source = body.get("source") or {}
    required = body.get("required_kinds")
    if not isinstance(source, dict) or (required is not None and not isinstance(required, list)):
        return JSONResponse({"detail": "source must be an object, required_kinds a list"},
                            status_code=400)
    try:
        result = REGISTRY.submit_bundle(
            str(body.get("build") or ""), body.get("entries"), publisher=record["subject"],
            source=source, required_kinds=required)
    except RegistryError as exc:
        _audit("bundle_rejected", subject=record["subject"], reason=str(exc)[:300])
        return JSONResponse({"detail": str(exc)}, status_code=422)
    _audit("bundle_submitted", subject=record["subject"], build=body.get("build"),
           bundle_id=result["bundle_id"], created=result["created"],
           checks_ok=result["checks"]["ok"])
    return JSONResponse(result, status_code=201 if result["created"] else 200)


@app.post("/v1/builds/{build}/channels/{channel}")
async def set_channel(build: str, channel: str, request: Request) -> JSONResponse:
    record = _require(request, "bundles:publish")
    if isinstance(record, JSONResponse):
        return record
    payload = await _parse_payload(request)
    bundle_id = payload.get("bundle_id") or ""
    try:
        REGISTRY.set_channel(build, channel, bundle_id, record["subject"])
    except RegistryError as exc:
        _audit("channel_rejected", subject=record["subject"], build=build, channel=channel,
               bundle_id=bundle_id, reason=str(exc))
        return JSONResponse({"detail": str(exc)}, status_code=422)
    _audit("channel_set", subject=record["subject"], build=build, channel=channel,
           bundle_id=bundle_id)
    return JSONResponse({"build": build, "channel": channel, "bundle_id": bundle_id})


# ── 旧版工件接口（由 stable 包派生）───────────────────────────────────────
def _legacy_entries(build: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    bundle_id = REGISTRY.channel_bundle(build, "stable")
    manifest = REGISTRY.bundle_manifest(bundle_id) if bundle_id else None
    if manifest is None:
        return None, []
    return manifest, [e for e in manifest["entries"] if e["meta"].get("legacy_name")]


@app.get("/v1/artifacts/manifest")
async def artifacts_manifest(request: Request, device_build: str = "") -> JSONResponse:
    record = _require(request, "artifacts:read")
    if isinstance(record, JSONResponse):
        _audit("manifest_rejected", status=record.status_code)
        return record
    build = device_build or DEVICE_BUILD
    manifest, entries = _legacy_entries(build) if valid_build(build) else (None, [])
    if manifest is None:
        return JSONResponse(
            {"detail": f"unknown device_build {build!r}; known: {DEVICE_BUILD!r}"},
            status_code=404)
    legacy = {
        "schema": MANIFEST_SCHEMA,
        "device_build": build,
        "generated_at": manifest["created_at"],
        "bundle_id": manifest["bundle_id"],
        "artifacts": [{
            "name": e["meta"]["legacy_name"],
            "version": str(e["meta"].get("version") or ""),
            "sha256": e["sha256"],
            "bytes": e["bytes"],
            "media_type": e["media_type"],
            "receipt": e["meta"].get("receipt") or {},
        } for e in entries],
    }
    if META.get("kms_addr"):
        legacy["kms_addr"] = str(META["kms_addr"])
    _audit("manifest_served", username=record["subject"], device_build=build,
           bundle_id=manifest["bundle_id"])
    return JSONResponse(legacy)


@app.get("/v1/artifacts/{name}")
async def artifact_download(name: str, request: Request):
    record = _require(request, "artifacts:read")
    if isinstance(record, JSONResponse):
        _audit("artifact_rejected", name=name, status=record.status_code)
        return record
    _, entries = _legacy_entries(DEVICE_BUILD) if valid_build(DEVICE_BUILD) else (None, [])
    entry = next((e for e in entries if e["meta"]["legacy_name"] == name), None)
    if entry is None or REGISTRY.blob_info(entry["sha256"]) is None:
        return JSONResponse({"detail": f"unknown artifact {name!r}"}, status_code=404)
    _audit(
        "artifact_download", username=record["subject"], name=name,
        sha256=entry["sha256"], bytes=entry["bytes"],
        version=str(entry["meta"].get("version") or ""))
    return FileResponse(REGISTRY.blob_path(entry["sha256"]), media_type=entry["media_type"],
                        filename=name)


def _load_docs() -> list[dict[str, Any]]:
    """递归加载 docs/ 下全部 *.md（setup 按子目录拷贝手册）。

    doc 标识用相对 docs/ 的 posix 路径；软链文件跳过，解析后不在 docs/ 之内的一律跳过。
    """
    docs = []
    if not DOCS_DIR.is_dir():
        return docs
    root = DOCS_DIR.resolve()
    for path in sorted(DOCS_DIR.rglob("*.md")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        body = path.read_text(encoding="utf-8")
        docs.append({
            "doc": rel,
            "title": body.splitlines()[0].lstrip("# ").strip() if body else path.name,
            "body": body,
        })
    return docs


_TERM_RE = re.compile(r"[A-Za-z0-9_]+|[一-鿿]")


def _query_docs(query: str, limit: int) -> list[dict[str, Any]]:
    terms = _TERM_RE.findall(query.lower())
    scored = []
    for doc in DOCS:
        body_l = doc["body"].lower()
        score = sum(body_l.count(term) for term in terms)
        if score <= 0:
            continue
        pos = -1
        for term in terms:
            pos = body_l.find(term)
            if pos >= 0:
                break
        snippet = doc["body"][max(0, pos - 80):pos + 160].replace("\n", " ⏎ ") if pos >= 0 else ""
        scored.append({"doc": doc["doc"], "title": doc["title"],
                       "score": score, "snippet": snippet.strip()})
    scored.sort(key=lambda item: -item["score"])
    return scored[:limit]


@app.post("/v1/docs/query")
async def docs_query(request: Request) -> JSONResponse:
    record = _require(request, "docs:query")
    if isinstance(record, JSONResponse):
        _audit("docs_query_rejected", status=record.status_code)
        return record
    payload = await _parse_payload(request)
    query = (payload.get("q") or "").strip()
    try:
        limit = max(1, min(int(payload.get("limit") or "3"), 10))
    except ValueError:
        limit = 3
    results = _query_docs(query, limit)
    _audit("docs_query", username=record["subject"],
           terms=_TERM_RE.findall(query.lower())[:8], hits=len(results))
    return JSONResponse({"schema": "ist.excel.docs-query", "query": query, "results": results})


_init_data(Path(os.environ.get("CES_DATA_DIR")
                or _resolve_data_dir_from_argv()
                or DEFAULT_DATA_DIR))


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="compile-excel-server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("CES_PORT", "8900")))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data", default="", help="数据目录（覆盖 $CES_DATA_DIR）")
    parser.add_argument("--tls-cert", default="")
    parser.add_argument("--tls-key", default="")
    parser.add_argument("--insecure-lan", action="store_true")
    args = parser.parse_args()
    from deploy.tls_policy import serve_tls_problem, uvicorn_tls_kwargs

    problem = serve_tls_problem(args.host, args.tls_cert, args.tls_key, args.insecure_lan)
    if problem:
        raise SystemExit(problem)
    if args.data:
        _init_data(Path(args.data))
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning",
                **uvicorn_tls_kwargs(args.tls_cert, args.tls_key))


if __name__ == "__main__":
    main()
