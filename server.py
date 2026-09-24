#!/usr/bin/env python3
"""compile-excel-server：KMS / 知识库 / 工件分发平台（通用平台代码）。

本仓库**只含平台代码**，不含任何内部资产：
- 工件（xlsx/xml/tar.gz…）、知识库手册、device_build 元数据全部从数据目录加载
  （$CES_DATA_DIR，缺省 ./data；由部署侧灌入，见 deploy/provision.py）；
- 账号与密钥不预置：实例凭据（审计签名密钥等）在部署时由 provision 生成；
- OAuth 设备授权流内置 local 后端（任意账号名授权，用于自测/内网小规模），
  真实 OAuth 提供方在部署对接时替换（auth 后端是 data/artifacts_meta.json
  之外的独立扩展点，见 README「对接真实 OAuth」）。

接口：
  POST /device_authorize           设备授权发起（RFC 8628 风格）
  GET|POST /activate               授权页（local 后端：任意账号名）
  POST /token                      设备流轮询签发 / refresh_token 换新
  GET  /v1/artifacts/manifest      工件清单（版本+SHA256，启动快照）
  GET  /v1/artifacts/{name}        Bearer 鉴权下载（读活文件；审计不记 token）
  POST /v1/docs/query              知识库关键词检索
  GET  /healthz                    探活

跑法：python3 server.py [--port 8900] [--data <数据目录>]
依赖：fastapi + uvicorn。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

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

MANIFEST_SCHEMA = "ist.excel.artifact-manifest"
RECEIPT_SCHEMA = "ist.excel.promotion-receipt"

app = FastAPI(title="compile-excel-server")

# ── 数据目录（部署侧灌入；仓库内 .gitignore 排除）───────────────────────
DATA_DIR = Path(os.environ.get("CES_DATA_DIR")
                or _resolve_data_dir_from_argv()
                or DEFAULT_DATA_DIR)
ARTIFACTS_DIR = DATA_DIR / "artifacts"
DOCS_DIR = DATA_DIR / "docs"
META_PATH = DATA_DIR / "artifacts_meta.json"
AUDIT_PATH = DATA_DIR / "audit.log"
AUDIT_KEY_PATH = DATA_DIR / "audit_hmac_key"


def _load_meta() -> dict[str, Any]:
    """工件元数据：device_build + 每工件版本/media_type/receipt（部署配置）。"""
    if not META_PATH.is_file():
        raise RuntimeError(
            f"数据目录未初始化：{META_PATH} 不存在。"
            "先运行 deploy/provision.py（或部署侧灌入数据），见 README。")
    meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or "device_build" not in meta:
        raise RuntimeError(f"{META_PATH} 结构非法：需要 device_build 与 artifacts")
    return meta


META = _load_meta()
DEVICE_BUILD = str(META["device_build"])
ARTIFACT_META: dict[str, dict[str, Any]] = dict(META.get("artifacts") or {})


def _audit_key() -> bytes | None:
    """部署时生成的审计签名密钥（provision 产出，600）；缺省则审计不带 hmac。"""
    try:
        return bytes.fromhex(AUDIT_KEY_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


# ── 状态（进程内存；token 一律运行时签发，仓库与数据目录都不预置）────────
_device_flows: dict[str, dict[str, Any]] = {}
_access_tokens: dict[str, dict[str, Any]] = {}
_refresh_tokens: dict[str, dict[str, Any]] = {}


def _audit(event: str, **fields: Any) -> None:
    """JSONL 审计；调用方保证不含任何 token 值。有实例密钥时附 hmac。"""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update(fields)
    line = json.dumps(record, ensure_ascii=False)
    key = _audit_key()
    if key is not None:
        line = line + "\thmac=" + hmac.new(key, line.encode("utf-8"),
                                           hashlib.sha256).hexdigest()
    try:
        with open(AUDIT_PATH, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_manifest() -> dict[str, Any]:
    """启动时对工件快照一次（SHA 以 manifest 为准；下载读活文件，便于演练不匹配拒绝）。"""
    artifacts = []
    for name in sorted(ARTIFACT_META):
        meta = ARTIFACT_META[name]
        path = ARTIFACTS_DIR / name
        if not path.is_file():
            continue
        artifacts.append({
            "name": name,
            "version": str(meta.get("version") or ""),
            "sha256": _sha256_file(path),
            "bytes": path.stat().st_size,
            "media_type": str(meta.get("media_type") or "application/octet-stream"),
            "receipt": meta.get("receipt") or {},
        })
    return {
        "schema": MANIFEST_SCHEMA,
        "device_build": DEVICE_BUILD,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifacts": artifacts,
    }


MANIFEST_SNAPSHOT = _snapshot_manifest()
if META.get("kms_addr"):
    MANIFEST_SNAPSHOT["kms_addr"] = str(META["kms_addr"])


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


def _bearer_user(request: Request) -> str | None:
    """校验 Bearer token；有效返回用户名，过期/无效返回 None（差异经 401 语义呈现）。"""
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    record = _access_tokens.get(token)
    if record is None or record["exp"] < time.time():
        return None
    return str(record["username"])


def _issue_tokens(username: str, scope: str) -> dict[str, Any]:
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    now = time.time()
    _access_tokens[access] = {"username": username, "exp": now + ACCESS_TTL, "scope": scope}
    _refresh_tokens[refresh] = {"username": username, "exp": now + REFRESH_TTL, "scope": scope}
    _audit("token_issued", username=username, scope=scope, access_ttl=ACCESS_TTL)
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh,
        "scope": scope,
    }


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    payload = {"ok": True, "service": "compile-excel-server",
               "device_build": DEVICE_BUILD}
    if META.get("kms_addr"):
        payload["kms_addr"] = str(META["kms_addr"])
    return payload


@app.post("/device_authorize")
async def device_authorize(request: Request) -> JSONResponse:
    payload = await _parse_payload(request)
    client_id = payload.get("client_id") or "compile-excel-skill"
    scope = payload.get("scope") or "artifacts:read docs:query"
    device_code = secrets.token_urlsafe(32)
    user_code = "".join(secrets.choice("BCDFGHJKLMNPQRSTVWXZ") for _ in range(8))
    host = request.headers.get("host") or "127.0.0.1"
    verification_uri = f"http://{host}/activate"
    _device_flows[device_code] = {
        "client_id": client_id,
        "scope": scope,
        "user_code": user_code,
        "status": "pending",
        "username": "",
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


_ACTIVATE_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>compile-excel-server 设备授权</title>
<style>body{{font-family:sans-serif;max-width:32em;margin:4em auto;line-height:1.6}}
code{{background:#f4f4f4;padding:.2em .5em;font-size:1.2em}}</style></head><body>
<h2>设备授权请求</h2>
<p>终端正在等待授权。确认设备码：<code>{user_code}</code></p>
<form method="post" action="/activate">
  <input type="hidden" name="user_code" value="{user_code}">
  <p><label>账号名：<input name="username" required value="tester"></label></p>
  <button type="submit">授权</button>
</form></body></html>"""


@app.get("/activate", response_class=HTMLResponse)
async def activate_page(user_code: str = "") -> HTMLResponse:
    return HTMLResponse(_ACTIVATE_PAGE.format(user_code=user_code or "________"))


@app.post("/activate")
async def activate_submit(request: Request) -> HTMLResponse:
    """local 授权后端：任意账号名即放行（对接真实 OAuth 时替换本端点）。"""
    payload = await _parse_payload(request)
    user_code = (payload.get("user_code") or "").strip()
    username = (payload.get("username") or "").strip() or "tester"
    flow = next(
        (f for f in _device_flows.values()
         if f["user_code"] == user_code and f["exp"] > time.time()),
        None,
    )
    if flow is None:
        return HTMLResponse("<h2>设备码无效或已过期</h2>", status_code=400)
    if flow["status"] == "pending":
        flow["status"] = "approved"
        flow["username"] = username
        _audit("device_authorized", username=username, client_id=flow["client_id"])
    return HTMLResponse(
        f"<h2>已授权（{username}）</h2><p>回到终端继续；登录完成后可关闭本页。</p>")


@app.post("/token")
async def token(request: Request) -> JSONResponse:
    payload = await _parse_payload(request)
    grant_type = payload.get("grant_type") or ""

    if grant_type == DEVICE_GRANT:
        device_code = payload.get("device_code") or ""
        flow = _device_flows.get(device_code)
        if flow is None or flow["exp"] < time.time():
            _device_flows.pop(device_code, None)
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "device code unknown or expired"},
                status_code=400)
        if flow["status"] == "pending":
            return JSONResponse(
                {"error": "authorization_pending"}, status_code=400)
        if flow["status"] == "denied":
            _device_flows.pop(device_code, None)
            return JSONResponse({"error": "access_denied"}, status_code=400)
        _device_flows.pop(device_code, None)
        return JSONResponse(_issue_tokens(flow["username"], flow["scope"]))

    if grant_type == "refresh_token":
        refresh = payload.get("refresh_token") or ""
        record = _refresh_tokens.pop(refresh, None)
        if record is None or record["exp"] < time.time():
            _audit("token_refresh_rejected")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "refresh token unknown or expired"},
                status_code=400)
        return JSONResponse(_issue_tokens(str(record["username"]), str(record["scope"])))

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


def _unauthorized() -> JSONResponse:
    return JSONResponse(
        {"detail": "missing, invalid or expired bearer token"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


@app.get("/v1/artifacts/manifest")
async def artifacts_manifest(request: Request, device_build: str = "") -> JSONResponse:
    if _bearer_user(request) is None:
        _audit("manifest_rejected")
        return _unauthorized()
    if device_build and device_build != MANIFEST_SNAPSHOT["device_build"]:
        return JSONResponse(
            {"detail": f"unknown device_build {device_build!r}; "
                       f"known: {MANIFEST_SNAPSHOT['device_build']!r}"},
            status_code=404)
    username = _bearer_user(request)
    _audit("manifest_served", username=username, device_build=MANIFEST_SNAPSHOT["device_build"])
    return JSONResponse(MANIFEST_SNAPSHOT)


@app.get("/v1/artifacts/{name}")
async def artifact_download(name: str, request: Request):
    user = _bearer_user(request)
    if user is None:
        _audit("artifact_rejected", name=name)
        return _unauthorized()
    entry = next(
        (a for a in MANIFEST_SNAPSHOT["artifacts"] if a["name"] == name), None)
    path = ARTIFACTS_DIR / name
    if entry is None or not path.is_file():
        return JSONResponse({"detail": f"unknown artifact {name!r}"}, status_code=404)
    _audit(
        "artifact_download", username=user, name=name,
        sha256=entry["sha256"], bytes=entry["bytes"], version=entry["version"])
    return FileResponse(
        path, media_type=entry["media_type"], filename=name)


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


DOCS = _load_docs()
_TERM_RE = re.compile(r"[A-Za-z0-9_]+|[\u4e00-\u9fff]")


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
    user = _bearer_user(request)
    if user is None:
        _audit("docs_query_rejected")
        return _unauthorized()
    payload = await _parse_payload(request)
    query = (payload.get("q") or "").strip()
    try:
        limit = max(1, min(int(payload.get("limit") or "3"), 10))
    except ValueError:
        limit = 3
    results = _query_docs(query, limit)
    _audit("docs_query", username=user, terms=_TERM_RE.findall(query.lower())[:8],
           hits=len(results))
    return JSONResponse({"schema": "ist.excel.docs-query", "query": query, "results": results})


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="compile-excel-server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("CES_PORT", "8900")))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--data", default="", help="数据目录（覆盖 $CES_DATA_DIR）")
    args = parser.parse_args()
    if args.data:
        global DATA_DIR, ARTIFACTS_DIR, DOCS_DIR, META_PATH, AUDIT_PATH, AUDIT_KEY_PATH
        global META, DEVICE_BUILD, ARTIFACT_META, MANIFEST_SNAPSHOT, DOCS
        DATA_DIR = Path(args.data)
        ARTIFACTS_DIR = DATA_DIR / "artifacts"
        DOCS_DIR = DATA_DIR / "docs"
        META_PATH = DATA_DIR / "artifacts_meta.json"
        AUDIT_PATH = DATA_DIR / "audit.log"
        AUDIT_KEY_PATH = DATA_DIR / "audit_hmac_key"
        META = _load_meta()
        DEVICE_BUILD = str(META["device_build"])
        ARTIFACT_META = dict(META.get("artifacts") or {})
        MANIFEST_SNAPSHOT = _snapshot_manifest()
        DOCS = _load_docs()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
