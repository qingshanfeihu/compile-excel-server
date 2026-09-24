"""网关 HTTP 服务：MCP streamable HTTP 的请求/应答子集（POST /mcp，JSON-RPC 2.0），只用标准库。

- 每个请求都要 `Authorization: Bearer <用户令牌>`，经服务端 /v1/introspect 确认有效、取 scope；
- 监听非回环地址时必须配 TLS（config 加载时已检查）；
- GET /healthz 不鉴权，只回 ok，不泄露任何床状态。
"""

from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .introspect import IntrospectError
from .tools import TOOL_SPECS, Caller, Gateway

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "compile-excel-gateway", "version": "0.1.0"}
MAX_BODY = 64 * 1024 * 1024


def _rpc_result(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def handle_rpc(gateway: Gateway, caller: Caller, message: Any) -> dict[str, Any] | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _rpc_error(None, -32600, "invalid request")
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        return _rpc_result(msg_id, {"protocolVersion": requested or PROTOCOL_VERSION,
                                    "capabilities": {"tools": {"listChanged": False}},
                                    "serverInfo": SERVER_INFO})
    if method and str(method).startswith("notifications/"):
        return None
    if method == "ping":
        return _rpc_result(msg_id, {})
    if method == "tools/list":
        visible = [s for s in TOOL_SPECS if s["scope"] in caller.scopes]
        return _rpc_result(msg_id, {"tools": [
            {"name": s["name"], "description": s["description"], "inputSchema": s["input_schema"],
             "annotations": {"readOnlyHint": s["read_only"]}} for s in visible]})
    if method == "tools/call":
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _rpc_error(msg_id, -32602, "tools/call needs a tool name")
        try:
            outcome = gateway.call(caller, params["name"], params.get("arguments") or {})
        except Exception as exc:  # noqa: BLE001 — 工具边界：只回类型，细节进审计
            gateway.audit("tool_crashed", tool=params["name"], subject=caller.subject,
                          error=type(exc).__name__)
            outcome = {"ok": False, "error": f"internal error ({type(exc).__name__})"}
        return _rpc_result(msg_id, {
            "content": [{"type": "text", "text": json.dumps(outcome, ensure_ascii=False)}],
            "structuredContent": outcome, "isError": outcome.get("ok") is False})
    if msg_id is None:
        return None
    return _rpc_error(msg_id, -32601, f"method not found: {method}")


def make_handler(gateway: Gateway) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "cexg"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # 不把请求行（可能含路径参数）打到 stderr
            return

        def _send(self, status: int, body: dict[str, Any] | list | None,
                  headers: dict[str, str] | None = None) -> None:
            raw = b"" if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send(200, {"ok": True, "service": "compile-excel-gateway"})
            else:
                self._send(404, {"error": "not found"})

        def _caller(self) -> Caller | None:
            header = self.headers.get("Authorization") or ""
            if not header.lower().startswith("bearer "):
                return None
            try:
                info = gateway.server.introspect(header[7:].strip())
            except IntrospectError:
                raise
            if not info.get("active"):
                return None
            return Caller(subject=str(info.get("username") or info.get("sub") or ""),
                          scopes=frozenset(str(info.get("scope") or "").split()))

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/mcp":
                self._send(404, {"error": "not found"})
                return
            try:
                caller = self._caller()
            except IntrospectError as exc:
                self._send(503, {"error": f"cannot verify token: {exc}"})
                return
            if caller is None or not caller.subject:
                self._send(401, {"error": "missing, invalid or expired bearer token"},
                           {"WWW-Authenticate": 'Bearer error="invalid_token"'})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(413 if length > MAX_BODY else 400, {"error": "bad request body size"})
                return
            try:
                message = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeError, ValueError):
                self._send(400, _rpc_error(None, -32700, "parse error"))
                return
            if isinstance(message, list):
                replies = [r for r in (handle_rpc(gateway, caller, m) for m in message) if r]
                self._send(200, replies) if replies else self._send(202, None)
                return
            reply = handle_rpc(gateway, caller, message)
            self._send(200, reply) if reply is not None else self._send(202, None)

    return Handler


def build_server(gateway: Gateway) -> ThreadingHTTPServer:
    cfg = gateway.cfg
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(gateway))
    if cfg.tls_cert and cfg.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cfg.tls_cert), str(cfg.tls_key))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd
