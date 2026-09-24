"""向 compile-excel-server 内省用户令牌，并用网关自己的客户端身份取数据包里的规则文件。

内省结果缓存最多 30 秒（且不超过令牌自身的过期时间）；令牌在服务端被撤销后，最迟 30 秒内网关就拒绝它。
缓存键是令牌的 SHA-256，进程内不留令牌原文。
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

CACHE_SECONDS = 30.0


class IntrospectError(RuntimeError):
    pass


class ServerClient:
    def __init__(self, server_url: str, client_id: str, secret_file: Path, *,
                 timeout: float = 15.0):
        self.server_url = server_url.rstrip("/")
        self.client_id = client_id
        self.secret_file = Path(secret_file)
        self.timeout = timeout
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _secret(self) -> str:
        info = self.secret_file.stat()
        if info.st_mode & 0o077:
            raise IntrospectError("gateway client secret file must be 0600")
        return self.secret_file.read_text(encoding="utf-8").strip()

    def _basic(self) -> str:
        raw = f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self._secret())}"
        return "Basic " + base64.b64encode(raw.encode()).decode()

    def _post(self, path: str, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        req = urllib.request.Request(
            self.server_url + path, data=urllib.parse.urlencode(form).encode(),
            headers={"Authorization": self._basic(),
                     "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read() or b"{}")
            except ValueError:
                body = {}
            return exc.code, body
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise IntrospectError(f"server unreachable ({type(exc).__name__})") from None

    def introspect(self, token: str) -> dict[str, Any]:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return hit[1]
        status, body = self._post("/v1/introspect", {"token": token})
        if status != 200:
            raise IntrospectError(f"introspection failed (HTTP {status})")
        ttl = CACHE_SECONDS
        if body.get("active") and body.get("exp"):
            ttl = max(0.0, min(ttl, float(body["exp"]) - now))
        with self._lock:
            self._cache[key] = (now + ttl, body)
            if len(self._cache) > 4096:
                for stale in [k for k, (exp, _) in self._cache.items() if exp <= now]:
                    self._cache.pop(stale, None)
        return body

    def fetch_bundle_file(self, build: str, path: str) -> bytes:
        """取 stable 包里某个条目（例如 projections/domain_grammar.json），按清单 SHA 校验。"""
        status, issued = self._post("/token", {"grant_type": "client_credentials",
                                               "scope": "bundles:read"})
        if status != 200 or "access_token" not in issued:
            raise IntrospectError("gateway client cannot read bundles (needs bundles:read)")
        headers = {"Authorization": f"Bearer {issued['access_token']}"}

        def get(url: str) -> bytes:
            req = urllib.request.Request(self.server_url + url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                raise IntrospectError(f"GET {url} failed (HTTP {exc.code})") from None
            except (urllib.error.URLError, OSError) as exc:
                raise IntrospectError(f"server unreachable ({type(exc).__name__})") from None

        manifest = json.loads(get(f"/v1/builds/{urllib.parse.quote(build)}/bundle"))
        entry = next((e for e in manifest.get("entries") or [] if e.get("path") == path), None)
        if entry is None:
            raise IntrospectError(f"bundle for {build} has no {path}")
        data = get(f"/v1/blobs/{entry['sha256']}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise IntrospectError(f"{path} does not match the bundle manifest sha")
        return data
