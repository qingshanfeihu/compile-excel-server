# ruff: noqa: F401
# 逐字抽自 InfoTest main/ist_core/security_scrub.py（到 scrub_text 为止）。
# 改判据先改 InfoTest 源再重新抽取，不在这里手改。

from __future__ import annotations

import hashlib
import json
import os
import re
from urllib.parse import quote
from pathlib import Path
from typing import Any


_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|authorization|cookie|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|community|"
    r"jumphost[_-]?pass|"
    r"(?<![a-z])pin(?![a-z])|"
    r"密码|口令|令牌|密钥|凭据)"
)
_METRIC_AMBIGUOUS_KEY_RE = re.compile(r"(?i)(?:token|credential)")
_STRONG_SECRET_KEY_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|(?<![a-z])pin(?![a-z])|private[_-]?key|"
    r"jumphost[_-]?pass|密码|口令)"
)
_SHA256_HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
_AUTHORIZATION_SCHEME_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      ["']?Authorization["']?
      (?:\s*[:=]\s*|\s+)
      (?P<quote>["']?)
    )
    (?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+
    (?P=quote)
    """
)
_QUOTED_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      ["']?
      (?:OPENAI_API_KEY|DEEPSEEK_API_KEY|MINERU_TOKEN|
         IST_JUMPHOST_PASS|JUMPHOST_PASS|APV_PASSWORD|
         Authorization|password|passwd|pwd|secret|token|
         api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|
         credential|community|密码|口令|令牌|密钥|凭据)
      ["']?
      \s*(?::|=)\s*
    )
    (?P<quote>["'])
    (?P<value>.*?)
    (?P=quote)
    """
)
_UNQUOTED_PHRASE_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      \b(?:password|passwd|pwd|secret|token|
          api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|
          credential|community)
      \s*(?::|=)\s*
    )
    (?P<value>
      (?!\s*(?:["']|\*{4}))
      (?=[^,\r\n;}\]]*\s)
      [^,\r\n;}\]]+?
    )
    (?=
      \s+\b(?:password|passwd|pwd|secret|token|
             api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|
             credential|community)\b\s*(?::|=)
      |[,;\r\n}\]]
      |$
    )
    """
)
_NAMED_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      ["']?
      (?:OPENAI_API_KEY|DEEPSEEK_API_KEY|MINERU_TOKEN|
         IST_JUMPHOST_PASS|JUMPHOST_PASS|APV_PASSWORD|
         Authorization|Bearer|password|passwd|pwd|secret|token|
         api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|credential|community)
      ["']?
      \s*(?::|=)\s*
    )
    (?P<quote>["']?)
    (?P<value>Bearer\s+[^,\s}\]]+|[^,\s}\]"']+)
    (?P=quote)
    """
)
_SPACE_SECRET_RE = re.compile(
    r"""(?ix)
    \b(?P<key>Authorization|password|passwd|pwd|secret|
       token|api[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|
       credential|community)
    (?P<sep>[^\S\r\n]+)
    (?P<value>Bearer\s+\S+|\S+)
    """
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SSHPASS_RE = re.compile(r"\bsshpass\s+(?:-[A-Za-z]\s+\S+\s+)*?-p\s*(?P<value>\S+)")
_CURL_USER_RE = re.compile(
    r"""(?ix)
    \bcurl\b (?P<gap>[^\r\n&|;]{0,200}?)
    (?<=\s)
    (?P<flag>--user[=\s]|-u\s*)
    (?P<quote>["']?)
    (?P<user>[^:\s"']{0,120}:)
    (?P<value>[^\s"']+)
    """
)
_SUDO_STDIN_RE = re.compile(
    r"""(?ix)
    \becho\s+
    (?P<quote>["'])(?P<value>[^\r\n]{0,200}?)(?P=quote)
    (?P<pipe>\s*\|\s*(?:/usr/bin/)?sudo\b[^\r\n]{0,40}?-S\b)
    """
)
_SENDLINE_RE = re.compile(
    r"""(?ix)
    \bsendline\s*\(\s*
    (?P<quote>["'])(?P<value>[^\r\n]{0,200}?)(?P=quote)
    (?P<tail>\s*\))
    """
)
_URL_USERINFO_RE = re.compile(
    r"""(?x)
    (?P<prefix>[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]{1,120}:)
    (?P<value>[^\s@/]{1,200})
    (?P<at>@)
    """
)
_SUDO_PROMPT_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      \[sudo\]\s*
      (?:password|passwd|口令|密码)[^\r\n:：]{0,40}[:：]\s*
    )
    (?P<value>[^\r\n]+)
    """
)
_DEVICE_INTERNAL_PATH_RE = re.compile(
    r"(?<![\w.-])/home/test(?:/[^\s`'\"<>|]*)?"
)
_UNIX_INTERNAL_PATH_RE = re.compile(
    r"""(?x)
    (?<![\w.-])
    /(?:Users|private|var|tmp|opt|etc|home|root)
    (?:/[^\s`'"<>|:;,)\]}]+)+
    """
)
_WINDOWS_INTERNAL_PATH_RE = re.compile(
    r"""(?ix)
    \b[A-Z]:\\(?:Users|ProgramData|Windows|Temp)
    (?:\\[^\s`'"<>|:;,)\]}]+)+
    """
)
_BUSINESS_TOKENS = frozenset({
    "auto_block",
    "author_definition_gap_disclosed",
    "batch_abandon",
    "batch_use_case",
    "batch_use_xml",
    "case_terminal_static_void",
    "confirm",
    "continue",
    "correct",
    "defect",
    "defect_conditional",
    "deesc_defect",
    "deesc_engineering_fault",
    "deesc_keep",
    "deesc_rebed",
    "deesc_reswitch",
    "deesc_retry",
    "downgrade",
    "keep",
    "reflow_tau",
    "reorder",
    "resume",
    "retry",
    "stop",
    "suspend",
})
_NON_SECRET_CREDENTIAL_KEYS = frozenset({
    "bed_lease_id",
    "credential_refs",
    "credential_valid",
    "lint_credential_id",
    "option_tokens",
    "tokens",
    "tokens_in",
    "tokens_out",
})

_OVERRIDE_PROJECTION_KEYS = frozenset({
    "override_schema",
    "override_class",
    "override_token_sha256",
})


_SENSITIVE_KEYS_CACHE: tuple[frozenset[str], tuple[str, ...]] = (frozenset(), ())

#: 环境变量**名字形态**判凭据，只给字面值兜底那一趟用（不进结构化键名判定）。
#:
#: `_SENSITIVE_KEY_RE` 是按词根匹配的，词根表里有 `password|passwd|pwd` 却没有裸 `pass`，
#: 也没有裸 `key`；`jumphost[_-]?pass` 是后来单独补进去的一条特例——特例本身就是「一般形态
#: 没覆盖」的证据。实测 `environment.example` 登记的 30 个凭据形态变量里有 11 个不被它命中
#: （`IST_MYSQL_PASS`、`IST_REMOTE_PASS` 这两个还在 `env_inventory.HARD_REQUIRED_ENV` 里），
#: 它们的值因此从来没进过字面值兜底那一趟。
#:
#: 本仓的登记表就是命名约定的正本（`environment.example`，见 AGENTS.md「安全」）：名字以
#: 这几个后缀结尾的登记项都是凭据。判定只在这里放宽，不动 `_SENSITIVE_KEY_RE`——那条正则
#: 同时管结构化键名脱敏（`scrub_value`），放宽它会连带改掉载荷里键名的判定面。
_CREDENTIAL_ENV_SUFFIXES = ("_KEY", "_TOKEN", "_PASS", "_PASSWORD", "_SECRET")

#: 名字带凭据词根、值却不是密钥的登记形态，字面值兜底不收：`*_HOST_KEY` 是跳板机的
#: **公开**主机密钥指纹（pin，与 known_hosts 里那行同物）；`*_FIELD` 是响应里的字段名
#: 配置（`AGILE_TOKEN_FIELD=data.token`），遮它会把正文里每个 `data.token` 打成 `****`；
#: `*_TOKENS` 是计数（`IST_LLM_MAX_OUTPUT_TOKENS=128000`）。判据取自登记表
#: `environment.example` 的占位值（守门 `test_every_registered_credential_variable_
#: reaches_the_literal_pass` 双向钉：占位值标为凭据的必须收，没标的必须不收）。
_NON_CREDENTIAL_ENV_SUFFIXES = ("_HOST_KEY", "_FIELD", "_TOKENS")


def _is_credential_env_name(name: str) -> bool:
    if name.endswith(_NON_CREDENTIAL_ENV_SUFFIXES):
        return False
    return bool(_SENSITIVE_KEY_RE.search(name)) or name.endswith(
        _CREDENTIAL_ENV_SUFFIXES
    )


def _sensitive_env_keys() -> tuple[str, ...]:
    global _SENSITIVE_KEYS_CACHE
    keys = frozenset(os.environ)
    cached_keys, cached = _SENSITIVE_KEYS_CACHE
    if keys == cached_keys:
        return cached
    found = tuple(sorted(k for k in keys if _is_credential_env_name(k)))
    _SENSITIVE_KEYS_CACHE = (keys, found)
    return found


#: percent-encoding 里的转义字节；十六进制大小写两种形态都要当孪生。
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-F]{2}")

#: 字面值兜底的第二层缓存：(敏感键元组, 各键当前原始值元组, 算好的替换表)。
#: 第一层（`_SENSITIVE_KEYS_CACHE`）只缓存键名集合，值每次现取——但编码孪生是对
#: 固定值做的常量工作，热路径上每次重算等于把 `test_scrub_hot_path_cost.py` 立的
#: 契约（不许每次调用重做常量工作）从后门再破一次。判据精确：键集变、任一值变都重算。
_SECRET_VALUES_CACHE: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]] = (
    (), (), (),
)


def _encoded_twins(candidate: str) -> tuple[str, ...]:
    """一个凭据字面值在响应正文里可能出现的编码形态。

    端点把密钥拼回 URL 再回显时是 percent-encoding：Python 侧 `quote(safe="")` 与
    JS 侧 `encodeURIComponent`（参考实现 `reference/opencode/packages/llm/src/route/
    executor.ts` 的 `secretValues()` 用的就是它）的保留字集合不同——JS 不编码
    `! ' ( ) *`——两种都算；十六进制大小写各一份。

    编码不出来就只留原串：POSIX 下 `os.environ` 用 surrogateescape 解码，凭据值带
    非 UTF-8 字节时是带孤立代理的 str，`quote` 默认 `errors="strict"` 会抛
    `UnicodeEncodeError`。这一趟是兜底，绝不能因为孪生算不出而把原串那一趟一起抛掉
    ——`scrub_text` 此前是全函数，调用点里有按「它不会抛」写的 handler。
    """
    twins: list[str] = []
    for safe in ("", "!'()*"):
        try:
            encoded = quote(candidate, safe=safe, errors="surrogateescape")
        except (UnicodeError, TypeError):  # 孪生算不出不影响原串那一趟
            continue
        if encoded == candidate:
            continue
        twins.append(encoded)
        lowered = _PERCENT_ESCAPE_RE.sub(lambda m: m.group(0).lower(), encoded)
        if lowered != encoded:
            twins.append(lowered)
    return tuple(twins)


def _loaded_secret_values() -> tuple[str, ...]:
    """进程里真正装着的凭据字面值，连同它们的编码形态。

    规则式脱敏只认「键名旁边的值」与几种已知前缀；端点把密钥原样回显在错误正文里、
    而它既不带已知前缀也不挨着任何键名时，规则一条都不命中。字面值这一趟是兜底。

    参考实现把这一层单独做了一遍：`reference/opencode/packages/llm/src/route/executor.ts`
    的 `secretValues()` 收集本次请求真正发出去的那些值（含 `Bearer <token>` 里的裸 token），
    再把它们**连同 URL 编码形态**在响应正文里逐一替换；守门是
    `reference/opencode/packages/llm/test/executor.test.ts` 里回显密钥那条。编码形态见
    `_encoded_twins`；结果按键集 + 原始值精确缓存（`_SECRET_VALUES_CACHE`）。
    """
    global _SECRET_VALUES_CACHE
    keys = _sensitive_env_keys()
    raw = tuple(str(os.environ.get(key) or "") for key in keys)
    cached_keys, cached_raw, cached_values = _SECRET_VALUES_CACHE
    if keys == cached_keys and raw == cached_raw:
        return cached_values
    values: set[str] = set()
    for value in raw:
        for candidate in (value, value.strip()):
            if len(candidate) < 8:
                continue
            values.add(candidate)
            values.update(_encoded_twins(candidate))
    result = tuple(sorted(values, key=len, reverse=True))
    _SECRET_VALUES_CACHE = (keys, raw, result)
    return result


_SK_PREFIX_TOKEN_RE = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{16,}")
_URL_QUERY_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>[?&](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|key|token)=)
    (?P<value>[^&\s"'<>]+)
    """
)
_DISCLOSURE_NEAR_TOKEN_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      \b(?:api[\s_-]?key|apikey|access[\s_-]?token|auth[\s_-]?token|token|
           secret|password|passwd|credential)\b
      |令牌|密钥|秘钥|口令|密码|凭据
    )
    (?P<gap>[^\r\n]{0,40}?[\s:=,"'（(])
    (?P<value>(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,})
    """
)


def scrub_disclosure_text(text: Any, *, scrub_paths: bool = True) -> str:
    out = scrub_text(text, scrub_paths=scrub_paths)
    if not out:
        return ""
    out = _URL_QUERY_SECRET_RE.sub(lambda m: f"{m.group('prefix')}****", out)
    out = _SK_PREFIX_TOKEN_RE.sub("****", out)
    out = _DISCLOSURE_NEAR_TOKEN_RE.sub(
        lambda m: f"{m.group('prefix')}{m.group('gap')}****", out,
    )
    return out


_PROJECT_ROOT: str | None = None
_HOME_CACHE: tuple[str, str] = ("\x00", "")


def _path_roots() -> tuple[str, str]:
    global _PROJECT_ROOT, _HOME_CACHE
    if _PROJECT_ROOT is None:
        _PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
    home_env = os.environ.get("HOME") or ""
    if _HOME_CACHE[0] != home_env:
        _HOME_CACHE = (home_env, str(Path.home()))
    return _PROJECT_ROOT, _HOME_CACHE[1]


def scrub_text(text: Any, *, scrub_paths: bool = True) -> str:
    out = str(text or "")
    if not out:
        return ""
    out = _AUTHORIZATION_SCHEME_RE.sub(
        lambda m: f"{m.group('prefix')}****{m.group('quote')}",
        out,
    )
    out = _QUOTED_SECRET_RE.sub(
        lambda m: f"{m.group('prefix')}{m.group('quote')}****{m.group('quote')}",
        out,
    )
    out = _UNQUOTED_PHRASE_SECRET_RE.sub(
        lambda m: f"{m.group('prefix')}****",
        out,
    )
    out = _NAMED_SECRET_RE.sub(
        lambda m: f"{m.group('prefix')}{m.group('quote')}****{m.group('quote')}",
        out,
    )
    out = _SPACE_SECRET_RE.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}****",
        out,
    )
    out = _BEARER_RE.sub("Bearer ****", out)
    out = _SSHPASS_RE.sub(
        lambda m: m.group(0)[: m.start("value") - m.start(0)] + "****", out,
    )
    out = _CURL_USER_RE.sub(
        lambda m: (
            f"curl{m.group('gap')}{m.group('flag')}{m.group('quote')}"
            f"{m.group('user')}****{m.group('quote')}"
        ),
        out,
    )
    out = _SUDO_STDIN_RE.sub(
        lambda m: (
            f"echo {m.group('quote')}****{m.group('quote')}{m.group('pipe')}"
        ),
        out,
    )
    out = _SENDLINE_RE.sub(
        lambda m: (
            f"sendline({m.group('quote')}****{m.group('quote')}{m.group('tail')}"
        ),
        out,
    )
    out = _SUDO_PROMPT_RE.sub(lambda m: f"{m.group('prefix')}****", out)
    out = _URL_USERINFO_RE.sub(
        lambda m: f"{m.group('prefix')}****{m.group('at')}", out,
    )
    for value in _loaded_secret_values():
        out = out.replace(value, "****")
    if scrub_paths:
        project, home = _path_roots()
        if project:
            out = out.replace(project, "<project-root>")
        if home:
            out = out.replace(home, "<user-home>")
        out = _DEVICE_INTERNAL_PATH_RE.sub("<device-internal-path>", out)
        out = _UNIX_INTERNAL_PATH_RE.sub("<internal-path>", out)
        out = _WINDOWS_INTERNAL_PATH_RE.sub("<internal-path>", out)
    return out
