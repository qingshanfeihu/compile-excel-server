"""网关的 MCP 工具：租约、环境自检、提交用例、状态与结果、只读探测、设备初始化（两步确认）。

每个工具都要求令牌带 jumphost:run；init_device 另要 jumphost:admin。
会碰设备的工具（env_prepare、case_submit、probe_show、init_device）都要带当前租约的 lease_id 与 token，
并且在床锁空闲时才执行。说明文字给模型看，用英文。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import console, framework, gates
from .audit_chain import AuditChain
from .config import GatewayConfig
from .introspect import IntrospectError, ServerClient
from .state import LeaseError, StateStore
from .vendor.credential_literals import MirrorCredentialLiteralError, mirror_credential_literals

GRAMMAR_PATH = "projections/domain_grammar.json"
LITERALS_TTL_S = 600
RUNNER_LOST = ("the runner exited without recording an end (killed by a gateway restart, OOM or "
               "an operator); this run produced no verdicts to read - resubmit the workbook")
_MYSQL_UNSAFE_RE = re.compile(r"[^0-9A-Za-z_]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# probe_show：只许 show/get 开头的一行，参数只用这些字符——没有 | ; & ` $ < > \ 换行
# 这类能接第二条命令、重定向写文件或在设备 shell 里展开的字符
_PROBE_RE = re.compile(r"^(?:show|get)(?: +[A-Za-z0-9_.,:/@%+=*\"'-]+)* *$", re.IGNORECASE)
_PROBE_MAX = 200


class ToolError(RuntimeError):
    pass


def mysql_safe_build(raw: str) -> str:
    """同 InfoTest bed.mysql_safe_build：设备自述的完整版本 → 执行构建名。"""
    s = _MYSQL_UNSAFE_RE.sub("_", str(raw or "")).strip("_")
    if s and s[0].isdigit():
        s = "b_" + s
    return s


@dataclass
class Caller:
    subject: str
    scopes: frozenset[str]


LEASE_PROPS = {
    "lease_id": {"type": "string", "description": "lease_id returned by lease_acquire."},
    "token": {"type": "integer", "description": "Fencing token returned by lease_acquire."},
}


def _schema(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required,
            "additionalProperties": False}


TOOL_SPECS: list[dict[str, Any]] = [
    {"name": "lease_acquire", "scope": "jumphost:run", "read_only": False,
     "description": "Lease the test bed for yourself. Returns lease_id and a fencing token that "
                    "every device-touching tool needs. Leases expire after the configured TTL; "
                    "call lease_heartbeat while working and lease_release when done.",
     "input_schema": _schema({}, [])},
    {"name": "lease_heartbeat", "scope": "jumphost:run", "read_only": False,
     "description": "Extend your bed lease.", "input_schema": _schema(LEASE_PROPS, ["lease_id", "token"])},
    {"name": "lease_release", "scope": "jumphost:run", "read_only": False,
     "description": "Release your bed lease.", "input_schema": _schema(LEASE_PROPS, ["lease_id", "token"])},
    {"name": "lease_status", "scope": "jumphost:run", "read_only": True,
     "description": "Who holds the bed lease and whether a run is in progress.",
     "input_schema": _schema({}, [])},
    {"name": "env_prepare", "scope": "jumphost:run", "read_only": True,
     "description": "Check the bed before running cases: framework files present, framework conf "
                    "readable, devices reachable, the device's own build matches the gateway's "
                    "bundle build, destructive-command rules and credential literals available. "
                    "Pass device_build (the build your cases were compiled for): a different build "
                    "is refused; without it the result says build_checked=false. "
                    "Read-only; needs your lease.",
     "input_schema": _schema({**LEASE_PROPS,
                              "device_build": {"type": "string", "description": "Build the "
                                               "cases were compiled for; must equal this bed's."}},
                             ["lease_id", "token"])},
    {"name": "case_submit", "scope": "jumphost:run", "read_only": False,
     "description": "Run a compiled case workbook on the bed. The workbook is frozen, checked "
                    "(zip/size limits, Excel contract, destructive commands, framework credential "
                    "literals) and staged read-only; the staged sha must equal the frozen sha. "
                    "Returns task_id; poll case_status, then read case_results.",
     "input_schema": _schema({**LEASE_PROPS,
                              "xlsx_b64": {"type": "string", "description": "Workbook bytes, base64."},
                              "module": {"type": "string", "description": "Staging module; defaults to the gateway's configured module."}},
                             ["lease_id", "token", "xlsx_b64"])},
    {"name": "case_status", "scope": "jumphost:run", "read_only": True,
     "description": "State of a submitted run (running/done/lost) with the last lines of its log. "
                    "lost means the runner died without recording an end (gateway restart, OOM, "
                    "operator kill); nothing more will come from that run.",
     "input_schema": _schema({"task_id": {"type": "string"}}, ["task_id"])},
    {"name": "case_results", "scope": "jumphost:run", "read_only": True,
     "description": "Per-case results of a finished run from the framework result database, with "
                    "each case's framework log. Logs older than the delivery time are marked stale "
                    "and must not be read as this run's evidence. channel=runner_lost means the "
                    "run died before finishing and has no verdicts; resubmit it.",
     "input_schema": _schema({"task_id": {"type": "string"}}, ["task_id"])},
    {"name": "probe_show", "scope": "jumphost:run", "read_only": True,
     "description": "Run one read-only show/get command on a device and return its output. "
                    "One line of at most 200 characters starting with show or get; arguments use "
                    "letters, digits, spaces and _ . , : / @ % + = * \" ' - only (no pipes, "
                    "';', '&', '$', backticks, redirection or control characters). "
                    "truncated=true means the device prompt did not come back in time and the "
                    "output may be incomplete. Needs your lease.",
     "input_schema": _schema({**LEASE_PROPS,
                              "command": {"type": "string"},
                              "device_index": {"type": "integer", "minimum": 0}},
                             ["lease_id", "token", "command"])},
    {"name": "bed_topology", "scope": "jumphost:run", "read_only": True,
     "description": "Network facts of this bed (network_topology.json, InfoTest layout): every "
                    "bed host's interfaces from the jumphost, device interfaces from a read-only "
                    "'show ip address', the L2 domains the jumphost sits in. Compile-time checks "
                    "(reachability, VIP and trigger-host choice, real-server addresses) read it. "
                    "services lists the bed's standing services from the gateway config "
                    "({host, ip, proto, port, note}; proto is http/https/tcp/udp/dns; empty when "
                    "none are configured). Cached on the gateway; refresh=true re-probes. Needs "
                    "your lease.",
     "input_schema": _schema({**LEASE_PROPS, "refresh": {"type": "boolean"}},
                             ["lease_id", "token"])},
    {"name": "init_device", "scope": "jumphost:admin", "read_only": False,
     "description": "Wipe and re-baseline devices over the serial console. Two steps: step=prepare "
                    "returns the exact plan and a one-time confirmation code; show the plan to the "
                    "user, and only after they approve call step=confirm with that code. The code "
                    "only binds confirm to that exact plan; the human approval itself is enforced "
                    "by the client's permission prompt for this tool, not by the gateway. "
                    "device_index picks one device; otherwise device_count (at least 1) takes the "
                    "first N; with neither, every device in the conf. Needs jumphost:admin and "
                    "your lease.",
     "input_schema": _schema({**LEASE_PROPS,
                              "step": {"type": "string", "enum": ["prepare", "confirm"]},
                              "device_index": {"type": "integer", "minimum": 0},
                              "device_count": {"type": "integer", "minimum": 1},
                              "confirmation": {"type": "string"}},
                             ["lease_id", "token", "step"])},
]


class Gateway:
    def __init__(self, cfg: GatewayConfig, server: ServerClient | None = None):
        self.cfg = cfg
        self.state = StateStore(cfg.state_dir, cfg.lease_ttl_s)
        self.server = server or ServerClient(cfg.server_url, cfg.client_id, cfg.client_secret_file)
        self._grammar_lock = threading.Lock()
        self._literals: tuple[float, frozenset[str]] | None = None
        self.audit_path = cfg.state_dir / "audit.log"
        self._audit = AuditChain(self.audit_path)
        self.handlers: dict[str, Callable[[Caller, dict[str, Any]], dict[str, Any]]] = {
            "lease_acquire": self.lease_acquire, "lease_heartbeat": self.lease_heartbeat,
            "lease_release": self.lease_release, "lease_status": self.lease_status,
            "env_prepare": self.env_prepare, "case_submit": self.case_submit,
            "case_status": self.case_status, "case_results": self.case_results,
            "probe_show": self.probe_show, "bed_topology": self.bed_topology,
            "init_device": self.init_device,
        }

    # ── 公共 ──────────────────────────────────────────────
    def audit(self, event: str, **fields: Any) -> None:
        """哈希链审计（gateway/audit_chain.py）；`cexg audit-verify` 复核。"""
        self._audit.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "event": event, **fields})

    def call(self, caller: Caller, name: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = next((s for s in TOOL_SPECS if s["name"] == name), None)
        if spec is None:
            return {"ok": False, "error": f"unknown tool {name!r}"}
        if spec["scope"] not in caller.scopes or "jumphost:run" not in caller.scopes:
            return {"ok": False, "error": f"your token lacks the {spec['scope']} scope"}
        if not isinstance(args, dict):
            return {"ok": False, "error": "arguments must be an object"}
        try:
            result = self.handlers[name](caller, args)
        except (LeaseError, ToolError, gates.GateError, framework.FrameworkError,
                IntrospectError) as exc:
            secrets = self.secrets()
            problems = getattr(exc, "problems", None)
            self.audit("tool_refused", tool=name, subject=caller.subject,
                       reason=framework.redact(str(exc)[:500], secrets))
            return framework.redact({"ok": False, "error": str(exc),
                                     **({"problems": problems} if problems else {})}, secrets)
        # 日志尾、每案日志、探测回显、结果库报错……回给客户端的一切都过一遍已知口令
        return framework.redact({"ok": True, **result}, self.secrets())

    def _lease(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.check(caller.subject, str(args.get("lease_id") or ""), args.get("token"))

    def grammar(self) -> dict[str, Any]:
        """自毁规则等文法：从服务端 stable 包取，缓存到状态目录；取不到且无缓存就拒绝。"""
        cache = self.cfg.state_dir / "domain_grammar.json"
        with self._grammar_lock:
            try:
                data = self.server.fetch_bundle_file(self.cfg.build, GRAMMAR_PATH)
                tmp = cache.with_suffix(".tmp")
                tmp.write_bytes(data)
                tmp.replace(cache)
            except IntrospectError:
                if not cache.is_file():
                    raise
            return json.loads(cache.read_text(encoding="utf-8"))

    def credential_literals(self) -> frozenset[str]:
        """框架 lib/ 与 smoke_test/ 源码里的凭据字面量（与 InfoTest 镜像同一范围）。
        一份 Python 源码都没有就说明框架不完整，拒绝，而不是当成“没有凭据”。"""
        values: set[str] = set()
        scanned = 0
        for sub in ("lib", "smoke_test"):
            root = self.cfg.apv_src / sub
            if not root.is_dir() or next(root.rglob("*.py"), None) is None:
                continue
            try:
                values |= mirror_credential_literals(root)
            except MirrorCredentialLiteralError as exc:
                raise ToolError(f"cannot extract framework credential literals: {exc}") from None
            scanned += 1
        if not scanned:
            raise ToolError("framework lib/ and smoke_test/ contain no Python sources")
        self._literals = (time.monotonic(), frozenset(values))
        return frozenset(values)

    def secrets(self) -> tuple[str, ...]:
        """网关知道的口令字面值（长的在前）：框架凭据字面量、conf 口令项、结果库口令。
        凭据字面量要解析整个框架源码，缓存 LITERALS_TTL_S 秒
        （case_submit/env_prepare 每次都会刷新）。"""
        cached = self._literals
        if cached is None or time.monotonic() - cached[0] > LITERALS_TTL_S:
            try:
                self.credential_literals()
            except (ToolError, OSError):
                self._literals = (time.monotonic(), frozenset())
        values = set(self._literals[1] if self._literals else ()) | framework.conf_secrets(self.cfg)
        values.add(framework.mysql_password(self.cfg))
        return tuple(sorted((v for v in values if len(v) >= framework.MIN_SECRET_LEN),
                            key=len, reverse=True))

    # ── 租约 ──────────────────────────────────────────────
    def lease_acquire(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        lease = self.state.acquire(caller.subject)
        self.audit("lease_acquired", subject=caller.subject, lease_id=lease["lease_id"],
                   token=lease["token"], renewed=lease["renewed"])
        return lease

    def lease_heartbeat(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        return self.state.heartbeat(caller.subject, str(args.get("lease_id") or ""),
                                    args.get("token"))

    def lease_release(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        self.state.release(caller.subject, str(args.get("lease_id") or ""), args.get("token"))
        self.audit("lease_released", subject=caller.subject, lease_id=args.get("lease_id"))
        return {"released": True}

    def lease_status(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        status = self.state.status()
        if status.get("holder") != caller.subject:
            # 租约号与 fencing token 只给持有人本人；别人只看到谁占着、还剩多久
            status.pop("lease_id", None)
            status.pop("token", None)
        return status

    # ── 环境自检 ──────────────────────────────────────────
    def env_prepare(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        self._lease(caller, args)
        # 客户端按哪个构建编的用例：与本床不符就不用往下查了（老客户端不带，照查但注明没核对）
        wanted = args.get("device_build")
        build_checked = wanted not in (None, "")
        if build_checked and mysql_safe_build(str(wanted)) != self.cfg.build:
            raise ToolError(f"device_build {str(wanted)!r} is not this bed's build "
                            f"{self.cfg.build!r}; compile against {self.cfg.build!r} or use the "
                            "gateway of the bed that runs your build")
        checks: list[dict[str, Any]] = []

        def add(key: str, ok: bool, detail: str = "") -> None:
            checks.append({"check": key, "ok": ok, "detail": detail})

        cfg = self.cfg
        add("framework_files", (cfg.apv_src / "lib" / "test_xlsx.py").is_file()
            and cfg.py38.is_file(), f"apv_src={cfg.apv_src.name}, py38={cfg.py38.name}")
        try:
            parser = framework.read_conf(cfg)
            ips = framework.device_ips(parser)
            framework.device_credentials(parser, cfg.build)
            add("framework_conf", bool(ips), f"{len(ips)} device(s) in conf")
        except framework.FrameworkError as exc:
            add("framework_conf", False, str(exc))
            ips = []
        for index, ip in enumerate(ips):
            add(f"device_{index}_reachable", framework.device_reachable(ip), f"tcp/22 on device {index}")
        grammar: dict[str, Any] = {}
        try:
            grammar = self.grammar()
            gates.load_patterns(grammar)
            add("destructive_rules", True, "from the server bundle")
        except Exception as exc:  # noqa: BLE001
            add("destructive_rules", False, str(exc))
        try:
            add("credential_literals", True, f"{len(self.credential_literals())} literal(s)")
        except ToolError as exc:
            add("credential_literals", False, str(exc))
        probe_spec = (grammar.get("bed_probes") or {}).get("build") or {}
        if ips and probe_spec.get("cmd") and probe_spec.get("extract"):
            with self.state.bed_lock() as locked:
                if not locked:
                    add("device_build", False, "bed busy (a run is in progress)")
                else:
                    out = framework.probe(cfg, str(probe_spec["cmd"]), cfg.build, 0)
                    match = re.search(str(probe_spec["extract"]), out.get("output") or "")
                    if match is None:
                        add("device_build", False, out.get("error") or "build not found in output")
                    else:
                        device_build = mysql_safe_build(match.group(1).strip())
                        add("device_build", device_build == cfg.build,
                            f"device reports {device_build}, gateway bundle is {cfg.build}")
        else:
            add("device_build", False, "no bed_probes.build in the bundle grammar")
        return {"ready": all(c["ok"] for c in checks), "checks": checks,
                "build_checked": build_checked}

    # ── 上机 ──────────────────────────────────────────────
    def case_submit(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._lease(caller, args)
        try:
            data = base64.b64decode(str(args.get("xlsx_b64") or ""), validate=True)
        except (binascii.Error, ValueError):
            raise ToolError("xlsx_b64 is not valid base64") from None
        module = framework.safe(args.get("module") or self.cfg.default_module, "module")
        frozen = gates.freeze(data)
        gates.check(frozen, grammar=self.grammar(), credential_literals=self.credential_literals())
        submit = framework.safe(frozen.autoids[0], "autoid")
        fd = self.state.try_bed_lock()
        if fd is None:
            raise ToolError("bed busy: another run or device operation is in progress")
        try:
            # 冻结、取规则、抽凭据字面量可能要几十秒：租约在这期间过期或被接管，就不能再上机
            lease = self._lease(caller, args)
            staged = framework.stage_case(self.cfg, module, submit, frozen.data, frozen.sha256)
            task_id = f"cex_{module}_{submit}_{int(time.time() * 1000)}"
            deliver_epoch = time.time()
            framework.launch_run(self.cfg, task_id, module, submit, self.cfg.build, fd)
        finally:
            os.close(fd)
        self.state.record_task(
            task_id=task_id, lease_id=lease["lease_id"], token=lease["token"],
            holder=caller.subject, module=module, autoid=submit, build=self.cfg.build,
            case_ids=list(frozen.autoids), xlsx_sha256=frozen.sha256,
            staging_dir=staged["staging_dir"], deliver_epoch=deliver_epoch,
            created_at=time.time())
        self.audit("case_submitted", subject=caller.subject, task_id=task_id,
                   sha256=frozen.sha256, cases=len(frozen.autoids))
        return {"task_id": task_id, "sha256": frozen.sha256, "bytes": frozen.size,
                "case_ids": list(frozen.autoids), "deliver_epoch": int(deliver_epoch)}

    def _own_task(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self.state.task(str(args.get("task_id") or ""))
        if task is None or task["holder"] != caller.subject:
            raise ToolError("unknown task_id (or not yours)")
        return task

    def case_status(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self._own_task(caller, args)
        status = framework.read_status(self.cfg, task["task_id"])
        return {"task_id": task["task_id"], "state": status.get("state", "unknown"),
                "rc": status.get("rc"), "log_tail": status.get("log_tail", ""),
                **({"note": RUNNER_LOST} if status.get("state") == "lost" else {})}

    def case_results(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self._own_task(caller, args)
        status = framework.read_status(self.cfg, task["task_id"])
        if status.get("state") == "lost":
            return {"task_id": task["task_id"], "channel": "runner_lost", "state": "lost",
                    "rc": None, "explanation": RUNNER_LOST}
        if status.get("state") != "done":
            return {"task_id": task["task_id"], "channel": "not_completed",
                    "state": status.get("state", "unknown")}
        finished = status.get("finished_at")
        max_epoch = float(finished) + 60 if finished else None
        # 同一落位目录的下一次投递之后才出现的报告目录属于那次任务：结束后 60 秒的宽限
        # 挡不住紧接着的下一轮（返工重投常常一两分钟内就到）
        following = self.state.next_delivery(task["module"], task["autoid"], task["deliver_epoch"])
        if following is not None:
            max_epoch = following if max_epoch is None else min(max_epoch, following)
        run_dir = framework.report_run_dir(
            self.cfg, task["module"], task["autoid"], task["deliver_epoch"] - 3, max_epoch)
        # 找不到本次运行的报告目录就没有本次的判定：宁可 not_run，也不借用别的运行留下的行
        queried = (framework.query_results(self.cfg, task["build"], task["case_ids"],
                                           run_dir=run_dir)
                   if run_dir else {"results": {}})
        # 日志与判定同源：只取本次运行的报告目录；找不到就不给日志，也不借别的运行的
        logs = (framework.batch_logs(self.cfg, task["module"], task["autoid"],
                                     task["deliver_epoch"] - 3, run_dir=run_dir)
                if run_dir else {})
        cases = []
        results = queried.get("results") or {}
        for case_id in task["case_ids"]:
            log = logs.get(case_id) or {}
            cases.append({"case_id": case_id, "result": results.get(case_id),
                          "log_stale": bool(log.get("stale")), "log": log.get("log", "")})
        if "error" in queried:
            channel = "query_error"
        elif any(c["result"] is None for c in cases):
            channel = "missing_after_done"
        else:
            channel = "ready"
        return {"task_id": task["task_id"], "channel": channel, "rc": status.get("rc"),
                "xlsx_sha256": task["xlsx_sha256"], "cases": cases, "run_dir": run_dir,
                "ignored_rows": queried.get("ignored_rows", 0),
                **({"query_error": queried["error"]} if "error" in queried else {})}

    # ── 只读探测 ──────────────────────────────────────────
    def probe_show(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        command = str(args.get("command") or "")
        if (_CONTROL_RE.search(command) or len(command.strip()) > _PROBE_MAX
                or not _PROBE_RE.match(command.strip())
                or command.count('"') % 2 or command.count("'") % 2):
            raise ToolError("probe_show takes one read-only line starting with show/get "
                            f"(at most {_PROBE_MAX} characters; arguments limited to letters, "
                            "digits, spaces and _ . , : / @ % + = * \" ' -)")
        self._lease(caller, args)
        index = int(args.get("device_index") or 0)
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            result = framework.probe(self.cfg, command.strip(), self.cfg.build, index)
        if "error" in result:
            raise ToolError(f"probe failed: {result['error']}")
        return result

    def bed_topology(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        from . import bed

        self._lease(caller, args)
        cache = self.cfg.state_dir / "bed_topology.json"
        # 常驻服务清单来自网关配置，不进探测缓存：改了配置下一次调用就看得到
        services = {"services": [dict(item) for item in self.cfg.bed_services]}
        if not args.get("refresh"):
            try:
                return {**json.loads(cache.read_text(encoding="utf-8")), **services}
            except (OSError, ValueError):
                pass
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            try:
                result = bed.collect(
                    self.cfg,
                    hosts=lambda hosts: framework.bed_hosts(self.cfg, hosts),
                    probe_show_ip=lambda index: framework.probe(
                        self.cfg, "show ip address", self.cfg.build, index).get("output") or "",
                    reachable=framework.device_reachable)
            except framework.FrameworkError as exc:
                raise ToolError(str(exc)) from None
        tmp = cache.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, cache)
        self.audit("bed_topology", subject=caller.subject, sha256=result["sha256"],
                          devices=len(result["topology"].get("devices") or []))
        return {**result, **services}

    # ── 设备初始化（两步）──────────────────────────────────
    def _init_plan(self, args: dict[str, Any]) -> dict[str, Any]:
        if not self.cfg.init_commands:
            raise ToolError("init_device.commands is empty in the gateway config")
        parser = framework.read_conf(self.cfg)
        ips = framework.device_ips(parser)
        if args.get("device_index") is not None:
            index = int(args["device_index"])
            if not 0 <= index < min(len(ips), self.cfg.max_devices):
                raise ToolError(f"device_index {index} is not in the framework conf")
            indices = [index]
        else:
            count = len(ips)
            if args.get("device_count") is not None:
                # 显式给的 0 或负数是错，不能落成“全部设备”
                count = int(args["device_count"])
                if count < 1:
                    raise ToolError(f"device_count must be at least 1, got {count} "
                                    "(omit it to initialize every device in the conf)")
            if count > len(ips) or count > self.cfg.max_devices or count < 1:
                raise ToolError(f"device_count {count} exceeds the {len(ips)} device(s) in conf "
                                f"or the limit {self.cfg.max_devices}")
            indices = list(range(count))
        port_names = framework.ports(parser)
        return {"devices": [{"device": idx, "tty": self.cfg.tty_name.format(idx=idx),
                             "commands": console.render_commands(
                                 list(self.cfg.init_commands), idx, port_names)}
                            for idx in indices]}

    def init_device(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        lease = self._lease(caller, args)
        step = args.get("step")
        if step == "prepare":
            plan = self._init_plan(args)
            code = self.state.new_challenge(caller.subject, lease["lease_id"], plan)
            self.audit("init_prepared", subject=caller.subject,
                       devices=[d["device"] for d in plan["devices"]])
            return {"plan": plan, "confirmation": code, "expires_in_s": 300,
                    "next": "Show this plan to the user. Only after they approve, call "
                            "init_device with step=confirm and this confirmation code."}
        if step != "confirm":
            raise ToolError("step must be prepare or confirm")
        plan = self.state.consume_challenge(str(args.get("confirmation") or ""),
                                            caller.subject, lease["lease_id"])
        parser = framework.read_conf(self.cfg)
        creds = framework.device_credentials(parser, self.cfg.build)
        results = []
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            for device in plan["devices"]:
                argv = [part.format(tty=device["tty"]) for part in self.cfg.console_command]
                outcome = console.init_one(
                    device["device"], console_argv=argv, tty=device["tty"],
                    hostname=creds.get("hostname") or "", user=creds["user"],
                    passwd=creds["passwd"], commands=device["commands"],
                    long_commands=self.cfg.init_long_commands,
                    step_timeout=self.cfg.init_step_timeout_s,
                    login_timeout=self.cfg.login_timeout_s)
                results.append(outcome.as_dict())
        ok = sum(r["status"] == "ok" for r in results)
        self.audit("init_done", subject=caller.subject, ok=ok, total=len(results),
                   failed=[r["device"] for r in results if r["status"] != "ok"])
        return {"initialized": ok, "failed": len(results) - ok, "total": len(results),
                "details": results}


def load_gateway(config_path: Path) -> Gateway:
    from .config import load

    return Gateway(load(Path(config_path)))
