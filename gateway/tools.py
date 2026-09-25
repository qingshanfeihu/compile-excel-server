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
_MYSQL_UNSAFE_RE = re.compile(r"[^0-9A-Za-z_]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


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
                    "Read-only; needs your lease.",
     "input_schema": _schema(LEASE_PROPS, ["lease_id", "token"])},
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
     "description": "State of a submitted run (running/done) with the last lines of its log.",
     "input_schema": _schema({"task_id": {"type": "string"}}, ["task_id"])},
    {"name": "case_results", "scope": "jumphost:run", "read_only": True,
     "description": "Per-case results of a finished run from the framework result database, with "
                    "each case's framework log. Logs older than the delivery time are marked stale "
                    "and must not be read as this run's evidence.",
     "input_schema": _schema({"task_id": {"type": "string"}}, ["task_id"])},
    {"name": "probe_show", "scope": "jumphost:run", "read_only": True,
     "description": "Run one read-only show/get command on a device and return its output. "
                    "Single line only; no control characters or ';'. Needs your lease.",
     "input_schema": _schema({**LEASE_PROPS,
                              "command": {"type": "string"},
                              "device_index": {"type": "integer", "minimum": 0}},
                             ["lease_id", "token", "command"])},
    {"name": "init_device", "scope": "jumphost:admin", "read_only": False,
     "description": "Wipe and re-baseline devices over the serial console. Two steps: step=prepare "
                    "returns the exact plan and a one-time confirmation code; show the plan to the "
                    "user, and only after they approve call step=confirm with that code. Needs "
                    "jumphost:admin and your lease.",
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
        self.audit_path = cfg.state_dir / "audit.log"
        self._audit = AuditChain(self.audit_path)
        self.handlers: dict[str, Callable[[Caller, dict[str, Any]], dict[str, Any]]] = {
            "lease_acquire": self.lease_acquire, "lease_heartbeat": self.lease_heartbeat,
            "lease_release": self.lease_release, "lease_status": self.lease_status,
            "env_prepare": self.env_prepare, "case_submit": self.case_submit,
            "case_status": self.case_status, "case_results": self.case_results,
            "probe_show": self.probe_show, "init_device": self.init_device,
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
            problems = getattr(exc, "problems", None)
            self.audit("tool_refused", tool=name, subject=caller.subject, reason=str(exc)[:500])
            return {"ok": False, "error": str(exc), **({"problems": problems} if problems else {})}
        return {"ok": True, **result}

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
        return frozenset(values)

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
        return {"ready": all(c["ok"] for c in checks), "checks": checks}

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
                "rc": status.get("rc"), "log_tail": status.get("log_tail", "")}

    def case_results(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self._own_task(caller, args)
        status = framework.read_status(self.cfg, task["task_id"])
        if status.get("state") != "done":
            return {"task_id": task["task_id"], "channel": "not_completed",
                    "state": status.get("state", "unknown")}
        finished = status.get("finished_at")
        run_dir = framework.report_run_dir(
            self.cfg, task["module"], task["autoid"], task["deliver_epoch"] - 3,
            float(finished) + 60 if finished else None)
        # 找不到本次运行的报告目录就没有本次的判定：宁可 not_run，也不借用别的运行留下的行
        queried = (framework.query_results(self.cfg, task["build"], task["case_ids"],
                                           run_dir=run_dir)
                   if run_dir else {"results": {}})
        logs = framework.batch_logs(self.cfg, task["module"], task["autoid"],
                                    task["deliver_epoch"] - 3)
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
        if (not command.strip() or _CONTROL_RE.search(command) or ";" in command
                or command.strip().split(None, 1)[0].lower() not in ("show", "get")):
            raise ToolError("probe_show takes one line starting with show/get, "
                            "with no control characters or ';'")
        self._lease(caller, args)
        index = int(args.get("device_index") or 0)
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            result = framework.probe(self.cfg, command.strip(), self.cfg.build, index)
        if "error" in result:
            raise ToolError(f"probe failed: {result['error']}")
        return result

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
            count = int(args.get("device_count") or len(ips))
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
