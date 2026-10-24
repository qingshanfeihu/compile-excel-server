"""网关的 MCP 工具：租约、环境自检、提交用例、状态与结果、只读探测、设备初始化（两步确认）。

每个工具都要求令牌带 jumphost:run；init_device 另要 jumphost:admin。
会碰设备的工具（env_prepare、case_submit、probe_show、init_device）都要带当前租约的 lease_id 与 token，
并且在床锁空闲时才执行。说明文字给模型看，用英文。
"""

from __future__ import annotations

import base64
import binascii
import json
import hashlib
import fcntl
import secrets as random_secrets
from datetime import datetime, timezone
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import console, framework, gates
from .audit_chain import AuditChain
from .auth import Caller, StaticSecretAuth  # noqa: F401 — Caller 在这里再导出，service 与测试从这里取
from .config import GatewayConfig
from .state import LeaseError, StateStore
from .vendor.credential_literals import MirrorCredentialLiteralError, mirror_credential_literals

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


class RedactionUnavailable(ToolError):
    """No successful framework literal scan exists; no device text may escape."""


def mysql_safe_build(raw: str) -> str:
    """同 InfoTest bed.mysql_safe_build：设备自述的完整版本 → 执行构建名。"""
    s = _MYSQL_UNSAFE_RE.sub("_", str(raw or "")).strip("_")
    if s and s[0].isdigit():
        s = "b_" + s
    return s


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
                    "device_count is how many devices the framework conf lists (APV_0 .. "
                    "APV_<device_count-1>); a case can only use those. conf.device_ips gives "
                    "their management IPs in conf order (conf.device_names their names when the "
                    "conf names them); the conf field is absent when the conf cannot be read. "
                    "Pass device_build (the build your cases were compiled for): a different build "
                    "is refused; without it the result says build_checked=false. "
                    "Read-only; needs your lease.",
     "input_schema": _schema({**LEASE_PROPS,
                              "device_build": {"type": "string", "description": "Build the "
                                               "cases were compiled for; must equal this bed's."}},
                             ["lease_id", "token"])},
    {"name": "case_submit", "scope": "jumphost:run", "read_only": False,
     "description": "Run a frozen, checked workbook on the leased bed. Pair request_id with not_after "
                    "(UTC deadline); omit both for legacy calls with request_record=none. Same request_id "
                    "and workbook bytes plus resolved module replay the stored receipt; conflicts refuse "
                    "at admission. Recorded replies have request_record=recorded, request_id, journal_id, "
                    "journal_since and subject; collected history has request_record=collected. Refusals "
                    "carry stage and reached_device. Interrupted recovery may return state=not_started "
                    "without a task_id. Successful launch returns task_id, submit_autoid and module. "
                    "Poll case_status then case_results; never resubmit an uncertain dispatch.",
     "input_schema": _schema({**LEASE_PROPS,
                              "request_id": {"type": "string", "maxLength": 128, "pattern": "^[A-Za-z0-9:._-]+$", "description": "Unique dispatch attempt; must be paired with not_after, never reused for changed work."},
            "not_after": {"type": "string", "format": "date-time", "description": "UTC admission deadline (Z or +00:00); pair with request_id and retain the original value for reconciliation."},
            "xlsx_b64": {"type": "string", "description": "Workbook bytes, base64."},
                              "module": {"type": "string", "description": "Staging module; defaults to the gateway's configured module."}},
                             ["lease_id", "token", "xlsx_b64"])},
    {"name":"case_request","scope":"jumphost:run","read_only":True,
     "description":"Read request_id without a lease or device operation. Every answer includes found, "
                   "gateway_time, gc_before, journal_id, journal_since and resolved subject. Before dispatch "
                   "freeze journal_id and subject; not found proves non-execution only for the same journal_id "
                   "and submit subject with gateway_time > original not_after > gc_before >= journal_since. "
                   "Found answers include state/stage/reached_device; pending contact is null and must be polled. "
                   "task_id appears only after confirmed runner start.",
     "input_schema":_schema({"request_id":{"type":"string"}},["request_id"])},
    {"name": "case_status", "scope": "jumphost:run", "read_only": True,
     "description": "State of a submitted run (running/done/lost) with the last lines of its log. "
                    "lost means the runner died without recording an end (gateway restart, OOM, "
                    "operator kill); nothing more will come from that run.",
     "input_schema": _schema({"task_id": {"type": "string"}}, ["task_id"])},
    {"name": "case_results", "scope": "jumphost:run", "read_only": True,
     "description": "Per-case results, owned logs and sessions for this task_id only; echoes request_id. "
                    "ownership=staging_directory means a unique delivery directory was verified, not a time "
                    "window. ownership=none and ownership_reason disclose legacy_layout, no_report or "
                    "ambiguous_reports; early channels disclose not_determined_runner_lost or "
                    "not_determined_not_completed. Inspect this dispatch evidence rather than repeatedly reading. "
                    "Missing or overwritten database rows remain missing, never borrowed from another run. "
                    "channel identifies ready, missing_after_done, query_error, not_completed or runner_lost. "
                    "rc is the process exit code and does not itself establish a case verdict.",
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
    def __init__(self, cfg: GatewayConfig, auth: StaticSecretAuth | None = None):
        self.cfg = cfg
        self.state = StateStore(cfg.state_dir, cfg.lease_ttl_s)
        self.auth = auth or StaticSecretAuth.from_config(cfg)
        self._progress = threading.local()
        self._grammar_lock = threading.Lock()
        self._grammar: tuple[tuple[int, int], dict[str, Any]] | None = None
        self._literals: tuple[float, frozenset[str]] | None = None
        self.audit_path = cfg.state_dir / "audit.log"
        self._audit = AuditChain(self.audit_path)
        self._audit_delivery_lock = threading.Lock()
        self.handlers: dict[str, Callable[[Caller, dict[str, Any]], dict[str, Any]]] = {
            "lease_acquire": self.lease_acquire, "lease_heartbeat": self.lease_heartbeat,
            "lease_release": self.lease_release, "lease_status": self.lease_status,
            "env_prepare": self.env_prepare, "case_submit": self.case_submit,
            "case_request": self.case_request, "case_status": self.case_status, "case_results": self.case_results,
            "probe_show": self.probe_show, "bed_topology": self.bed_topology,
            "init_device": self.init_device,
        }

    # ── 公共 ──────────────────────────────────────────────
    def audit(self, event: str, **fields: Any) -> bool:
        """Append a hash-chain event; expose whether AuditChain actually persisted it."""
        with self._audit_delivery_lock:
            previous = self._audit._prev  # AuditChain advances this only after a successful write.
            self._audit.append({'ts':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                                'event':event,**fields})
            return self._audit._prev != previous

    def flush_request_audit(self):
        self.state.flush_request_events(lambda event:self.audit('request_state',**event))

    def call(self, caller: Caller, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._call(caller, name, args)
        except RedactionUnavailable:
            # Do not put the failed scan's source bytes or the unfiltered result in the receipt or audit.
            self.audit('redaction_unavailable', tool=name, subject=caller.subject)
            return {'ok': False, 'error': 'framework credential literal scan unavailable; device text withheld',
                    'stage': 'redaction', 'reached_device': getattr(self._progress, 'reached', False),
                    'next_action': 'Repair unreadable or invalid framework sources, then retry this read to refresh the literal set'}

    def _call(self, caller: Caller, name: str, args: dict[str, Any]) -> dict[str, Any]:
        spec = next((s for s in TOOL_SPECS if s["name"] == name), None)
        if spec is None:
            return {"ok": False, "error": f"unknown tool {name!r}", "stage":"admission", "reached_device":False}
        if spec["scope"] not in caller.scopes or "jumphost:run" not in caller.scopes:
            return {"ok": False, "error": f"your token lacks the {spec['scope']} scope", "stage":"admission", "reached_device":False}
        if not isinstance(args, dict):
            return {"ok": False, "error": "arguments must be an object", "stage":"admission", "reached_device":False}
        if name == "case_submit" and ("request_id" in args or "not_after" in args):
            result = self._request_submit(caller, args)
        else:
            result = self._invoke(caller, name, args)
        if name in ('case_submit', 'case_request'):
            result.update(self.state.journal_identity(), subject=caller.subject)
        return result

    def _admission_refusal(self, caller, args, message):
        reply = framework.redact({'ok':False,'error':message,'stage':'admission',
                                  'reached_device':False},self.secrets())
        self.audit('tool_refused',tool='case_submit',subject=caller.subject,
                   request_id=args.get('request_id'),stage='admission',reached_device=False,
                   reason=reply['error'])
        return reply

    def _set_stage(self, stage):
        self._progress.stage = stage
        rid = getattr(self._progress, 'request_id', None)
        if rid:
            self.state.update_request(rid, stage=stage)

    def _invoke(self, caller, name, args):
        self._progress.request_id = args.get('request_id') if name == 'case_submit' else None
        self._progress.stage, self._progress.reached = "admission", False
        try:
            result = self.handlers[name](caller, args)
        except (LeaseError, ToolError, gates.GateError, framework.FrameworkError, OSError, ValueError) as exc:
            if name == 'case_submit' and args.get('request_id'):
                row, _, _ = self.state.request_snapshot(args['request_id'],caller.subject)
                if row and row['task_id']:
                    paths = framework.task_paths(self.cfg,row['task_id'])
                    if paths['start'].exists() or (paths['alive'].exists() and
                                                   not framework.runner_gone(self.cfg,row['task_id'])):
                        return framework.redact({'ok':True,**self._task_receipt(
                            self.state.task(row['task_id']))},self.secrets())
            stage, reached = self._progress.stage, self._progress.reached
            secrets = self.secrets()
            problems = getattr(exc, "problems", None)
            self.audit("tool_refused", tool=name, subject=caller.subject,
                       request_id=args.get("request_id"),stage=stage,reached_device=reached,
                       reason=framework.redact(str(exc)[:500], secrets))
            return framework.redact({"ok": False, "error": str(exc), "stage":stage,"reached_device":reached,
                                     **({'request_record':'none'} if name=='case_submit' and not args.get('request_id') else {}),
                                     **({"problems": problems} if problems else {})}, secrets)
        finally:
            self._progress.request_id = None
        # 日志尾、每案日志、探测回显、结果库报错……回给客户端的一切都过一遍已知口令
        return framework.redact({"ok": True, **({"request_record": "none"} if name == "case_submit" else {}),
                                 **result}, self.secrets())

    def reconcile_request(self, rid, holder):
        row, _, _ = self.state.request_snapshot(rid,holder)
        if not row or row['state'] not in ('received','starting'):
            return row
        # Nonblocking: a live admission/launch owns this lock. Never turn its work into a refusal.
        path = self.state.request_lock_path(rid)
        fd = os.open(path,os.O_RDWR | os.O_CREAT,0o600)
        try:
            try:
                fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if row['task_id'] and framework.task_paths(self.cfg, row['task_id'])['start'].exists():
                    return self._recover_request_row(row)
                return row
            row, _, _ = self.state.request_snapshot(rid,holder)
            if row['state'] not in ('received','starting'):
                return row
            return self._recover_request_row(row)
        finally:
            os.close(fd)

    def _task_receipt(self, task):
        return {'task_id':task['task_id'],'sha256':task['xlsx_sha256'],
                'bytes':(Path(task['staging_dir']) / 'case.xlsx').stat().st_size,
                'case_ids':task['case_ids'],'deliver_epoch':round(task['deliver_epoch'], 6),
                'submit_autoid':task['autoid'],'module':task['module']}

    def _recover_request_row(self, row):
        paths = framework.task_paths(self.cfg,row['task_id']) if row['task_id'] else None
        if paths and paths['start'].exists():
            state,reached,reason = 'started',True,None
        elif paths and paths['alive'].exists() and not framework.runner_gone(self.cfg,row['task_id']):
            return row
        else:
            state,reached,reason = 'not_started',False,'gateway stopped before runner start; submit a new request_id'
        fields = dict(state=state,reached_device=int(reached),stage=row['stage'] if reached else 'interrupted')
        if not row['reply']:
            if reached:
                reply = {'ok':True,**self._task_receipt(self.state.task(row['task_id']))}
            else:
                reply = {'ok':True,'state':'not_started','stage':'interrupted','interrupted_stage':row['stage'],
                         'next_action':reason,'reached_device':False}
            reply.update(request_id=row['request_id'],request_record='recorded')
            fields['reply'] = json.dumps(framework.redact(reply,self.secrets()))
        self.state.update_request(row['request_id'],**fields)
        self.flush_request_audit()
        return {**row,**fields,'reason':reason}

    def case_request(self, caller, args):
        rid = args.get('request_id')
        if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}',rid):
            raise ToolError('invalid request_id; supply the id from the submit receipt')
        self.reconcile_request(rid,caller.subject)
        row,now,floor = self.state.request_snapshot(rid,caller.subject)
        result = {'found':bool(row),'gateway_time':now,'gc_before':floor,'subject':caller.subject}
        if row:
            result.update(request_id=rid,state=row['state'],stage=row['stage'],
                          reached_device=(None if row['state'] in ('received','starting') else bool(row['reached_device'])),
                          xlsx_sha256=row['xlsx_sha256'] or None,received_at=row['received_at'],
                          not_after=row['not_after'])
            if row['reached_device'] and row['task_id']:
                result['task_id'] = row['task_id']
            if row['state'] in ('received','starting'):
                result['next_action'] = 'admission or runner launch is active; poll case_request with this request_id'
            elif row['state'] == 'not_started':
                result['reason'] = 'gateway stopped before runner start; submit a new request_id'
        return result

    def _request_submit(self, caller, args):
        try:
            rid = args.get('request_id')
            if 'request_id' not in args or 'not_after' not in args:
                raise ToolError('request_id and not_after must be supplied together')
            if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9:._-]{1,128}',rid):
                raise ToolError('request_id must contain 1 to 128 ASCII letters, digits or :._-')
            stamp = datetime.fromisoformat(str(args['not_after']).replace('Z','+00:00'))
            if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
                raise ValueError('not UTC')
            deadline = stamp.timestamp()
        except (ToolError,ValueError,binascii.Error) as exc:
            return self._admission_refusal(caller,args,str(exc))
        module_error = None
        try:
            module = framework.safe(args.get('module') or self.cfg.default_module, 'module')
        except framework.FrameworkError as exc:
            module, module_error = None, str(exc)
        decode_error = None
        try:
            raw = base64.b64decode(str(args.get('xlsx_b64') or ''),validate=True)
            digest = hashlib.sha256(raw).hexdigest()
        except (ValueError,binascii.Error):
            digest = ''  # No workbook bytes exist; never present this as a workbook hash.
            decode_error = 'xlsx_b64 is not valid base64; fix the encoding and use a new request_id'
        with self.state.request_lock(rid):
            row, fresh = self.state.reserve_request(rid, caller.subject, digest, deadline, admission_error=decode_error or module_error, module=module)
            if row.get('collected'):
                return {**self._admission_refusal(caller, args, 'request falls within collected history; inspect the original dispatch before using a new request_id'), 'request_record': 'collected'}
            if row['holder'] != caller.subject or row['xlsx_sha256'] != digest or row['module'] != module:
                return self._admission_refusal(caller,args,
                    'request_id conflicts with an existing request; use a new request_id')
            if not fresh:
                if row['state'] in ('received','starting') and not row['reply']:
                    row = self._recover_request_row(row)
                if row['reply']:
                    return json.loads(row['reply'])
                return {'ok':True,'request_id':rid,'state':row['state'],'reached_device':None if row['state'] in ('received','starting') else bool(row['reached_device'])}
            self.flush_request_audit()
            if row['reply']:
                reply = json.loads(row['reply'])
            elif decode_error:
                reply = {'ok':False,'error':decode_error,'stage':'admission','reached_device':False}
            elif row['expired']:
                reply = {'ok':False,'error':'request expired before admission; use a new request_id and deadline',
                         'stage':'admission','reached_device':False}
            else:
                reply = self._invoke(caller,'case_submit',args)
            if not reply['ok'] and reply.get('stage') == 'admission':
                self.audit('tool_refused',tool='case_submit',subject=caller.subject,
                           request_id=rid,stage='admission',reached_device=False,
                           reason=reply['error'])
            reply.update(request_id=rid,request_record='recorded')
            marked = (reply['ok'] and reply.get('task_id') and
                      framework.task_paths(self.cfg,reply['task_id'])['start'].exists())
            state = ('started' if marked else 'starting') if reply['ok'] else 'rejected'
            self.state.update_request(rid,reply=json.dumps(reply),state=state,
                                      stage=reply.get('stage'),reached_device=int(bool(marked)))
            self.flush_request_audit()
            return reply

    def _lease(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        self._set_stage("lease")
        return self.state.check(caller.subject, str(args.get("lease_id") or ""), args.get("token"))

    def grammar(self) -> dict[str, Any]:
        """自毁规则等文法：跳板机本地文件（hub.grammar_file），由运维随 hub 的规则资产更新，按 mtime 重读。
        文件不在或不是 JSON 就拒绝上机，不猜。"""
        path = self.cfg.grammar_file
        with self._grammar_lock:
            try:
                info = path.stat()
            except OSError:
                raise ToolError(f"rules file missing on the jumphost: {path} (publish the hub's "
                                "rule asset there before submitting)") from None
            key = (info.st_mtime_ns, info.st_size)
            if self._grammar is None or self._grammar[0] != key:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except ValueError as exc:
                    raise ToolError(f"rules file is not valid JSON: {path} ({exc})") from None
                if not isinstance(data, dict):
                    raise ToolError(f"rules file must be a JSON object: {path}")
                self._grammar = (key, data)
            return self._grammar[1]

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
                if cached is None:
                    raise RedactionUnavailable('no successful framework credential literal scan') from None
                # Keep its original timestamp: the next call retries rather than caching a failed empty scan.

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
        # 客户端按哪个构建编的用例：与本床不符就不用往下查了（老客户端不带，照查但注明没核对）
        wanted = args.get("device_build")
        build_checked = wanted not in (None, "")
        if build_checked and mysql_safe_build(str(wanted)) != self.cfg.build:
            raise ToolError(f"device_build {str(wanted)!r} is not this bed's build "
                            f"{self.cfg.build!r}; compile against {self.cfg.build!r} or use the "
                            "gateway of the bed that runs your build")
        self._lease(caller, args)
        self._set_stage('precheck')
        checks: list[dict[str, Any]] = []

        def add(key: str, ok: bool, detail: str = "") -> None:
            checks.append({"check": key, "ok": ok, "detail": detail})

        cfg = self.cfg
        add("framework_files", (cfg.apv_src / "lib" / "test_xlsx.py").is_file()
            and cfg.py38.is_file(), f"apv_src={cfg.apv_src.name}, py38={cfg.py38.name}")
        conf: dict[str, Any] | None = None
        try:
            parser = framework.read_conf(cfg)
            ips = framework.device_ips(parser)
            framework.device_credentials(parser, cfg.build)
            add("framework_conf", bool(ips), f"{len(ips)} device(s) in conf: "
                + ", ".join(f"APV_{i}" for i in range(len(ips))))
            # hub 结果解析按 conf 顺序把 runner 日志行归到 APV_<i>：IP 按 conf 原顺序交出，
            # 不重排、不猜；conf 给了设备名（[comm] marks）就同序附上，没给就没有这个键
            conf = {"device_ips": list(ips)}
            names = framework.device_names(parser)
            if names:
                conf["device_names"] = names
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
            self._set_stage('bed_busy')
            with self.state.bed_lock() as locked:
                if not locked:
                    add("device_build", False, "bed busy (a run is in progress)")
                else:
                    self._set_stage("probe")
                    out = framework.probe(cfg, str(probe_spec["cmd"]), cfg.build, 0)
                    self._progress.reached |= bool(out.get("reached_device"))
                    match = re.search(str(probe_spec["extract"]), out.get("output") or "")
                    if match is None:
                        add("device_build", False, out.get("error") or "build not found in output")
                    else:
                        device_build = mysql_safe_build(match.group(1).strip())
                        add("device_build", device_build == cfg.build,
                            f"device reports {device_build}, gateway bundle is {cfg.build}")
        else:
            add("device_build", False, "no bed_probes.build in the bundle grammar")
        out = {"ready": all(c["ok"] for c in checks), "checks": checks,
               "build_checked": build_checked, "device_count": len(ips),
               "stage":self._progress.stage,"reached_device":self._progress.reached}
        # conf 读不到就没有 conf 字段：空数组会冒充“读到了、零台设备”
        if conf is not None:
            out["conf"] = conf
        return out

    # ── 上机 ──────────────────────────────────────────────
    def case_submit(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        try:
            data = base64.b64decode(str(args.get("xlsx_b64") or ""), validate=True)
        except (binascii.Error, ValueError):
            raise ToolError("xlsx_b64 is not valid base64") from None
        module = framework.safe(args.get("module") or self.cfg.default_module, "module")
        lease = self._lease(caller, args)
        self._set_stage("precheck")
        frozen = gates.freeze(data)
        device_count = len(framework.device_ips(framework.read_conf(self.cfg)))
        gates.check(frozen, grammar=self.grammar(), credential_literals=self.credential_literals(),
                    device_count=device_count)
        submit = framework.safe(frozen.autoids[0], "autoid")
        self._set_stage("bed_busy")
        fd = self.state.try_bed_lock()
        if fd is None:
            raise ToolError("bed busy: another run or device operation is in progress")
        try:
            # 冻结、取规则、抽凭据字面量可能要几十秒：租约在这期间过期或被接管，就不能再上机
            lease = self._lease(caller, args)
            self._set_stage("staging")
            task_id = f"cex_{random_secrets.token_hex(16)}"
            staged = framework.stage_case(self.cfg, module, submit, frozen.data, frozen.sha256, task_id)
            deliver_epoch = time.time()
            self.state.record_task(
                task_id=task_id, lease_id=lease["lease_id"], token=lease["token"],
                holder=caller.subject, module=module, autoid=submit, build=self.cfg.build,
                case_ids=list(frozen.autoids), xlsx_sha256=frozen.sha256,
                staging_dir=staged["staging_dir"], deliver_epoch=deliver_epoch,
                created_at=time.time(), request_id=args.get("request_id"))
            if args.get('request_id'):
                self.flush_request_audit()
            self._set_stage("launch")
            framework.launch_run(self.cfg, task_id, module, submit, self.cfg.build, fd)
        finally:
            os.close(fd)
        self.audit("case_submitted", subject=caller.subject, task_id=task_id,
                   sha256=frozen.sha256, cases=len(frozen.autoids))
        return {"task_id": task_id, "sha256": frozen.sha256, "bytes": frozen.size,
                "case_ids": list(frozen.autoids), "deliver_epoch": round(deliver_epoch, 6),
                "submit_autoid": submit, "module": module}

    def _own_task(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self.state.task(str(args.get("task_id") or ""))
        if task is None or task["holder"] != caller.subject:
            raise ToolError("unknown task_id (or not yours)")
        rid = self.state.task_request(task['task_id'])
        if rid:
            self.reconcile_request(rid,caller.subject)
        return task

    def case_status(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self._own_task(caller, args)
        status = framework.read_status(self.cfg, task["task_id"])
        return {"task_id": task["task_id"], "state": status.get("state", "unknown"),
                "rc": status.get("rc"), "log_tail": status.get("log_tail", ""),
                **({"note": RUNNER_LOST} if status.get("state") == "lost" else {})}

    def case_results(self, caller: Caller, args: dict[str, Any]) -> dict[str, Any]:
        task = self._own_task(caller, args)
        identity = {'task_id':task['task_id'],'request_id':self.state.task_request(task['task_id']),
                    'ownership':'none', 'complete':False, 'xlsx_sha256':task['xlsx_sha256'],
                    'submitted_at':datetime.fromtimestamp(round(task['deliver_epoch'], 6), timezone.utc).isoformat(timespec='microseconds')}
        status = framework.read_status(self.cfg, task["task_id"])
        if status.get("state") == "lost":
            return {**identity, "channel": "runner_lost", "state": "lost",
                    "ownership_reason": "not_determined_runner_lost",
                    "next_action": "Have the operator recover this task's runner and dispatch evidence before determining report ownership",
                    "rc": None, "explanation": RUNNER_LOST}
        if status.get("state") != "done":
            return {**identity, "channel": "not_completed",
                    "ownership_reason": "not_determined_not_completed",
                    "next_action": "Poll case_status for this task until done or lost, then read case_results",
                    "state": status.get("state", "unknown")}
        ownership = framework.delivery_report_lookup(self.cfg,task['staging_dir'])
        base = ownership['base']
        run_dir = base.relative_to(self.cfg.apv_src / 'report').parts[0] if base else None
        queried = (framework.query_results(self.cfg,task['build'],task['case_ids'],run_dir=run_dir,
                    report_path=base.relative_to(self.cfg.apv_src).as_posix()) if base else {'results':{}})
        logs = framework.delivery_logs(base) if base else {}
        cases = []
        results = queried.get("results") or {}
        for case_id in task["case_ids"]:
            log = logs.get(case_id) or {}
            case = {"case_id": case_id, "result": results.get(case_id),
                    "log_stale": bool(log.get("stale")), "log": log.get("log", "")}
            # 归因要看设备当时回了什么：没过的案带上本次运行里它的设备会话与触发机会话
            if base is not None and str(case["result"] or "").lower() != "pass":
                case["sessions"] = framework.case_sessions(base, case_id)
            cases.append(case)
        if "error" in queried:
            channel = "query_error"
        elif any(c["result"] is None for c in cases):
            channel = "missing_after_done"
        else:
            channel = "ready"
        complete = (channel == 'ready' and base is not None and bool(cases)
                    and len(cases) == len(set(task['case_ids']))
                    and all(str(c['result']).upper() in ('PASS', 'FAIL')
                            and c['log'] and not c['log_stale'] for c in cases))
        return {**identity, "complete":bool(complete),
                "ownership":"staging_directory" if base is not None else "none", "ownership_reason":ownership['reason'], "channel": channel, "rc": status.get("rc"),
                "xlsx_sha256": task["xlsx_sha256"], "cases": cases, "run_dir": run_dir,
                "submit_autoid": task["autoid"], "module": task["module"],
                "report_dir": (base.relative_to(self.cfg.apv_src).as_posix()
                               if base is not None else None),
                "ignored_rows": queried.get("ignored_rows", 0),
                **({'next_action':'Inspect this dispatch log, collector layout and owned result-store rows; ask the operator to restore retained evidence or report an ownership capability gap before a new request_id'}
                   if channel != 'ready' else {}),
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
        self._set_stage('bed_busy')
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            self._set_stage('probe')
            result = framework.probe(self.cfg, command.strip(), self.cfg.build, index)
        self._set_stage("probe")
        self._progress.reached = bool(result.get("reached_device"))
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
        def topology_probe(index):
            self._set_stage('probe')
            result = framework.probe(self.cfg,'show ip address',self.cfg.build,index)
            self._progress.reached |= bool(result.get('reached_device'))
            return result.get('output') or ''
        self._set_stage('bed_busy')
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            self._set_stage('probe')
            try:
                result = bed.collect(
                    self.cfg,
                    hosts=lambda hosts: framework.bed_hosts(self.cfg, hosts),
                    probe_show_ip=topology_probe,
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
        step = args.get("step")
        if step not in ('prepare', 'confirm'):
            raise ToolError('step must be prepare or confirm')
        plan = self._init_plan(args) if step == 'prepare' else None
        if step == 'confirm' and not args.get('confirmation'):
            raise ToolError('confirmation is required; call init_device with step=prepare')
        lease = self._lease(caller, args)
        if step == "prepare":
            code = self.state.new_challenge(caller.subject, lease["lease_id"], plan)
            self.audit("init_prepared", subject=caller.subject,
                       devices=[d["device"] for d in plan["devices"]])
            return {"plan": plan, "confirmation": code, "expires_in_s": 300,
                    "next": "Show this plan to the user. Only after they approve, call "
                            "init_device with step=confirm and this confirmation code."}
        if step != "confirm":
            raise ToolError("step must be prepare or confirm")
        self._set_stage('admission')
        plan = self.state.consume_challenge(str(args.get("confirmation") or ""),
                                            caller.subject, lease["lease_id"])
        self._set_stage('initialization')
        parser = framework.read_conf(self.cfg)
        creds = framework.device_credentials(parser, self.cfg.build)
        results = []
        self._set_stage('bed_busy')
        with self.state.bed_lock() as locked:
            if not locked:
                raise ToolError("bed busy: a run is in progress")
            for device in plan["devices"]:
                argv = [part.format(tty=device["tty"]) for part in self.cfg.console_command]
                self._set_stage("initialization")
                outcome = console.init_one(
                    device["device"], console_argv=argv, tty=device["tty"],
                    hostname=creds.get("hostname") or "", user=creds["user"],
                    passwd=creds["passwd"], commands=device["commands"],
                    long_commands=self.cfg.init_long_commands,
                    step_timeout=self.cfg.init_step_timeout_s,
                    login_timeout=self.cfg.login_timeout_s)
                self._set_stage("initialization")
                self._progress.reached |= outcome.reached_device
                results.append(outcome.as_dict())
        ok = sum(r["status"] == "ok" for r in results)
        self.audit("init_done", subject=caller.subject, ok=ok, total=len(results),
                   failed=[r["device"] for r in results if r["status"] != "ok"])
        return {"initialized": ok, "failed": len(results) - ok, "total": len(results),
                "details": results,"stage":self._progress.stage,"reached_device":self._progress.reached}


def load_gateway(config_path: Path) -> Gateway:
    from .config import load

    return Gateway(load(Path(config_path)))
