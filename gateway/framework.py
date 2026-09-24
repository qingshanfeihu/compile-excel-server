"""与跳板机上测试框架打交道：读 conf、落位用例、起 pytest、读状态/日志、经 py38 代理取结果与探测。

合并自 InfoTest device_mcp_server/tools.py 与 device_mcp_client.py 客户端脚本（两份几乎逐行重复）。
改动：
- conf 名只来自 gateway.toml；
- runner 由网关直接起（bash，不再套 setsid），床锁 fd 继承给它，pytest 结束内核自动放锁；
- 状态文件先写临时文件再改名；runner 不碰锁文件；
- case.xlsx 落位后设为只读，远端 sha 必须等于冻结时的 sha；
- 凭据经 stdin 交给 py38 代理，不进命令行参数。
"""

from __future__ import annotations

import configparser
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import GatewayConfig
from .vendor.cex_core.security_scrub import scrub_text

AGENT = Path(__file__).resolve().parent / "agent" / "jumphost_agent.py"
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class FrameworkError(RuntimeError):
    pass


def safe(value: Any, what: str) -> str:
    text = str(value or "")
    if not _SAFE.match(text) or ".." in text:
        raise FrameworkError(f"{what} must be a safe name (letters, digits, . _ -): {text!r}")
    return text


def read_conf(cfg: GatewayConfig) -> configparser.ConfigParser:
    try:
        text = cfg.conf_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise FrameworkError(f"framework conf unreadable: {cfg.conf_path.name} "
                             f"({type(exc).__name__})") from None
    lines = [line for line in text.splitlines()
             if not line.strip().startswith(("<<<<<<", "======", ">>>>>>"))]
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read_string("\n".join(lines))
    return parser


def device_ips(parser: configparser.ConfigParser) -> list[str]:
    if not parser.has_option("comm", "ssh_ips"):
        return []
    return [ip.strip() for ip in parser.get("comm", "ssh_ips").split(",") if ip.strip()]


def device_credentials(parser: configparser.ConfigParser, build: str) -> dict[str, str]:
    """按构建名选设备段（与 InfoTest _parse_device_conn 同一规则），取 user/passwd/hostname。"""
    prefix = ""
    if re.search(r"array", build, re.I) or re.search(r"nodebug[-_](Beta|Rel)_APV", build, re.I):
        prefix = "array"
    elif re.search(r"infosec.*APV", build, re.I):
        prefix = "infosec"
    elif re.search(r"nsae", build, re.I):
        prefix = "nsae"
    if re.search(r"HG[-_]U", build, re.I):
        suffix = "_hgu"
    elif re.search(r"HG[-_]K", build, re.I):
        suffix = "_hgk"
    else:
        suffix = "_ustack"
    section = (prefix + suffix) if prefix else ""
    sections = [section] if (section and parser.has_section(section)) else [
        s for s in parser.sections() if s not in ("comm", "other", "env")]
    found: dict[str, str] = {}
    for name in sections:
        user = parser.get(name, "user", fallback="")
        passwd = parser.get(name, "passwd", fallback="") or parser.get(name, "password",
                                                                          fallback="")
        if user and passwd:
            found = {"user": user, "passwd": passwd,
                     "hostname": parser.get(name, "hostname", fallback="")}
            break
    if not found:
        raise FrameworkError("device credentials not found in the framework conf")
    return found


def mysql_ip(parser: configparser.ConfigParser) -> str:
    value = parser.get("other", "mysql_ip", fallback="").strip()
    if not value:
        raise FrameworkError("framework conf has no [other] mysql_ip")
    return value


def ports(parser: configparser.ConfigParser) -> list[str]:
    if parser.has_option("comm", "ports"):
        values = [p.strip() for p in parser.get("comm", "ports").split(",") if p.strip()]
        if len(values) >= 3:
            return values[:3]
    return ["port1", "port2", "port3"]


# ── 用例落位与运行 ──────────────────────────────────────────────────────
def staging_dir(cfg: GatewayConfig, module: str, autoid: str) -> Path:
    return cfg.staging_parent / f"ist_staging_{safe(module, 'module')}" / safe(autoid, 'autoid')


def stage_case(cfg: GatewayConfig, module: str, autoid: str, data: bytes,
               expected_sha256: str) -> dict[str, Any]:
    import hashlib

    stg = staging_dir(cfg, module, autoid)
    stg.mkdir(parents=True, exist_ok=True)
    final = stg / "case.xlsx"
    tmp = stg / f".case.xlsx.{os.getpid()}.tmp"
    with open(tmp, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o444)
    os.replace(tmp, final)
    for name in ("test_xlsx.py", "excel_contract.json"):
        target = cfg.apv_src / "lib" / name
        link = stg / name
        if link.is_symlink() or link.exists():
            link.unlink()
        if target.exists():
            link.symlink_to(os.path.relpath(target, stg))
    remote = hashlib.sha256(final.read_bytes()).hexdigest()
    if remote != expected_sha256:
        raise FrameworkError("staged workbook sha does not match the frozen upload; not running")
    return {"staging_dir": str(stg), "xlsx": str(final), "bytes": final.stat().st_size,
            "sha256": remote}


def task_paths(cfg: GatewayConfig, task_id: str) -> dict[str, Path]:
    root = cfg.state_dir / "tasks"
    root.mkdir(parents=True, exist_ok=True)
    return {name: root / f"{task_id}{suffix}" for name, suffix in (
        ("runner", ".sh"), ("log", ".log"), ("status", ".status.json"), ("junit", ".xml"))}


def launch_run(cfg: GatewayConfig, task_id: str, module: str, autoid: str, build: str,
               bed_lock_fd: int) -> None:
    """起 runner。床锁 fd 继承给 runner 进程组；本函数返回后调用方关闭自己的那份 fd。"""
    stg = staging_dir(cfg, module, autoid)
    node = stg / "test_xlsx.py"
    if not node.exists():
        node = stg
    paths = task_paths(cfg, task_id)
    q = shlex.quote
    status_tmp = str(paths["status"]) + ".tmp"
    done_json = ('{"task_id": "%s", "state": "done", "rc": %%d, "finished_at": %%d}' % task_id)
    script = "\n".join([
        "#!/bin/bash",
        f"cd {q(str(cfg.apv_src))} || exit 97",
        f"timeout --kill-after=30 {int(cfg.run_max_s)} {q(str(cfg.py38))} -m pytest -s "
        f"{q(str(node))} --build {q(build)} --junitxml {q(str(paths['junit']))} "
        f"> {q(str(paths['log']))} 2>&1",
        "RC=$?",
        f"printf {q(done_json)} \"$RC\" \"$(date +%s)\" > {q(status_tmp)} && "
        f"mv -f {q(status_tmp)} {q(str(paths['status']))}",
        "",
    ])
    paths["runner"].write_text(script, encoding="utf-8")
    os.chmod(paths["runner"], 0o700)
    running = {"task_id": task_id, "state": "running", "started_at": int(time.time())}
    tmp = paths["status"].with_suffix(".json.tmp")
    tmp.write_text(json.dumps(running), encoding="utf-8")
    os.replace(tmp, paths["status"])
    subprocess.Popen(
        ["bash", str(paths["runner"])], cwd=str(cfg.apv_src), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        pass_fds=(bed_lock_fd,), close_fds=True)


def read_status(cfg: GatewayConfig, task_id: str) -> dict[str, Any]:
    paths = task_paths(cfg, task_id)
    try:
        status = json.loads(paths["status"].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        status = {"state": "unknown"}
    tail = ""
    try:
        with open(paths["log"], "r", encoding="utf-8", errors="replace") as stream:
            tail = "".join(stream.readlines()[-25:])
    except OSError:
        pass
    status["log_tail"] = scrub_text(tail)
    return status


def batch_logs(cfg: GatewayConfig, module: str, autoid: str, min_epoch: float,
               max_chars: int = 3500) -> dict[str, dict[str, Any]]:
    """最新一份报告目录里每个用例的日志；mtime 早于 min_epoch 的判为 stale（上一轮留下的）。"""
    pattern = f"report/*/*/ist_staging_{safe(module, 'module')}/{safe(autoid, 'autoid')}" \
              "/test_xlsx/case.xlsx"
    bases = sorted(cfg.apv_src.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    out: dict[str, dict[str, Any]] = {}
    if not bases:
        return out
    for case_dir in sorted(p for p in bases[0].iterdir() if p.is_dir()):
        log = case_dir / f"{case_dir.name}.txt"
        if not log.is_file():
            continue
        mtime = log.stat().st_mtime
        stale = min_epoch > 0 and 0 < mtime < min_epoch
        text = "" if stale else log.read_text(encoding="utf-8", errors="replace")[-max_chars:]
        out[case_dir.name] = {"mtime": int(mtime), "stale": stale, "log": scrub_text(text)}
    return out


# ── py38 代理 ──────────────────────────────────────────────────────────
def agent_call(cfg: GatewayConfig, request: dict[str, Any], timeout: float = 120) -> dict[str, Any]:
    """在框架的 py38 里跑 jumphost_agent；请求（含凭据）走 stdin，结果是最后一行 JSON。"""
    try:
        proc = subprocess.run(
            [str(cfg.py38), str(AGENT)], input=json.dumps(request), capture_output=True,
            text=True, timeout=timeout, cwd=str(cfg.apv_src),
            env={**os.environ, "IST_APV_SRC": str(cfg.apv_src)})
    except subprocess.TimeoutExpired:
        return {"error": f"agent timed out after {timeout}s"}
    except OSError as exc:
        return {"error": f"agent could not start: {type(exc).__name__}"}
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                break
    return {"error": "agent returned no JSON", "stderr": scrub_text(proc.stderr[-800:])}


def query_results(cfg: GatewayConfig, build: str, case_ids: list[str]) -> dict[str, Any]:
    parser = read_conf(cfg)
    request: dict[str, Any] = {"op": "results", "mysql_ip": mysql_ip(parser), "build": build,
                               "case_ids": list(case_ids), "apv_src": str(cfg.apv_src)}
    if cfg.mysql_password_file:
        request.update({"mysql_password": cfg.mysql_password_file.read_text(encoding="utf-8").strip(),
                        "mysql_user": cfg.mysql_user, "mysql_db": cfg.mysql_db})
    return agent_call(cfg, request)


def probe(cfg: GatewayConfig, command: str, build: str, device_index: int) -> dict[str, Any]:
    parser = read_conf(cfg)
    ips = device_ips(parser)
    if not 0 <= device_index < len(ips):
        raise FrameworkError(f"device_index {device_index} is not in the framework conf")
    creds = device_credentials(parser, build)
    result = agent_call(cfg, {"op": "probe", "ip": ips[device_index], "user": creds["user"],
                              "passwd": creds["passwd"], "command": command}, timeout=90)
    if "output" in result:
        result["output"] = scrub_text(result["output"])
    return result


def device_reachable(ip: str, port: int = 22, timeout: float = 3.0) -> bool:
    import socket

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
