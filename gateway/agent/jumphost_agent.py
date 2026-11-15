#!/usr/bin/env python3
"""jumphost_agent：在测试框架自带的 py38 里执行的小代理（由网关子进程调用）。

只做需要框架运行环境的事：
- probe：SSH 到设备执行一条只读命令（paramiko，框架环境自带）；
- results：查结果库（给了口令就用 pymysql 直连，否则借框架自己的 lib.mysqldb.Result_DB）；
- hosts：用框架自己的字面凭据登床内主机取接口地址（拓扑事实），主机密钥首见即钉。
请求是 stdin 上的一个 JSON（含凭据，不进命令行参数）；结果是 stdout 最后一行 JSON。
必须兼容 Python 3.8：不用 3.9+ 语法。
合并自 InfoTest device_mcp_server/tools.py 的 probe_show 与 result_db.py。
"""

from __future__ import print_function

import json
import re
import sys
import time
import codecs
import base64

# 设备提示符：缓冲区最后一行以 # 或 > 结尾（锚在缓冲区末尾，回显中间的 '#' 不算）
_PROMPT_END = re.compile(r"(?:^|[\r\n])([^\r\n]*?)(?:\([^)\r\n]*\))?[#>][ \t]*$")
_PASSWORD_END = re.compile(r"(?:^|[\r\n])[^\r\n]*assword:?[ \t]*$", re.I)
# 分页提示行：设备实际画的是“换行、空格、--More--、空格”（网关留存的真实回答里就是这个形状），
# 所以标记前允许空白；锚在缓冲区末尾，输出中间的字面 --More-- 不算。
_PAGER_LINE = re.compile(r"(?:^|[\r\n])([ \t]*--More--[ \t\b]*)$", re.I)
_PAGER_WIDTH = len("--More--")
PROMPT_WAIT_S = 5.0      # 登录后与 enable/terminal length 各等多久提示符
COMMAND_WAIT_S = 45.0    # 探测命令本身最多等多久（大输出分好几块到）
QUIET_S = 0.3            # 看到提示符后再静候这么久没有新数据才算收完


def normalize_build_name(build_name):
    b = build_name
    b = re.sub(r".*(ArrayOS.*?\.array)", r"\1", b)
    b = re.sub(r".*(nodebug.*?\.click)", r"\1", b)
    b = re.sub(r".*(Rel.*?).click", r"\1", b)
    b = re.sub(r".*(Rel.*?).array", r"\1", b)
    b = re.sub(r".*(Beta.*?).click", r"\1", b)
    b = re.sub(r".*(Beta.*?).array", r"\1", b)
    b = re.sub(r".*(Alpha.*?).click", r"\1", b)
    b = re.sub(r".*(Alpha.*?).array", r"\1", b)
    b = re.sub(r"-", r"_", b)
    return b


def bare_autoid(case_id):
    s = str(case_id).strip()
    if s.startswith("test_"):
        s = s[len("test_"):]
    m = re.match(r"^(.+?)\.[A-Za-z]+$", s)
    if m:
        s = m.group(1)
    return s


def op_results(req):
    table = normalize_build_name(str(req["build"]))
    if not re.match(r"^[A-Za-z0-9_.]+$", table):
        return {"error": "build name does not map to a safe table name"}
    bare = [bare_autoid(c) for c in req.get("case_ids") or []]
    if not bare:
        return {"results": {}}
    clauses, params = [], []
    for b in bare:
        clauses.append("(case_id = %s OR case_id LIKE %s OR case_id LIKE %s)")
        params.extend([b, b + ".%", "test_" + b + "%"])
    sql = "SELECT case_id, result, url FROM `%s` WHERE %s" % (table, " OR ".join(clauses))
    if req.get("mysql_password"):
        import pymysql

        conn = pymysql.connect(host=req["mysql_ip"], port=3306,
                               user=req.get("mysql_user") or "root",
                               passwd=req["mysql_password"],
                               db=req.get("mysql_db") or "smoke_test", charset="UTF8")
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            cur.close()
        finally:
            conn.close()
    else:
        apv_src = req.get("apv_src") or "."
        if apv_src not in sys.path:
            sys.path.insert(0, apv_src)
        from lib.mysqldb import Result_DB

        class _Config(object):
            pass

        config = _Config()
        config.other = {"mysql_ip": req["mysql_ip"]}
        database = Result_DB.__new__(Result_DB)
        database.configer = config
        rows = database.db_exec([(sql, params)]) or []
    # 同一构建表里一案可能有多行（别的床、上一轮）；只认 url 落在本次运行报告目录下的那行
    marker = "/report/%s/" % req["run_dir"] if req.get("run_dir") else None
    owned = '/' + req['report_path'].strip('/') + '/' if req.get('report_path') else None
    results, ignored = {}, 0
    for row in rows:
        case_id, result = row[0], row[1]
        url = str(row[2] or "") if len(row) > 2 else ""
        if marker is None or marker not in url or (owned is not None and owned not in url):
            ignored += 1
            continue
        results[bare_autoid(case_id)] = str(result)
    return {"results": results, "ignored_rows": ignored}


class _CsiView(object):
    """Interpret only complete ANSI CSI controls; keep incomplete ones pending."""
    def __init__(self):
        self.phase = "text"
        self.pending = []

    def feed(self, text):
        out = []
        for char in text:
            if self.phase == "text":
                if char == "\x1b":
                    self.pending = [char]
                    self.phase = "escape"
                else:
                    out.append(char)
                continue
            if self.phase == "escape" and char == "[":
                self.pending.append(char)
                self.phase = "parameter"
                continue
            code = ord(char)
            if self.phase == "parameter" and 0x30 <= code <= 0x3f:
                self.pending.append(char)
                continue
            if self.phase in ("parameter", "intermediate") and 0x20 <= code <= 0x2f:
                self.pending.append(char)
                self.phase = "intermediate"
                continue
            if self.phase in ("parameter", "intermediate") and 0x40 <= code <= 0x7e:
                self.pending = []
                self.phase = "text"
                continue
            out.extend(self.pending)
            self.pending = []
            self.phase = "text"
            if char == "\x1b":
                self.pending = [char]
                self.phase = "escape"
            else:
                out.append(char)
        return "".join(out)

    def finish(self):
        remaining = "".join(self.pending)
        self.pending = []
        self.phase = "text"
        return remaining


def _erase_forms(drawn):
    """What a pager may send to wipe its prompt before the next page, longest first.

    Two spellings, each for the width the device drew (`drawn`, blanks included) and for the bare
    marker: w backspaces, w blanks, w backspaces; or w times backspace, blank, backspace."""
    forms = []
    for width in sorted({_PAGER_WIDTH, len(drawn)}, reverse=True):
        forms.append("\b" * width + " " * width + "\b" * width)
        forms.append("\b \b" * width)
    return tuple(forms)


def read_until_prompt(chan, prompt, timeout, quiet=None, raw=None, raw_bytes=None):
    """Read one frame, preserving wire bytes while interpreting pager controls."""
    quiet = QUIET_S if quiet is None else quiet
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    view = _CsiView()
    erase_forms = ()
    erase_pending = ""
    erase_expected = False
    awaiting_page = False
    buf = ""
    end = time.monotonic() + timeout
    seen_at = None
    eof = False
    while time.monotonic() < end:
        if chan.recv_ready():
            data = chan.recv(65535)
            if not data:
                eof = True
                break
            if raw_bytes is not None:
                raw_bytes.append(data)
            text = decoder.decode(data)
            if raw is not None:
                raw.append(text)
            text = view.feed(text)
            if erase_expected:
                erase_pending += text
                matched = next((form for form in erase_forms
                                if erase_pending.startswith(form)), None)
                if matched is not None:
                    text = erase_pending[len(matched):]
                    erase_pending = ""
                    erase_expected = False
                elif any(form.startswith(erase_pending) for form in erase_forms):
                    continue
                else:
                    text = erase_pending
                    erase_pending = ""
                    erase_expected = False
            if text:
                awaiting_page = False
            buf += text
            marker = _PAGER_LINE.search(buf)
            if marker:
                erase_forms = _erase_forms(marker.group(1).strip("\b"))
                buf = buf[:marker.start(1)]
                chan.send(" ")
                erase_expected = True
                awaiting_page = True
                seen_at = None
                continue
            ready = not decoder.getstate()[0] and not view.pending and not awaiting_page and prompt.search(buf)
            seen_at = time.monotonic() if ready else None
            continue
        if seen_at is not None and time.monotonic() - seen_at >= quiet:
            return buf, True
        if getattr(chan, "closed", False):
            eof = True
            break
        time.sleep(0.05)
    incomplete_utf8 = bool(decoder.getstate()[0])
    tail = decoder.decode(b"", final=True)
    if raw is not None:
        raw.append(tail)
    incomplete_csi = bool(view.pending)
    buf += erase_pending + view.feed(tail) + view.finish()
    complete = eof and not incomplete_utf8 and not incomplete_csi and not awaiting_page and bool(prompt.search(buf))
    return buf, complete


def _probe_wire_capture(chunks):
    data = b"".join(chunks)
    return {"raw_output": data.decode("utf-8", "replace"),
            "raw_output_encoding": "utf-8-replace",
            "raw_output_base64": base64.b64encode(data).decode("ascii")}


def op_probe(req):
    import paramiko

    cmd = str(req.get("command") or "").strip()
    ssh = paramiko.SSHClient()
    # 设备常被重装，主机密钥会变；与 InfoTest 现行做法一致
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    reached = False
    wire_bytes = []
    try:
        ssh.connect(hostname=req["ip"], port=22, username=req["user"], password=req["passwd"],
                timeout=15, look_for_keys=False, allow_agent=False)
        reached = True
        if req.get('login_marker'):
            with open(req['login_marker'], 'w') as marker:
                marker.write('logged in')
        chan = ssh.invoke_shell()
        banner, complete = read_until_prompt(chan, _PROMPT_END, PROMPT_WAIT_S)
        if not complete:
            raise RuntimeError("terminal login prompt was not completely observed")
        # 登录后的那一行提示符定下主机名；命令输出要等到“主机名[(模式)]#”出现在末尾才算完
        match = _PROMPT_END.search(banner)
        host = match.group(1).strip() if match and match.group(1).strip() else ""
        prompt = re.compile(r"(?:^|[\r\n])" + re.escape(host) + r"(?:\([^)\r\n]*\))?[#>][ \t]*$") \
            if host else _PROMPT_END
        either = re.compile("|".join((prompt.pattern, _PASSWORD_END.pattern)), re.I)
        chan.send("enable\n")
        echo, complete = read_until_prompt(chan, either, PROMPT_WAIT_S)
        if not complete:
            raise RuntimeError("terminal enable prompt was not completely observed")
        if _PASSWORD_END.search(echo) or not re.search(r"#[ \t]*$", echo.rstrip("\r\n")):
            chan.send("\n")
            _, complete = read_until_prompt(chan, prompt, PROMPT_WAIT_S)
            if not complete:
                raise RuntimeError("terminal enable completion was not observed")
        chan.send("terminal length 0\n")
        _, complete = read_until_prompt(chan, prompt, PROMPT_WAIT_S)
        if not complete:
            raise RuntimeError("terminal paging setup prompt was not completely observed")
        chan.send(cmd + "\n")
        out, complete = read_until_prompt(chan, prompt, COMMAND_WAIT_S, raw_bytes=wire_bytes)
    except Exception as exc:
        result = {"error": "%s: %s" % (type(exc).__name__, exc), "reached_device": reached}
        result.update(_probe_wire_capture(wire_bytes))
        return result
    finally:
        ssh.close()
    raw = out.splitlines()
    lines = [ln for ln in raw if ln.strip() not in (cmd, "")]
    tail = list(lines)
    while tail and (not tail[-1].strip() or re.match(r"^\S*[#>]$", tail[-1].strip())):
        tail.pop()
    core = "\n".join(tail).strip()
    if core and re.match(r"^\^+$", core):
        result = {"command": cmd, "syntax_error": True, "reached_device": True,
                  "output": "%% Invalid input: command %r is invalid on this device" % cmd}
        result.update(_probe_wire_capture(wire_bytes))
        return result
    result = {"command": cmd, "output": "\n".join(lines), "reached_device": True}
    result.update(_probe_wire_capture(wire_bytes))
    if not complete:
        # 等不到设备提示符：输出可能不全，不能当完整回显用
        result.update(truncated=True, note="no device prompt within %ds; output may be "
                                           "incomplete" % int(COMMAND_WAIT_S))
    return result


def framework_credentials(apv_src):
    """框架 lib/ssh_server.py 里登测试床主机的那一处字面凭据（与 InfoTest 拓扑生成器同一取法）。

    只认恰好一处 connect(username=<字面>, password=<字面>)：多处时不知道哪对该配哪对，宁可不取。
    """
    import ast

    import io
    with io.open(apv_src.rstrip("/") + "/lib/ssh_server.py", encoding="utf-8", errors="replace") as fh:
        tree = ast.parse(fh.read())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "connect":
            kw = dict((k.arg, k.value) for k in node.keywords)
            user, password = kw.get("username"), kw.get("password")
            if isinstance(user, ast.Constant) and isinstance(password, ast.Constant) \
                    and isinstance(user.value, str) and isinstance(password.value, str):
                found.append((user.value, password.value))
    if len(found) != 1:
        raise RuntimeError("framework ssh_server.py has %d literal connect credentials; "
                           "need exactly one" % len(found))
    return found[0]


def op_hosts(req):
    """逐台登床内主机取接口地址（ip -o addr show）。主机密钥首见即钉，之后不一致就不递口令。"""
    import hashlib
    import socket

    import paramiko

    user, password = framework_credentials(req["apv_src"])
    pins_path = req.get("pins") or ""
    try:
        with open(pins_path) as fh:
            pins = json.load(fh)
    except (IOError, OSError, ValueError):
        pins = {}
    out = {}
    for name, ip in sorted((req.get("hosts") or {}).items()):
        transport = None
        try:
            sock = socket.create_connection((ip, 22), timeout=8)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=8)
            key = transport.get_remote_server_key()
            fingerprint = key.get_name() + ":" + hashlib.sha256(key.asbytes()).hexdigest()
            pinned = pins.get(ip)
            if pinned and pinned != fingerprint:
                out[name] = {"ip": ip, "error": "host_key_mismatch"}
                continue
            transport.auth_password(user, password)
            chan = transport.open_session(timeout=8)
            chan.settimeout(20)
            chan.exec_command("ip -o addr show 2>/dev/null || ifconfig -a")
            data = b""
            while True:
                chunk = chan.recv(65536)
                if not chunk:
                    break
                data += chunk
            pins.setdefault(ip, fingerprint)
            out[name] = {"ip": ip, "output": data.decode("utf-8", "replace")}
        except Exception as exc:  # noqa: BLE001 — 单台失败不连累别台，记下原因
            out[name] = {"ip": ip, "error": "%s: %s" % (type(exc).__name__, exc)}
        finally:
            if transport is not None:
                transport.close()
    if pins_path:
        tmp = pins_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(pins, fh, sort_keys=True)
        import os
        os.replace(tmp, pins_path)
    return {"hosts": out}


def op_stage_image(req):
    """build_install 的镜像落位：InfoTest 的升级用例只在床内文件服务器（stage_dir）上没有镜像时才从它的镜像库下载，
    镜像库不一定有被测构建；这里像 InfoTest 的调度一样先把构建库里的镜像放到那里。文件已在且非空就不动（同升级用例的
    判断）；否则在跳板机上从构建库流式下载，经框架自己的主机登录写到同目录的临时名，写完再换名，半截文件从不占正名。"""
    import hashlib
    import os
    import socket
    import urllib.request

    import paramiko

    image, folder, url = req["image"], req["dir"].rstrip("/"), req["source"].rstrip("/") + "/" + req["image"]
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$", image) or ".." in image:
        return {"error": "image is not a plain file name"}
    user, password = framework_credentials(req["apv_src"])
    pins_path = req.get("pins") or ""
    try:
        with open(pins_path) as fh:
            pins = json.load(fh)
    except (IOError, OSError, ValueError):
        pins = {}
    ip = req["ip"]
    sock = socket.create_connection((ip, 22), timeout=10)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=10)
        key = transport.get_remote_server_key()
        fingerprint = key.get_name() + ":" + hashlib.sha256(key.asbytes()).hexdigest()
        if pins.get(ip) and pins[ip] != fingerprint:
            return {"error": "host_key_mismatch", "host": req.get("host")}
        transport.auth_password(user, password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        target, partial = folder + "/" + image, folder + "/." + image + ".part"
        try:
            size = sftp.stat(target).st_size
        except IOError:
            size = None
        if size:
            return {"status": "present", "path": target, "bytes": size}
        written = 0
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=60) as response, sftp.open(partial, "wb") as out:
            out.set_pipelined(True)
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                written += len(chunk)
        if written == 0:
            sftp.remove(partial)
            return {"status": "failed", "error": "the build repository returned an empty image", "source": url}
        if size is not None:
            sftp.remove(target)
        sftp.rename(partial, target)
        sftp.chmod(target, 0o777)
        pins.setdefault(ip, fingerprint)
        if pins_path:
            with open(pins_path + ".tmp", "w") as fh:
                json.dump(pins, fh, sort_keys=True)
            os.replace(pins_path + ".tmp", pins_path)
        return {"status": "fetched", "path": target, "bytes": written, "sha256": digest.hexdigest(), "source": url}
    finally:
        transport.close()


OPS = {"results": op_results, "probe": op_probe, "hosts": op_hosts, "stage_image": op_stage_image}


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
        handler = OPS.get(req.get("op"))
        if handler is None:
            result = {"error": "unknown op"}
        else:
            result = handler(req)
    except Exception as exc:  # noqa: BLE001 — 代理边界：只回异常类型与消息
        result = {"error": "%s: %s" % (type(exc).__name__, exc)}
    sys.stdout.write(json.dumps(result) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
