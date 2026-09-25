#!/usr/bin/env python3
"""jumphost_agent：在测试框架自带的 py38 里执行的小代理（由网关子进程调用）。

只做两件需要框架运行环境的事：
- probe：SSH 到设备执行一条只读命令（paramiko，框架环境自带）；
- results：查结果库（给了口令就用 pymysql 直连，否则借框架自己的 lib.mysqldb.Result_DB）。
请求是 stdin 上的一个 JSON（含凭据，不进命令行参数）；结果是 stdout 最后一行 JSON。
必须兼容 Python 3.8：不用 3.9+ 语法。
合并自 InfoTest device_mcp_server/tools.py 的 probe_show 与 result_db.py。
"""

from __future__ import print_function

import json
import re
import sys
import time


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
    results, ignored = {}, 0
    for row in rows:
        case_id, result = row[0], row[1]
        url = str(row[2] or "") if len(row) > 2 else ""
        if marker is None or marker not in url:
            ignored += 1
            continue
        results[bare_autoid(case_id)] = str(result)
    return {"results": results, "ignored_rows": ignored}


def op_probe(req):
    import paramiko

    cmd = str(req.get("command") or "").strip()
    ssh = paramiko.SSHClient()
    # 设备常被重装，主机密钥会变；与 InfoTest 现行做法一致
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=req["ip"], port=22, username=req["user"], password=req["passwd"],
                timeout=15, look_for_keys=False, allow_agent=False)
    try:
        chan = ssh.invoke_shell()

        def read_until(token, timeout):
            buf = ""
            end = time.time() + timeout
            while time.time() < end:
                if chan.recv_ready():
                    buf += chan.recv(65535).decode("utf-8", "replace")
                    if token in buf:
                        break
                else:
                    time.sleep(0.1)
            return buf

        read_until("#", 5)
        chan.send("enable\n")
        echo = read_until("#", 5)
        if "assword" in echo.lower() or not re.search(r"#\s*$", echo.rstrip()):
            chan.send("\n")
            read_until("#", 5)
        chan.send("terminal length 0\n")
        read_until("#", 3)
        chan.send(cmd + "\n")
        out = read_until("#", 10)
    finally:
        ssh.close()
    raw = out.splitlines()
    lines = [ln for ln in raw if ln.strip() not in (cmd, "")]
    tail = list(lines)
    while tail and (not tail[-1].strip() or re.match(r"^\S*[#>]$", tail[-1].strip())):
        tail.pop()
    core = "\n".join(tail).strip()
    if core and re.match(r"^\^+$", core):
        return {"command": cmd, "syntax_error": True,
                "output": "%% Invalid input: command %r is invalid on this device" % cmd}
    return {"command": cmd, "output": "\n".join(lines)}


OPS = {"results": op_results, "probe": op_probe}


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
