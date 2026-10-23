"""网关状态：单床租约（fencing token）、任务记录、初始化确认码；床锁用 flock。

床锁 `<state>/bed.lock`：
- 上机时锁的文件描述符继承给 runner 进程组（pass_fds），pytest 活着锁就在，进程死了内核自动释放；
- 探测、初始化在网关进程里非阻塞取同一把锁，取不到就是 busy；
- 不写 pid、不删锁文件——InfoTest run.lock 的几种竞态都来自“写 pid + 删文件”。

租约是逻辑上的“谁在用这张床”：带 TTL，要续期；会改床状态的操作必须带当前的 lease_id 与 token。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
 request_id TEXT PRIMARY KEY, holder TEXT NOT NULL, xlsx_sha256 TEXT NOT NULL,
 not_after REAL NOT NULL, received_at REAL NOT NULL, state TEXT NOT NULL,
 reply TEXT, task_id TEXT, module TEXT, stage TEXT, reached_device INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS request_events (
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, state TEXT NOT NULL,
 event_at REAL NOT NULL, task_id TEXT, stage TEXT, reached_device INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS request_meta (name TEXT PRIMARY KEY, value REAL NOT NULL);
CREATE TABLE IF NOT EXISTS lease (
    bed        TEXT PRIMARY KEY,
    lease_id   TEXT NOT NULL,
    holder     TEXT NOT NULL,
    token      INTEGER NOT NULL,
    acquired_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    released   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks (
    task_id    TEXT PRIMARY KEY,
    request_id TEXT,
    lease_id   TEXT NOT NULL,
    token      INTEGER NOT NULL,
    holder     TEXT NOT NULL,
    module     TEXT NOT NULL,
    autoid     TEXT NOT NULL,
    build      TEXT NOT NULL,
    case_ids   TEXT NOT NULL,
    xlsx_sha256 TEXT NOT NULL,
    staging_dir TEXT NOT NULL,
    deliver_epoch REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS init_challenges (
    code_hash  TEXT PRIMARY KEY,
    holder     TEXT NOT NULL,
    lease_id   TEXT NOT NULL,
    plan_json  TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
"""

BED = "bed"


class LeaseError(RuntimeError):
    """租约不成立：没有、过期、被别人持有、token 过时。消息给模型看，用英文。"""


class StateStore:
    def __init__(self, state_dir: Path, lease_ttl_s: int = 1800):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.lock_path = self.dir / "bed.lock"
        self.db_path = self.dir / "state.db"
        self.lease_ttl_s = lease_ttl_s
        with self._conn() as conn:
            conn.executescript('BEGIN IMMEDIATE;\n' + _SCHEMA)
            conn.execute("INSERT OR IGNORE INTO request_meta(name,value) VALUES('journal_since',?)", (time.time(),))
            conn.execute("INSERT OR IGNORE INTO request_meta(name,value) VALUES('journal_id',?)", ('journal-' + secrets.token_hex(16),))
            if 'request_id' not in {r[1] for r in conn.execute('PRAGMA table_info(tasks)')}:
                conn.execute('ALTER TABLE tasks ADD COLUMN request_id TEXT')
            if 'module' not in {r[1] for r in conn.execute('PRAGMA table_info(requests)')}:
                conn.execute('ALTER TABLE requests ADD COLUMN module TEXT')
                conn.execute('UPDATE requests SET module=(SELECT module FROM tasks WHERE tasks.task_id=requests.task_id)')
            conn.commit()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=10000")
            yield conn
        finally:
            conn.close()

    def journal_identity(self):
        with self._conn() as conn:
            return dict(conn.execute("SELECT name,value FROM request_meta WHERE name IN ('journal_id','journal_since')"))

    @staticmethod
    def _request_now(conn):
        floor = conn.execute("SELECT max(value) FROM request_meta WHERE name IN ('clock_floor','journal_since')").fetchone()[0]
        now = max(time.time(), floor or 0.0)
        conn.execute("INSERT INTO request_meta(name,value) VALUES('clock_floor',?) "
                     "ON CONFLICT(name) DO UPDATE SET value=max(value,excluded.value)", (now,))
        return now

    def request_lock_path(self, request_id):
        # Fixed stripes avoid retaining a lock inode forever for every expired request.
        return self.dir / ('request-' + hashlib.sha256(request_id.encode()).hexdigest()[:2] + '.lock')

    @contextmanager
    def request_lock(self, request_id: str):
        path = self.request_lock_path(request_id)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def reserve_request(self, request_id, holder, sha256, not_after, admission_error=None, module=None):
        with self._conn() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = self._request_now(conn)
            row = conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone()
            if row:
                conn.commit()
                return dict(row), False
            floor = conn.execute("SELECT value FROM request_meta WHERE name='gc_before'").fetchone()
            if floor and not_after <= floor[0]:
                conn.commit()
                return {'collected': True}, False
            error = admission_error or ('request expired before admission; use a new request_id and deadline' if not_after <= now else None)
            reply = json.dumps({'ok': False, 'error': error, 'stage': 'admission', 'reached_device': False,
                                'request_id': request_id, 'request_record': 'recorded'}) if error else None
            conn.execute('INSERT INTO requests(request_id,holder,xlsx_sha256,not_after,received_at,state,stage,reply,module) '
                         'VALUES(?,?,?,?,?,?,?,?,?)', (request_id,holder,sha256,not_after,now,'rejected' if error else 'received','admission',reply,module))
            row = dict(conn.execute('SELECT * FROM requests WHERE request_id=?', (request_id,)).fetchone())
            self._request_event(conn,request_id)
            row['expired'] = not_after <= now
            conn.commit()
            return row, True

    def update_request(self, request_id, **fields):
        with self._conn() as conn:
            conn.execute('BEGIN IMMEDIATE')
            before = conn.execute('SELECT state FROM requests WHERE request_id=?',(request_id,)).fetchone()
            conn.execute('UPDATE requests SET ' + ','.join(k+'=?' for k in fields) +
                         ' WHERE request_id=?', (*fields.values(),request_id))
            if before and 'state' in fields and before[0] != fields['state']:
                self._request_event(conn,request_id)
            conn.commit()

    @staticmethod
    def _request_event(conn, request_id):
        conn.execute('INSERT INTO request_events(request_id,state,event_at,task_id,stage,reached_device) '
                     'SELECT request_id,state,?,task_id,stage,reached_device FROM requests WHERE request_id=?',
                     (StateStore._request_now(conn),request_id))

    def flush_request_events(self, append):
        # At least once: a crash between append and commit may repeat the same event_id,
        # but cannot lose a committed transition. Never discard a failed append.
        while True:
            with self._conn() as conn:
                conn.execute('BEGIN IMMEDIATE')
                rows = conn.execute('SELECT * FROM request_events ORDER BY event_id LIMIT 128').fetchall()
                if not rows:
                    conn.commit()
                    return
                for row in rows:
                    if not append(dict(row)):
                        conn.commit()
                        return
                    conn.execute('DELETE FROM request_events WHERE event_id=?',(row['event_id'],))
                conn.commit()

    def gc_requests(self, cutoff):
        with self._conn() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = self._request_now(conn)
            rows = conn.execute("SELECT request_id,not_after FROM requests WHERE received_at<? "
                                "AND not_after<? AND state IN ('rejected','started','not_started')",
                                (cutoff,now)).fetchall()
            if rows:
                floor = max(r['not_after'] for r in rows)
                conn.execute("INSERT INTO request_meta(name,value) VALUES('gc_before',?) "
                             "ON CONFLICT(name) DO UPDATE SET value=max(value,excluded.value)",(floor,))
                conn.executemany('DELETE FROM requests WHERE request_id=?',[(r['request_id'],) for r in rows])
            conn.commit()
            return len(rows)

    def request_snapshot(self, request_id, holder):
        with self._conn() as conn:
            conn.execute('BEGIN IMMEDIATE')
            now = self._request_now(conn)
            row = conn.execute('SELECT * FROM requests WHERE request_id=? AND holder=?',
                               (request_id,holder)).fetchone()
            floor = conn.execute("SELECT value FROM request_meta WHERE name='gc_before'").fetchone()
            conn.commit()
            since = conn.execute("SELECT value FROM request_meta WHERE name='journal_since'").fetchone()[0]
            return (dict(row) if row else None), now, max(since, floor[0] if floor else since)

    # ── 床锁 ─────────────────────────────────────────────
    def try_bed_lock(self) -> int | None:
        """非阻塞取床锁；成功返回持锁的 fd（调用方负责关闭或交给子进程继承）。"""
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd

    def bed_busy(self) -> bool:
        fd = self.try_bed_lock()
        if fd is None:
            return True
        os.close(fd)
        return False

    @contextmanager
    def bed_lock(self) -> Iterator[bool]:
        fd = self.try_bed_lock()
        try:
            yield fd is not None
        finally:
            if fd is not None:
                os.close(fd)

    # ── 租约 ─────────────────────────────────────────────
    def _next_token(self, conn: sqlite3.Connection) -> int:
        conn.execute("INSERT OR IGNORE INTO counters(name, value) VALUES ('fencing', 0)")
        conn.execute("UPDATE counters SET value = value + 1 WHERE name='fencing'")
        return int(conn.execute("SELECT value FROM counters WHERE name='fencing'").fetchone()[0])

    def _current(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        row = conn.execute("SELECT * FROM lease WHERE bed=?", (BED,)).fetchone()
        if row is None or row["released"] or row["expires_at"] < time.time():
            return None
        return row

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        return {"lease_id": row["lease_id"], "holder": row["holder"], "token": row["token"],
                "expires_at": int(row["expires_at"]),
                "expires_in_s": max(0, int(row["expires_at"] - time.time()))}

    def acquire(self, holder: str) -> dict[str, Any]:
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                current = self._current(conn)
                if current is not None and current["holder"] != holder:
                    conn.execute("COMMIT")
                    raise LeaseError(
                        f"bed is leased by {current['holder']} for another "
                        f"{int(current['expires_at'] - now)}s")
                if current is not None:
                    conn.execute("UPDATE lease SET expires_at=? WHERE bed=?",
                                 (now + self.lease_ttl_s, BED))
                    row = conn.execute("SELECT * FROM lease WHERE bed=?", (BED,)).fetchone()
                    conn.execute("COMMIT")
                    return {**self._public(row), "renewed": True}
                token = self._next_token(conn)
                lease_id = "lease-" + secrets.token_hex(8)
                conn.execute(
                    "INSERT INTO lease(bed, lease_id, holder, token, acquired_at, expires_at,"
                    " released) VALUES (?, ?, ?, ?, ?, ?, 0) ON CONFLICT(bed) DO UPDATE SET"
                    " lease_id=excluded.lease_id, holder=excluded.holder, token=excluded.token,"
                    " acquired_at=excluded.acquired_at, expires_at=excluded.expires_at,"
                    " released=0", (BED, lease_id, holder, token, now, now + self.lease_ttl_s))
                row = conn.execute("SELECT * FROM lease WHERE bed=?", (BED,)).fetchone()
                conn.execute("COMMIT")
            except LeaseError:
                raise
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return {**self._public(row), "renewed": False}

    def check(self, holder: str, lease_id: str, token: Any) -> dict[str, Any]:
        with self._conn() as conn:
            current = self._current(conn)
        if current is None:
            raise LeaseError("no active lease on this bed; call lease_acquire first")
        if current["holder"] != holder or current["lease_id"] != lease_id:
            raise LeaseError("this lease is not held by you (expired or taken over)")
        try:
            token_value = int(token)
        except (TypeError, ValueError):
            raise LeaseError("token must be the integer returned by lease_acquire") from None
        if token_value != current["token"]:
            raise LeaseError("stale fencing token; the lease was re-acquired since")
        return self._public(current)

    def heartbeat(self, holder: str, lease_id: str, token: Any) -> dict[str, Any]:
        self.check(holder, lease_id, token)
        with self._conn() as conn:
            conn.execute("UPDATE lease SET expires_at=? WHERE bed=? AND lease_id=?",
                         (time.time() + self.lease_ttl_s, BED, lease_id))
            row = conn.execute("SELECT * FROM lease WHERE bed=?", (BED,)).fetchone()
        return self._public(row)

    def release(self, holder: str, lease_id: str, token: Any) -> None:
        self.check(holder, lease_id, token)
        with self._conn() as conn:
            conn.execute("UPDATE lease SET released=1 WHERE bed=? AND lease_id=?",
                         (BED, lease_id))

    def status(self) -> dict[str, Any]:
        with self._conn() as conn:
            current = self._current(conn)
        return {"leased": current is not None,
                **(self._public(current) if current is not None else {}),
                "bed_busy": self.bed_busy()}

    def expire_now_for_tests(self) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE lease SET expires_at=0 WHERE bed=?", (BED,))

    # ── 任务 ─────────────────────────────────────────────
    def record_task(self, **fields: Any) -> None:
        fields = dict(fields)
        request_id = fields.get("request_id")
        fields["case_ids"] = json.dumps(fields["case_ids"])
        columns = ", ".join(fields)
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"INSERT INTO tasks({columns}) VALUES ({', '.join('?' * len(fields))})",
                         tuple(fields.values()))
            if request_id:
                conn.execute("UPDATE requests SET state='starting',task_id=? WHERE request_id=?",
                             (fields['task_id'],request_id))
                self._request_event(conn,request_id)
            conn.commit()

    def protected_request_tasks(self):
        with self._conn() as conn:
            return {r[0] for r in conn.execute("SELECT task_id FROM requests WHERE task_id IS NOT NULL "
                    "AND (not_after>=? OR state IN ('received','starting'))",(time.time(),))}

    def task_request(self, task_id):
        with self._conn() as conn:
            row = conn.execute('SELECT request_id FROM tasks WHERE task_id=?',(task_id,)).fetchone()
            return row[0] if row else None

    def task(self, task_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["case_ids"] = json.loads(data["case_ids"])
        return data

    def tasks_created_before(self, epoch: float) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT task_id FROM tasks WHERE created_at<?",
                                (epoch,)).fetchall()
        return [row[0] for row in rows]

    def delete_tasks(self, task_ids: list[str]) -> None:
        with self._conn() as conn:
            conn.executemany("DELETE FROM tasks WHERE task_id=?", [(t,) for t in task_ids])

    def next_delivery(self, module: str, autoid: str, after_epoch: float) -> float | None:
        """同一落位目录（module + autoid）在 after_epoch 之后的下一次投递时刻；没有就是 None。"""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MIN(deliver_epoch) FROM tasks WHERE module=? AND autoid=? AND deliver_epoch>?",
                (module, autoid, after_epoch)).fetchone()
        return float(row[0]) if row and row[0] is not None else None

    # ── 初始化确认码 ─────────────────────────────────────
    def new_challenge(self, holder: str, lease_id: str, plan: dict[str, Any],
                      ttl_s: int = 300) -> str:
        code = secrets.token_hex(4)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO init_challenges(code_hash, holder, lease_id, plan_json, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (hashlib.sha256(code.encode()).hexdigest(), holder, lease_id,
                 json.dumps(plan, sort_keys=True), time.time() + ttl_s))
        return code

    def consume_challenge(self, code: str, holder: str, lease_id: str) -> dict[str, Any]:
        digest = hashlib.sha256(str(code or "").encode()).hexdigest()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM init_challenges WHERE code_hash=?",
                               (digest,)).fetchone()
            if (row is None or row["used"] or row["expires_at"] < time.time()
                    or row["holder"] != holder or row["lease_id"] != lease_id):
                conn.execute("COMMIT")
                raise LeaseError("confirmation code is unknown, used, expired, or not yours; "
                                 "call init_device with step=prepare again")
            conn.execute("UPDATE init_challenges SET used=1 WHERE code_hash=?", (digest,))
            conn.execute("COMMIT")
        return json.loads(row["plan_json"])
