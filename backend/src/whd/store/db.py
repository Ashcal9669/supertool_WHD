"""SQLite persistence: device identities, name history, discovery runs, events, captures.

Synchronous sqlite3 behind a lock; async callers use `asyncio.to_thread`.
Schema versions are tracked with PRAGMA user_version.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from whd.model.events import SEVERITY_RANK, Event, EventFilter

SCHEMA: list[str] = [
    # v1
    """
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        bus TEXT NOT NULL,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        last_snapshot_json TEXT NOT NULL
    );
    CREATE TABLE device_names (
        device_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        PRIMARY KEY (device_id, kind, name)
    );
    CREATE TABLE discovery_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at REAL NOT NULL,
        duration_ms REAL NOT NULL,
        mode TEXT NOT NULL,
        device_count INTEGER NOT NULL,
        issues_json TEXT NOT NULL
    );
    """,
    # v2: events
    """
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_boottime_ns INTEGER NOT NULL,
        ts_wall REAL NOT NULL,
        source TEXT NOT NULL,
        device_id TEXT,
        severity INTEGER NOT NULL,
        category TEXT NOT NULL,
        kind TEXT NOT NULL,
        json TEXT NOT NULL
    );
    CREATE INDEX events_ts ON events(ts_boottime_ns);
    CREATE INDEX events_dev ON events(device_id, ts_boottime_ns);
    CREATE INDEX events_cat ON events(category, ts_boottime_ns);
    """,
    # v3: captures
    """
    CREATE TABLE captures (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at REAL NOT NULL,
        started_ns INTEGER,
        stopped_ns INTEGER,
        config_json TEXT NOT NULL,
        stats_json TEXT NOT NULL,
        mode TEXT NOT NULL
    );
    CREATE TABLE capture_events (
        capture_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        ts_boottime_ns INTEGER NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (capture_id, seq)
    );
    CREATE TABLE capture_artifacts (
        capture_id TEXT NOT NULL,
        name TEXT NOT NULL,
        content_type TEXT NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (capture_id, name)
    );
    """,
    # v4: audit log for privileged / user-initiated actions
    """
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail_json TEXT NOT NULL
    );
    """,
    # v5: key/value state (journal cursor, settings)
    """
    CREATE TABLE kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated REAL NOT NULL
    );
    """,
]


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    def close(self) -> None:
        with self.lock:
            self.conn.close()

    def migrate(self) -> None:
        with self.lock:
            v = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
            for i in range(v, len(SCHEMA)):
                self.conn.executescript("BEGIN;" + SCHEMA[i] + f"PRAGMA user_version={i + 1};COMMIT;")

    @property
    def schema_version(self) -> int:
        with self.lock:
            return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    # ---------------------------------------------------------------- devices
    def upsert_devices(self, devices: Iterable[Any], now: float | None = None) -> dict[str, dict[str, Any]]:
        """Record devices; returns {id: {first_seen, last_seen, names: {kind: [names]}}}."""
        now = now or time.time()
        out: dict[str, dict[str, Any]] = {}
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                for d in devices:
                    snap = d.model_dump_json()
                    self.conn.execute(
                        "INSERT INTO devices(id,bus,first_seen,last_seen,last_snapshot_json) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, "
                        "last_snapshot_json=excluded.last_snapshot_json",
                        (d.id, d.bus, now, now, snap),
                    )
                    for kind, kind_names in (("netdev", d.netdevs), ("phy", d.phys)):
                        for n in kind_names:
                            self.conn.execute(
                                "INSERT INTO device_names(device_id,kind,name,first_seen,last_seen) "
                                "VALUES(?,?,?,?,?) ON CONFLICT(device_id,kind,name) "
                                "DO UPDATE SET last_seen=excluded.last_seen",
                                (d.id, kind, n, now, now),
                            )
                    row = self.conn.execute(
                        "SELECT first_seen,last_seen FROM devices WHERE id=?", (d.id,)
                    ).fetchone()
                    names: dict[str, list[str]] = {}
                    for r in self.conn.execute(
                        "SELECT kind,name FROM device_names WHERE device_id=? ORDER BY first_seen", (d.id,)
                    ):
                        names.setdefault(r["kind"], []).append(r["name"])
                    out[d.id] = {
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                        "names": names,
                    }
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return out

    def known_devices(self) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(r)
                for r in self.conn.execute(
                    "SELECT id,bus,first_seen,last_seen,last_snapshot_json FROM devices ORDER BY id"
                )
            ]

    def device_snapshot(self, device_id: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.conn.execute(
                "SELECT last_snapshot_json FROM devices WHERE id=?", (device_id,)
            ).fetchone()
        return json.loads(r[0]) if r else None

    def record_discovery(
        self,
        started_at: float,
        duration_ms: float,
        mode: str,
        device_count: int,
        issues: list[dict[str, Any]],
    ) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO discovery_runs(started_at,duration_ms,mode,device_count,issues_json) VALUES(?,?,?,?,?)",
                (started_at, duration_ms, mode, device_count, json.dumps(issues)),
            )
            return int(cur.lastrowid or 0)

    def discovery_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM discovery_runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) | {"issues": json.loads(r["issues_json"])} for r in rows]

    # ----------------------------------------------------------------- events
    def insert_events(self, events: list[Event]) -> None:
        if not events:
            return
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                for e in events:
                    cur = self.conn.execute(
                        "INSERT INTO events(ts_boottime_ns,ts_wall,source,device_id,severity,category,kind,json) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (
                            e.ts_boottime_ns,
                            e.ts_wall,
                            e.source,
                            e.device_id,
                            SEVERITY_RANK[e.severity],
                            e.category,
                            e.kind,
                            "",
                        ),
                    )
                    e.id = int(cur.lastrowid or 0)
                    self.conn.execute("UPDATE events SET json=? WHERE id=?", (e.model_dump_json(), e.id))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def query_events(
        self,
        flt: EventFilter | None = None,
        after_id: int | None = None,
        limit: int = 1000,
        order: str = "asc",
    ) -> list[Event]:
        flt = flt or EventFilter()
        where: list[str] = []
        args: list[Any] = []
        if after_id is not None:
            where.append("id > ?")
            args.append(after_id)
        if flt.device_id:
            where.append("device_id = ?")
            args.append(flt.device_id)
        if flt.categories:
            where.append(f"category IN ({','.join('?' * len(flt.categories))})")
            args += flt.categories
        if flt.min_severity:
            where.append("severity >= ?")
            args.append(SEVERITY_RANK[flt.min_severity])
        if flt.since_ns is not None:
            where.append("ts_boottime_ns >= ?")
            args.append(flt.since_ns)
        if flt.until_ns is not None:
            where.append("ts_boottime_ns <= ?")
            args.append(flt.until_ns)
        sql = "SELECT json FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY id {'DESC' if order == 'desc' else 'ASC'}"
        out: list[Event] = []
        with self.lock:
            cur = self.conn.execute(sql, args)
            for (j,) in cur:
                e = Event.model_validate_json(j)
                if flt.matches(e):
                    out.append(e)
                    if len(out) >= limit:
                        break
        return out

    def event_count(self) -> int:
        with self.lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def prune_events(self, keep: int) -> int:
        with self.lock:
            r = self.conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
            if r is None:
                return 0
            cur = self.conn.execute("DELETE FROM events WHERE id <= ?", (int(r) - keep,))
            return cur.rowcount

    # ---------------------------------------------------------------- captures
    def capture_upsert(self, cap: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO captures(id,name,state,created_at,started_ns,stopped_ns,config_json,stats_json,mode) "
                "VALUES(:id,:name,:state,:created_at,:started_ns,:stopped_ns,:config_json,:stats_json,:mode) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name,state=excluded.state,"
                "started_ns=excluded.started_ns,stopped_ns=excluded.stopped_ns,config_json=excluded.config_json,"
                "stats_json=excluded.stats_json",
                cap,
            )

    def capture_get(self, cid: str) -> dict[str, Any] | None:
        with self.lock:
            r = self.conn.execute("SELECT * FROM captures WHERE id=?", (cid,)).fetchone()
        return dict(r) if r else None

    def capture_list(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.conn.execute("SELECT * FROM captures ORDER BY created_at DESC")]

    def capture_delete(self, cid: str) -> None:
        with self.lock:
            self.conn.execute("BEGIN")
            self.conn.execute("DELETE FROM capture_events WHERE capture_id=?", (cid,))
            self.conn.execute("DELETE FROM capture_artifacts WHERE capture_id=?", (cid,))
            self.conn.execute("DELETE FROM captures WHERE id=?", (cid,))
            self.conn.execute("COMMIT")

    def capture_add_events(self, cid: str, start_seq: int, events: list[Event]) -> None:
        with self.lock:
            self.conn.executemany(
                "INSERT OR REPLACE INTO capture_events(capture_id,seq,ts_boottime_ns,json) VALUES(?,?,?,?)",
                [(cid, start_seq + i, e.ts_boottime_ns, e.model_dump_json()) for i, e in enumerate(events)],
            )

    def capture_drop_oldest(self, cid: str, count: int) -> None:
        with self.lock:
            self.conn.execute(
                "DELETE FROM capture_events WHERE capture_id=? AND seq IN "
                "(SELECT seq FROM capture_events WHERE capture_id=? ORDER BY seq ASC LIMIT ?)",
                (cid, cid, count),
            )

    def capture_events(self, cid: str, limit: int | None = None) -> list[Event]:
        sql = "SELECT seq, json FROM capture_events WHERE capture_id=? ORDER BY seq ASC"
        args: list[Any] = [cid]
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit)
        with self.lock:
            rows = list(self.conn.execute(sql, args))
        out = []
        for seq, js in rows:
            e = Event.model_validate_json(js)
            e.id = int(seq)  # capture-local sequence number (stable within one capture)
            out.append(e)
        return out

    def capture_event_stats(self, cid: str) -> tuple[int, int]:
        with self.lock:
            r = self.conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(json)),0) FROM capture_events WHERE capture_id=?",
                (cid,),
            ).fetchone()
        return int(r[0]), int(r[1])

    def capture_put_artifact(self, cid: str, name: str, content_type: str, data: bytes) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO capture_artifacts VALUES(?,?,?,?)", (cid, name, content_type, data)
            )

    def capture_artifacts(self, cid: str) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(r)
                for r in self.conn.execute(
                    "SELECT name,content_type,LENGTH(data) AS size FROM capture_artifacts WHERE capture_id=?",
                    (cid,),
                )
            ]

    def capture_artifact(self, cid: str, name: str) -> tuple[str, bytes] | None:
        with self.lock:
            r = self.conn.execute(
                "SELECT content_type,data FROM capture_artifacts WHERE capture_id=? AND name=?", (cid, name)
            ).fetchone()
        return (r[0], bytes(r[1])) if r else None

    # --------------------------------------------------------------------- kv
    def kv_get(self, key: str) -> str | None:
        with self.lock:
            r = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return str(r[0]) if r else None

    def kv_set(self, key: str, value: str) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO kv(key,value,updated) VALUES(?,?,?)", (key, value, time.time())
            )

    # ------------------------------------------------------------------ audit
    def audit(self, actor: str, action: str, detail: dict[str, Any]) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO audit(ts,actor,action,detail_json) VALUES(?,?,?,?)",
                (time.time(), actor, action, json.dumps(detail, default=str)),
            )

    def audit_log(self, limit: int = 200) -> list[dict[str, Any]]:
        with self.lock:
            return [
                dict(r) for r in self.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
            ]
