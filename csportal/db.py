"""Embedded database (SQLite) with forward-only migrations and a customer-scoped accessor."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE secrets (name TEXT PRIMARY KEY, sealed TEXT NOT NULL, updated_at TEXT);
    CREATE TABLE plans (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
        quota_gb INTEGER NOT NULL, price_gb_month REAL NOT NULL, min_monthly REAL DEFAULT 0,
        currency TEXT DEFAULT 'USD', egress_gb_price REAL DEFAULT 0,
        modules TEXT NOT NULL DEFAULT '[]',
        allow_public_buckets INTEGER DEFAULT 0, allow_platform_services INTEGER DEFAULT 0,
        allow_object_lock INTEGER DEFAULT 1, allow_own_identity INTEGER DEFAULT 0,
        max_buckets INTEGER DEFAULT 100, auto_quota_gb INTEGER DEFAULT 0, state TEXT DEFAULT 'active');
    CREATE TABLE customers (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, plan_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', tenant_ref TEXT, contact_email TEXT,
        quota_gb INTEGER NOT NULL, modules_off TEXT NOT NULL DEFAULT '[]', error TEXT DEFAULT '',
        created_at TEXT NOT NULL, closed_at TEXT,
        FOREIGN KEY (plan_id) REFERENCES plans(id));
    CREATE TABLE users (
        id TEXT PRIMARY KEY, customer_id TEXT, email TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL,
        pw_hash TEXT, totp_sealed TEXT, mfa_enabled INTEGER DEFAULT 0, totp_last_step INTEGER DEFAULT 0,
        failed INTEGER DEFAULT 0, locked_until TEXT, state TEXT DEFAULT 'invited',
        created_at TEXT NOT NULL, last_login TEXT,
        UNIQUE (customer_id, email),
        FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE UNIQUE INDEX users_email_csp ON users(email) WHERE customer_id IS NULL;
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, surface TEXT NOT NULL, csrf TEXT NOT NULL,
        mfa_ok INTEGER DEFAULT 0, created_at TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at TEXT NOT NULL,
        ip TEXT, flash TEXT DEFAULT '', FOREIGN KEY (user_id) REFERENCES users(id));
    CREATE TABLE invitations (
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, purpose TEXT NOT NULL,
        expires_at TEXT NOT NULL, used INTEGER DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id));
    CREATE TABLE usage_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id TEXT NOT NULL, ts TEXT NOT NULL,
        bytes_used INTEGER NOT NULL, objects INTEGER NOT NULL, buckets TEXT DEFAULT '[]',
        FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE INDEX usage_samples_ct ON usage_samples(customer_id, ts);
    CREATE TABLE statements (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, period TEXT NOT NULL, avg_gb REAL NOT NULL,
        peak_gb REAL NOT NULL, storage_amount REAL NOT NULL, other_amount REAL DEFAULT 0, total REAL NOT NULL,
        currency TEXT NOT NULL, state TEXT DEFAULT 'closed', adjusts TEXT, note TEXT DEFAULT '',
        created_at TEXT NOT NULL, UNIQUE (customer_id, period, adjusts),
        FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE TABLE alert_rules (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, threshold_pct INTEGER NOT NULL,
        channel TEXT NOT NULL, target TEXT NOT NULL, last_fired TEXT, active INTEGER DEFAULT 1,
        FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE TABLE alert_events (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, rule_id TEXT, ts TEXT NOT NULL,
        message TEXT NOT NULL, FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE TABLE quota_requests (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, requested_gb INTEGER NOT NULL, reason TEXT,
        state TEXT DEFAULT 'open', decided_by TEXT, decided_at TEXT, decision_note TEXT, created_at TEXT NOT NULL,
        requested_by TEXT, FOREIGN KEY (customer_id) REFERENCES customers(id));
    CREATE TABLE notices (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT, starts_at TEXT, ends_at TEXT,
        active INTEGER DEFAULT 1, created_at TEXT NOT NULL);
    CREATE TABLE outbox (
        id TEXT PRIMARY KEY, customer_id TEXT, to_addr TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
        state TEXT DEFAULT 'queued', error TEXT, created_at TEXT NOT NULL, sent_at TEXT);
    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, customer_id TEXT, actor TEXT NOT NULL,
        actor_kind TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT,
        request_id TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE INDEX audit_customer ON audit(customer_id, id);
    CREATE TABLE jobs_state (name TEXT PRIMARY KEY, last_run TEXT, last_status TEXT, last_detail TEXT);
    """),
    (2, """
    CREATE TABLE audit_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, upto_id INTEGER NOT NULL, hash TEXT NOT NULL, mac TEXT NOT NULL);
    CREATE TABLE audit_anchor (
        id INTEGER PRIMARY KEY CHECK (id = 1), upto_id INTEGER NOT NULL, hash TEXT NOT NULL, mac TEXT NOT NULL,
        pruned_at TEXT NOT NULL, rows_pruned INTEGER NOT NULL);
    ALTER TABLE sessions ADD COLUMN reauth_at TEXT;
    CREATE TABLE approvals (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, summary TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}',
        requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending', decided_by TEXT, decided_at TEXT, note TEXT DEFAULT '');
    """),
]

# Tables whose rows belong to one customer. The scoped accessor refuses anything else.
CUSTOMER_TABLES = {"usage_samples", "statements", "alert_rules", "alert_events", "quota_requests", "audit"}
_SCOPED_COLS = {
    "usage_samples": {"ts", "bytes_used", "objects", "buckets"},
    "statements": {"period", "avg_gb", "peak_gb", "storage_amount", "other_amount", "total", "currency", "state",
                   "adjusts", "note", "created_at", "id"},
    "alert_rules": {"id", "threshold_pct", "channel", "target", "last_fired", "active"},
    "alert_events": {"id", "rule_id", "ts", "message"},
    "quota_requests": {"id", "requested_gb", "reason", "state", "decided_by", "decided_at", "decision_note",
                       "created_at", "requested_by"},
}


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write = threading.RLock()
        self.migrate()

    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA synchronous=FULL")
            self._local.c = c
        return c

    def migrate(self) -> int:
        c = self.conn()
        c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        row = c.execute("SELECT MAX(version) v FROM schema_version").fetchone()
        cur = row["v"] or 0
        for ver, sql in MIGRATIONS:
            if ver > cur:
                with self.tx():
                    for stmt in [s for s in sql.split(";\n") if s.strip()]:
                        c.execute(stmt)
                    c.execute("INSERT INTO schema_version(version) VALUES (?)", (ver,))
                cur = ver
        return cur

    def schema_version(self) -> int:
        return self.conn().execute("SELECT MAX(version) v FROM schema_version").fetchone()["v"] or 0

    @contextmanager
    def tx(self):
        with self._write:
            c = self.conn()
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def run(self, sql: str, params=()) -> sqlite3.Cursor:
        with self._write:
            return self.conn().execute(sql, params)

    def one(self, sql: str, params=()):
        return self.conn().execute(sql, params).fetchone()

    def all(self, sql: str, params=()):
        return self.conn().execute(sql, params).fetchall()

    def setting(self, key: str, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set_setting(self, key: str, value: str) -> None:
        self.run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, value))

    def for_customer(self, customer_id: str) -> "Scoped":
        return Scoped(self, customer_id)

    def backup(self, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._write:
            out = sqlite3.connect(dest)
            try:
                self.conn().backup(out)
            finally:
                out.close()


class Scoped:
    """Data access limited to one customer. Every query carries the customer id; modules on the
    customer surface use only this accessor, so a module cannot read another customer's rows."""

    def __init__(self, db: Database, customer_id: str):
        if not customer_id:
            raise ValueError("customer id required")
        self.db, self.cid = db, customer_id

    def _check(self, table: str):
        if table not in CUSTOMER_TABLES:
            raise PermissionError(f"table {table} is not customer-scoped")

    def select(self, table: str, where: str = "", params=(), order: str = "", limit: int = 0):
        self._check(table)
        sql = f"SELECT * FROM {table} WHERE customer_id=?" + (f" AND ({where})" if where else "")
        if order:
            sql += f" ORDER BY {order}"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.db.all(sql, (self.cid, *params))

    def one(self, table: str, where: str = "", params=(), order: str = ""):
        r = self.select(table, where, params, order, 1)
        return r[0] if r else None

    def insert(self, table: str, **vals) -> None:
        self._check(table)
        if table not in _SCOPED_COLS:
            raise PermissionError(f"table {table} is read-only for scoped access")
        bad = set(vals) - _SCOPED_COLS[table]
        if bad:
            raise ValueError(f"unknown columns {bad}")
        cols = ["customer_id", *vals]
        self.db.run(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                    (self.cid, *vals.values()))

    def update(self, table: str, id_: str, **vals) -> int:
        self._check(table)
        if table not in _SCOPED_COLS:
            raise PermissionError(f"table {table} is read-only for scoped access")
        bad = set(vals) - _SCOPED_COLS[table]
        if bad:
            raise ValueError(f"unknown columns {bad}")
        sets = ",".join(f"{k}=?" for k in vals)
        return self.db.run(f"UPDATE {table} SET {sets} WHERE id=? AND customer_id=?",
                           (*vals.values(), id_, self.cid)).rowcount

    def delete(self, table: str, id_: str) -> int:
        self._check(table)
        if table not in _SCOPED_COLS or table in ("statements", "audit"):
            raise PermissionError(f"table {table} cannot be deleted from")
        return self.db.run(f"DELETE FROM {table} WHERE id=? AND customer_id=?", (id_, self.cid)).rowcount
