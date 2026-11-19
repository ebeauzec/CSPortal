"""Append-only, hash-chained audit log. Tampering with any row breaks the chain."""
from __future__ import annotations

import hashlib
import json
import logging
import threading

from . import logs
from .util import iso

log = logging.getLogger("csportal.security")
_GENESIS = "0" * 64


class Audit:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()

    @staticmethod
    def _digest(prev: str, row: dict) -> str:
        blob = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((prev + blob).encode()).hexdigest()

    def record(self, action: str, actor: str = "system", actor_kind: str = "system", customer_id: str | None = None,
               target: str = "", detail: str = "", ip: str = "") -> int:
        ts = iso()
        rid = logs.request_id.get()
        with self._lock, self.db.tx() as c:
            last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else _GENESIS
            row = {"ts": ts, "customer_id": customer_id, "actor": actor, "actor_kind": actor_kind,
                   "action": action, "target": target, "detail": detail, "ip": ip, "request_id": rid}
            h = self._digest(prev, row)
            cur = c.execute(
                "INSERT INTO audit(ts,customer_id,actor,actor_kind,action,target,detail,ip,request_id,prev_hash,hash)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ts, customer_id, actor, actor_kind, action, target, detail, ip, rid, prev, h))
            rowid = cur.lastrowid
        logs.event(log, logging.INFO, "audit", audit_id=rowid, action=action, actor=actor,
                   customer_id=customer_id, target=target)
        return rowid

    def verify(self) -> tuple[bool, int | None, int]:
        """Return (ok, first_bad_id, rows_checked)."""
        prev, n = _GENESIS, 0
        for r in self.db.conn().execute("SELECT * FROM audit ORDER BY id"):
            row = {"ts": r["ts"], "customer_id": r["customer_id"], "actor": r["actor"],
                   "actor_kind": r["actor_kind"], "action": r["action"], "target": r["target"],
                   "detail": r["detail"], "ip": r["ip"], "request_id": r["request_id"]}
            if r["prev_hash"] != prev or self._digest(prev, row) != r["hash"]:
                return False, r["id"], n
            prev, n = r["hash"], n + 1
        return True, None, n

    def for_customer(self, customer_id: str, limit: int = 200):
        return self.db.all("SELECT * FROM audit WHERE customer_id=? ORDER BY id DESC LIMIT ?", (customer_id, limit))

    def recent(self, limit: int = 200, action_like: str = ""):
        if action_like:
            return self.db.all("SELECT * FROM audit WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                               (action_like + "%", limit))
        return self.db.all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
