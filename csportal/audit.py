"""Append-only, hash-chained audit log with signed checkpoints and retention.

Each record carries the hash of the one before it, so changing or removing a record in the middle breaks the chain.
That alone can not show that the *newest* records were cut off, or that the whole chain was rebuilt. So the portal
also writes **checkpoints**: the id and hash of the newest record, signed (HMAC-SHA-256) with a key derived from the
master key. Verification fails if a checkpoint does not match the chain, has a bad signature, or points past the end.

**Retention.** Records older than the retention period are written to an archive file and removed. The hash and id
of the last removed record are kept in a signed **anchor**, so the remaining chain still verifies from that point.
Nothing is removed if the chain does not verify first.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import threading
from pathlib import Path

from . import logs
from .util import iso, parse_iso, utcnow

log = logging.getLogger("csportal.security")
_GENESIS = "0" * 64
_COLS = ("ts", "customer_id", "actor", "actor_kind", "action", "target", "detail", "ip", "request_id")


class Audit:
    def __init__(self, db, mac_key: bytes | None = None):
        self.db = db
        self._lock = threading.Lock()
        self._mac_key = mac_key

    @staticmethod
    def _digest(prev: str, row: dict) -> str:
        blob = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((prev + blob).encode()).hexdigest()

    def _mac(self, kind: str, upto_id: int, h: str) -> str:
        if not self._mac_key:
            return ""
        return hmac.new(self._mac_key, f"{kind}:{upto_id}:{h}".encode(), hashlib.sha256).hexdigest()

    def _mac_ok(self, kind: str, upto_id: int, h: str, mac: str) -> bool:
        return not self._mac_key or hmac.compare_digest(self._mac(kind, upto_id, h), mac or "")

    def record(self, action: str, actor: str = "system", actor_kind: str = "system", customer_id: str | None = None,
               target: str = "", detail: str = "", ip: str = "") -> int:
        ts = iso()
        rid = logs.request_id.get()
        with self._lock, self.db.tx() as c:
            last = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            if last:
                prev = last["hash"]
            else:
                anchor = c.execute("SELECT hash FROM audit_anchor WHERE id=1").fetchone()
                prev = anchor["hash"] if anchor else _GENESIS
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

    # ------------------------------------------------------------------ verification
    def verify_full(self) -> dict:
        """{ok, bad_id, rows, problems:[...], checkpoints, anchor_id}. Problems are plain words."""
        problems: list[str] = []
        bad_id = None
        anchor = self.db.one("SELECT * FROM audit_anchor WHERE id=1")
        prev = _GENESIS
        if anchor:
            if not self._mac_ok("anchor", anchor["upto_id"], anchor["hash"], anchor["mac"]):
                problems.append("The retention anchor has a bad signature.")
            prev = anchor["hash"]
        n, last_id, first = 0, None, True
        hashes: dict[int, str] = {}
        for r in self.db.conn().execute("SELECT * FROM audit ORDER BY id"):
            row = {k: r[k] for k in _COLS}
            if r["prev_hash"] != prev or self._digest(prev, row) != r["hash"]:
                problems.append(f"The chain is broken at record {r['id']}.")
                bad_id = r["id"]
                break
            if first and anchor and r["id"] <= anchor["upto_id"]:
                problems.append("Records that should have been removed by retention are still present out of order.")
                bad_id = r["id"]
                break
            first = False
            prev, n, last_id = r["hash"], n + 1, r["id"]
            hashes[r["id"]] = r["hash"]
        cps = self.db.all("SELECT * FROM audit_checkpoints ORDER BY id")
        if bad_id is None:
            for cp in cps:
                if anchor and cp["upto_id"] <= anchor["upto_id"]:
                    continue
                if not self._mac_ok("checkpoint", cp["upto_id"], cp["hash"], cp["mac"]):
                    problems.append(f"Checkpoint {cp['id']} has a bad signature.")
                elif cp["upto_id"] not in hashes:
                    problems.append(f"Records up to {cp['upto_id']} were expected (checkpoint {cp['id']}) but are missing.")
                elif hashes[cp["upto_id"]] != cp["hash"]:
                    problems.append(f"Record {cp['upto_id']} does not match checkpoint {cp['id']}: the log was rewritten.")
        return {"ok": not problems, "bad_id": bad_id, "rows": n, "problems": problems, "checkpoints": len(cps),
                "anchor_id": anchor["upto_id"] if anchor else None}

    def verify(self) -> tuple[bool, int | None, int]:
        """Return (ok, first_bad_id, rows_checked)."""
        v = self.verify_full()
        return v["ok"], v["bad_id"], v["rows"]

    # ------------------------------------------------------------------ checkpoints
    def checkpoint(self) -> bool:
        """Sign the newest record. Returns False when there is nothing new to sign."""
        with self._lock, self.db.tx() as c:
            last = c.execute("SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            if not last:
                return False
            cp = c.execute("SELECT upto_id FROM audit_checkpoints ORDER BY id DESC LIMIT 1").fetchone()
            if cp and cp["upto_id"] == last["id"]:
                return False
            c.execute("INSERT INTO audit_checkpoints(ts,upto_id,hash,mac) VALUES (?,?,?,?)",
                      (iso(), last["id"], last["hash"], self._mac("checkpoint", last["id"], last["hash"])))
            # keep the newest 500; older ones add nothing once a newer one covers them
            c.execute("DELETE FROM audit_checkpoints WHERE id <= (SELECT MAX(id) FROM audit_checkpoints) - 500")
        return True

    def resign(self, new_key: bytes | None) -> None:
        """Sign every checkpoint and the anchor again under a new key (used by master-key rotation)."""
        self._mac_key = new_key
        with self.db.tx() as c:
            for cp in c.execute("SELECT * FROM audit_checkpoints").fetchall():
                c.execute("UPDATE audit_checkpoints SET mac=? WHERE id=?", (self._mac("checkpoint", cp["upto_id"], cp["hash"]), cp["id"]))
            a = c.execute("SELECT * FROM audit_anchor WHERE id=1").fetchone()
            if a:
                c.execute("UPDATE audit_anchor SET mac=? WHERE id=1", (self._mac("anchor", a["upto_id"], a["hash"]),))

    # ------------------------------------------------------------------ retention
    def prune(self, retention_days: int, archive_dir: Path, keep_last: int = 1000) -> dict:
        """Archive and remove records older than the retention period. Refuses to act on a chain that does not verify."""
        v = self.verify_full()
        if not v["ok"]:
            return {"pruned": 0, "refused": "The audit chain does not verify. " + " ".join(v["problems"][:2])}
        cutoff = iso(utcnow() - dt.timedelta(days=retention_days))
        with self._lock:
            newest = self.db.one("SELECT MAX(id) m FROM audit")["m"] or 0
            row = self.db.one("SELECT MAX(id) m FROM audit WHERE ts < ? AND id <= ?", (cutoff, max(0, newest - keep_last)))
            upto = row["m"] if row else None
            if not upto:
                return {"pruned": 0, "refused": ""}
            rows = self.db.all("SELECT * FROM audit WHERE id <= ? ORDER BY id", (upto,))
            archive_dir.mkdir(parents=True, exist_ok=True)
            name = f"audit-{rows[0]['id']}-{rows[-1]['id']}.jsonl"
            body = "".join(json.dumps(dict(r), sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
            (archive_dir / name).write_text(body, encoding="utf-8")
            (archive_dir / (name + ".sha256")).write_text(hashlib.sha256(body.encode()).hexdigest() + "  " + name + "\n", encoding="utf-8")
            last_hash = rows[-1]["hash"]
            with self.db.tx() as c:
                old = c.execute("SELECT rows_pruned FROM audit_anchor WHERE id=1").fetchone()
                total = len(rows) + (old["rows_pruned"] if old else 0)
                c.execute("DELETE FROM audit WHERE id <= ?", (upto,))
                c.execute("INSERT INTO audit_anchor(id,upto_id,hash,mac,pruned_at,rows_pruned) VALUES (1,?,?,?,?,?) "
                          "ON CONFLICT(id) DO UPDATE SET upto_id=excluded.upto_id, hash=excluded.hash, mac=excluded.mac, "
                          "pruned_at=excluded.pruned_at, rows_pruned=excluded.rows_pruned",
                          (upto, last_hash, self._mac("anchor", upto, last_hash), iso(), total))
                c.execute("DELETE FROM audit_checkpoints WHERE upto_id <= ?", (upto,))
        self.record("audit.pruned", "system", "system", None, name, f"{len(rows)} records up to id {upto} archived and removed")
        self.checkpoint()
        return {"pruned": len(rows), "archive": name, "refused": ""}

    # ------------------------------------------------------------------ reading
    def for_customer(self, customer_id: str, limit: int = 200):
        return self.db.all("SELECT * FROM audit WHERE customer_id=? ORDER BY id DESC LIMIT ?", (customer_id, limit))

    def recent(self, limit: int = 200, action_like: str = ""):
        if action_like:
            return self.db.all("SELECT * FROM audit WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                               (action_like + "%", limit))
        return self.db.all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
