"""Background jobs: usage sampling, alert checks, month close, session clean-up (and demo data growth)."""
from __future__ import annotations

import logging
import threading
import time
import traceback

import json

from . import approvals, logs, ops, services
from .util import iso

jlog = logging.getLogger("csportal.job")


class JobRunner:
    def __init__(self, app):
        self.app = app
        self.jobs: list[dict] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        jc = app.cfg.d["jobs"]
        self.add("usage-sample", jc["usage_sample_minutes"] * 60, self._usage)
        self.add("alert-check", jc["alert_check_minutes"] * 60, lambda: f"{services.check_alerts(app)} alert(s) sent")
        self.add("month-close", 6 * 3600, self._month)
        self.add("session-purge", 3600, lambda: f"{app.auth.purge_expired()} session(s) removed")
        self.add("audit-checkpoint", jc["audit_checkpoint_minutes"] * 60, self._checkpoint)
        self.add("audit-retention", 24 * 3600, self._retention)
        self.add("approval-expiry", 3600, lambda: f"{approvals.expire(app)} request(s) expired")
        if jc["backup_hours"] > 0:
            self.add("backup", jc["backup_hours"] * 3600, self._backup)
        if jc["drift_hours"] > 0:
            self.add("drift-check", jc["drift_hours"] * 3600, self._drift)
        if app.cfg.demo and hasattr(app.backend, "advance"):
            self.add("demo-growth", 120, self._demo)

    def add(self, name: str, every_s: int, fn) -> None:
        self.jobs.append({"name": name, "every": every_s, "fn": fn, "next": time.monotonic() + 5})

    def _usage(self) -> str:
        ok, bad = services.sample_all(self.app)
        if bad:
            raise RuntimeError(f"{bad} customer(s) could not be sampled ({ok} ok)")
        return f"{ok} customer(s) sampled"

    def _month(self) -> str:
        n = sum(services.close_period(self.app, p) for p in services.closed_periods_due(self.app))
        return f"{n} statement(s) created"

    def _checkpoint(self) -> str:
        return "checkpoint signed" if self.app.audit.checkpoint() else "nothing new to sign"

    def _retention(self) -> str:
        r = self.app.audit.prune(self.app.cfg.d["security"]["audit_retention_days"], self.app.cfg.data_dir / "audit-archive")
        if r["refused"]:
            raise RuntimeError(r["refused"])
        return f"{r['pruned']} record(s) archived and removed" + (f" ({r['archive']})" if r.get("archive") else "")

    def _backup(self) -> str:
        r = ops.backup_now(self.app)
        return f"{r['file']} ({r['bytes']:,} bytes); {r['removed_old']} old backup(s) removed"

    def _drift(self) -> str:
        rep = ops.drift_report(self.app)
        self.app.db.set_setting("drift.last", json.dumps({"at": iso(), **rep}))
        msg = ops.drift_summary(rep)
        if not rep["ok"]:
            raise RuntimeError(msg)
        return msg

    def _demo(self) -> str:
        self.app.backend.advance()
        return "demo data advanced"

    def run_one(self, job: dict) -> None:
        t0 = time.monotonic()
        status, detail = "ok", ""
        try:
            detail = job["fn"]() or ""
        except Exception as e:
            status, detail = "failed", f"{type(e).__name__}: {e}"[:300]
            logs.event(jlog, logging.ERROR, "job failed", job=job["name"], error=detail, trace=logs.scrub(traceback.format_exc())[-1500:])
        else:
            logs.event(jlog, logging.INFO, "job done", job=job["name"], detail=detail, ms=int((time.monotonic() - t0) * 1000))
        self.app.db.run("INSERT INTO jobs_state(name,last_run,last_status,last_detail) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                        "last_run=excluded.last_run,last_status=excluded.last_status,last_detail=excluded.last_detail",
                        (job["name"], iso(), status, detail))

    def _loop(self) -> None:
        while not self._stop.wait(2):
            now = time.monotonic()
            for j in self.jobs:
                if now >= j["next"]:
                    j["next"] = now + j["every"]
                    self.run_one(j)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
