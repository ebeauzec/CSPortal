"""Customer-visible activity history and the CSP audit view with chain verification."""
from __future__ import annotations

import csv
import io

from ..web import ui
from ..web.core import Raw, text_response

MODULE = {"id": "audit-reports", "name": "Activity and audit", "version": "1.0.0", "surfaces": ["customer", "admin"],
          "requires": [], "description": "Who changed what, per customer; tamper-evident audit for the provider.",
          "nav": [{"surface": "customer", "label": "Activity", "path": "/activity", "perm": "activity.view", "group": "Account", "order": 50},
                  {"surface": "admin", "label": "Audit log", "path": "/audit", "perm": "audit.view", "group": "System", "order": 10}]}


def register(app):
    @app.route("customer", "GET", "/activity", perm="activity.view", module="audit-reports")
    def activity(ctx):
        rows = ctx.scoped.select("audit", order="id DESC", limit=300)
        tbl = ui.table(["When (UTC)", "Who", "What", "Target", "Detail"],
                       [[r["ts"][:19].replace("T", " "), r["actor"], r["action"], r["target"] or "", r["detail"] or ""] for r in rows],
                       "No activity yet.")
        return ui.page(ctx, "Activity", Raw(ui.card("Changes made to your account", tbl, actions=ui.link("/activity.csv", "Download CSV", "btn"))), "/activity")

    @app.route("customer", "GET", "/activity.csv", perm="activity.view", module="audit-reports")
    def activity_csv(ctx):
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["time_utc", "actor", "action", "target", "detail"])
        for r in ctx.scoped.select("audit", order="id", limit=100000):
            w.writerow([r["ts"]] + [("'" + c) if c and c[:1] in "=+-@" else c for c in (r["actor"], r["action"], r["target"] or "", r["detail"] or "")])
        return text_response(out.getvalue(), "text/csv; charset=utf-8", filename="activity.csv")

    @app.route("admin", "GET", "/audit", perm="audit.view", module="audit-reports")
    def audit_view(ctx):
        q = ctx.q("action")
        rows = app.audit.recent(300, q)
        ok, bad, n = app.audit.verify()
        chain = ui.badge(f"Chain intact ({n:,} records)", "ok") if ok else ui.badge(f"CHAIN BROKEN at record {bad}", "bad")
        flt = Raw('<form method="get" action="/audit"><label>Action starts with <input name="action" value="%s"></label> <button class="btn small">Filter</button></form>' % ui.esc(q))
        tbl = ui.table(["#", "When (UTC)", "Actor", "Action", "Customer", "Target", "Detail", "IP", "Request"],
                       [[r["id"], r["ts"][:19].replace("T", " "), r["actor"], r["action"], r["customer_id"] or "", r["target"] or "",
                         r["detail"] or "", r["ip"] or "", r["request_id"] or ""] for r in rows], "No records.")
        return ui.page(ctx, "Audit log", Raw(ui.card("Integrity", Raw(f"<p>{chain}</p><p class='muted'>Each record contains a hash of the one before it. "
                                                                         "Any change to an earlier record breaks the chain.</p>")) + ui.card("Records", Raw(flt + tbl))), "/audit")
