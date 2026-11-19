"""Customer dashboard (UC1-UC4 at a glance) and the admin overview."""
from __future__ import annotations

from .. import services
from ..util import GB, TB, human_bytes, money
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "tenant-dashboard", "name": "Dashboard", "version": "1.0.0", "core": True,
          "surfaces": ["customer", "admin"], "requires": [],
          "description": "Overview of the customer's storage account; overview of the service for the provider.",
          "nav": [{"surface": "customer", "label": "Dashboard", "path": "/", "perm": "dashboard.view", "group": "", "order": 1},
                  {"surface": "admin", "label": "Overview", "path": "/", "perm": "admin.overview", "group": "", "order": 1}]}


def register(app):
    @app.route("customer", "GET", "/", perm="dashboard.view")
    def dashboard(ctx):
        c = ctx.customer
        plan = services.customer_plan(app, c)
        usage = app.backend.usage(c["tenant_ref"])
        quota = c["quota_gb"] * GB
        pct = usage["bytes_used"] / quota * 100 if quota else 0
        series = services.usage_series(app, c["id"], 120)
        mtd = services.month_to_date(app, c)
        buckets = app.backend.list_buckets(c["tenant_ref"])
        ep = app.backend.endpoints(c["tenant_ref"])
        stats = ui.grid(
            ui.stat("Stored", human_bytes(usage["bytes_used"]), f"{usage['objects']:,} objects"),
            ui.stat("Quota used", f"{pct:.0f}%", f"{human_bytes(usage['bytes_used'])} of {human_bytes(quota)}"),
            ui.stat("Buckets", str(len(buckets)), f"limit {plan['max_buckets']}"),
            ui.stat("This month so far", money(mtd["amount"], mtd["currency"]) if ctx.can("billing.view") else "-", plan["name"] + " plan"),
            cols=4)
        meter = ui.card("Quota", ui.meter(usage["bytes_used"], quota))
        chart = ui.card("Storage over time (GB)", ui.line_chart(series, "", quota=c["quota_gb"]), actions=ui.link("/usage", "Usage details"))
        brows = [[ui.link(f"/buckets/{b['name']}", b["name"]), human_bytes(b["bytes"]), f"{b['objects']:,}",
                  ui.badge("versioned", "ok") if b["versioning"] == "enabled" else ui.badge("no versioning", "warn")]
                 for b in buckets[:6]]
        btab = ui.card("Buckets", ui.table(["Name", "Size", "Objects", "Protection"], brows, "No buckets yet. Create your first bucket."),
                       actions=ui.link("/buckets", "All buckets"))
        conn = ui.card("Connect your applications", ui.kv([
            ("S3 endpoint", Raw("<code>" + ", ".join(ep["s3"]) + "</code>")), ("Region", ", ".join(ep["regions"])),
            ("Access keys", ui.link("/keys", "Manage access keys"))]))
        recent = ctx.scoped.select("audit", order="id DESC", limit=5)
        act = ui.card("Recent activity", ui.table(["When", "Who", "What"],
                      [[r["ts"][:16].replace("T", " "), r["actor"], r["action"]] for r in recent], "No activity yet."),
                      actions=ui.link("/activity", "All activity")) if ctx.can("activity.view") else ""
        return ui.page(ctx, f"Welcome, {ctx.sess.name.split()[0]}", Raw(stats + meter + chart + ui.grid(btab, conn, cols=2) + act), "/")

    @app.route("admin", "GET", "/", perm="admin.overview")
    def admin_overview(ctx):
        db = app.db
        n = lambda sql, p=(): db.one(sql, p)[0]
        total = n("SELECT COUNT(*) FROM customers WHERE state!='closed'")
        active = n("SELECT COUNT(*) FROM customers WHERE state='active'")
        pending = n("SELECT COUNT(*) FROM customers WHERE state='pending'")
        qopen = n("SELECT COUNT(*) FROM quota_requests WHERE state='open'")
        used = sum((services.latest_sample(app, c["id"]) or {"bytes_used": 0})["bytes_used"]
                   for c in db.all("SELECT id FROM customers WHERE state IN ('active','suspended')"))
        h = app.backend.health()
        g = app.backend.grid_overview()
        stats = ui.grid(ui.stat("Customers", str(total), f"{active} active, {pending} pending"),
                        ui.stat("Stored for customers", human_bytes(used)),
                        ui.stat("Open quota requests", str(qopen)),
                        ui.stat("Storage service", "OK" if h["ok"] else "PROBLEM", h["release"]), cols=4)
        grid_card = ui.card("Grid", ui.kv([
            ("Capacity", f"{human_bytes(g['used_bytes'])} of {human_bytes(g['capacity_bytes'])}"),
            ("Nodes", f"{g['nodes_ok']} of {g['nodes_total']} healthy"),
            ("Connector", f"{app.backend.name}" + ("" if app.backend.verified else " (not verified on a real grid)")),
            ("Alerts", ", ".join(a["title"] for a in g["alerts"]) or "None")]))
        pend = db.all("SELECT * FROM customers WHERE state='pending'")
        pend_card = ui.card("Needs attention", ui.table(
            ["Customer", "Problem"], [[ui.link(f"/customers/{c['id']}", c["name"]), c["error"] or "Waiting to be provisioned"] for c in pend],
            "Nothing needs attention."))
        qrows = db.all("SELECT q.*, c.name cname FROM quota_requests q JOIN customers c ON c.id=q.customer_id WHERE q.state='open' ORDER BY q.created_at LIMIT 5")
        qcard = ui.card("Quota requests", ui.table(["Customer", "Requested", "When"],
                        [[r["cname"], f"{r['requested_gb']:,} GB", r["created_at"][:10]] for r in qrows], "No open requests."),
                        actions=ui.link("/quota", "Open queue"))
        return ui.page(ctx, "Overview", Raw(stats + ui.grid(grid_card, pend_card, cols=2) + qcard), "/")
