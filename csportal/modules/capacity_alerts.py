"""UC4: quota meter, alerts, quota requests, service status (customer); request queue and notices (admin)."""
from __future__ import annotations

from .. import services
from ..util import GB, human_bytes, iso, new_id, valid_email
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "capacity-alerts", "name": "Capacity, alerts and status", "version": "1.0.0", "surfaces": ["customer", "admin"],
          "requires": [], "description": "Quota thresholds and alerts, quota requests, service status and notices.",
          "nav": [{"surface": "customer", "label": "Alerts and quota", "path": "/alerts", "perm": "alerts.view", "group": "Service", "order": 30},
                  {"surface": "customer", "label": "Service status", "path": "/status", "perm": "status.view", "group": "Service", "order": 40},
                  {"surface": "admin", "label": "Quota requests", "path": "/quota", "perm": "quota.view", "group": "Customers", "order": 20},
                  {"surface": "admin", "label": "Status notices", "path": "/notices", "perm": "notices.view", "group": "Service", "order": 30}]}


def register(app):
    @app.route("customer", "GET", "/alerts", perm="alerts.view", module="capacity-alerts")
    def alerts(ctx):
        c = ctx.customer
        u = app.backend.usage(c["tenant_ref"])
        plan = services.customer_plan(app, c)
        rules = ctx.scoped.select("alert_rules", order="threshold_pct")
        can = ctx.can("alerts.edit")
        rrows = [[f"{r['threshold_pct']}%", r["channel"], r["target"], r["last_fired"][:16].replace("T", " ") if r["last_fired"] else "-",
                  ui.button("Delete", "/alerts/delete", ctx.sess.csrf, {"rule": r["id"]}, "small danger", confirm="Delete this alert?") if can else ""]
                 for r in rules]
        events = ctx.scoped.select("alert_events", order="ts DESC", limit=8)
        body = ui.card("Quota", Raw(ui.meter(u["bytes_used"], c["quota_gb"] * GB) +
                                    f"<p class='muted'>{human_bytes(u['bytes_used'])} of {human_bytes(c['quota_gb'] * GB)} used.</p>"))
        body += ui.card("Alert rules", Raw(ui.table(["When use reaches", "Send by", "To", "Last sent", ""], rrows,
                                                   "No alerts set. Add one so you hear before the quota is full.")))
        if can:
            body += ui.card("Add an alert", ui.form("/alerts", [
                {"name": "threshold", "label": "Alert when use reaches (%)", "type": "number", "value": "80", "attrs": {"min": "1", "max": "100"}},
                {"name": "email", "label": "Send to e-mail", "type": "email", "value": ctx.sess.email}], ctx.sess.csrf, "Add alert"))
        body += ui.card("Recent alerts", ui.table(["When", "Message"], [[e["ts"][:16].replace("T", " "), e["message"]] for e in events], "No alerts sent yet."))
        # quota requests
        reqs = ctx.scoped.select("quota_requests", order="created_at DESC", limit=8)
        body += ui.card("Quota requests", ui.table(["When", "Requested", "State", "Note"], [
            [r["created_at"][:10], f"{r['requested_gb']:,} GB", ui.badge(r["state"], "ok" if r["state"] == "approved" else "bad" if r["state"] == "declined" else "warn"),
             r["decision_note"] or r["reason"] or ""] for r in reqs], "No requests."))
        if ctx.can("quota.request"):
            auto = plan["auto_quota_gb"]
            hint = f"Requests up to {auto:,} GB are approved automatically." if auto else "A person at the service provider reviews each request."
            body += ui.card("Ask for more quota", ui.form("/quota/request", [
                {"name": "gb", "label": "New total quota (GB)", "type": "number", "value": str(c["quota_gb"] * 2), "attrs": {"min": str(c["quota_gb"] + 1), "max": "100000000"}},
                {"name": "reason", "label": "Why do you need it?", "required": False}], ctx.sess.csrf, "Send request",
                extra=Raw(f'<p class="muted">{ui.esc(hint)}</p>')))
        return ui.page(ctx, "Alerts and quota", Raw(body), "/alerts")

    @app.route("customer", "POST", "/alerts", perm="alerts.edit", module="capacity-alerts")
    def alert_add(ctx):
        if not ctx.f("threshold").isdigit() or not 1 <= int(ctx.f("threshold")) <= 100 or not valid_email(ctx.f("email")):
            ctx.flash("Error: Enter a percentage from 1 to 100 and a valid e-mail address.")
            return redirect("/alerts")
        if len(ctx.scoped.select("alert_rules")) >= 10:
            ctx.flash("Error: At most 10 alerts.")
            return redirect("/alerts")
        ctx.scoped.insert("alert_rules", id=new_id("ar_"), threshold_pct=int(ctx.f("threshold")), channel="email", target=ctx.f("email").lower())
        ctx.audit("alert.create", ctx.f("threshold") + "%")
        ctx.flash("Alert added.")
        return redirect("/alerts")

    @app.route("customer", "POST", "/alerts/delete", perm="alerts.edit", module="capacity-alerts")
    def alert_del(ctx):
        ctx.scoped.delete("alert_rules", ctx.f("rule"))
        ctx.audit("alert.delete", ctx.f("rule"))
        ctx.flash("Alert deleted.")
        return redirect("/alerts")

    @app.route("customer", "POST", "/quota/request", perm="quota.request", module="capacity-alerts")
    def quota_request(ctx):
        c = ctx.customer
        gb = int(ctx.f("gb")) if ctx.f("gb").isdigit() else 0
        if gb <= c["quota_gb"] or gb > 100_000_000:
            ctx.flash("Error: Ask for more than your current quota.")
            return redirect("/alerts")
        plan = services.customer_plan(app, c)
        rid = new_id("q_")
        ctx.scoped.insert("quota_requests", id=rid, requested_gb=gb, reason=ctx.f("reason")[:300], state="open", created_at=iso(), requested_by=ctx.sess.email)
        ctx.audit("quota.request", f"{gb} GB", ctx.f("reason")[:100])
        if plan["auto_quota_gb"] and gb <= plan["auto_quota_gb"]:
            services.set_quota(app, c["id"], gb, "system (auto-approve)", ctx.req.ip, "auto-approved by plan")
            ctx.scoped.update("quota_requests", rid, state="approved", decided_by="auto", decided_at=iso(), decision_note="Approved automatically by your plan.")
            ctx.flash(f"Your quota is now {gb:,} GB.")
        else:
            ctx.flash("Request sent. The service provider will review it.")
        return redirect("/alerts")

    @app.route("customer", "GET", "/status", perm="status.view", module="capacity-alerts")
    def status(ctx):
        h = app.backend.health()
        notices = services.active_notices(app)
        rows = [[n["kind"], n["title"], n["body"] or "", (n["starts_at"] or "")[:16].replace("T", " ")] for n in notices]
        body = ui.card("Service", Raw(f"<p>{ui.badge('Operational', 'ok') if h['ok'] else ui.badge('Degraded', 'bad')} "
                                      f"<span class='muted'>Storage service for your account.</span></p>"))
        body += ui.card("Notices and maintenance", ui.table(["Type", "Title", "Details", "From"], rows, "No active notices."))
        return ui.page(ctx, "Service status", Raw(body), "/status")

    # ------------------------------------------------------------ admin
    @app.route("admin", "GET", "/quota", perm="quota.view", module="capacity-alerts")
    def admin_quota(ctx):
        rows = app.db.all("SELECT q.*, c.name cname, c.quota_gb cur FROM quota_requests q JOIN customers c ON c.id=q.customer_id "
                          "ORDER BY (q.state='open') DESC, q.created_at DESC LIMIT 100")
        can = ctx.can("quota.decide")
        trs = []
        for r in rows:
            act = ""
            if r["state"] == "open" and can:
                act = Raw(f'<form method="post" action="/quota/{ui.esc(r["id"])}" class="stack">'
                          f'<input type="hidden" name="_csrf" value="{ui.esc(ctx.sess.csrf)}">'
                          '<input type="text" name="note" placeholder="Note to customer (optional)" maxlength="300"> '
                          '<button class="btn primary small" name="decision" value="approved">Approve</button> '
                          '<button class="btn danger small" name="decision" value="declined">Decline</button></form>')
            trs.append([r["created_at"][:10], r["cname"], f"{r['cur']:,} GB", f"{r['requested_gb']:,} GB", r["reason"] or "",
                        ui.badge(r["state"], "ok" if r["state"] == "approved" else "bad" if r["state"] == "declined" else "warn"), act])
        return ui.page(ctx, "Quota requests", Raw(ui.card("Requests", ui.table(["Date", "Customer", "Current", "Requested", "Reason", "State", "Decision"], trs, "No requests."))), "/quota")

    @app.route("admin", "POST", "/quota/{rid}", perm="quota.decide", module="capacity-alerts")
    def admin_quota_decide(ctx):
        r = app.db.one("SELECT * FROM quota_requests WHERE id=? AND state='open'", (ctx.params["rid"],))
        if not r:
            return redirect("/quota")
        decision = "approved" if ctx.f("decision") == "approved" else "declined"
        if decision == "approved":
            services.set_quota(app, r["customer_id"], r["requested_gb"], ctx.sess.email, ctx.req.ip, "quota request approved")
        app.db.run("UPDATE quota_requests SET state=?, decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                   (decision, ctx.sess.email, iso(), ctx.f("note")[:300], r["id"]))
        app.audit.record("quota.decision", ctx.sess.email, "user", r["customer_id"], r["id"], f"{decision} {r['requested_gb']} GB", ctx.req.ip)
        ctx.flash(f"Request {decision}.")
        return redirect("/quota")

    @app.route("admin", "GET", "/notices", perm="notices.view", module="capacity-alerts")
    def admin_notices(ctx):
        ns = app.db.all("SELECT * FROM notices ORDER BY created_at DESC LIMIT 50")
        can = ctx.can("notices.edit")
        rows = [[n["kind"], n["title"], n["body"] or "", ui.badge("active", "ok") if n["active"] else ui.badge("ended"),
                 ui.button("End", "/notices/end", ctx.sess.csrf, {"id": n["id"]}, "small") if can and n["active"] else ""] for n in ns]
        body = ui.card("Notices shown to customers", ui.table(["Type", "Title", "Details", "State", ""], rows, "No notices."))
        if can:
            body += ui.card("Publish a notice", ui.form("/notices", [
                {"name": "kind", "label": "Type", "type": "select", "options": [("info", "Information"), ("maintenance", "Planned maintenance"), ("incident", "Incident")]},
                {"name": "title", "label": "Title"}, {"name": "body", "label": "Details", "required": False}], ctx.sess.csrf, "Publish"))
        return ui.page(ctx, "Status notices", Raw(body), "/notices")

    @app.route("admin", "POST", "/notices", perm="notices.edit", module="capacity-alerts")
    def admin_notice_add(ctx):
        app.db.run("INSERT INTO notices(id,kind,title,body,starts_at,created_at) VALUES (?,?,?,?,?,?)",
                   (new_id("n_"), ctx.f("kind") if ctx.f("kind") in ("info", "maintenance", "incident") else "info", ctx.f("title")[:120], ctx.f("body")[:500], iso(), iso()))
        ctx.audit("notice.publish", ctx.f("title")[:60])
        ctx.flash("Notice published.")
        return redirect("/notices")

    @app.route("admin", "POST", "/notices/end", perm="notices.edit", module="capacity-alerts")
    def admin_notice_end(ctx):
        app.db.run("UPDATE notices SET active=0, ends_at=? WHERE id=?", (iso(), ctx.f("id")))
        ctx.audit("notice.end", ctx.f("id"))
        return redirect("/notices")
