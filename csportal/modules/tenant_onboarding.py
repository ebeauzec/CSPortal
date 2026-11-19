"""UC1 (admin side): create, suspend, resume, close customers and their grid tenants."""
from __future__ import annotations

import json

from .. import approvals, services
from ..auth import AuthError
from ..util import GB, human_bytes, valid_email
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "tenant-onboarding", "name": "Customer onboarding", "version": "1.0.0", "surfaces": ["admin"],
          "requires": ["catalogue"], "description": "Create and manage customers and their StorageGRID tenant accounts.",
          "nav": [{"surface": "admin", "label": "Customers", "path": "/customers", "perm": "customers.view", "group": "Customers", "order": 10}]}

_STATE = {"active": "ok", "pending": "warn", "suspended": "warn", "closed": "bad"}


def register(app):
    @app.route("admin", "GET", "/customers", perm="customers.view", module="tenant-onboarding")
    def customers(ctx):
        rows = []
        for c in app.db.all("SELECT c.*, p.name pname FROM customers c JOIN plans p ON p.id=c.plan_id ORDER BY c.name"):
            s = services.latest_sample(app, c["id"])
            used = s["bytes_used"] if s else 0
            pct = f"{used / (c['quota_gb'] * GB) * 100:.0f}%" if c["quota_gb"] else "-"
            rows.append([ui.link(f"/customers/{c['id']}", c["name"]), c["pname"], ui.badge(c["state"], _STATE.get(c["state"], "")),
                         f"{human_bytes(used)} ({pct})", f"{c['quota_gb']:,} GB", c["created_at"][:10]])
        act = ui.link("/customers/new", "New customer", "btn primary") if ctx.can("customers.provision") else ""
        return ui.page(ctx, "Customers", Raw(ui.card("All customers", ui.table(["Customer", "Plan", "State", "Stored", "Quota", "Since"], rows, "No customers yet."))),
                       "/customers", actions=act)

    @app.route("admin", "GET", "/customers/new", perm="customers.provision", module="tenant-onboarding")
    def new_form(ctx):
        plans = app.db.all("SELECT * FROM plans WHERE state='active' ORDER BY price_gb_month DESC")
        if not plans:
            return ui.page(ctx, "New customer", Raw(ui.card("No plans", Raw('<p>Create a <a href="/plans">plan</a> first.</p>'))), "/customers")
        return ui.page(ctx, "New customer", Raw(ui.card("Create a customer", ui.form("/customers", [
            {"name": "name", "label": "Customer name"},
            {"name": "plan", "label": "Plan", "type": "select", "options": [(p["id"], f"{p['name']} ({p['quota_gb']:,} GB)") for p in plans]},
            {"name": "admin_name", "label": "First administrator's name"},
            {"name": "email", "label": "First administrator's e-mail", "type": "email",
             "help": "They receive an invitation to set a password and set up multi-factor authentication."}], ctx.sess.csrf, "Create customer"))), "/customers")

    @app.route("admin", "POST", "/customers", perm="customers.provision", module="tenant-onboarding")
    def create(ctx):
        if not ctx.f("name") or not valid_email(ctx.f("email")):
            ctx.flash("Error: Enter the customer name and a valid e-mail address.")
            return redirect("/customers/new")
        try:
            cid = services.provision_customer(app, ctx.f("name")[:100], ctx.f("plan"), ctx.f("email"), ctx.f("admin_name")[:100], ctx.sess.email, ctx.req.ip)
        except (AuthError, ValueError) as e:
            ctx.flash("Error: " + str(e))
            return redirect("/customers/new")
        c = app.db.one("SELECT * FROM customers WHERE id=?", (cid,))
        ctx.flash("Customer created and invitation sent." if c["state"] == "active" else f"Customer saved, but the storage account could not be created: {c['error']}")
        return redirect(f"/customers/{cid}")

    @app.route("admin", "GET", "/customers/{cid}", perm="customers.view", module="tenant-onboarding")
    def detail(ctx):
        c = app.db.one("SELECT * FROM customers WHERE id=?", (ctx.params["cid"],))
        if not c:
            return redirect("/customers")
        plan = services.customer_plan(app, c)
        s = services.latest_sample(app, c["id"])
        used = s["bytes_used"] if s else 0
        can = ctx.can("customers.edit")
        facts = ui.card("Customer", ui.kv([("Name", c["name"]), ("State", ui.badge(c["state"], _STATE.get(c["state"], ""))), ("Plan", plan["name"]),
                                           ("Storage account", c["tenant_ref"] or "(not created)"), ("Contact", c["contact_email"] or "-"),
                                           ("Created", c["created_at"][:10]), ("Problem", c["error"] or "-")]))
        usage = ui.card("Usage", Raw(ui.meter(used, c["quota_gb"] * GB, f"{human_bytes(used)} of {c['quota_gb']:,} GB") +
                                     ui.line_chart(services.usage_series(app, c["id"], 120), "", quota=c["quota_gb"])))
        actions = []
        if can:
            if c["state"] == "pending":
                actions.append(ui.button("Retry provisioning", f"/customers/{c['id']}/retry", ctx.sess.csrf, {}, "primary"))
            if c["state"] == "active":
                actions.append(ui.button("Suspend", f"/customers/{c['id']}/suspend", ctx.sess.csrf, {}, "danger", confirm="Suspend this customer? Their users are signed out and storage access is disabled."))
            if c["state"] == "suspended":
                actions.append(ui.button("Resume", f"/customers/{c['id']}/resume", ctx.sess.csrf, {}, "primary"))
            if c["state"] in ("active", "suspended"):
                actions.append(ui.button("Resend first invitation", f"/customers/{c['id']}/reinvite", ctx.sess.csrf, {}))
        acard = ui.card("Actions", Raw("".join(str(a) for a in actions) or "<p class='muted'>None available.</p>"))
        forms = ""
        if can and c["state"] in ("active", "suspended"):
            plans = app.db.all("SELECT * FROM plans WHERE state='active'")
            forms = ui.grid(
                ui.card("Quota", ui.form(f"/customers/{c['id']}/quota", [{"name": "gb", "label": "Quota (GB)", "type": "number", "value": str(c["quota_gb"]),
                                                                          "attrs": {"min": "1", "max": "100000000"}}], ctx.sess.csrf, "Set quota")),
                ui.card("Plan", ui.form(f"/customers/{c['id']}/plan", [{"name": "plan", "label": "Plan", "type": "select", "value": c["plan_id"],
                                                                        "options": [(p["id"], p["name"]) for p in plans]}], ctx.sess.csrf, "Change plan")), cols=2)
        ent = app.entitlement_report(c)
        off = json.loads(c["modules_off"] or "[]")
        erows = [[e["name"], ui.badge("on", "ok") if e["on"] else ui.badge("off", "warn"), e["why"] or "",
                  (ui.button("Switch " + ("on" if e["id"] in off else "off"), f"/customers/{c['id']}/module", ctx.sess.csrf,
                             {"module": e["id"], "on": "1" if e["id"] in off else "0"}, "small") if can and (e["id"] in off or e["on"]) else "")] for e in ent]
        entcard = ui.card("Features this customer can use", ui.table(["Feature", "State", "Why", ""], erows))
        users = app.db.all("SELECT * FROM users WHERE customer_id=? ORDER BY name", (c["id"],))
        ucard = ui.card("Portal users", ui.table(["Name", "E-mail", "Role", "State", "MFA", "Last sign-in"],
                        [[u["name"], u["email"], u["role"], u["state"], "on" if u["mfa_enabled"] else "-", (u["last_login"] or "-")[:16]] for u in users]))
        recent = ui.card("Recent activity", ui.table(["When", "Who", "What", "Target"], [[r["ts"][:16].replace("T", " "), r["actor"], r["action"], r["target"] or ""]
                                                                                       for r in app.audit.for_customer(c["id"], 10)]))
        closing = ""
        if ctx.can("customers.delete") and c["state"] in ("active", "suspended"):
            closing = ui.card("Close account", Raw("<p class='muted'>Closing signs everyone out and ends the service. Data is kept until the storage account is deleted.</p>" +
                              ui.form(f"/customers/{c['id']}/close", [{"name": "confirm", "label": f"Type the customer name ({c['name']}) to confirm"}],
                                      ctx.sess.csrf, "Close account", cls="danger")))
        return ui.page(ctx, c["name"], Raw(ui.grid(facts, acard, cols=2) + usage + forms + entcard + ucard + recent + closing), "/customers",
                       actions=ui.link("/customers", "All customers", "btn"))

    def _c(ctx):
        return app.db.one("SELECT * FROM customers WHERE id=?", (ctx.params["cid"],))

    @app.route("admin", "POST", "/customers/{cid}/retry", perm="customers.provision", module="tenant-onboarding")
    def retry(ctx):
        ok = services.complete_provisioning(app, ctx.params["cid"], ctx.sess.email, ctx.req.ip)
        ctx.flash("Provisioning completed." if ok else "Error: Provisioning failed again. See the problem shown for the customer and the logs.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/suspend", perm="customers.edit", module="tenant-onboarding")
    def suspend(ctx):
        services.suspend_customer(app, ctx.params["cid"], True, ctx.sess.email, ctx.req.ip)
        ctx.flash("Customer suspended.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/resume", perm="customers.edit", module="tenant-onboarding")
    def resume(ctx):
        services.suspend_customer(app, ctx.params["cid"], False, ctx.sess.email, ctx.req.ip)
        ctx.flash("Customer resumed.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/reinvite", perm="customers.edit", module="tenant-onboarding")
    def reinvite(ctx):
        u = app.db.one("SELECT * FROM users WHERE customer_id=? AND role='administrator' ORDER BY created_at LIMIT 1", (ctx.params["cid"],))
        if u:
            tok = app.auth.invite_token(u["id"])
            services.send_mail(app, u["email"], "Your account", f"Set your password here:\n{services.invite_link(app, tok)}\n", ctx.params["cid"])
            app.audit.record("user.reinvite", ctx.sess.email, "user", ctx.params["cid"], u["email"], "", ctx.req.ip)
            ctx.flash("Invitation sent.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/quota", perm="customers.edit", module="tenant-onboarding")
    def quota(ctx):
        if not ctx.f("gb").isdigit() or not 1 <= int(ctx.f("gb")) <= 100_000_000:
            ctx.flash("Error: Enter a whole number of GB.")
        else:
            services.set_quota(app, ctx.params["cid"], int(ctx.f("gb")), ctx.sess.email, ctx.req.ip)
            ctx.flash("Quota updated.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/plan", perm="customers.edit", module="tenant-onboarding")
    def plan(ctx):
        c, p = _c(ctx), services.get_plan(app, ctx.f("plan"))
        if c and p:
            app.db.run("UPDATE customers SET plan_id=? WHERE id=?", (p["id"], c["id"]))
            if c["tenant_ref"]:
                app.backend.update_tenant(c["tenant_ref"], features=services.plan_features(p))
            app.audit.record("customer.plan_change", ctx.sess.email, "user", c["id"], p["id"], f"{c['plan_id']} -> {p['id']}", ctx.req.ip)
            ctx.flash("Plan changed. Quota is unchanged; set it separately if the new plan differs.")
        return redirect(f"/customers/{ctx.params['cid']}")

    @app.route("admin", "POST", "/customers/{cid}/module", perm="customers.edit", module="tenant-onboarding")
    def module(ctx):
        c = _c(ctx)
        off = set(json.loads(c["modules_off"] or "[]"))
        (off.discard if ctx.f("on") == "1" else off.add)(ctx.f("module"))
        app.db.run("UPDATE customers SET modules_off=? WHERE id=?", (json.dumps(sorted(off)), c["id"]))
        app.audit.record("customer.module", ctx.sess.email, "user", c["id"], ctx.f("module"), "on" if ctx.f("on") == "1" else "off", ctx.req.ip)
        return redirect(f"/customers/{c['id']}")

    @app.route("admin", "POST", "/customers/{cid}/close", perm="customers.delete", module="tenant-onboarding", reauth=True)
    def close(ctx):
        c = _c(ctx)
        if ctx.f("confirm") != c["name"]:
            ctx.flash("Error: The name did not match. Nothing was changed.")
            return redirect(f"/customers/{c['id']}")
        try:
            done, msg = approvals.submit(app, "customer.close", c["id"], f"Close the account of {c['name']}", {"cid": c["id"]},
                                         ctx.sess.email, ctx.sess.user_id, ctx.req.ip)
        except approvals.ApprovalError as e:
            ctx.flash("Error: " + str(e))
            return redirect(f"/customers/{c['id']}")
        ctx.flash(msg)
        return redirect("/customers" if done else "/approvals")
