"""Service catalogue: plans, rate cards, feature entitlements, and the module switchboard."""
from __future__ import annotations

import json

from .. import services
from ..util import money, new_id
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "catalogue", "name": "Plans and catalogue", "version": "1.0.0", "surfaces": ["admin"], "requires": [],
          "description": "Plans, rate cards and which modules each plan includes.",
          "nav": [{"surface": "admin", "label": "Plans", "path": "/plans", "perm": "plans.view", "group": "Finance", "order": 20},
                  {"surface": "admin", "label": "Modules", "path": "/modules", "perm": "modules.view", "group": "Platform", "order": 10}]}


def _num(v: str, default: float = 0.0) -> float:
    try:
        return max(0.0, float(v))
    except ValueError:
        return default


def register(app):
    cust_modules = lambda: [(mid, m["name"]) for mid, m in sorted(app.modules.items()) if "customer" in m["surfaces"] and not m.get("core")]

    @app.route("admin", "GET", "/plans", perm="plans.view", module="catalogue")
    def plans(ctx):
        rows = []
        for p in app.db.all("SELECT * FROM plans ORDER BY price_gb_month DESC"):
            n = app.db.one("SELECT COUNT(*) FROM customers WHERE plan_id=? AND state!='closed'", (p["id"],))[0]
            rows.append([ui.link(f"/plans/{p['id']}", p["name"]), f"{p['quota_gb']:,} GB", money(p["price_gb_month"], p["currency"]) + " / GB-month",
                         money(p["min_monthly"], p["currency"]), str(len(json.loads(p["modules"]))), str(n), ui.badge(p["state"], "ok" if p["state"] == "active" else "")])
        act = ui.link("/plans/new", "New plan", "btn primary") if ctx.can("plans.edit") else ""
        return ui.page(ctx, "Plans", Raw(ui.card("Service plans", ui.table(["Plan", "Default quota", "Price", "Minimum", "Features", "Customers", "State"], rows, "No plans."))), "/plans", actions=act)

    def _form(ctx, p, action):
        mods = json.loads(p["modules"]) if p else [m for m, _ in cust_modules()]
        v = lambda k, d="": (p[k] if p else d)
        fields = [
            {"name": "name", "label": "Plan name", "value": v("name")},
            {"name": "description", "label": "Description", "value": v("description"), "required": False},
            {"name": "quota_gb", "label": "Default quota (GB)", "type": "number", "value": v("quota_gb", 1000), "attrs": {"min": "1"}},
            {"name": "price", "label": "Price per GB-month", "type": "number", "value": v("price_gb_month", 0.02), "attrs": {"step": "0.0001", "min": "0"}},
            {"name": "min_monthly", "label": "Minimum monthly charge", "type": "number", "value": v("min_monthly", 0), "attrs": {"step": "0.01", "min": "0"}},
            {"name": "currency", "label": "Currency", "type": "select", "value": v("currency", "USD"), "options": [(c, c) for c in ("USD", "EUR", "GBP", "AED")]},
            {"name": "max_buckets", "label": "Maximum buckets", "type": "number", "value": v("max_buckets", 100), "attrs": {"min": "1"}},
            {"name": "auto_quota_gb", "label": "Auto-approve quota requests up to (GB, 0 = never)", "type": "number", "value": v("auto_quota_gb", 0), "attrs": {"min": "0"}},
            {"name": "allow_object_lock", "label": "Allow Object Lock", "type": "checkbox", "value": v("allow_object_lock", 1)},
            {"name": "allow_public_buckets", "label": "Allow public buckets", "type": "checkbox", "value": v("allow_public_buckets", 0)},
            {"name": "allow_platform_services", "label": "Allow platform services (replication, notifications)", "type": "checkbox", "value": v("allow_platform_services", 0)},
            {"name": "allow_own_identity", "label": "Allow the customer's own identity provider", "type": "checkbox", "value": v("allow_own_identity", 0)},
        ]
        for mid, mname in cust_modules():
            fields.append({"name": "mod_" + mid, "label": f"Include: {mname}", "type": "checkbox", "value": mid in mods})
        return ui.form(action, fields, ctx.sess.csrf, "Save plan")

    @app.route("admin", "GET", "/plans/new", perm="plans.edit", module="catalogue")
    def plan_new(ctx):
        return ui.page(ctx, "New plan", Raw(ui.card("Plan", _form(ctx, None, "/plans"))), "/plans")

    @app.route("admin", "GET", "/plans/{pid}", perm="plans.view", module="catalogue")
    def plan_edit(ctx):
        p = services.get_plan(app, ctx.params["pid"])
        if not p:
            return redirect("/plans")
        body = _form(ctx, p, f"/plans/{p['id']}") if ctx.can("plans.edit") else ui.kv([("Name", p["name"])])
        return ui.page(ctx, p["name"], Raw(ui.card("Plan", body)), "/plans")

    def _save(ctx, pid):
        f = ctx.f
        mods = [m for m, _ in cust_modules() if f("mod_" + m)]
        vals = (f("name")[:80], f("description")[:300], int(_num(f("quota_gb"), 100)) or 1, _num(f("price")), _num(f("min_monthly")),
                f("currency") if f("currency") in ("USD", "EUR", "GBP", "AED") else "USD", json.dumps(mods),
                int(bool(f("allow_public_buckets"))), int(bool(f("allow_platform_services"))), int(bool(f("allow_object_lock"))),
                int(bool(f("allow_own_identity"))), int(_num(f("max_buckets"), 100)) or 1, int(_num(f("auto_quota_gb"))))
        cols = "name,description,quota_gb,price_gb_month,min_monthly,currency,modules,allow_public_buckets,allow_platform_services,allow_object_lock,allow_own_identity,max_buckets,auto_quota_gb"
        if pid:
            app.db.run("UPDATE plans SET " + ",".join(c + "=?" for c in cols.split(",")) + " WHERE id=?", (*vals, pid))
            app.audit.record("plan.update", ctx.sess.email, "user", None, pid, f("name"), ctx.req.ip)
        else:
            pid = new_id("p_")
            app.db.run(f"INSERT INTO plans(id,{cols}) VALUES ({','.join('?' * 14)})", (pid, *vals))
            app.audit.record("plan.create", ctx.sess.email, "user", None, pid, f("name"), ctx.req.ip)
        ctx.flash("Plan saved. Existing customers keep their quota; entitlements follow the plan immediately.")
        return redirect("/plans")

    @app.route("admin", "POST", "/plans", perm="plans.edit", module="catalogue")
    def plan_create(ctx):
        return _save(ctx, None)

    @app.route("admin", "POST", "/plans/{pid}", perm="plans.edit", module="catalogue")
    def plan_update(ctx):
        return _save(ctx, ctx.params["pid"])

    @app.route("admin", "GET", "/modules", perm="modules.view", module="catalogue")
    def modules(ctx):
        off = json.loads(app.db.setting("modules_off", "[]"))
        rows = []
        for mid, m in sorted(app.modules.items()):
            if m.get("core"):
                state = ui.badge("core", "")
            else:
                state = ui.badge("on", "ok") if mid not in off else ui.badge("off", "warn")
            act = ""
            if ctx.can("modules.edit") and not m.get("core"):
                act = ui.button("Switch " + ("on" if mid in off else "off"), "/modules/toggle", ctx.sess.csrf, {"id": mid, "on": "1" if mid in off else "0"}, "small")
            rows.append([m["name"], m["version"], ", ".join(m["surfaces"]), ", ".join(m.get("requires") or []) or "-", m["description"], state, act])
        return ui.page(ctx, "Modules", Raw(ui.card("Installed modules", ui.table(["Module", "Version", "Surfaces", "Needs", "Purpose", "State", ""], rows)) +
                                           ui.card("How entitlement works", Raw("<p class='muted'>A customer can use a feature when the module is on here, the customer's plan includes it, "
                                                                                "and it is not switched off for that customer.</p>"))), "/modules")

    @app.route("admin", "POST", "/modules/toggle", perm="modules.edit", module="catalogue")
    def toggle(ctx):
        mid = ctx.f("id")
        m = app.modules.get(mid)
        if not m or m.get("core"):
            return redirect("/modules")
        off = set(json.loads(app.db.setting("modules_off", "[]")))
        on = ctx.f("on") == "1"
        if on:
            missing = [r for r in m.get("requires", []) if r in off]
            if missing:
                ctx.flash("Error: Switch on the required module first: " + ", ".join(missing))
                return redirect("/modules")
            off.discard(mid)
        else:
            dependents = [x for x, mm in app.modules.items() if mid in mm.get("requires", []) and x not in off]
            if dependents:
                ctx.flash("Error: These modules need it: " + ", ".join(dependents))
                return redirect("/modules")
            off.add(mid)
        app.db.set_setting("modules_off", json.dumps(sorted(off)))
        app.audit.record("module.on" if on else "module.off", ctx.sess.email, "user", None, mid, "", ctx.req.ip)
        return redirect("/modules")
