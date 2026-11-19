"""Demo mode: a pre-populated service so every use case can be shown without a grid.

Demo mode only runs against the built-in simulator, uses its own data directory, shows a banner on every
page and lists its sample accounts on the sign-in page. It is refused in production configuration.
All names, addresses and figures are invented. Domains use the reserved .example name.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import random

from . import services
from .util import GB, TB, iso, new_id, utcnow

DEMO_PASSWORD = "Demo-Portal-2026!"

PLANS = [
    # id, name, desc, quota_gb, price, min, auto_quota, modules, flags(lock, public, platform, identity), max_buckets
    ("p_starter", "Starter", "Small teams and backups", 1000, 0.025, 10.0, 0,
     ["tenant-access", "s3-access", "buckets", "usage-billing", "capacity-alerts", "audit-reports"], (1, 0, 0, 0), 20),
    ("p_business", "Business", "Production workloads", 5000, 0.018, 50.0, 10000,
     ["tenant-access", "s3-access", "buckets", "usage-billing", "capacity-alerts", "audit-reports"], (1, 1, 0, 0), 100),
    ("p_enterprise", "Enterprise", "Regulated and large scale", 50000, 0.012, 500.0, 100000,
     ["tenant-access", "s3-access", "buckets", "usage-billing", "capacity-alerts", "audit-reports"], (1, 1, 1, 1), 500),
]

STAFF = [("Alex Morgan", "admin@demo.example", "super-administrator", "Super administrator"),
         ("Sam Ortega", "ops@demo.example", "operations", "Operations"),
         ("Jo Lindqvist", "finance@demo.example", "finance", "Finance"),
         ("Pat Nakamura", "support@demo.example", "support", "Support")]

# name, plan, quota_gb, state, users[(name,email,role)], buckets[(name, GB, versioning, lock, public, lifecycle)]
CUSTOMERS = [
    ("Riverbend Analytics", "p_business", 5000, "active",
     [("Dana Whitfield", "dana@riverbend.example", "administrator"), ("Omar Haddad", "omar@riverbend.example", "operator"),
      ("Priya Raman", "priya@riverbend.example", "billing"), ("Lee Tanaka", "lee@riverbend.example", "read-only")],
     [("riverbend-raw-events", 2150, "enabled", False, False, [{"id": "expire-old-versions", "prefix": "", "expire_days": 0, "noncurrent_days": 30, "abort_multipart_days": 7}]),
      ("riverbend-curated", 940, "enabled", False, False, []),
      ("riverbend-backups", 710, "enabled", True, False, [{"id": "keep-2y", "prefix": "daily/", "expire_days": 730, "noncurrent_days": 0, "abort_multipart_days": 0}]),
      ("riverbend-web-assets", 38, "enabled", False, True, [])]),
    ("Harbourview Media", "p_starter", 1000, "active",
     [("Mara Eliot", "mara@harbourview.example", "administrator"), ("Tom Okafor", "tom@harbourview.example", "operator")],
     [("hv-media-archive", 770, "off", False, False, []), ("hv-render-cache", 105, "off", False, False, [])]),
    ("Kestrel Health Group", "p_enterprise", 50000, "pending", [("Ines Duarte", "ines@kestrel.example", "administrator")], []),
]

STORAGE_USERS = {
    "Riverbend Analytics": [("etl-pipeline", "ETL jobs", "rw"), ("bi-readonly", "BI dashboards", "ro"), ("backup-agent", "Backup software", "rw")],
    "Harbourview Media": [("render-farm", "Render nodes", "rw")],
}


def demo_accounts(surface: str) -> list[dict]:
    if surface == "admin":
        return [{"label": r, "email": e} for _, e, _, r in STAFF]
    out = []
    for name, plan, q, st, users, _ in CUSTOMERS:
        for un, ue, role in users:
            out.append({"label": f"{name} - {role}", "email": ue})
    return out


def _wipe(app) -> None:
    for t in ("alert_events", "alert_rules", "quota_requests", "statements", "usage_samples", "invitations", "sessions", "outbox",
              "notices", "audit", "audit_checkpoints", "audit_anchor", "approvals", "users", "customers", "plans", "secrets", "jobs_state"):
        app.db.run(f"DELETE FROM {t}")
    app.db.run("DELETE FROM settings WHERE key IN ('modules_off')")
    if hasattr(app.backend, "reset"):
        app.backend.reset()


def reset_and_seed(app) -> None:
    _wipe(app)
    seed(app)


def seed(app) -> None:
    if not app.cfg.demo:
        raise RuntimeError("seed is for demo mode only")
    rnd = random.Random(42)
    sim = app.backend
    db, auth = app.db, app.auth
    # plans
    for pid, name, desc, q, price, mn, auto, mods, (lock, pub, plat, ident), maxb in PLANS:
        db.run("INSERT INTO plans(id,name,description,quota_gb,price_gb_month,min_monthly,currency,modules,allow_object_lock,allow_public_buckets,"
               "allow_platform_services,allow_own_identity,max_buckets,auto_quota_gb) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (pid, name, desc, q, price, mn, "USD", json.dumps(mods), lock, pub, plat, ident, maxb, auto))
    # staff
    for name, email, role, _ in STAFF:
        auth.create_user(email, name, role, None, password=DEMO_PASSWORD, actor="demo-seed")
    now = utcnow()
    for cname, pid, quota, state, users, buckets in CUSTOMERS:
        plan = services.get_plan(app, pid)
        slug = cname.lower().split()[0]
        cid = new_id("c_")
        created = iso(now - dt.timedelta(days=400))
        db.run("INSERT INTO customers(id,name,slug,plan_id,state,contact_email,quota_gb,created_at,error) VALUES (?,?,?,?,?,?,?,?,?)",
               (cid, cname, slug, pid, state, users[0][1], quota, created, ""))
        for un, ue, role in users:
            auth.create_user(ue, un, role, cid, password=DEMO_PASSWORD, actor="demo-seed")
        if state == "pending":
            db.run("UPDATE customers SET error=? WHERE id=?", ("Simulated: the storage service did not answer when the account was created. Use Retry provisioning.", cid))
            u = db.one("SELECT id FROM users WHERE customer_id=?", (cid,))
            db.run("UPDATE users SET state='invited', pw_hash=NULL WHERE id=?", (u["id"],))
            continue
        ref = sim.create_tenant(f"{slug}-{cid[-4:]}", quota * GB, services.plan_features(plan))
        db.run("UPDATE customers SET tenant_ref=? WHERE id=?", (ref, cid))
        t = sim.s["tenants"][ref]
        sim.create_group(ref, "readwrite", "read-write")
        sim.create_group(ref, "readonly", "read-only")
        for su, desc, acc in STORAGE_USERS.get(cname, []):
            sim.create_user(ref, su, desc, ["readwrite" if acc == "rw" else "readonly"])
            sim.create_key(ref, su)
        total = 0
        for bname, gb, ver, lock, pub, lc in buckets:
            sim.create_bucket(ref, bname, "us-east-1", ver == "enabled", lock)
            b = t["buckets"][bname]
            b["bytes"], b["objects"] = int(gb * GB), int(gb * GB / (6 * 10 ** 6))
            b["public"], b["lifecycle"], b["versioning"] = pub, lc, ver
            total += b["bytes"]
        sim._save()
        # one year of daily usage with growth, a weekly rhythm and noise
        days = 365
        bshare = [(bn, g) for bn, g, *_ in buckets]
        sumg = sum(g for _, g in bshare) or 1
        for d in range(days, -1, -1):
            frac = (days - d) / days
            level = total * (0.35 + 0.65 * (frac ** 1.15)) * (1 + 0.012 * math.sin(d / 3.0) + rnd.uniform(-0.004, 0.004))
            ts = (now - dt.timedelta(days=d)).replace(hour=12, minute=0, second=0, microsecond=0)
            bl = [{"name": bn, "bytes": int(level * g / sumg), "objects": int(level * g / sumg / 6e6)} for bn, g in bshare]
            db.run("INSERT INTO usage_samples(customer_id,ts,bytes_used,objects,buckets) VALUES (?,?,?,?,?)",
                   (cid, iso(ts), int(level), sum(x["objects"] for x in bl), json.dumps(bl)))
        # statements for the last 11 full months
        first = now.replace(day=1)
        for k in range(1, 12):
            m = (first - dt.timedelta(days=1)); first_k = first
            for _ in range(k - 1):
                first_k = (first_k - dt.timedelta(days=1)).replace(day=1)
            pm = (first_k - dt.timedelta(days=1)).strftime("%Y-%m")
            services.close_period(app, pm, "demo-seed", cid)
        # alerts
        db.run("INSERT INTO alert_rules(id,customer_id,threshold_pct,channel,target) VALUES (?,?,?,?,?)", (new_id("ar_"), cid, 80, "email", users[0][1]))
        db.run("INSERT INTO alert_rules(id,customer_id,threshold_pct,channel,target) VALUES (?,?,?,?,?)", (new_id("ar_"), cid, 95, "email", users[0][1]))
        # plans that charge: audit trail
        for who, what, tgt, ago in [(users[0][1], "bucket.create", buckets[0][0], 60), (users[0][1], "storage_user.create", "etl-pipeline" if cname.startswith("River") else "render-farm", 58),
                                    (users[0][1], "key.create", "etl-pipeline" if cname.startswith("River") else "render-farm", 58),
                                    (users[-1][1], "bucket.versioning", buckets[0][0], 20), (users[0][1], "alert.create", "80%", 12)]:
            app.audit.record(what, who, "user", cid, tgt, "", "203.0.113.10")
    # alert event + quota requests
    hv = db.one("SELECT * FROM customers WHERE slug='harbourview'")
    db.run("INSERT INTO alert_events(id,customer_id,ts,message) VALUES (?,?,?,?)",
           (new_id("ae_"), hv["id"], iso(now - dt.timedelta(days=2)), "Storage use is 85% of your quota (alert at 80%)."))
    db.run("INSERT INTO quota_requests(id,customer_id,requested_gb,reason,state,created_at,requested_by) VALUES (?,?,?,?,?,?,?)",
           (new_id("q_"), hv["id"], 2000, "New season of footage is being ingested.", "open", iso(now - dt.timedelta(days=1)), "mara@harbourview.example"))
    rb = db.one("SELECT * FROM customers WHERE slug='riverbend'")
    db.run("INSERT INTO quota_requests(id,customer_id,requested_gb,reason,state,decided_by,decided_at,decision_note,created_at,requested_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
           (new_id("q_"), rb["id"], 5000, "Analytics growth", "approved", "ops@demo.example", iso(now - dt.timedelta(days=90)), "Approved.", iso(now - dt.timedelta(days=91)), "dana@riverbend.example"))
    # notices
    db.run("INSERT INTO notices(id,kind,title,body,starts_at,created_at) VALUES (?,?,?,?,?,?)",
           (new_id("n_"), "maintenance", "Planned maintenance", "Site B, Saturday 02:00-04:00 UTC. No interruption expected; requests may be slower.", iso(now), iso(now)))
    # staff activity
    for what, tgt in [("plan.update", "p_business"), ("customer.create", "Kestrel Health Group"), ("quota.set", "Riverbend Analytics")]:
        app.audit.record(what, "admin@demo.example", "user", None, tgt, "", "10.0.0.5")
