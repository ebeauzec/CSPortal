"""Business services shared by both surfaces and the job runner."""
from __future__ import annotations

import datetime as dt
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage

from . import logs
from .backends.base import BackendError
from .util import GB, iso, month_of, new_id, parse_iso, slugify, utcnow

log = logging.getLogger("csportal")
jlog = logging.getLogger("csportal.job")


# ------------------------------------------------------------------ plans
def plan_features(plan) -> dict:
    return {"object_lock": bool(plan["allow_object_lock"]), "platform_services": bool(plan["allow_platform_services"]),
            "own_identity": bool(plan["allow_own_identity"]), "public_buckets": bool(plan["allow_public_buckets"]),
            "max_buckets": plan["max_buckets"]}


def get_plan(app, plan_id: str):
    return app.db.one("SELECT * FROM plans WHERE id=?", (plan_id,))


def customer_plan(app, customer):
    return get_plan(app, customer["plan_id"])


# ------------------------------------------------------------------ grid credentials (encrypted)
def grid_creds_getter(app):
    def get(ref: str):
        r = app.db.one("SELECT sealed FROM secrets WHERE name=?", ("tenant:" + ref,))
        return json.loads(app.box.open(r["sealed"], "tenant:" + ref)) if r else None
    return get


def grid_creds_putter(app):
    def put(ref: str, creds: dict):
        cur = grid_creds_getter(app)(ref) or {}
        cur.update(creds)
        app.db.run("INSERT INTO secrets(name,sealed,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET "
                   "sealed=excluded.sealed, updated_at=excluded.updated_at",
                   ("tenant:" + ref, app.box.seal(json.dumps(cur), "tenant:" + ref), iso()))
    return put


# ------------------------------------------------------------------ mail
def redact_links(body: str) -> str:
    import re
    return re.sub(r"(/(?:invite|reset)/)[A-Za-z0-9_-]+", r"\1[REDACTED]", body)


def send_mail(app, to: str, subject: str, body: str, customer_id: str | None = None) -> str:
    mid = new_id("m_")
    app.db.run("INSERT INTO outbox(id,customer_id,to_addr,subject,body,created_at) VALUES (?,?,?,?,?,?)",
               (mid, customer_id, to, subject, body, iso()))
    smtp = app.cfg.d["smtp"]
    if app.cfg.demo or not smtp["host"]:
        app.db.run("UPDATE outbox SET state=? WHERE id=?", ("captured" if app.cfg.demo else "not-configured", mid))
        return mid
    try:
        import os
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = smtp["from"], to, subject
        msg.set_content(body)
        with smtplib.SMTP(smtp["host"], int(smtp["port"]), timeout=20) as s:
            if smtp["starttls"]:
                s.starttls(context=ssl.create_default_context())
            pw = os.environ.get(smtp["password_env"], "")
            if smtp["username"] and pw:
                s.login(smtp["username"], pw)
            s.send_message(msg)
        # Once delivered, the stored copy no longer holds any single-use link.
        app.db.run("UPDATE outbox SET state='sent', sent_at=?, body=? WHERE id=?", (iso(), redact_links(body), mid))
    except Exception as e:  # mail must never break a request
        logs.event(log, logging.WARNING, "mail failed", to=to, error=str(e)[:200])
        app.db.run("UPDATE outbox SET state='failed', error=? WHERE id=?", (str(e)[:300], mid))
    return mid


def invite_link(app, token: str, purpose: str = "invite", admin: bool = False) -> str:
    base = app.cfg.d["admin_public_url" if admin else "public_url"].rstrip("/")
    return f"{base}/{purpose}/{token}"


# ------------------------------------------------------------------ notices
def active_notices(app) -> list:
    now = iso()
    return app.db.all("SELECT * FROM notices WHERE active=1 AND (starts_at IS NULL OR starts_at<=?) "
                      "AND (ends_at IS NULL OR ends_at>=?) ORDER BY created_at DESC", (now, now))


# ------------------------------------------------------------------ provisioning
def provision_customer(app, name: str, plan_id: str, contact_email: str, admin_name: str, actor: str, ip: str = "") -> str:
    """Create the customer record, the grid tenant, the first administrator and the invitation.
    A failure at the back end leaves the customer 'pending' with the error and a retry action."""
    plan = get_plan(app, plan_id)
    if not plan:
        raise ValueError("Unknown plan.")
    slug = slugify(name)
    base, n = slug, 1
    while app.db.one("SELECT 1 FROM customers WHERE slug=?", (slug,)):
        n += 1
        slug = f"{base}-{n}"
    cid = new_id("c_")
    app.db.run("INSERT INTO customers(id,name,slug,plan_id,state,contact_email,quota_gb,created_at) VALUES (?,?,?,?,?,?,?,?)",
               (cid, name.strip(), slug, plan_id, "pending", contact_email.lower(), plan["quota_gb"], iso()))
    app.audit.record("customer.create", actor, "user", cid, name, f"plan={plan_id}", ip)
    uid = app.auth.create_user(contact_email, admin_name or contact_email, "administrator", cid, actor=actor, ip=ip)
    complete_provisioning(app, cid, actor, ip, first_user=uid)
    return cid


def complete_provisioning(app, cid: str, actor: str, ip: str = "", first_user: str | None = None) -> bool:
    c = app.db.one("SELECT * FROM customers WHERE id=?", (cid,))
    plan = customer_plan(app, c)
    try:
        if not c["tenant_ref"]:
            ref = app.backend.create_tenant(f"{c['slug']}-{c['id'][-4:]}", int(c["quota_gb"]) * GB, plan_features(plan))
            app.db.run("UPDATE customers SET tenant_ref=? WHERE id=?", (ref, cid))
            app.audit.record("tenant.create", actor, "user", cid, ref, "", ip)
        app.db.run("UPDATE customers SET state='active', error='' WHERE id=?", (cid,))
    except BackendError as e:
        app.db.run("UPDATE customers SET state='pending', error=? WHERE id=?", (e.message, cid))
        app.audit.record("tenant.create_failed", actor, "user", cid, "", e.message, ip)
        logs.event(log, logging.ERROR, "provisioning failed", customer=cid, code=e.code, message=e.message)
        return False
    uid = first_user or (app.db.one("SELECT id FROM users WHERE customer_id=? ORDER BY created_at LIMIT 1", (cid,)) or {"id": None})["id"]
    if uid:
        u = app.db.one("SELECT * FROM users WHERE id=?", (uid,))
        if u and u["state"] == "invited":
            tok = app.auth.invite_token(uid)
            send_mail(app, u["email"], f"Your {app.cfg.d['branding']['name']} account",
                      f"Hello {u['name']},\n\nYour storage account is ready. Set your password here:\n"
                      f"{invite_link(app, tok)}\n\nThe link works for 72 hours.\n", cid)
    sample_usage(app, c)
    return True


def suspend_customer(app, cid: str, suspend: bool, actor: str, ip: str = "") -> None:
    c = app.db.one("SELECT * FROM customers WHERE id=?", (cid,))
    if c["tenant_ref"]:
        app.backend.set_suspended(c["tenant_ref"], suspend)
    app.db.run("UPDATE customers SET state=? WHERE id=?", ("suspended" if suspend else "active", cid))
    if suspend:
        for u in app.db.all("SELECT id FROM users WHERE customer_id=?", (cid,)):
            app.auth.revoke_user_sessions(u["id"])
    app.audit.record("customer.suspend" if suspend else "customer.resume", actor, "user", cid, c["name"], "", ip)


def set_quota(app, cid: str, quota_gb: int, actor: str, ip: str = "", reason: str = "") -> None:
    c = app.db.one("SELECT * FROM customers WHERE id=?", (cid,))
    if c["tenant_ref"]:
        app.backend.update_tenant(c["tenant_ref"], quota_bytes=int(quota_gb) * GB)
    app.db.run("UPDATE customers SET quota_gb=? WHERE id=?", (int(quota_gb), cid))
    app.audit.record("quota.set", actor, "user", cid, c["name"], f"{c['quota_gb']} GB -> {quota_gb} GB {reason}".strip(), ip)


# ------------------------------------------------------------------ usage
def sample_usage(app, customer) -> dict | None:
    if not customer["tenant_ref"] or customer["state"] not in ("active", "suspended"):
        return None
    u = app.backend.usage(customer["tenant_ref"])
    app.db.run("INSERT INTO usage_samples(customer_id,ts,bytes_used,objects,buckets) VALUES (?,?,?,?,?)",
               (customer["id"], iso(), u["bytes_used"], u["objects"], json.dumps(u["buckets"])))
    return u


def sample_all(app) -> tuple[int, int]:
    ok = bad = 0
    for c in app.db.all("SELECT * FROM customers WHERE state IN ('active','suspended') AND tenant_ref IS NOT NULL"):
        try:
            sample_usage(app, c)
            ok += 1
        except BackendError as e:
            bad += 1
            logs.event(jlog, logging.WARNING, "usage sample failed", customer=c["id"], code=e.code)
    return ok, bad


def usage_series(app, cid: str, days: int = 365) -> list[tuple[str, float]]:
    """One point per day (the last sample of that day), in GB."""
    since = iso(utcnow() - dt.timedelta(days=days))
    rows = app.db.all("SELECT substr(ts,1,10) d, bytes_used FROM usage_samples WHERE customer_id=? AND ts>=? ORDER BY ts",
                      (cid, since))
    last: dict[str, int] = {}
    for r in rows:
        last[r["d"]] = r["bytes_used"]
    return [(d[5:], v / GB) for d, v in sorted(last.items())]


def latest_sample(app, cid: str):
    return app.db.one("SELECT * FROM usage_samples WHERE customer_id=? ORDER BY ts DESC LIMIT 1", (cid,))


# ------------------------------------------------------------------ statements
def close_period(app, period: str, actor: str = "system", customer_id: str | None = None) -> int:
    """Create the monthly statement for every customer that has samples and no statement yet.
    A closed statement is never changed; corrections are separate adjustment rows."""
    n = 0
    start = f"{period}-01T00:00:00Z"
    y, m = int(period[:4]), int(period[5:7])
    end_dt = dt.datetime(y + (m == 12), (m % 12) + 1, 1, tzinfo=dt.timezone.utc)
    q = "SELECT * FROM customers WHERE state IN ('active','suspended')" + (" AND id=?" if customer_id else "")
    for c in app.db.all(q, (customer_id,) if customer_id else ()):
        if app.db.one("SELECT 1 FROM statements WHERE customer_id=? AND period=? AND adjusts IS NULL", (c["id"], period)):
            continue
        rows = app.db.all("SELECT bytes_used FROM usage_samples WHERE customer_id=? AND ts>=? AND ts<?",
                          (c["id"], start, iso(end_dt)))
        if not rows:
            continue
        plan = customer_plan(app, c)
        avg = sum(r["bytes_used"] for r in rows) / len(rows) / GB
        peak = max(r["bytes_used"] for r in rows) / GB
        storage = max(float(plan["min_monthly"]), round(avg * float(plan["price_gb_month"]), 2))
        app.db.run("INSERT INTO statements(id,customer_id,period,avg_gb,peak_gb,storage_amount,other_amount,total,currency,created_at) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (new_id("st_"), c["id"], period, round(avg, 3), round(peak, 3), storage, 0, storage, plan["currency"], iso()))
        app.audit.record("statement.close", actor, "system", c["id"], period, f"total={storage}")
        n += 1
    return n


def adjust_statement(app, statement_id: str, amount: float, note: str, actor: str, ip: str = "") -> None:
    s = app.db.one("SELECT * FROM statements WHERE id=?", (statement_id,))
    if not s or s["adjusts"]:
        raise ValueError("Statement not found, or it is itself an adjustment.")
    n = app.db.one("SELECT COUNT(*) n FROM statements WHERE adjusts LIKE ?", (statement_id + ":%",))["n"] + 1
    app.db.run("INSERT INTO statements(id,customer_id,period,avg_gb,peak_gb,storage_amount,other_amount,total,currency,state,adjusts,note,created_at) "
               "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (new_id("st_"), s["customer_id"], s["period"], 0, 0, 0, amount, amount, s["currency"], "adjustment",
                f"{statement_id}:{n}", note[:300], iso()))
    app.audit.record("statement.adjust", actor, "user", s["customer_id"], s["period"], f"{amount} {note}", ip)


def closed_periods_due(app) -> list[str]:
    """Previous full months that have samples but no statements."""
    now = utcnow()
    first = now.replace(day=1)
    prev = (first - dt.timedelta(days=1))
    return [month_of(prev)]


def month_to_date(app, customer) -> dict:
    plan = customer_plan(app, customer)
    start = utcnow().strftime("%Y-%m-01T00:00:00Z")
    rows = app.db.all("SELECT bytes_used FROM usage_samples WHERE customer_id=? AND ts>=?", (customer["id"], start))
    if not rows:
        return {"avg_gb": 0.0, "amount": float(plan["min_monthly"]), "currency": plan["currency"]}
    avg = sum(r["bytes_used"] for r in rows) / len(rows) / GB
    return {"avg_gb": avg, "amount": max(float(plan["min_monthly"]), round(avg * float(plan["price_gb_month"]), 2)),
            "currency": plan["currency"]}


# ------------------------------------------------------------------ alerts
def check_alerts(app) -> int:
    fired = 0
    for c in app.db.all("SELECT * FROM customers WHERE state='active'"):
        s = latest_sample(app, c["id"])
        if not s or not c["quota_gb"]:
            continue
        pct = s["bytes_used"] / (c["quota_gb"] * GB) * 100
        for r in app.db.all("SELECT * FROM alert_rules WHERE customer_id=? AND active=1 ORDER BY threshold_pct", (c["id"],)):
            if pct >= r["threshold_pct"]:
                if r["last_fired"] and parse_iso(r["last_fired"]) > utcnow() - dt.timedelta(hours=24):
                    continue
                msg = f"Storage use is {pct:.0f}% of your quota (alert at {r['threshold_pct']}%)."
                app.db.run("INSERT INTO alert_events(id,customer_id,rule_id,ts,message) VALUES (?,?,?,?,?)",
                           (new_id("ae_"), c["id"], r["id"], iso(), msg))
                app.db.run("UPDATE alert_rules SET last_fired=? WHERE id=?", (iso(), r["id"]))
                if r["channel"] == "email":
                    send_mail(app, r["target"], f"Storage alert for {c['name']}", msg, c["id"])
                app.audit.record("alert.fired", "system", "system", c["id"], r["id"], msg)
                fired += 1
            elif r["last_fired"] and pct < r["threshold_pct"] - 5:
                app.db.run("UPDATE alert_rules SET last_fired=NULL WHERE id=?", (r["id"],))   # re-arm below the threshold
    return fired


# ------------------------------------------------------------------ bucket posture
def bucket_posture(b: dict) -> list[tuple[str, bool, str]]:
    """(label, good, advice) rows for the protection panel."""
    return [
        ("Versioning", b["versioning"] == "enabled",
         "Turn versioning on so deleted or overwritten objects can be recovered."),
        ("Object Lock", bool(b["object_lock"]), "Object Lock can only be chosen when a bucket is created. Use it for data that must not change."),
        ("Private", not b["public"], "This bucket allows public reads. Make sure that is intended."),
        ("Lifecycle rules", bool(b["lifecycle"]), "Add a rule to expire old versions and incomplete uploads and keep costs down."),
    ]
