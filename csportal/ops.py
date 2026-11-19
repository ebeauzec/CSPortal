"""Operations that keep the service healthy and its data under control: backups, drift check, key rotation, personal data.

Everything here is plain functions on the application, used by the job runner, the admin console and the command line.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import sqlite3
from pathlib import Path

from . import crypto, logs
from .util import GB, iso

log = logging.getLogger("csportal.ops")
_BACKUP = re.compile(r"^csportal-(\d{8}T\d{6}Z)(?:-(\d+))?\.db$")


# ------------------------------------------------------------------ backups
def backup_dir(app) -> Path:
    return app.cfg.data_dir / "backups"


def _order(f: Path):
    """Newest last: by time stamp, then by the counter used when two copies are made in the same second."""
    m = _BACKUP.match(f.name)
    return (m.group(1), int(m.group(2) or 1)) if m else (f.name, 0)


def list_backups(app) -> list[dict]:
    d = backup_dir(app)
    out = []
    for f in sorted(d.glob("csportal-*.db"), key=_order, reverse=True) if d.exists() else []:
        st = f.stat()
        out.append({"name": f.name, "bytes": st.st_size, "modified": iso(dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc))})
    return out


def check_backup(path: Path) -> str:
    """Open a backup read-only and run SQLite's integrity check. Returns "ok" or the problem."""
    try:
        c = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            res = c.execute("PRAGMA integrity_check").fetchone()[0]
            c.execute("SELECT COUNT(*) FROM audit").fetchone()
        finally:
            c.close()
        return "ok" if res == "ok" else str(res)[:200]
    except Exception as e:                                  # a damaged file raises in many ways
        return f"{type(e).__name__}: {e}"[:200]


def backup_now(app, keep: int | None = None, label: str = "csportal") -> dict:
    """Write a consistent copy, check it, then remove the oldest copies beyond `keep` (0 keeps all)."""
    keep = app.cfg.d["jobs"].get("backup_keep", 14) if keep is None else keep
    stamp = iso().replace(":", "").replace("-", "")
    dest = backup_dir(app) / f"{label}-{stamp}.db"
    same = [f for f in backup_dir(app).glob(f"{label}-{stamp}*.db")]
    if same:                                                # another copy in the same second: count on from the highest one
        n = max(_order(f)[1] for f in same) + 1
        dest = backup_dir(app) / f"{label}-{stamp}-{n}.db"
    app.db.backup(dest)
    state = check_backup(dest)
    if state != "ok":
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"The backup did not pass its check and was removed: {state}")
    removed = 0
    if keep and label == "csportal":
        old = [b for b in list_backups(app) if _BACKUP.match(b["name"])]
        for b in old[keep:]:
            (backup_dir(app) / b["name"]).unlink(missing_ok=True)
            removed += 1
    return {"file": dest.name, "bytes": dest.stat().st_size, "removed_old": removed}


# ------------------------------------------------------------------ drift between portal and grid
def drift_report(app) -> dict:
    """Compare the portal's customers with the tenant accounts on the grid. Nothing is changed."""
    tenants = {t["ref"]: t for t in app.backend.list_tenants()}
    custs = app.db.all("SELECT * FROM customers WHERE tenant_ref IS NOT NULL AND state NOT IN ('closed')")
    known = {c["tenant_ref"] for c in app.db.all("SELECT tenant_ref FROM customers WHERE tenant_ref IS NOT NULL")}
    missing, quota = [], []
    for c in custs:
        t = tenants.get(c["tenant_ref"])
        if t is None:
            missing.append({"customer_id": c["id"], "customer": c["name"], "ref": c["tenant_ref"]})
        elif int(t["quota_bytes"]) != int(c["quota_gb"]) * GB:
            quota.append({"customer_id": c["id"], "customer": c["name"], "ref": c["tenant_ref"], "portal_bytes": int(c["quota_gb"]) * GB,
                          "grid_bytes": int(t["quota_bytes"])})
    unknown = [{"ref": r, "name": t["name"], "quota_bytes": t["quota_bytes"]} for r, t in tenants.items() if r not in known]
    return {"checked": len(custs), "grid_accounts": len(tenants), "missing_on_grid": missing, "quota_mismatch": quota,
            "not_in_portal": unknown, "ok": not (missing or quota)}


def drift_summary(rep: dict) -> str:
    return (f"{rep['checked']} customer(s) checked: {len(rep['missing_on_grid'])} missing on the grid, "
            f"{len(rep['quota_mismatch'])} quota difference(s); {len(rep['not_in_portal'])} grid account(s) not managed here")


def align_quota(app, customer_id: str, actor: str, ip: str = "") -> bool:
    c = app.db.one("SELECT * FROM customers WHERE id=? AND tenant_ref IS NOT NULL", (customer_id,))
    if not c:
        return False
    app.backend.update_tenant(c["tenant_ref"], quota_bytes=int(c["quota_gb"]) * GB)
    app.audit.record("drift.quota_aligned", actor, "user", c["id"], c["name"], f"grid quota set to {c['quota_gb']} GB (portal value)", ip)
    return True


# ------------------------------------------------------------------ tenant credentials
def set_tenant_password(app, slug: str, password: str, actor: str, ip: str = "") -> None:
    """Keep a new tenant root password after it was changed on the grid. It is tested with a real call first; if the
    grid refuses it, the old value stays. Raises ValueError with a message for the operator."""
    from . import services
    c = app.db.one("SELECT * FROM customers WHERE slug=? AND tenant_ref IS NOT NULL", (slug,))
    if not c:
        raise ValueError("No customer with that short name and a grid account.")
    if not password:
        raise ValueError("No password given.")
    get, put = services.grid_creds_getter(app), services.grid_creds_putter(app)
    before = get(c["tenant_ref"]) or {}
    user = before.get("username", "root")
    put(c["tenant_ref"], {"username": user, "password": password})
    try:
        getattr(app.backend, "_tokens", {}).pop(c["tenant_ref"], None)
        app.backend.list_users(c["tenant_ref"])                       # a real call with the new credentials
    except Exception as e:
        put(c["tenant_ref"], {"username": user, "password": before.get("password", "")})
        raise ValueError(f"The grid did not accept the new password. The old value was kept. ({e})")
    app.audit.record("tenant.credentials_updated", actor, "user", c["id"], c["name"], "tenant management password replaced", ip)


# ------------------------------------------------------------------ master key rotation
def rotate_master_key(app, new_key: bytes) -> dict:
    """Re-encrypt every stored secret under a new master key, then re-sign the audit checkpoints.

    All or nothing: every value is decrypted with the old key first; if any fails nothing is changed. The caller must
    stop the service first and start it again with the new key afterwards."""
    if len(new_key) != 32:
        raise ValueError("The new master key must be exactly 32 bytes.")
    old, new = app.box, crypto.SecretBox(new_key)
    plan: list[tuple[str, str, str]] = []          # (table, key, new sealed)
    for r in app.db.all("SELECT name, sealed FROM secrets"):
        plan.append(("secrets", r["name"], new.seal(old.open(r["sealed"], r["name"]), r["name"])))
    for r in app.db.all("SELECT id, totp_sealed FROM users WHERE totp_sealed IS NOT NULL"):
        plan.append(("users", r["id"], new.seal(old.open(r["totp_sealed"], "totp:" + r["id"]), "totp:" + r["id"])))
    for r in app.db.all("SELECT id, payload FROM approvals"):
        plan.append(("approvals", r["id"], new.seal(old.open(r["payload"], "approval:" + r["id"]), "approval:" + r["id"])))
    with app.db.tx() as c:
        for table, key, sealed in plan:
            if table == "secrets":
                c.execute("UPDATE secrets SET sealed=?, updated_at=? WHERE name=?", (sealed, iso(), key))
            elif table == "approvals":
                c.execute("UPDATE approvals SET payload=? WHERE id=?", (sealed, key))
            else:
                c.execute("UPDATE users SET totp_sealed=? WHERE id=?", (sealed, key))
    # prove it before reporting success
    for r in app.db.all("SELECT name, sealed FROM secrets"):
        new.open(r["sealed"], r["name"])
    for r in app.db.all("SELECT id, totp_sealed FROM users WHERE totp_sealed IS NOT NULL"):
        new.open(r["totp_sealed"], "totp:" + r["id"])
    for r in app.db.all("SELECT id, payload FROM approvals"):
        new.open(r["payload"], "approval:" + r["id"])
    app.audit.resign(new.derive("audit-checkpoint"))
    app.box = app.auth.box = new
    app.audit.record("system.master_key_rotated", "cli", "system", None, "", f"{len(plan)} secret(s) re-encrypted")
    return {"secrets": sum(1 for p in plan if p[0] == "secrets"), "totp": sum(1 for p in plan if p[0] == "users")}


# ------------------------------------------------------------------ personal data
def person_export(app, email: str) -> dict:
    """Everything the portal holds about one e-mail address, without secrets or password hashes."""
    email = email.strip().lower()
    users = app.db.all("SELECT id, customer_id, email, name, role, state, mfa_enabled, created_at, last_login FROM users WHERE email=?", (email,))
    ids = [u["id"] for u in users]
    audit = app.db.all("SELECT * FROM audit WHERE lower(actor)=? OR lower(target)=? OR lower(detail) LIKE ? ORDER BY id", (email, email, f"%{email}%"))
    outbox = app.db.all("SELECT id, created_at, subject, state, sent_at FROM outbox WHERE lower(to_addr)=?", (email,))
    sessions = app.db.all(f"SELECT created_at, last_seen, surface, ip FROM sessions WHERE user_id IN ({','.join('?' * len(ids))})", ids) if ids else []
    return {"generated_at": iso(), "email": email, "accounts": [dict(u) for u in users], "sessions": [dict(s) for s in sessions],
            "audit_records": [dict(a) for a in audit], "mail": [dict(o) for o in outbox],
            "notes": ["Secrets, password hashes and multi-factor secrets are never included.",
                      "Audit records are kept for their retention period so the log stays tamper-evident."]}


def person_erase(app, email: str, actor: str, ip: str = "") -> dict:
    """Remove the account(s), sessions, invitations and stored mail for one address.

    Audit records are NOT changed: rewriting them would break the tamper-evident chain. They leave the system when the
    retention period ends (security.audit_retention_days). The erasure itself is recorded with a hash, not the address."""
    email = email.strip().lower()
    users = app.db.all("SELECT * FROM users WHERE email=?", (email,))
    for u in users:
        if u["role"] in ("administrator", "super-administrator") and u["state"] == "active":
            same = "customer_id=?" if u["customer_id"] else "customer_id IS NULL"
            params = (u["customer_id"], u["role"], u["id"]) if u["customer_id"] else (u["role"], u["id"])
            others = app.db.one(f"SELECT COUNT(*) n FROM users WHERE {same} AND role=? AND state='active' AND id!=?", params)["n"]
            if others == 0:
                raise ValueError("This person is the last active administrator. Appoint another administrator first.")
    n_out = app.db.run("DELETE FROM outbox WHERE lower(to_addr)=?", (email,)).rowcount
    for u in users:
        app.db.run("DELETE FROM sessions WHERE user_id=?", (u["id"],))
        app.db.run("DELETE FROM invitations WHERE user_id=?", (u["id"],))
        app.db.run("DELETE FROM users WHERE id=?", (u["id"],))
    digest = hashlib.sha256(email.encode()).hexdigest()[:12]
    app.audit.record("privacy.erase", actor, "user", None, f"person:{digest}",
                     f"{len(users)} account(s) and {n_out} stored mail(s) removed; audit records stay until retention ends", ip)
    return {"accounts": len(users), "mail": n_out}
