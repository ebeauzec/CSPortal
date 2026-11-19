"""Four-eyes approval for the most dangerous provider actions.

When `security.four_eyes` is on and at least two super administrators are active, closing a customer, changing the
grid connection and removing a staff member are not carried out when asked. They are written down as a request that a
**different** super administrator must approve (or reject) within `security.approval_hours`. The approver sees what
will happen. The action runs once, with the original values, at the moment of approval.

The request body can hold a secret (the grid password), so it is stored encrypted under the master key.
Every step is written to the audit log: requested, approved, rejected, expired, executed.
"""
from __future__ import annotations

import datetime as dt
import json
import logging

from . import services
from .util import iso, new_id, parse_iso, utcnow

log = logging.getLogger("csportal.approvals")


class ApprovalError(Exception):
    pass


# ------------------------------------------------------------------ the actions themselves
def do_close_customer(app, payload: dict, actor: str, ip: str) -> str:
    c = app.db.one("SELECT * FROM customers WHERE id=?", (payload["cid"],))
    if not c or c["state"] == "closed":
        raise ApprovalError("The customer no longer exists or is already closed.")
    services.suspend_customer(app, c["id"], True, actor, ip)
    app.db.run("UPDATE customers SET state='closed', closed_at=? WHERE id=?", (iso(), c["id"]))
    app.audit.record("customer.close", actor, "user", c["id"], c["name"], "", ip)
    return "Account closed."


def do_remove_staff(app, payload: dict, actor: str, ip: str) -> str:
    u = app.db.one("SELECT * FROM users WHERE id=? AND customer_id IS NULL", (payload["uid"],))
    if not u:
        raise ApprovalError("That staff member no longer exists.")
    if u["role"] == "super-administrator" and app.db.one(
            "SELECT COUNT(*) FROM users WHERE customer_id IS NULL AND role='super-administrator' AND state='active' AND id!=?",
            (u["id"],))[0] == 0:
        raise ApprovalError("There must be at least one super administrator.")
    app.auth.revoke_user_sessions(u["id"])
    app.db.run("DELETE FROM invitations WHERE user_id=?", (u["id"],))
    app.db.run("DELETE FROM users WHERE id=?", (u["id"],))
    app.audit.record("staff.remove", actor, "user", None, u["email"], "", ip)
    return "Removed."


def do_save_grid(app, payload: dict, actor: str, ip: str) -> str:
    from . import settings as S
    from .backends import gridcheck
    from .bootstrap import build_backend
    conn = S.GridConn.from_json(payload["conn"], app.cfg.d["backend"]["storagegrid"].get("ca_file", ""))
    S.save_grid(app.db, conn)
    changed = ["settings"]
    if payload.get("password"):
        S.secret_put(app.db, app.box, S.GRID_SECRET, payload["password"])
        changed.append("password changed")
    elif payload.get("clear_password"):
        S.secret_clear(app.db, S.GRID_SECRET)
        changed.append("saved password removed")
    fp = ",".join(c["sha256"][:11] for c in S.cert_infos(conn.ca_pem)[0])
    app.audit.record("grid.settings.update", actor, "user", None, "",
                     f"nodes=[{S.format_nodes(conn.nodes).replace(chr(10), '; ')}] api={conn.api_version} account={conn.account_id} "
                     f"user={conn.username} endpoints=[{S.format_endpoints(conn.endpoints).replace(chr(10), '; ')}] ca={fp or 'none'} "
                     f"timeout={conn.timeout} ({', '.join(changed)})", ip)
    if app.cfg.demo:
        return "Saved. Demo mode keeps using the simulated grid."
    app.backend = build_backend(app.cfg, app.db, app.box, {"app": app})
    result = gridcheck.summary(gridcheck.diagnose(conn, S.grid_password(app.cfg, app.db, app.box)))
    S.save_test(app.db, result)
    return "Saved and applied. " + ("The connection test passed." if result["ok"] else
                                    f"The connection test found {result['failed']} problem(s): see the result below.")


KINDS = {
    "customer.close": ("Close a customer account", do_close_customer),
    "staff.remove": ("Remove a staff member", do_remove_staff),
    "grid.settings": ("Change the storage grid connection", do_save_grid),
}


# ------------------------------------------------------------------ the workflow
def active_approvers(app) -> int:
    return app.db.one("SELECT COUNT(*) n FROM users WHERE customer_id IS NULL AND role='super-administrator' AND state='active'")["n"]


def required(app) -> bool:
    """On only when asked for and when a second person exists who could approve."""
    return bool(app.cfg.d["security"].get("four_eyes")) and active_approvers(app) >= 2


def submit(app, kind: str, target: str, summary: str, payload: dict, actor_email: str, actor_id: str, ip: str) -> tuple[bool, str]:
    """Run the action now, or file a request. Returns (done, message for the screen)."""
    if kind not in KINDS:
        raise ApprovalError("Unknown action.")
    if not required(app):
        return True, KINDS[kind][1](app, payload, actor_email, ip)
    expire(app)
    if app.db.one("SELECT 1 FROM approvals WHERE kind=? AND target=? AND state='pending'", (kind, target)):
        raise ApprovalError("This action is already waiting for approval.")
    aid = new_id("ap_")
    hours = app.cfg.d["security"].get("approval_hours", 72)
    sealed = app.box.seal(json.dumps(payload), "approval:" + aid)
    app.db.run("INSERT INTO approvals(id,kind,target,summary,payload,requested_by,requested_at,expires_at) VALUES (?,?,?,?,?,?,?,?)",
               (aid, kind, target, summary[:300], sealed, actor_id, iso(), iso(utcnow() + dt.timedelta(hours=hours))))
    app.audit.record("approval.requested", actor_email, "user", None, aid, f"{kind}: {summary[:200]}", ip)
    return False, f"This needs approval by another super administrator. Request {aid} was filed and is valid for {hours} hours."


def expire(app) -> int:
    n = 0
    for r in app.db.all("SELECT id, kind FROM approvals WHERE state='pending' AND expires_at < ?", (iso(),)):
        app.db.run("UPDATE approvals SET state='expired', decided_at=? WHERE id=?", (iso(), r["id"]))
        app.audit.record("approval.expired", "system", "system", None, r["id"], r["kind"])
        n += 1
    return n


def decide(app, aid: str, approve: bool, user_email: str, user_id: str, ip: str, note: str = "") -> str:
    expire(app)
    r = app.db.one("SELECT * FROM approvals WHERE id=?", (aid,))
    if not r or r["state"] != "pending":
        raise ApprovalError("This request is not waiting any more.")
    if r["requested_by"] == user_id:
        raise ApprovalError("A different super administrator must decide. You cannot approve your own request.")
    if not approve:
        app.db.run("UPDATE approvals SET state='rejected', decided_by=?, decided_at=?, note=? WHERE id=?",
                   (user_id, iso(), note[:300], aid))
        app.audit.record("approval.rejected", user_email, "user", None, aid, f"{r['kind']}: {note[:200]}", ip)
        return "Rejected. Nothing was changed."
    payload = json.loads(app.box.open(r["payload"], "approval:" + aid))
    # claim first, so two clicks cannot run it twice
    if app.db.run("UPDATE approvals SET state='approved', decided_by=?, decided_at=?, note=? WHERE id=? AND state='pending'",
                  (user_id, iso(), note[:300], aid)).rowcount != 1:
        raise ApprovalError("This request is not waiting any more.")
    app.audit.record("approval.approved", user_email, "user", None, aid, f"{r['kind']}: {r['summary'][:200]}", ip)
    try:
        msg = KINDS[r["kind"]][1](app, payload, user_email, ip)
    except Exception as e:
        app.db.run("UPDATE approvals SET state='failed', note=? WHERE id=?", (str(e)[:300], aid))
        app.audit.record("approval.failed", user_email, "user", None, aid, str(e)[:200], ip)
        raise
    app.db.run("UPDATE approvals SET payload=? WHERE id=?", (app.box.seal("{}", "approval:" + aid), aid))   # the secret is no longer needed
    return msg


def withdraw(app, aid: str, user_email: str, user_id: str, ip: str) -> None:
    r = app.db.one("SELECT * FROM approvals WHERE id=? AND state='pending'", (aid,))
    if not r or r["requested_by"] != user_id:
        raise ApprovalError("Only the person who asked can withdraw a waiting request.")
    app.db.run("UPDATE approvals SET state='withdrawn', decided_at=?, payload=? WHERE id=?",
               (iso(), app.box.seal("{}", "approval:" + aid), aid))
    app.audit.record("approval.withdrawn", user_email, "user", None, aid, r["kind"], ip)


def pending(app) -> list:
    expire(app)
    return app.db.all("SELECT a.*, u.email requester FROM approvals a LEFT JOIN users u ON u.id=a.requested_by "
                      "WHERE a.state='pending' ORDER BY a.requested_at")


def recent(app, limit: int = 30) -> list:
    return app.db.all("SELECT a.*, u.email requester, d.email decider FROM approvals a LEFT JOIN users u ON u.id=a.requested_by "
                      "LEFT JOIN users d ON d.id=a.decided_by WHERE a.state!='pending' ORDER BY a.requested_at DESC LIMIT ?", (limit,))
