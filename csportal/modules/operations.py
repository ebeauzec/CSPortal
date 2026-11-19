"""Admin: approvals queue, drift check, backups, audit integrity, personal-data tools."""
from __future__ import annotations

import hashlib
import json

from .. import approvals, ops
from ..util import human_bytes, iso
from ..web import ui
from ..web.core import Raw, Response, redirect

MODULE = {"id": "operations", "name": "Operations", "version": "1.0.0", "core": True, "surfaces": ["admin"], "requires": [],
          "description": "Approvals by a second administrator, drift check against the grid, backups, audit integrity, personal-data export and erasure.",
          "nav": [{"surface": "admin", "label": "Approvals", "path": "/approvals", "perm": "approvals.view", "group": "System", "order": 5},
                  {"surface": "admin", "label": "Operations", "path": "/operations", "perm": "system.view", "group": "System", "order": 6},
                  {"surface": "admin", "label": "Privacy", "path": "/privacy", "perm": "users.manage", "group": "System", "order": 40}]}

_STATE = {"pending": "warn", "approved": "ok", "rejected": "bad", "expired": "", "failed": "bad", "withdrawn": ""}


def register(app):
    # ------------------------------------------------------------ approvals
    @app.route("admin", "GET", "/approvals", perm="approvals.view")
    def approvals_page(ctx):
        csrf, me = ctx.sess.csrf, ctx.sess.user_id
        rows = []
        for r in approvals.pending(app):
            mine = r["requested_by"] == me
            if mine:
                act = ui.button("Withdraw", "/approvals/withdraw", csrf, {"id": r["id"]}, "small")
            else:
                act = Raw(ui.button("Approve", "/approvals/decide", csrf, {"id": r["id"], "approve": "1"}, "small primary",
                                    confirm="Approve this action? It runs now.") +
                          ui.button("Reject", "/approvals/decide", csrf, {"id": r["id"], "approve": "0"}, "small danger"))
            rows.append([approvals.KINDS.get(r["kind"], (r["kind"],))[0], r["summary"], r["requester"] or "-",
                         r["requested_at"][:16].replace("T", " "), r["expires_at"][:16].replace("T", " "), act])
        pend = ui.table(["Action", "What will happen", "Asked by", "Asked", "Valid until", ""], rows, "Nothing is waiting for approval.")
        hist = ui.table(["Action", "What", "Asked by", "Decided by", "Result", "When"],
                        [[approvals.KINDS.get(r["kind"], (r["kind"],))[0], r["summary"], r["requester"] or "-", r["decider"] or "-",
                          ui.badge(r["state"], _STATE.get(r["state"], "")), (r["decided_at"] or r["requested_at"])[:16].replace("T", " ")]
                         for r in approvals.recent(app)], "No earlier requests.")
        on = app.cfg.d["security"].get("four_eyes")
        n = approvals.active_approvers(app)
        status = (ui.badge("on", "ok") if on and n >= 2 else ui.badge("on, but only one super administrator", "warn") if on else ui.badge("off", "warn"))
        info = Raw(f"<p>Second-administrator approval is {status}. When it is on, closing a customer, changing the grid connection and removing staff "
                   "wait here until a <strong>different</strong> super administrator approves. Change it under All settings, Security.</p>")
        return ui.page(ctx, "Approvals", Raw(ui.card("How it works", info) + ui.card("Waiting", pend) + ui.card("History", hist)), "/approvals")

    @app.route("admin", "POST", "/approvals/decide", perm="approvals.decide", reauth=True)
    def approvals_decide(ctx):
        try:
            msg = approvals.decide(app, ctx.f("id"), ctx.f("approve") == "1", ctx.sess.email, ctx.sess.user_id, ctx.req.ip, ctx.f("note"))
            ctx.flash(msg)
        except approvals.ApprovalError as e:
            ctx.flash("Error: " + str(e))
        return redirect("/approvals")

    @app.route("admin", "POST", "/approvals/withdraw", perm="approvals.view")
    def approvals_withdraw(ctx):
        try:
            approvals.withdraw(app, ctx.f("id"), ctx.sess.email, ctx.sess.user_id, ctx.req.ip)
            ctx.flash("Withdrawn.")
        except approvals.ApprovalError as e:
            ctx.flash("Error: " + str(e))
        return redirect("/approvals")

    # ------------------------------------------------------------ operations
    @app.route("admin", "GET", "/operations", perm="system.view")
    def operations_page(ctx):
        csrf, edit = ctx.sess.csrf, ctx.can("system.edit")
        v = app.audit.verify_full()
        audit_kv = ui.kv([("Chain", ui.badge(f"intact, {v['rows']:,} records", "ok") if v["ok"] else ui.badge("PROBLEM", "bad")),
                          ("Signed checkpoints", f"{v['checkpoints']:,}"),
                          ("Retention anchor", f"records up to {v['anchor_id']} archived and removed" if v["anchor_id"] else "none (nothing removed yet)"),
                          ("Retention", f"{app.cfg.d['security']['audit_retention_days']} days")])
        probs = Raw("<ul class='bad'>" + "".join(f"<li>{ui.esc(p)}</li>" for p in v["problems"]) + "</ul>") if v["problems"] else ""
        audit_card = ui.card("Audit log integrity", Raw(str(audit_kv) + str(probs) + (
            ui.button("Sign a checkpoint now", "/operations/checkpoint", csrf, {}) if edit else "") +
            "<p class='muted'>Each record contains the hash of the one before it, and signed checkpoints prove nothing was cut off the end. "
            "Records older than the retention period are archived to the data folder and removed, with a signed anchor so the rest still verifies.</p>"))

        bk = ops.list_backups(app)
        bk_rows = [[b["name"], human_bytes(b["bytes"]), b["modified"][:16].replace("T", " "),
                    ui.button("Check", "/operations/backup/check", csrf, {"name": b["name"]}, "small") if edit else ""] for b in bk[:15]]
        bk_card = ui.card("Backups", Raw(ui.table(["File", "Size", "Written", ""], bk_rows, "No backups yet.") +
                                         (ui.button("Back up now", "/operations/backup", csrf, {}, "primary") if edit else "") +
                                         f"<p class='muted'>Kept: the newest {app.cfg.d['jobs'].get('backup_keep', 14)}. Every copy is opened and "
                                         "integrity-checked when it is made. Store copies away from this host, and keep the master key separate from them.</p>"))

        row = app.db.one("SELECT value FROM settings WHERE key='drift.last'")
        rep = json.loads(row["value"]) if row else None
        drift_body = ""
        if rep:
            drift_body += f"<p class='muted'>Last checked {ui.esc(rep['at'][:19].replace('T', ' '))}: {ui.esc(ops.drift_summary(rep))}</p>"
            miss = [[m["customer"], m["ref"], "The account is not on the grid. Check the grid, or recreate the customer."] for m in rep["missing_on_grid"]]
            quo = [[q["customer"], human_bytes(q["portal_bytes"]), human_bytes(q["grid_bytes"]),
                    ui.button("Set grid to portal value", "/operations/drift/align", csrf, {"cid": q["customer_id"]}, "small",
                              confirm="Set the grid quota to the portal value?") if edit else ""] for q in rep["quota_mismatch"]]
            unk = [[u["name"], u["ref"], human_bytes(u["quota_bytes"])] for u in rep["not_in_portal"]]
            if miss:
                drift_body += str(ui.table(["Customer", "Grid reference", "Problem"], miss))
            if quo:
                drift_body += str(ui.table(["Customer", "Portal quota", "Grid quota", ""], quo))
            if unk:
                drift_body += "<h3>Accounts on the grid that the portal does not manage</h3>" + str(ui.table(["Name", "Reference", "Quota"], unk))
            if rep["ok"] and not unk:
                drift_body += "<p>" + str(ui.badge("No differences", "ok")) + "</p>"
        else:
            drift_body = "<p class='muted'>Not checked yet.</p>"
        drift_card = ui.card("Drift between the portal and the grid", Raw(drift_body + (ui.button("Check now", "/operations/drift", csrf, {}, "primary") if edit else "") +
                                                                          "<p class='muted'>Compares customers and quotas with the tenant accounts on the grid. Nothing is changed unless you press a button.</p>"))
        return ui.page(ctx, "Operations", Raw(ui.grid(audit_card, bk_card, cols=2) + drift_card), "/operations")

    @app.route("admin", "POST", "/operations/checkpoint", perm="system.edit")
    def op_checkpoint(ctx):
        ctx.flash("Checkpoint signed." if app.audit.checkpoint() else "Nothing new to sign.")
        return redirect("/operations")

    @app.route("admin", "POST", "/operations/backup", perm="system.edit")
    def op_backup(ctx):
        try:
            r = ops.backup_now(app)
        except RuntimeError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/operations")
        ctx.audit("system.backup", r["file"], f"{r['bytes']} bytes")
        ctx.flash(f"Backup {r['file']} written and checked.")
        return redirect("/operations")

    @app.route("admin", "POST", "/operations/backup/check", perm="system.edit")
    def op_backup_check(ctx):
        name = ctx.f("name")
        known = {b["name"] for b in ops.list_backups(app)}
        if name not in known:
            ctx.flash("Error: That backup does not exist.")
        else:
            res = ops.check_backup(ops.backup_dir(app) / name)
            ctx.flash(f"{name}: " + ("passed the integrity check." if res == "ok" else "Error: FAILED: " + res))
        return redirect("/operations")

    @app.route("admin", "POST", "/operations/drift", perm="system.edit")
    def op_drift(ctx):
        try:
            rep = ops.drift_report(app)
        except Exception as e:                                          # grid unreachable and similar
            ctx.flash("Error: The check could not run: " + str(e)[:200])
            return redirect("/operations")
        app.db.set_setting("drift.last", json.dumps({"at": iso(), **rep}))
        ctx.audit("drift.check", "", ops.drift_summary(rep))
        ctx.flash(ops.drift_summary(rep))
        return redirect("/operations")

    @app.route("admin", "POST", "/operations/drift/align", perm="system.edit", reauth=True)
    def op_align(ctx):
        ok = ops.align_quota(app, ctx.f("cid"), ctx.sess.email, ctx.req.ip)
        ctx.flash("The grid quota was set to the portal value. Run the check again." if ok else "Error: That customer was not found.")
        return redirect("/operations")

    # ------------------------------------------------------------ privacy
    @app.route("admin", "GET", "/privacy", perm="users.manage")
    def privacy_page(ctx):
        csrf = ctx.sess.csrf
        exp = ui.form("/privacy/export", [{"name": "email", "label": "E-mail address", "type": "email"}], csrf, "Download everything held")
        era = ui.form("/privacy/erase", [{"name": "email", "label": "E-mail address", "type": "email"},
                                         {"name": "confirm", "label": "Type the address again to confirm", "type": "email"}], csrf, "Erase this person")
        note = Raw("<p class='muted'>For data subject requests. The export lists the accounts, sessions, stored mail and audit records that mention the address. "
                   "Erasure removes the accounts, sessions, invitations and stored mail. <strong>Audit records stay</strong> until the retention period ends, because "
                   "changing them would break the tamper-evident chain; the erasure itself is recorded without the address. Both actions are in the audit log.</p>")
        return ui.page(ctx, "Privacy", Raw(ui.card("Personal data", note) + ui.card("Export", exp) + ui.card("Erase", era)), "/privacy")

    @app.route("admin", "POST", "/privacy/export", perm="users.manage", reauth=True)
    def privacy_export(ctx):
        data = ops.person_export(app, ctx.f("email"))
        ctx.audit("privacy.export", hashlib.sha256(ctx.f("email").lower().encode()).hexdigest()[:12],
                  f"{len(data['accounts'])} account(s), {len(data['audit_records'])} audit record(s)")
        r = Response(200, json.dumps(data, indent=2, ensure_ascii=False).encode(), ctype="application/json")
        r.header("Content-Disposition", 'attachment; filename="personal-data.json"')
        return r

    @app.route("admin", "POST", "/privacy/erase", perm="users.manage", reauth=True)
    def privacy_erase(ctx):
        if ctx.f("email").lower() != ctx.f("confirm").lower():
            ctx.flash("Error: The two addresses do not match. Nothing was changed.")
            return redirect("/privacy")
        try:
            r = ops.person_erase(app, ctx.f("email"), ctx.sess.email, ctx.req.ip)
        except ValueError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/privacy")
        ctx.flash(f"Erased {r['accounts']} account(s) and {r['mail']} stored mail(s).")
        return redirect("/privacy")
