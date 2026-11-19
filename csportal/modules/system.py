"""Admin core: system health, log viewer, diagnostic bundle, backup, staff users, branding, demo reset."""
from __future__ import annotations

import io
import json
import platform
import re
import sys
import zipfile
from pathlib import Path

from .. import COPYRIGHT, PRODUCT, __version__, crypto, logs, services
from ..auth import AuthError, CSP_ROLES
from ..util import human_bytes, iso, valid_email
from ..web import ui
from ..web.core import Raw, Response, redirect, text_response

MODULE = {"id": "system", "name": "System", "version": "1.0.0", "core": True, "surfaces": ["admin"], "requires": [],
          "description": "Health, logs, diagnostics, backup, staff users, branding.",
          "nav": [{"surface": "admin", "label": "System health", "path": "/system", "perm": "system.view", "group": "System", "order": 1},
                  {"surface": "admin", "label": "Logs", "path": "/logs", "perm": "logs.view", "group": "System", "order": 20},
                  {"surface": "admin", "label": "Mail outbox", "path": "/outbox", "perm": "system.view", "group": "System", "order": 30},
                  {"surface": "admin", "label": "Staff users", "path": "/staff", "perm": "users.manage", "group": "Platform", "order": 20},
                  {"surface": "admin", "label": "Branding", "path": "/branding", "perm": "settings.edit", "group": "Platform", "order": 30}]}

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_SECRET_CFG = re.compile(r"(?i)(password|secret|key|token)")


def _scrub_cfg(d):
    if isinstance(d, dict):
        return {k: ("[REDACTED]" if _SECRET_CFG.search(k) and isinstance(v, str) and v and not k.endswith("_env") else _scrub_cfg(v)) for k, v in d.items()}
    return d


def build_bundle(app) -> bytes:
    """One portable archive with what is needed to diagnose a problem remotely. No secrets, no object data."""
    buf = io.BytesIO()
    v = app.audit.verify_full()
    files: dict[str, str] = {}
    files["system.json"] = json.dumps({
        "product": PRODUCT, "version": __version__, "created": iso(), "python": sys.version, "platform": platform.platform(),
        "mode": app.cfg.d["mode"], "schema_version": app.db.schema_version(), "uptime_s": int(__import__("time").time() - app.started),
        "modules": {k: v["version"] for k, v in app.modules.items()}, "connector": app.backend.name,
        "connector_verified_on_real_grid": app.backend.verified}, indent=2)
    files["config.json"] = json.dumps(_scrub_cfg(app.cfg.d), indent=2)
    files["backend_health.json"] = json.dumps(app.backend.health(), indent=2)
    from .. import settings as S
    gc = S.load_grid(app.cfg, app.db)
    files["grid_connection.json"] = json.dumps({
        "admin_nodes": [vars(n) for n in gc.nodes], "api_version": gc.api_version, "account_id": gc.account_id, "username": gc.username,
        "password": S.grid_password_source(app.cfg, app.db), "ca_certificates": S.cert_infos(gc.ca_pem)[0], "ca_file": gc.ca_file,
        "source_address": gc.source_address, "timeout": gc.timeout, "s3_endpoints": [vars(e) for e in gc.endpoints],
        "active_admin_node": getattr(app.backend, "base", ""), "last_test": S.last_test(app.db),
        "settings_changed_in_console": [r["key"] for r in app.db.all("SELECT key FROM settings WHERE key LIKE 'cfg.%' ORDER BY key")]}, indent=2)
    files["audit_chain.json"] = json.dumps({"intact": v["ok"], "first_bad_id": v["bad_id"], "records": v["rows"], "problems": v["problems"],
                                           "checkpoints": v["checkpoints"], "archived_up_to_id": v["anchor_id"]}, indent=2)
    from .. import ops
    files["backups.json"] = json.dumps(ops.list_backups(app), indent=2)
    row = app.db.one("SELECT value FROM settings WHERE key='drift.last'")
    files["drift_last.json"] = row["value"] if row else "{}"
    files["approvals_waiting.json"] = json.dumps([{"id": r["id"], "kind": r["kind"], "summary": r["summary"], "expires_at": r["expires_at"]}
                                                  for r in app.db.all("SELECT * FROM approvals WHERE state='pending'")], indent=2)
    files["jobs.json"] = json.dumps([dict(r) for r in app.db.all("SELECT * FROM jobs_state")], indent=2)
    files["customers_summary.json"] = json.dumps([dict(r) for r in app.db.all(
        "SELECT id, state, plan_id, quota_gb, error, created_at FROM customers")], indent=2)
    ld = app.log_dir or app.cfg.data_dir / "logs"
    files["logs/csportal.log.txt"] = "\n".join(logs.tail(Path(ld) / "csportal.log", 5000))
    files["logs/access.log.txt"] = "\n".join(logs.tail(Path(ld) / "access.log", 2000))
    manifest = ["CSPortal diagnostic bundle", f"Created: {iso()}", f"Version: {__version__}", "",
                "Contents (all secrets removed; no customer object data):"] + [f"  {k}" for k in sorted(files)]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MANIFEST.txt", "\n".join(manifest) + "\n")
        for k, v in files.items():
            z.writestr(k, logs.scrub(v))
    return buf.getvalue()


def register(app):
    @app.route("admin", "GET", "/system", perm="system.view")
    def system(ctx):
        h = app.backend.health()
        ok, bad, n = app.audit.verify()
        jobs = app.db.all("SELECT * FROM jobs_state ORDER BY name")
        ld = Path(app.log_dir or app.cfg.data_dir / "logs")
        logsize = sum(f.stat().st_size for f in ld.glob("*.log*")) if ld.exists() else 0
        dbsize = app.db.path.stat().st_size if app.db.path.exists() else 0
        facts = ui.card("Service", ui.kv([
            ("Product", f"{PRODUCT} {__version__}"), ("Mode", ui.badge("DEMO", "warn") if app.cfg.demo else ui.badge("production", "ok")),
            ("Schema version", str(app.db.schema_version())), ("Database size", human_bytes(dbsize)), ("Log size", human_bytes(logsize)),
            ("Audit chain", ui.badge(f"intact, {n:,} records", "ok") if ok else ui.badge(f"BROKEN at {bad}", "bad")),
            ("Outgoing mail", "Configured" if app.cfg.d["smtp"]["host"] and not app.cfg.demo else ui.badge("not sending", "warn"))]))
        conn = ui.kv([("Connector", app.backend.name), ("Description", app.backend.description),
                      ("Verified on a real grid", ui.badge("yes", "ok") if app.backend.verified else ui.badge("no", "warn")),
                      ("Reachable", ui.badge("yes", "ok") if h["ok"] else ui.badge("no", "bad")), ("Release / API", h["release"]), ("Detail", h["detail"])])
        extra = ""
        if hasattr(app.backend, "conformance") and ctx.can("system.edit"):
            extra = ui.button("Run API conformance check", "/system/conformance", ctx.sess.csrf, {}, "")
        jt = ui.table(["Job", "Last run", "Status", "Detail"], [[j["name"], (j["last_run"] or "-")[:19], ui.badge(j["last_status"] or "-", "ok" if j["last_status"] == "ok" else "bad"), j["last_detail"] or ""] for j in jobs],
                      "Jobs have not run yet.")
        tools = ui.card("Tools", Raw(ui.link("/system/bundle", "Download diagnostic bundle", "btn primary") + " " +
                                     (ui.button("Create database backup", "/system/backup", ctx.sess.csrf, {}) if ctx.can("system.edit") else "") +
                                     "<p class='muted'>The diagnostic bundle is one file with versions, scrubbed configuration, job state, health and recent logs. "
                                     "It contains no passwords, keys or customer object data. Send it to whoever is fixing the problem.</p>" +
                                     (ui.button("Reset demo data", "/demo/reset", ctx.sess.csrf, {}, "danger",
                                                confirm="Erase all demo changes and rebuild the sample data? You will be signed out.")
                                      if app.cfg.demo and ctx.can("demo.reset") else "")))
        return ui.page(ctx, "System health", Raw(ui.grid(facts, ui.card("Storage connector", Raw(conn + extra)), cols=2) + ui.card("Background jobs", jt) + tools), "/system")

    @app.route("admin", "GET", "/outbox", perm="system.view")
    def outbox(ctx):
        rows = app.db.all("SELECT * FROM outbox ORDER BY created_at DESC LIMIT 50")
        full = ctx.can("system.edit")
        tbl = ui.table(["When", "To", "Subject", "State", "Message"],
                       [[r["created_at"][:16].replace("T", " "), r["to_addr"], r["subject"],
                         ui.badge(r["state"], "ok" if r["state"] == "sent" else "warn" if r["state"] in ("captured", "queued", "not-configured") else "bad"),
                         Raw("<pre class='log'>" + ui.esc(r["body"] if full else "(hidden)") + "</pre>")] for r in rows], "No messages.")
        note = ("Demo mode: mail is captured here and never sent." if app.cfg.demo else
                "Messages that could not be sent (no mail relay, or a failure) stay here with their set-password link so an administrator can pass it on. "
                "After delivery the link is removed from the stored copy.")
        test = ""
        if full:
            test = ui.card("Send a test message", Raw(
                "<p>Sends one short message through the mail settings now, and shows what happened. Use it after changing the mail relay, "
                "before relying on invitations.</p>" + str(ui.form("/outbox/test", [{"name": "to", "label": "Send to", "type": "email"}], ctx.sess.csrf, "Send test message"))))
        return ui.page(ctx, "Mail outbox", Raw(test + ui.card("Messages", Raw(f"<p class='muted'>{ui.esc(note)}</p>" + tbl))), "/outbox")

    @app.route("admin", "POST", "/outbox/test", perm="system.edit")
    def outbox_test(ctx):
        to = ctx.f("to").strip()
        if not valid_email(to):
            ctx.flash("Error: Enter a valid e-mail address.")
            return redirect("/outbox")
        mid = services.send_mail(app, to, f"Test message from {app.cfg.d['branding']['name']}",
                                 "This is a test message from the portal. If you can read it, outgoing mail works.\n")
        row = app.db.one("SELECT state, error FROM outbox WHERE id=?", (mid,))
        ctx.audit("mail.test", to, row["state"])
        ctx.flash({"sent": "Test message sent. Check the inbox, and the spam folder.",
                   "captured": "Demo mode: the message was captured below and not delivered.",
                   "not-configured": "Error: No mail relay is set. Enter the mail host under Settings, mail."}.get(
                       row["state"], "Error: The message could not be sent: " + (row["error"] or "unknown reason")))
        return redirect("/outbox")

    @app.route("admin", "POST", "/system/conformance", perm="system.edit")
    def conformance(ctx):
        rows = app.backend.conformance()
        miss = sum(1 for r in rows if r["status"] != "ok")
        app.audit.record("system.conformance", ctx.sess.email, "user", None, "", f"{miss} of {len(rows)} not confirmed", ctx.req.ip)
        tbl = ui.table(["Method", "Path", "Result", "Detail"], [[r["method"], r["path"], ui.badge(r["status"], "ok" if r["status"] == "ok" else "bad"), r["detail"]] for r in rows])
        return ui.page(ctx, "API conformance", Raw(ui.card(f"{len(rows) - miss} of {len(rows)} calls confirmed against the grid's own API description", tbl)), "/system")

    @app.route("admin", "GET", "/system/bundle", perm="system.view")
    def bundle(ctx):
        app.audit.record("system.bundle", ctx.sess.email, "user", None, "", "", ctx.req.ip)
        r = Response(200, build_bundle(app), ctype="application/zip")
        r.header("Content-Disposition", f'attachment; filename="csportal-diagnostics-{iso().replace(":", "")}.zip"')
        return r

    @app.route("admin", "POST", "/system/backup", perm="system.edit")
    def backup(ctx):
        from .. import ops
        try:
            r = ops.backup_now(app)
        except RuntimeError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/system")
        app.audit.record("system.backup", ctx.sess.email, "user", None, r["file"], f"{r['bytes']} bytes", ctx.req.ip)
        ctx.flash(f"Backup {r['file']} written and checked. Keep copies away from this host, and the master key separate from them.")
        return redirect("/system")

    # ------------------------------------------------------------ logs
    @app.route("admin", "GET", "/logs", perm="logs.view")
    def logs_view(ctx):
        which = ctx.q("file", "csportal")
        which = which if which in ("csportal", "access") else "csportal"
        n = int(ctx.q("n", "200")) if ctx.q("n", "200").isdigit() else 200
        lines = logs.tail(Path(app.log_dir or app.cfg.data_dir / "logs") / f"{which}.log", min(n, 2000), ctx.q("q"), ctx.q("level"))
        form = Raw('<form method="get" action="/logs" class="inline"><label>Log <select name="file" data-autosubmit>'
                   f'<option value="csportal"{" selected" if which == "csportal" else ""}>Application</option>'
                   f'<option value="access"{" selected" if which == "access" else ""}>Access</option></select></label> '
                   f'<label>Level <select name="level" data-autosubmit><option value="">All</option>' +
                   "".join(f'<option{" selected" if ctx.q("level") == l else ""}>{l}</option>' for l in ("DEBUG", "INFO", "WARNING", "ERROR")) +
                   f'</select></label> <label>Contains <input name="q" value="{ui.esc(ctx.q("q"))}"></label> '
                   f'<label>Lines <input name="n" value="{n}" size="4"></label> <button class="btn small">Show</button></form>')
        pre = Raw('<pre class="log">' + "\n".join(ui.esc(l) for l in reversed(lines)) + "</pre>" if lines else "<p class='muted'>No matching lines.</p>")
        ctx.audit("logs.view", which)
        return ui.page(ctx, "Logs", Raw(ui.card("Filter", form) + ui.card(f"{len(lines)} lines, newest first", pre) +
                                        ui.card("Log destinations", Raw(f"<p class='muted'>Files in <code>{ui.esc(str(Path(app.log_dir or app.cfg.data_dir / 'logs')))}</code> (rotated). "
                                                                     "Configure syslog forwarding in the configuration file (log.syslog). Secrets are removed from every line before it is written.</p>"))), "/logs")

    # ------------------------------------------------------------ staff users
    @app.route("admin", "GET", "/staff", perm="users.manage")
    def staff(ctx):
        us = app.db.all("SELECT * FROM users WHERE customer_id IS NULL ORDER BY name")
        rows = [[u["name"], u["email"], u["role"], u["state"], "on" if u["mfa_enabled"] else "-", (u["last_login"] or "-")[:16],
                 Raw(ui.button("Remove", "/staff/remove", ctx.sess.csrf, {"uid": u["id"]}, "small danger", confirm=f"Remove {u['email']}?") if u["id"] != ctx.sess.user_id else "")] for u in us]
        add = ui.form("/staff", [{"name": "name", "label": "Name"}, {"name": "email", "label": "E-mail", "type": "email"},
                                 {"name": "role", "label": "Role", "type": "select", "options": [(r, r) for r in CSP_ROLES]}], ctx.sess.csrf, "Invite")
        return ui.page(ctx, "Staff users", Raw(ui.card("Provider staff", ui.table(["Name", "E-mail", "Role", "State", "MFA", "Last sign-in", ""], rows)) + ui.card("Invite staff", add)), "/staff")

    @app.route("admin", "POST", "/staff", perm="users.manage")
    def staff_add(ctx):
        from .. import services
        try:
            uid = app.auth.create_user(ctx.f("email"), ctx.f("name"), ctx.f("role"), None, actor=ctx.sess.email, ip=ctx.req.ip)
            tok = app.auth.invite_token(uid)
            services.send_mail(app, ctx.f("email").lower(), "Your administration account", f"Set your password:\n{services.invite_link(app, tok, admin=True)}\n")
            ctx.flash("Invitation sent.")
        except AuthError as e:
            ctx.flash("Error: " + str(e))
        return redirect("/staff")

    @app.route("admin", "POST", "/staff/remove", perm="users.manage", reauth=True)
    def staff_remove(ctx):
        from .. import approvals
        u = app.db.one("SELECT * FROM users WHERE id=? AND customer_id IS NULL", (ctx.f("uid"),))
        if u and u["id"] != ctx.sess.user_id:
            try:
                done, msg = approvals.submit(app, "staff.remove", u["id"], f"Remove staff member {u['email']} ({u['role']})",
                                             {"uid": u["id"]}, ctx.sess.email, ctx.sess.user_id, ctx.req.ip)
            except approvals.ApprovalError as e:
                ctx.flash("Error: " + str(e))
                return redirect("/staff")
            ctx.flash(msg)
            return redirect("/staff" if done else "/approvals")
        return redirect("/staff")

    # ------------------------------------------------------------ branding
    @app.route("admin", "GET", "/branding", perm="settings.edit")
    def branding(ctx):
        b = ui.brand(app)
        return ui.page(ctx, "Branding", Raw(ui.card("White-label settings", ui.form("/branding", [
            {"name": "name", "label": "Company name", "value": b["name"]},
            {"name": "product", "label": "Service name", "value": b["product"]},
            {"name": "color", "label": "Brand colour (#rrggbb)", "value": b["color"], "attrs": {"pattern": "#[0-9a-fA-F]{6}"}},
            {"name": "support_email", "label": "Support e-mail", "type": "email", "value": b["support_email"], "required": False},
            {"name": "legal", "label": "Footer text (legal)", "value": b["legal"], "required": False}], ctx.sess.csrf, "Save")) +
            ui.card("Note", Raw("<p class='muted'>The copyright line and product version in the footer are part of the licence terms and always remain.</p>"))), "/branding")

    @app.route("admin", "POST", "/branding", perm="settings.edit")
    def branding_save(ctx):
        if not _COLOR.match(ctx.f("color")):
            ctx.flash("Error: Colour must look like #0b5fff.")
            return redirect("/branding")
        for k, mx in (("name", 80), ("product", 80), ("color", 7), ("support_email", 120), ("legal", 300)):
            app.db.set_setting("brand." + k, ctx.f(k)[:mx])
        ctx.audit("branding.update")
        ctx.flash("Saved.")
        return redirect("/branding")

    # ------------------------------------------------------------ demo
    if app.cfg.demo:
        @app.route("admin", "POST", "/demo/reset", perm="demo.reset")
        def demo_reset(ctx):
            from .. import demo
            demo.reset_and_seed(app)
            return redirect("/login").header("Set-Cookie", app.session_cookie("admin", "", 0))
