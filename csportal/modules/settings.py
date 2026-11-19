"""Admin: every configuration parameter, and the storage grid connection with a sheet for the grid administrators."""
from __future__ import annotations

import os

from .. import settings as S
from ..backends import gridcheck
from ..util import iso
from ..web import ui
from ..web.core import Raw, redirect, text_response

MODULE = {"id": "settings", "name": "Settings", "version": "1.0.0", "core": True, "surfaces": ["admin"], "requires": [],
          "description": "All configuration parameters, and the storage grid connection (admin nodes, gateway endpoints, credentials, certificates).",
          "nav": [{"surface": "admin", "label": "Storage grid", "path": "/grid", "perm": "system.view", "group": "Platform", "order": 5},
                  {"surface": "admin", "label": "All settings", "path": "/settings", "perm": "system.view", "group": "Platform", "order": 10}]}

_KIND = {"ok": "ok", "warn": "warn", "fail": "bad", "skipped": ""}


def _show(p: S.Param, v) -> Raw | str:
    if p.kind == "bool":
        return ui.badge("yes", "ok") if v else ui.badge("no", "")
    if v in ("", None):
        return Raw('<span class="muted">(not set)</span>')
    return str(v)


def _master_key_source() -> str:
    return "environment variable CSPORTAL_MASTER_KEY" if os.environ.get("CSPORTAL_MASTER_KEY") else "key file named above (or demo key)"


def register(app):
    cfg, db = app.cfg, app.db
    perm_edit = "settings.edit"

    # ------------------------------------------------------------------ helpers
    def _results_table(steps: list[dict]) -> Raw:
        rows = [[s["area"], s["check"], ui.badge({"ok": "OK", "warn": "Warning", "fail": "Failed", "skipped": "Skipped"}[s["status"]], _KIND[s["status"]]),
                 s["detail"], s["hint"]] for s in steps]
        return ui.table(["Where", "Check", "Result", "What happened", "What to do"], rows, "No checks have run.")

    def _last_test_card() -> Raw | str:
        lt = S.last_test(db)
        if not lt:
            return ui.card("Last connection test", Raw("<p class='muted'>The connection has not been tested yet. Use 'Test these settings'.</p>"))
        head = (ui.badge("passed", "ok") if lt["ok"] else ui.badge(f"{lt['failed']} failed", "bad")) + Raw(
            f" <span class='muted'>{ui.esc(lt['at'])}: {lt['checks']} checks, {lt['warnings']} warning(s)</span>")
        return ui.card("Last connection test", Raw(f"<p>{head}</p>" + _results_table(lt["steps"])))

    def _cert_rows(conn: S.GridConn) -> list[list]:
        infos, _ = S.cert_infos(conn.ca_pem)
        if conn.ca_file:
            try:
                more, _ = S.cert_infos(open(conn.ca_file, encoding="utf-8").read())
                infos = infos + more
            except OSError:
                pass
        return [[c["subject"], c["issuer"], c["not_after"], ui.badge(f"{c['days_left']} days", "ok" if c["days_left"] > 30 else "warn" if c["days_left"] > 0 else "bad"),
                 Raw(f"<code class='fp'>{ui.esc(c['sha256'])}</code>"), "yes" if c["is_ca"] else "no"] for c in infos]

    def _flows(conn: S.GridConn) -> list[list]:
        rows = []
        for n in conn.nodes:
            rows.append(["Portal host", f"Admin node {n.name}: {n.host}", f"TCP {n.port} (HTTPS)", "Management API: sign-in, tenant accounts, health, usage"])
        for e in conn.endpoints:
            from urllib.parse import urlparse
            u = urlparse(e.url)
            rows.append(["Portal host", f"S3 endpoint {e.name}: {u.hostname}", f"TCP {u.port or 443} (HTTPS)", "Bucket settings that only the S3 API can change"])
        for e in conn.endpoints:
            from urllib.parse import urlparse
            u = urlparse(e.url)
            rows.append(["Customers' applications", f"S3 endpoint {e.name}: {u.hostname}", f"TCP {u.port or 443} (HTTPS)", "Their own data traffic. It does not pass through the portal"])
        rows.append(["Admin nodes and gateways", "Portal host", "none", "The grid never connects to the portal. All connections start at the portal"])
        return rows

    def handover(conn: S.GridConn) -> str:
        lt = S.last_test(db)
        L = [f"STORAGE GRID CONNECTION SHEET for {ui.brand(app)['name']}", f"Created {iso()} by the portal's admin console. Contains no passwords.", ""]
        L += ["1. WHAT THE PORTAL CONNECTS TO", ""]
        L += [f"  Admin node {'(primary)' if i == 0 else '(failover)'}: {n.name}  {n.host}  port {n.port}" for i, n in enumerate(conn.nodes)] or ["  (none set)"]
        L += [f"  Management API version: {conn.api_version}", ""]
        L += ["2. IDENTITY THE PORTAL USES ON THE GRID", "",
              f"  Account ID: {conn.account_id}  (0 means the grid itself)", f"  User name:  {conn.username or '(not set)'}",
              f"  Password:   {S.grid_password_source(cfg, db)}", "",
              "  The user must be in a read-write group with these permissions (indicative; confirm against the",
              "  documentation for your StorageGRID release before use):"]
        L += [f"    - {a}: {b}" for a, b in S.GRID_PERMISSIONS]
        L += ["", "3. WHAT THE PORTAL CREATES FOR EACH CUSTOMER (TENANT)", ""] + [f"  - {t}" for t in S.TENANT_SERVICE_ACCOUNT]
        L += ["", "4. S3 GATEWAY ENDPOINTS GIVEN TO CUSTOMERS", ""]
        L += [f"  {e.name}: {e.url}  region {e.region}" + (f"  ({e.note})" if e.note else "") + ("  <- also used by the portal" if i == 0 else "")
              for i, e in enumerate(conn.endpoints)] or ["  (none set)"]
        L += ["", "5. NETWORK RULES NEEDED", ""] + [f"  {a} -> {b}   {c}   {d}" for a, b, c, d in _flows(conn)]
        if conn.source_address:
            L += [f"  The portal connects from: {conn.source_address}"]
        L += ["", "6. CERTIFICATES THE PORTAL TRUSTS", ""]
        certs = S.cert_infos(conn.ca_pem)[0]
        L += [f"  {c['subject']}  (issued by {c['issuer']}, valid until {c['not_after']})  SHA-256 {c['sha256']}" for c in certs] or \
             ["  (no CA certificate saved: the system trust store is used)" + (f" and the file {conn.ca_file}" if conn.ca_file else "")]
        L += ["  The admin node and gateway certificates must chain to one of these, and must list the address the portal connects to.", ""]
        if lt:
            L += [f"7. LAST CONNECTION TEST: {lt['at']}  {'PASSED' if lt['ok'] else str(lt['failed']) + ' FAILED'}", ""]
            L += [f"  [{s['status'].upper()}] {s['area']} - {s['check']}: {s['detail']}" + (f"  -> {s['hint']}" if s["hint"] else "") for s in lt["steps"]]
        return "\n".join(L) + "\n"

    def _grid_page(ctx, conn: S.GridConn, errors: list[str] | None = None, posted_pw_note: bool = False):
        can = ctx.can(perm_edit)
        h = app.backend.health()
        saved = db.one("SELECT 1 FROM settings WHERE key='grid.conn'") is not None
        status = ui.card("Connection status", ui.kv([
            ("Connector", f"{app.backend.name}" + ("" if cfg.demo else "")),
            ("Mode", ui.badge("DEMO: illustrative values, simulated grid, nothing is contacted", "warn") if cfg.demo else ui.badge("production", "ok")),
            ("Verified on a real grid", ui.badge("yes", "ok") if app.backend.verified else ui.badge("no: test on a non-production grid first", "warn")),
            ("Reachable now", ui.badge("yes", "ok") if h["ok"] else ui.badge("no", "bad")), ("Detail", h["detail"]),
            ("Admin node in use", getattr(app.backend, "base", "") or "-"),
            ("Settings come from", "saved in this console" if saved else ("demo sample values" if cfg.demo else "the configuration file")),
            ("Password", S.grid_password_source(cfg, db))]))
        err = Raw("<div class='flash error'>" + "<br>".join(ui.esc(e) for e in errors) + "</div>") if errors else ""
        if can:
            form = ui.form("/grid", [
                {"name": "nodes", "label": "Admin nodes (one per line: name, address[:port])", "type": "textarea", "rows": 4, "value": S.format_nodes(conn.nodes),
                 "help": "The first line is the primary and is tried first. If it cannot be reached the portal uses the next. Use a host name or address that the node's certificate lists."},
                {"name": "api_version", "label": "Management API version", "value": conn.api_version, "attrs": {"pattern": r"v\d{1,2}"}, "help": "For example v4. The test shows which versions the grid offers."},
                {"name": "account_id", "label": "Grid account ID", "value": conn.account_id, "help": "0 is the grid itself. The portal's provisioning user lives there."},
                {"name": "username", "label": "Grid user name for the portal", "value": conn.username, "help": "A dedicated user in a least-privilege group. Never the root user."},
                {"name": "password", "label": "Grid password", "type": "password", "required": False,
                 "help": f"Stored encrypted and never shown. Leave empty to keep it. Now: {S.grid_password_source(cfg, db)}."},
                {"name": "clear_password", "label": "Remove the saved password (use the environment variable instead)", "type": "checkbox"},
                {"name": "ca_pem", "label": "CA certificates to trust (PEM)", "type": "textarea", "rows": 8, "value": conn.ca_pem, "required": False,
                 "help": "Paste the CA certificate(s) that signed the admin node and gateway certificates, one after the other. Leave empty to use the system trust store"
                         + (f" and the file {conn.ca_file}" if conn.ca_file else "") + ". Certificates only: never paste a private key. Certificate checking can not be turned off."},
                {"name": "source_address", "label": "Address the grid sees the portal connecting from", "value": conn.source_address, "required": False,
                 "help": "For the grid administrators' firewall rules. Information only."},
                {"name": "timeout", "label": "Request timeout (seconds)", "type": "number", "value": conn.timeout, "attrs": {"min": "3", "max": "120"}},
                {"name": "endpoints", "label": "S3 gateway endpoints for customers (one per line: name | https://address[:port] | region | note)", "type": "textarea", "rows": 5,
                 "value": S.format_endpoints(conn.endpoints),
                 "help": "These are shown to customers as the addresses their applications use. The first is also used by the portal to apply bucket settings. "
                         "Use the load balancer endpoints that the grid administrator created, not individual storage nodes."}],
                ctx.sess.csrf, "Save and apply",
                extra=Raw('<div class="actions"><button class="btn" formaction="/grid/test">Test these settings first (nothing is saved)</button></div>'))
            settings_card = ui.card("Connection settings", Raw(str(err) + str(form) +
                                    ("<p class='muted'>Demo mode: values are saved for preview, but the simulated grid stays in use.</p>" if cfg.demo else "")))
        else:
            settings_card = ui.card("Connection settings", ui.kv([
                ("Admin nodes", Raw("<br>".join(ui.esc(f"{n.name}: {n.host}:{n.port}") for n in conn.nodes) or "(none)")), ("API version", conn.api_version),
                ("Account ID", conn.account_id), ("User", conn.username or "-"), ("Timeout", f"{conn.timeout} s")]))
        certs = ui.card("Certificates the portal trusts", ui.table(["Subject", "Issuer", "Valid until", "Time left", "SHA-256 fingerprint", "CA"], _cert_rows(conn),
                                                                      "No CA certificate saved. The system trust store is used."))
        eps = ui.card("S3 gateway endpoints customers see", ui.table(["Name", "Address", "Region", "Note", "Portal"], [
            [e.name, e.url, e.region, e.note, ui.badge("used for bucket settings", "ok") if i == 0 else ""] for i, e in enumerate(conn.endpoints)], "None set."))
        perms = ui.table(["Permission", "Why"], [[a, b] for a, b in S.GRID_PERMISSIONS])
        sheet = ui.card("For the grid administrators", Raw(
            "<p class='muted'>Everything the grid side needs to prepare, in one place. Download it as a text file to hand over.</p>" +
            "<h3>1. Identity the portal uses</h3>" + str(ui.kv([("Account ID", conn.account_id), ("User", conn.username or "(not set)"), ("Password", S.grid_password_source(cfg, db))])) +
            "<p>The user must be in a read-write group with these permissions. <strong>Indicative</strong>: confirm them against the documentation for your StorageGRID release.</p>" + str(perms) +
            "<h3>2. Network rules</h3>" + str(ui.table(["From", "To", "Port", "Purpose"], _flows(conn))) +
            (f"<p>The portal connects from: <strong>{ui.esc(conn.source_address)}</strong></p>" if conn.source_address else "") +
            "<h3>3. What the portal creates for each customer</h3><ul>" + "".join(f"<li>{ui.esc(t)}</li>" for t in S.TENANT_SERVICE_ACCOUNT) + "</ul>" +
            "<h3>4. Certificates</h3><p>The admin node and gateway certificates must chain to a CA listed above and must list the address the portal connects to.</p>" +
            str(ui.link("/grid/handover.txt", "Download this sheet (text)", "btn primary")),
        ))
        return ui.page(ctx, "Storage grid", Raw(status + settings_card + certs + eps + sheet + _last_test_card()), "/grid")

    def _conn_from_form(ctx, base: S.GridConn) -> tuple[S.GridConn, list[str]]:
        nodes, e1 = S.parse_nodes(ctx.f("nodes").replace("\r", ""), cfg.demo)
        eps, e2 = S.parse_endpoints(ctx.f("endpoints").replace("\r", ""), cfg.demo)
        errs = e1 + e2
        try:
            timeout = int(ctx.f("timeout") or 20)
        except ValueError:
            timeout, _ = 20, errs.append("Timeout must be a number of seconds.")
        conn = S.GridConn(nodes, ctx.f("api_version") or "v4", ctx.f("account_id") or "0", ctx.f("username"), ctx.f("ca_pem").replace("\r", ""),
                          base.ca_file, ctx.f("source_address"), timeout, eps)
        errs += S.validate_conn(conn, cfg.demo)
        _, cerr = S.cert_infos(conn.ca_pem)
        if cerr:
            errs.append(cerr)
        return conn, errs

    # ------------------------------------------------------------------ storage grid
    @app.route("admin", "GET", "/grid", perm="system.view")
    def grid(ctx):
        return _grid_page(ctx, S.load_grid(cfg, db))

    @app.route("admin", "GET", "/grid/handover.txt", perm="system.view")
    def grid_handover(ctx):
        ctx.audit("grid.handover.download")
        return text_response(handover(S.load_grid(cfg, db)), filename="storage-grid-connection-sheet.txt")

    @app.route("admin", "POST", "/grid/test", perm=perm_edit)
    def grid_test(ctx):
        conn, errs = _conn_from_form(ctx, S.load_grid(cfg, db))
        if errs:
            return _grid_page(ctx, conn, errs)
        pw = ctx.f("password") or S.grid_password(cfg, db, app.box)
        steps = gridcheck.simulate(conn) if cfg.demo else gridcheck.diagnose(conn, pw)
        result = gridcheck.summary(steps)
        S.save_test(db, result)
        ctx.audit("grid.test", "", f"{result['checks']} checks, {result['failed']} failed, {result['warnings']} warnings (settings not saved)")
        head = ui.badge("Passed", "ok") if result["ok"] else ui.badge(f"{result['failed']} check(s) failed", "bad")
        return ui.page(ctx, "Connection test", Raw(ui.card("Result", Raw(f"<p>{head} <span class='muted'>These settings have <strong>not</strong> been saved. "
                                                                         f"{'Demo mode: results are illustrative.' if cfg.demo else ''}</span></p>" + str(_results_table(steps)) +
                                                                         "<p>" + str(ui.link("/grid", "Back to the Storage grid page", "btn")) + "</p>"))), "/grid")

    @app.route("admin", "POST", "/grid", perm=perm_edit, reauth=True)
    def grid_save(ctx):
        old = S.load_grid(cfg, db)
        conn, errs = _conn_from_form(ctx, old)
        if errs:
            return _grid_page(ctx, conn, errs)
        from .. import approvals
        payload = {"conn": conn.to_json(), "password": ctx.f("password"), "clear_password": bool(ctx.f("clear_password"))}
        try:
            done, msg = approvals.submit(app, "grid.settings", "grid", f"Change the grid connection: {len(conn.nodes)} admin node(s), "
                                         f"{len(conn.endpoints)} endpoint(s), user {conn.username or '-'}"
                                         + (", new password" if payload["password"] else ""),
                                         payload, ctx.sess.email, ctx.sess.user_id, ctx.req.ip)
        except approvals.ApprovalError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/grid")
        ctx.flash(msg)
        return redirect("/grid" if done else "/approvals")

    # ------------------------------------------------------------------ all settings
    @app.route("admin", "GET", "/settings", perm="system.view")
    def settings_page(ctx):
        parts = []
        weak = S.weakened(cfg)
        if weak:
            parts.append(ui.card("Weaker than recommended", Raw("<ul>" + "".join(f"<li>{ui.esc(w)}</li>" for w in weak) + "</ul>"
                                                                "<p class='muted'>Changes that weaken security are recorded in the audit log.</p>")))
        parts.append(ui.card("How settings work", Raw(
            "<p class='muted'>Each value comes from the built-in default, the configuration file, or a change saved here (highest priority). "
            "Changes saved here are stored in the database, take effect as shown, and are recorded in the audit log. Secrets are write-only: they are never shown. "
            "Settings marked <em>Configuration file only</em> change how the service starts and are edited in the file, then the service is restarted.</p>")))
        for gid, gname in S.GROUPS:
            rows = []
            if gid == "storage":
                conn = S.load_grid(cfg, db)
                lt = S.last_test(db)
                rows += [["Storage connector", cfg.d["backend"]["type"], "file", "Configuration file only", ""]]
                rows += [[Raw("<strong>Grid connection</strong> (admin nodes, endpoints, account, certificates)"),
                          Raw(f"{len(conn.nodes)} admin node(s), {len(conn.endpoints)} gateway endpoint(s), user {ui.esc(conn.username or '-')}"),
                          "console" if db.one("SELECT 1 FROM settings WHERE key='grid.conn'") else "file", "On the Storage grid page", ui.link("/grid", "Open")],
                         ["Grid password", S.grid_password_source(cfg, db), "", "On the Storage grid page", ""],
                         ["Last connection test", (lt["at"] + (": passed" if lt["ok"] else f": {lt['failed']} failed")) if lt else "never run", "", "", ""]]
                parts.append(ui.card(gname, ui.table(["Setting", "Value", "Source", "Takes effect", ""], rows)))
                continue
            editable = False
            for p in [x for x in S.PARAMS if x.group == gid]:
                src = S.source_of(cfg, db, p)
                if p.apply in ("live", "restart"):
                    editable = True
                v = S.effective(cfg, p)
                label = Raw(f"{ui.esc(p.label)}" + (f"<br><small class='muted'>{ui.esc(p.help)}</small>" if p.help else ""))
                reset = ui.button("Use file value", "/settings/reset", ctx.sess.csrf, {"key": p.key}, "small") if src == "console" and ctx.can(perm_edit) else ""
                rows.append([label, _show(p, v), src, S.APPLY_TEXT[p.apply], reset])
            if gid == "network":
                rows.append(["Master key", ui.badge("provided", "ok"), "environment", "Configuration file only", Raw(f"<small class='muted'>{ui.esc(_master_key_source())}. The value is never shown.</small>")])
            if gid == "mail":
                src = "saved in the console (encrypted)" if S.secret_updated(db, "smtp:password") else (f"environment variable {cfg.d['smtp']['password_env']}" if os.environ.get(cfg.d["smtp"]["password_env"]) else "not set")
                rows.append(["Mail relay password", src, "", "Immediately", ""])
            act = ui.link(f"/settings/edit/{gid}", "Edit", "btn small") if editable and ctx.can(perm_edit) else None
            parts.append(ui.card(gname, ui.table(["Setting", "Value", "Source", "Takes effect", ""], rows), actions=act))
        b = ui.brand(app)
        parts.append(ui.card("Branding", Raw(str(ui.kv([("Company name", b["name"]), ("Service name", b["product"]), ("Colour", b["color"]), ("Support e-mail", b["support_email"])])) +
                                             "<p>" + str(ui.link("/branding", "Edit branding", "btn small")) + "</p>")))
        return ui.page(ctx, "All settings", Raw("".join(str(x) for x in parts)), "/settings")

    def _edit_fields(gid: str) -> list[dict]:
        out = []
        for p in [x for x in S.PARAMS if x.group == gid and x.apply in ("live", "restart")]:
            v = S.effective(cfg, p)
            f: dict = {"name": p.key.replace(".", "__"), "label": p.label, "help": (p.help + " " if p.help else "") + f"Takes effect: {S.APPLY_TEXT[p.apply].lower()}.",
                       "value": v if v is not None else ""}
            if p.kind == "bool":
                f["type"] = "checkbox"
            elif p.kind == "int":
                f.update(type="number", attrs={"min": str(p.lo), "max": str(p.hi)})
            elif p.kind == "choice":
                f.update(type="select", options=[(c, c) for c in p.choices])
            elif p.kind == "email":
                f["type"] = "email"
            if p.kind in ("text", "url", "email"):
                f["required"] = False if p.key in ("smtp.host", "smtp.username", "log.dir", "log.syslog") else True
            out.append(f)
        if gid == "mail":
            out += [{"name": "mail_password", "label": "Mail relay password", "type": "password", "required": False,
                     "help": "Stored encrypted and never shown. Leave empty to keep the current one."},
                    {"name": "mail_password_clear", "label": "Remove the saved mail password", "type": "checkbox"}]
        return out

    @app.route("admin", "GET", "/settings/edit/{gid}", perm=perm_edit)
    def edit(ctx):
        gid = ctx.params["gid"]
        names = dict(S.GROUPS)
        if gid not in names or not _edit_fields(gid):
            return redirect("/settings")
        return ui.page(ctx, f"Edit: {names[gid]}", Raw(ui.card(names[gid], ui.form(f"/settings/edit/{gid}", _edit_fields(gid), ctx.sess.csrf, "Save")) +
                                                     ui.card("Note", Raw("<p class='muted'>Settings that change how the service starts (addresses, ports, certificates, master key) are edited in the configuration file.</p>"))), "/settings")

    @app.route("admin", "POST", "/settings/edit/{gid}", perm=perm_edit)
    def edit_save(ctx):
        gid = ctx.params["gid"]
        if gid not in dict(S.GROUPS):
            return redirect("/settings")
        before_weak = set(S.weakened(cfg))
        changes, errors, restart = [], [], False
        for p in [x for x in S.PARAMS if x.group == gid and x.apply in ("live", "restart")]:
            raw = ctx.f(p.key.replace(".", "__")) if p.kind != "bool" else ("1" if ctx.f(p.key.replace(".", "__")) else "0")
            changed, err, old, new = S.change_param(app, p.key, raw)
            if err:
                errors.append(err)
            elif changed:
                changes.append(f"{p.key}: {old} -> {new}")
                restart = restart or p.apply == "restart"
        if gid == "mail":
            if ctx.f("mail_password"):
                S.secret_put(db, app.box, "smtp:password", ctx.f("mail_password"))
                changes.append("mail password changed")
            elif ctx.f("mail_password_clear"):
                S.secret_clear(db, "smtp:password")
                changes.append("saved mail password removed")
        newly = sorted(set(S.weakened(cfg)) - before_weak)
        if changes:
            ctx.audit("settings.update", gid, "; ".join(changes) + (f" | WEAKENED: {' '.join(newly)}" if newly else ""))
        if errors:
            ctx.flash("Error: " + " ".join(errors))
        elif changes:
            ctx.flash("Saved." + (" Some changes take effect after a restart." if restart else "") + (" Note: this weakens security." if newly else ""))
        else:
            ctx.flash("Nothing changed.")
        return redirect("/settings")

    @app.route("admin", "POST", "/settings/reset", perm=perm_edit)
    def reset(ctx):
        key = ctx.f("key")
        if S.reset_param(app, key):
            ctx.audit("settings.reset", key, "console value removed; the file value applies")
            ctx.flash("The configuration file value is used again.")
        return redirect("/settings")
