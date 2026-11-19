"""Tenant users and groups on the grid (the workloads and people that hold S3 access), plus portal users."""
from __future__ import annotations

import re

from .. import services
from ..auth import AuthError, CUSTOMER_ROLES
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "tenant-access", "name": "Users and groups", "version": "1.0.0", "surfaces": ["customer"],
          "requires": [], "description": "Portal users with roles; storage users and groups for applications.",
          "nav": [{"surface": "customer", "label": "People (portal)", "path": "/team", "perm": "access.view", "group": "Account", "order": 10},
                  {"surface": "customer", "label": "Storage users", "path": "/users", "perm": "access.view", "group": "Storage", "order": 30}]}

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}$")


def register(app):
    # ----------------------------------------------------------- portal users (people)
    @app.route("customer", "GET", "/team", perm="access.view", module="tenant-access")
    def team(ctx):
        us = app.db.all("SELECT * FROM users WHERE customer_id=? ORDER BY name", (ctx.customer["id"],))
        can = ctx.can("access.edit")
        rows = []
        for u in us:
            actions = ""
            if can and u["id"] != ctx.sess.user_id:
                actions = (ui.button("Resend invite", "/team/invite", ctx.sess.csrf, {"uid": u["id"]}, "small") if u["state"] == "invited" else "") + \
                          ui.button("Remove", "/team/remove", ctx.sess.csrf, {"uid": u["id"]}, "small danger", confirm=f"Remove {u['email']}?") + \
                          (ui.button("Reset MFA", "/team/mfa-reset", ctx.sess.csrf, {"uid": u["id"]}, "small",
                                     confirm="Reset multi-factor authentication for this person?") if u["mfa_enabled"] else "")
            rows.append([u["name"], u["email"], u["role"], ui.badge("active", "ok") if u["state"] == "active" else ui.badge(u["state"], "warn"),
                         ui.badge("on", "ok") if u["mfa_enabled"] else "-", Raw(actions)])
        tbl = ui.card("People who can sign in to this portal", ui.table(["Name", "E-mail", "Role", "State", "MFA", ""], rows))
        add = ui.card("Invite a person", ui.form("/team", [
            {"name": "name", "label": "Name"}, {"name": "email", "label": "E-mail", "type": "email"},
            {"name": "role", "label": "Role", "type": "select", "options": [(r, r) for r in CUSTOMER_ROLES],
             "help": "Administrator: everything. Operator: buckets and keys. Billing: usage and invoices. Read-only: view."}],
            ctx.sess.csrf, "Send invitation")) if can else ""
        return ui.page(ctx, "People", Raw(tbl + add), "/team")

    @app.route("customer", "POST", "/team", perm="access.edit", module="tenant-access")
    def team_add(ctx):
        try:
            uid = app.auth.create_user(ctx.f("email"), ctx.f("name"), ctx.f("role"), ctx.customer["id"], actor=ctx.sess.email, ip=ctx.req.ip)
        except AuthError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/team")
        _send_invite(ctx, uid)
        ctx.flash("Invitation sent.")
        return redirect("/team")

    def _send_invite(ctx, uid):
        u = app.db.one("SELECT * FROM users WHERE id=? AND customer_id=?", (uid, ctx.customer["id"]))
        if not u:
            return
        tok = app.auth.invite_token(uid)
        services.send_mail(app, u["email"], f"Your {app.cfg.d['branding']['name']} account",
                           f"Hello {u['name']},\n\n{ctx.sess.name} invited you. Set your password here:\n"
                           f"{services.invite_link(app, tok)}\n\nThe link works for 72 hours.\n", ctx.customer["id"])

    @app.route("customer", "POST", "/team/invite", perm="access.edit", module="tenant-access")
    def team_reinvite(ctx):
        _send_invite(ctx, ctx.f("uid"))
        ctx.audit("user.reinvite", ctx.f("uid"))
        ctx.flash("Invitation sent again.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/remove", perm="access.edit", module="tenant-access")
    def team_remove(ctx):
        u = app.db.one("SELECT * FROM users WHERE id=? AND customer_id=?", (ctx.f("uid"), ctx.customer["id"]))
        if u and u["id"] != ctx.sess.user_id:
            admins = app.db.one("SELECT COUNT(*) n FROM users WHERE customer_id=? AND role='administrator' AND state='active' AND id!=?",
                                (ctx.customer["id"], u["id"]))["n"]
            if u["role"] == "administrator" and admins == 0:
                ctx.flash("Error: There must be at least one administrator.")
                return redirect("/team")
            app.auth.revoke_user_sessions(u["id"])
            app.db.run("DELETE FROM invitations WHERE user_id=?", (u["id"],))
            app.db.run("DELETE FROM users WHERE id=?", (u["id"],))
            ctx.audit("user.remove", u["email"])
            ctx.flash("Person removed.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/mfa-reset", perm="access.edit", module="tenant-access")
    def team_mfa_reset(ctx):
        u = app.db.one("SELECT * FROM users WHERE id=? AND customer_id=?", (ctx.f("uid"), ctx.customer["id"]))
        if u:
            app.auth.disable_mfa(u["id"], ctx.sess.email, ctx.req.ip)
            app.auth.revoke_user_sessions(u["id"])
            ctx.flash("Multi-factor authentication reset. The person sets it up again at next sign-in.")
        return redirect("/team")

    # ----------------------------------------------------------- storage users and groups (grid tenant)
    @app.route("customer", "GET", "/users", perm="access.view", module="tenant-access")
    def users(ctx):
        us, gs = app.backend.list_users(ctx.ref), app.backend.list_groups(ctx.ref)
        can = ctx.can("access.edit")
        urows = [[ui.link(f"/keys?user={u['username']}", u["username"]), u["full_name"], ", ".join(u["groups"]) or "-",
                  ui.badge("disabled", "warn") if u["disabled"] else ui.badge("active", "ok"), str(u["keys"]),
                  Raw((ui.button("Enable" if u["disabled"] else "Disable", "/users/toggle", ctx.sess.csrf,
                                 {"user": u["username"], "disabled": "0" if u["disabled"] else "1"}, "small") +
                       ui.button("Delete", "/users/delete", ctx.sess.csrf, {"user": u["username"]}, "small danger",
                                 confirm=f"Delete storage user {u['username']} and all of its access keys?")) if can else "")]
                 for u in us]
        grows = [[g["name"], ui.badge(g["access"], "ok" if g["access"] == "read-write" else ""),
                  ui.button("Delete", "/groups/delete", ctx.sess.csrf, {"group": g["name"]}, "small danger", confirm="Delete this group?") if can else ""]
                 for g in gs]
        gopts = [(g["name"], g["name"]) for g in gs]
        parts = [ui.card("Storage users", ui.table(["User", "Name", "Groups", "State", "Keys", ""], urows,
                                                    "No storage users yet. Create a group, then a user.")),
                 ui.card("Groups", ui.table(["Group", "Access", ""], grows, "No groups yet."))]
        if can:
            parts.append(ui.grid(
                ui.card("Create a group", ui.form("/groups", [
                    {"name": "name", "label": "Group name"},
                    {"name": "access", "label": "Access to buckets", "type": "select",
                     "options": [("read-write", "Read and write"), ("read-only", "Read only")]}], ctx.sess.csrf, "Create group")),
                ui.card("Create a storage user", ui.form("/users", [
                    {"name": "username", "label": "User name", "help": "Letters, numbers, dot, hyphen, underscore."},
                    {"name": "full_name", "label": "Description", "help": "For example the application or team that uses it."},
                    {"name": "group", "label": "Group", "type": "select", "options": gopts or [("", "(create a group first)")]}],
                    ctx.sess.csrf, "Create user")), cols=2))
        return ui.page(ctx, "Storage users and groups", Raw("".join(parts)), "/users")

    @app.route("customer", "POST", "/groups", perm="access.edit", module="tenant-access")
    def group_add(ctx):
        n = ctx.f("name")
        if not _NAME.match(n):
            ctx.flash("Error: Use 2-31 letters, numbers, dot, hyphen or underscore.")
            return redirect("/users")
        app.backend.create_group(ctx.ref, n, ctx.f("access") if ctx.f("access") in ("read-write", "read-only") else "read-only")
        ctx.audit("group.create", n, ctx.f("access"))
        ctx.flash("Group created.")
        return redirect("/users")

    @app.route("customer", "POST", "/groups/delete", perm="access.edit", module="tenant-access")
    def group_del(ctx):
        app.backend.delete_group(ctx.ref, ctx.f("group"))
        ctx.audit("group.delete", ctx.f("group"))
        ctx.flash("Group deleted.")
        return redirect("/users")

    @app.route("customer", "POST", "/users", perm="access.edit", module="tenant-access")
    def user_add(ctx):
        n = ctx.f("username")
        if not _NAME.match(n) or not ctx.f("group"):
            ctx.flash("Error: Enter a valid user name and choose a group.")
            return redirect("/users")
        app.backend.create_user(ctx.ref, n, ctx.f("full_name")[:100], [ctx.f("group")])
        ctx.audit("storage_user.create", n, ctx.f("group"))
        ctx.flash("Storage user created. Create an access key for it next.")
        return redirect(f"/keys?user={n}")

    @app.route("customer", "POST", "/users/toggle", perm="access.edit", module="tenant-access")
    def user_toggle(ctx):
        app.backend.update_user(ctx.ref, ctx.f("user"), disabled=ctx.f("disabled") == "1")
        ctx.audit("storage_user.disable" if ctx.f("disabled") == "1" else "storage_user.enable", ctx.f("user"))
        ctx.flash("Updated.")
        return redirect("/users")

    @app.route("customer", "POST", "/users/delete", perm="access.edit", module="tenant-access")
    def user_del(ctx):
        app.backend.delete_user(ctx.ref, ctx.f("user"))
        ctx.audit("storage_user.delete", ctx.f("user"))
        ctx.flash("Storage user deleted.")
        return redirect("/users")
