"""People who sign in to the portal (roles, invitations, sessions) and the storage users and groups that hold S3 access."""
from __future__ import annotations

import re

from .. import services
from ..auth import AuthError, CUSTOMER_ROLES
from ..util import esc
from ..web import ui
from ..web.core import Raw, redirect

MODULE = {"id": "tenant-access", "name": "Users and groups", "version": "1.1.0", "surfaces": ["customer"],
          "requires": [], "description": "Portal people with roles and invitations; storage users and groups scoped to buckets.",
          "nav": [{"surface": "customer", "label": "People (portal)", "path": "/team", "perm": "access.view", "group": "Account", "order": 10},
                  {"surface": "customer", "label": "Storage users", "path": "/users", "perm": "access.view", "group": "Storage", "order": 30}]}

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}$")
ROLE_TEXT = {
    "administrator": "Everything: people and roles, storage users and groups, who can use each bucket, buckets and their settings, access keys, usage, invoices and alerts.",
    "operator": "Buckets and their settings (versioning, lifecycle, Object Lock, CORS) and access keys. Cannot change who has access, people, storage users or groups, and cannot delete buckets.",
    "billing": "Usage, statements, alerts and quota requests. Cannot see or change buckets or access.",
    "read-only": "View buckets, their access rules, access key IDs, usage and activity. Cannot change anything.",
}


def _check_boxes(prefix: str, names: list[str], chosen: set[str], stale: list[str] | None = None) -> str:
    out = []
    for n in names:
        out.append(f'<label class="check"><input type="checkbox" name="{esc(prefix)}{esc(n)}" value="1"{" checked" if n in chosen else ""}> {esc(n)}</label>')
    for n in stale or []:
        out.append(f'<label class="check"><input type="checkbox" name="{esc(prefix)}{esc(n)}" value="1" checked> {esc(n)} '
                   f'<span class="badge warn">bucket no longer exists</span></label>')
    return '<div class="field checks">' + "".join(out) + "</div>"


def register(app):
    def _person(ctx, uid):
        return app.db.one("SELECT * FROM users WHERE id=? AND customer_id=?", (uid, ctx.customer["id"]))

    def _other_admins(ctx, exclude_id):
        return app.db.one("SELECT COUNT(*) n FROM users WHERE customer_id=? AND role='administrator' AND state='active' AND id!=?",
                          (ctx.customer["id"], exclude_id))["n"]

    # ----------------------------------------------------------- portal users (people)
    @app.route("customer", "GET", "/team", perm="access.view", module="tenant-access")
    def team(ctx):
        us = app.db.all("SELECT * FROM users WHERE customer_id=? ORDER BY name", (ctx.customer["id"],))
        can = ctx.can("access.edit")
        rows = []
        for u in us:
            me = u["id"] == ctx.sess.user_id
            locked = app.auth.is_locked(u)
            inv, exp = app.auth.invite_state(u["id"]) if u["state"] == "invited" else ("", "")
            invcell = ("-" if not inv else ui.badge("open until " + exp[:16].replace("T", " "), "ok") if inv == "open" else
                       ui.badge("expired", "bad") if inv == "expired" else ui.badge("no link", "warn"))
            role = u["role"]
            if can and not me:
                opts = "".join(f'<option value="{r}"{" selected" if r == u["role"] else ""}>{r}</option>' for r in CUSTOMER_ROLES)
                role = Raw(f'<form method="post" action="/team/role" class="inline"><input type="hidden" name="_csrf" value="{esc(ctx.sess.csrf)}">'
                           f'<input type="hidden" name="uid" value="{esc(u["id"])}"><select name="role" aria-label="Role of {esc(u["email"])}">{opts}</select> '
                           f'<button class="btn small">Set</button></form>')
            actions = ""
            if can and not me:
                if u["state"] == "invited":
                    actions += ui.button("Send new invite", "/team/invite", ctx.sess.csrf, {"uid": u["id"]}, "small")
                    if inv in ("open", "expired"):
                        actions += ui.button("Revoke invite", "/team/invite/revoke", ctx.sess.csrf, {"uid": u["id"]}, "small",
                                             confirm="Cancel the invitation link? The person stays on the list without a way to sign in.")
                if locked:
                    actions += ui.button("Unlock", "/team/unlock", ctx.sess.csrf, {"uid": u["id"]}, "small")
                if u["state"] == "active":
                    actions += ui.button("Sign out everywhere", "/team/signout", ctx.sess.csrf, {"uid": u["id"]}, "small",
                                         confirm=f"End every session of {u['email']}?")
                if u["mfa_enabled"]:
                    actions += ui.button("Reset MFA", "/team/mfa-reset", ctx.sess.csrf, {"uid": u["id"]}, "small",
                                         confirm="Reset multi-factor authentication for this person?")
                actions += ui.button("Remove", "/team/remove", ctx.sess.csrf, {"uid": u["id"]}, "small danger", confirm=f"Remove {u['email']}?")
            state = ui.badge("locked", "bad") if locked else ui.badge("active", "ok") if u["state"] == "active" else ui.badge(u["state"], "warn")
            rows.append([u["name"] + (" (you)" if me else ""), u["email"], role, state, invcell,
                         ui.badge("on", "ok") if u["mfa_enabled"] else "-", Raw(actions)])
        tbl = ui.card("People who can sign in to this portal",
                      ui.table(["Name", "E-mail", "Role", "State", "Invitation", "MFA", ""], rows))
        add = ui.card("Invite a person", ui.form("/team", [
            {"name": "name", "label": "Name"}, {"name": "email", "label": "E-mail", "type": "email"},
            {"name": "role", "label": "Role", "type": "select", "options": [(r, r) for r in CUSTOMER_ROLES], "value": "read-only"}],
            ctx.sess.csrf, "Send invitation")) if can else ""
        roles = ui.card("What each role can do", ui.table(["Role", "Can"], [[r, ROLE_TEXT[r]] for r in CUSTOMER_ROLES]))
        note = ui.card("Good to know", Raw(
            "<ul class='plain'><li>An invitation link works once and for 72 hours. Sending a new one cancels the old one.</li>"
            "<li>Changing a role signs the person out. The new role applies at their next sign-in.</li>"
            "<li>You cannot change or remove your own entry, and the last active administrator cannot be demoted or removed.</li>"
            "<li>Every change on this page is written to the activity log.</li></ul>"))
        return ui.page(ctx, "People", Raw(tbl + add + roles + note), "/team")

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
        u = _person(ctx, uid)
        if not u:
            return
        tok = app.auth.invite_token(uid)
        services.send_mail(app, u["email"], f"Your {app.cfg.d['branding']['name']} account",
                           f"Hello {u['name']},\n\n{ctx.sess.name} invited you. Set your password here:\n"
                           f"{services.invite_link(app, tok)}\n\nThe link works once and for 72 hours.\n", ctx.customer["id"])

    @app.route("customer", "POST", "/team/invite", perm="access.edit", module="tenant-access")
    def team_reinvite(ctx):
        u = _person(ctx, ctx.f("uid"))
        if not u or u["state"] != "invited":
            ctx.flash("Error: That person has already set a password.")
            return redirect("/team")
        _send_invite(ctx, u["id"])
        ctx.audit("user.reinvite", u["email"])
        ctx.flash("A new invitation was sent. Earlier links no longer work.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/invite/revoke", perm="access.edit", module="tenant-access")
    def team_revoke(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["state"] == "invited":
            app.auth.revoke_invites(u["id"], ctx.sess.email, ctx.req.ip)
            ctx.flash("Invitation cancelled.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/role", perm="access.edit", module="tenant-access")
    def team_role(ctx):
        u = _person(ctx, ctx.f("uid"))
        role = ctx.f("role")
        if not u or role not in CUSTOMER_ROLES:
            ctx.flash("Error: Unknown person or role.")
        elif u["id"] == ctx.sess.user_id:
            ctx.flash("Error: You cannot change your own role. Ask another administrator.")
        elif u["role"] == "administrator" and role != "administrator" and u["state"] == "active" and _other_admins(ctx, u["id"]) == 0:
            ctx.flash("Error: There must be at least one active administrator.")
        elif role != u["role"]:
            app.auth.set_role(u["id"], role, ctx.sess.email, ctx.req.ip)
            ctx.flash(f"{u['email']} is now {role}. They are signed out and the new role applies at the next sign-in.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/signout", perm="access.edit", module="tenant-access")
    def team_signout(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            app.auth.revoke_user_sessions(u["id"])
            ctx.audit("user.sessions_ended", u["email"])
            ctx.flash("All sessions of that person were ended.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/unlock", perm="access.edit", module="tenant-access")
    def team_unlock(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u:
            app.auth.unlock(u["id"], ctx.sess.email, ctx.req.ip)
            ctx.flash("Account unlocked.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/remove", perm="access.edit", module="tenant-access")
    def team_remove(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            if u["role"] == "administrator" and u["state"] == "active" and _other_admins(ctx, u["id"]) == 0:
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
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            app.auth.disable_mfa(u["id"], ctx.sess.email, ctx.req.ip)
            app.auth.revoke_user_sessions(u["id"])
            ctx.flash("Multi-factor authentication reset. The person sets it up again at next sign-in.")
        return redirect("/team")

    # ----------------------------------------------------------- storage users and groups (grid tenant)
    def _scope_text(g, existing):
        if not g.get("buckets"):
            return Raw("<span class='muted'>all buckets</span>")
        return Raw(", ".join(esc(b) if b in existing else f'{esc(b)} <span class="badge warn">gone</span>' for b in g["buckets"]))

    @app.route("customer", "GET", "/users", perm="access.view", module="tenant-access")
    def users(ctx):
        us, gs = app.backend.list_users(ctx.ref), app.backend.list_groups(ctx.ref)
        bnames = [b["name"] for b in app.backend.list_buckets(ctx.ref)]
        can = ctx.can("access.edit")
        urows = [[ui.link(f"/keys?user={u['username']}", u["username"]), u["full_name"], ", ".join(u["groups"]) or "-",
                  ui.badge("disabled", "warn") if u["disabled"] else ui.badge("active", "ok"), str(u["keys"]),
                  Raw((ui.link(f"/users/edit?user={u['username']}", "Groups", "btn small") + " " +
                       ui.button("Enable" if u["disabled"] else "Disable", "/users/toggle", ctx.sess.csrf,
                                 {"user": u["username"], "disabled": "0" if u["disabled"] else "1"}, "small") +
                       ui.button("Delete", "/users/delete", ctx.sess.csrf, {"user": u["username"]}, "small danger",
                                 confirm=f"Delete storage user {u['username']} and all of its access keys?")) if can else "")]
                 for u in us]
        grows = [[g["name"], ui.badge(g["access"], "ok" if g["access"] == "read-write" else ""), _scope_text(g, bnames),
                  Raw((ui.link(f"/groups/edit?group={g['name']}", "Change", "btn small") + " " +
                       ui.button("Delete", "/groups/delete", ctx.sess.csrf, {"group": g["name"]}, "small danger", confirm="Delete this group?")) if can else "")]
                 for g in gs]
        gopts = [(g["name"], g["name"]) for g in gs]
        parts = [ui.card("Storage users", ui.table(["User", "Name", "Groups", "State", "Keys", ""], urows,
                                                    "No storage users yet. Create a group, then a user.")),
                 ui.card("Groups", ui.table(["Group", "Access", "Buckets", ""], grows, "No groups yet.")),
                 ui.card("How access works", Raw(
                     "<ul class='plain'><li>A <strong>group</strong> says what its members may do (read only, or read and write) and on which buckets.</li>"
                     "<li>A <strong>storage user</strong> belongs to one or more groups and holds S3 access keys. Applications sign in with those keys.</li>"
                     "<li>For finer rules on one bucket (a folder, a time of day, a network) use the bucket's <em>Access</em> page.</li>"
                     "<li>A group limited to named buckets cannot list the other buckets of the account.</li></ul>"))]
        if can:
            parts.append(ui.grid(
                ui.card("Create a group", ui.form("/groups", [
                    {"name": "name", "label": "Group name"},
                    {"name": "access", "label": "Access", "type": "select",
                     "options": [("read-write", "Read and write"), ("read-only", "Read only")]}], ctx.sess.csrf, "Create group",
                    extra=Raw('<div class="field"><strong>Limit to these buckets</strong><small class="muted"> (leave all unticked for every bucket)</small>' +
                              _check_boxes("scope_", bnames, set()) + "</div>"))),
                ui.card("Create a storage user", ui.form("/users", [
                    {"name": "username", "label": "User name", "help": "Letters, numbers, dot, hyphen, underscore."},
                    {"name": "full_name", "label": "Description", "help": "For example the application or team that uses it."},
                    {"name": "group", "label": "Group", "type": "select", "options": gopts or [("", "(create a group first)")]}],
                    ctx.sess.csrf, "Create user")), cols=2))
        return ui.page(ctx, "Storage users and groups", Raw("".join(parts)), "/users")

    def _chosen(ctx, prefix, names):
        return [n for n in names if ctx.f(prefix + n)]

    @app.route("customer", "POST", "/groups", perm="access.edit", module="tenant-access")
    def group_add(ctx):
        n = ctx.f("name")
        if not _NAME.match(n):
            ctx.flash("Error: Use 2-31 letters, numbers, dot, hyphen or underscore.")
            return redirect("/users")
        access = ctx.f("access") if ctx.f("access") in ("read-write", "read-only") else "read-only"
        scope = _chosen(ctx, "scope_", [b["name"] for b in app.backend.list_buckets(ctx.ref)])
        app.backend.create_group(ctx.ref, n, access, scope)
        ctx.audit("group.create", n, f"{access} buckets={','.join(scope) or 'all'}")
        ctx.flash("Group created.")
        return redirect("/users")

    @app.route("customer", "GET", "/groups/edit", perm="access.edit", module="tenant-access")
    def group_edit(ctx):
        g = next((x for x in app.backend.list_groups(ctx.ref) if x["name"] == ctx.q("group")), None)
        if not g:
            ctx.flash("Error: Group not found.")
            return redirect("/users")
        bnames = [b["name"] for b in app.backend.list_buckets(ctx.ref)]
        stale = [b for b in g.get("buckets", []) if b not in bnames]
        form = ui.form("/groups/update", [
            {"name": "group", "type": "hidden", "value": g["name"]},
            {"name": "access", "label": "Access", "type": "select", "value": g["access"],
             "options": [("read-write", "Read and write"), ("read-only", "Read only")]}], ctx.sess.csrf, "Save group",
            extra=Raw('<div class="field"><strong>Limit to these buckets</strong><small class="muted"> (none ticked = every bucket)</small>' +
                      _check_boxes("scope_", bnames, set(g.get("buckets", [])), stale) + "</div>"))
        return ui.page(ctx, f"Group {g['name']}", Raw(ui.card("Access and buckets", form) +
                       ui.card("Careful", Raw("<p class='muted'>Removing every tick gives the group access to <strong>all</strong> buckets, "
                                              "including buckets created later. A bucket that was deleted stays in the list until you untick it.</p>"))), "/users",
                       actions=ui.link("/users", "Back", "btn"))

    @app.route("customer", "POST", "/groups/update", perm="access.edit", module="tenant-access")
    def group_update(ctx):
        gname = ctx.f("group")
        g = next((x for x in app.backend.list_groups(ctx.ref) if x["name"] == gname), None)
        if not g:
            ctx.flash("Error: Group not found.")
            return redirect("/users")
        names = [b["name"] for b in app.backend.list_buckets(ctx.ref)] + list(g.get("buckets", []))
        access = ctx.f("access") if ctx.f("access") in ("read-write", "read-only") else g["access"]
        scope = _chosen(ctx, "scope_", list(dict.fromkeys(names)))
        scope = [b for b in scope if b in [x["name"] for x in app.backend.list_buckets(ctx.ref)]]
        app.backend.update_group(ctx.ref, gname, access, scope)
        ctx.audit("group.update", gname, f"{access} buckets={','.join(scope) or 'all'}")
        ctx.flash("Group saved.")
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

    @app.route("customer", "GET", "/users/edit", perm="access.edit", module="tenant-access")
    def user_edit(ctx):
        u = next((x for x in app.backend.list_users(ctx.ref) if x["username"] == ctx.q("user")), None)
        if not u:
            ctx.flash("Error: Storage user not found.")
            return redirect("/users")
        gnames = [g["name"] for g in app.backend.list_groups(ctx.ref)]
        form = ui.form("/users/groups", [{"name": "user", "type": "hidden", "value": u["username"]}], ctx.sess.csrf, "Save groups",
                       extra=Raw('<div class="field"><strong>Member of</strong>' + _check_boxes("g_", gnames, set(u["groups"])) + "</div>"))
        return ui.page(ctx, f"Groups of {u['username']}", Raw(ui.card("Group membership", form) + ui.card("Careful", Raw(
            "<p class='muted'>A storage user can do what all of its groups allow. Removing the last group leaves the user with no access.</p>"))),
            "/users", actions=ui.link("/users", "Back", "btn"))

    @app.route("customer", "POST", "/users/groups", perm="access.edit", module="tenant-access")
    def user_groups(ctx):
        gnames = [g["name"] for g in app.backend.list_groups(ctx.ref)]
        chosen = _chosen(ctx, "g_", gnames)
        app.backend.update_user(ctx.ref, ctx.f("user"), groups=chosen)
        ctx.audit("storage_user.groups", ctx.f("user"), ",".join(chosen) or "none")
        ctx.flash("Group membership saved.")
        return redirect("/users")

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
