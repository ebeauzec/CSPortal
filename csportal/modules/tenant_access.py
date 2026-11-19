"""People who sign in to the portal (roles, invitations, sessions) and the storage users and groups that hold S3 access."""
from __future__ import annotations

import re

from .. import services
from ..auth import AuthError, CUSTOMER_ROLES
from ..util import esc, valid_email
from ..web import ui
from ..web.core import Raw, html_response, redirect

MODULE = {"id": "tenant-access", "name": "Users and groups", "version": "1.2.0", "surfaces": ["customer"],
          "requires": [], "description": "Guided invitation and management of portal people with roles; storage users and groups scoped to buckets.",
          "nav": [{"surface": "customer", "label": "People (portal)", "path": "/team", "perm": "access.view", "group": "Account", "order": 10},
                  {"surface": "customer", "label": "Storage users", "path": "/users", "perm": "access.view", "group": "Storage", "order": 30}]}

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}$")
ROLE_TEXT = {
    "administrator": "Everything: people and roles, storage users and groups, who can use each bucket, buckets and their settings, access keys, usage, invoices and alerts.",
    "operator": "Buckets and their settings (versioning, lifecycle, Object Lock, CORS) and access keys. Cannot change who has access, people, storage users or groups, and cannot delete buckets.",
    "billing": "Usage, statements, alerts and quota requests. Cannot see or change buckets or access.",
    "read-only": "View buckets, their access rules, access key IDs, usage and activity. Cannot change anything.",
}


ROLE_TITLE = {"administrator": "Administrator", "operator": "Operator", "billing": "Billing", "read-only": "Read only"}
_ROLE_ORDER = ["read-only", "billing", "operator", "administrator"]


def _roles():
    return [r for r in _ROLE_ORDER if r in CUSTOMER_ROLES] + [r for r in CUSTOMER_ROLES if r not in _ROLE_ORDER]


def _role_radios(selected: str, name: str = "role") -> str:
    """One radio option per role, each with a plain description."""
    out = []
    for r in _roles():
        hint = ROLE_TEXT.get(r, "")
        if r == "administrator":
            hint += " Give this to as few people as possible."
        out.append(f'<label class="option"><input type="radio" name="{esc(name)}" value="{esc(r)}"{" checked" if r == selected else ""}> '
                   f'<span><strong>{esc(ROLE_TITLE.get(r, r))}</strong><small class="muted">{esc(hint)}</small></span></label>')
    return "".join(out)


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
    def _mfa_required():
        return bool(app.cfg.d["security"]["customer_mfa_required"])

    def _status(u):
        """The state of a person in plain words, as a badge."""
        if app.auth.is_locked(u):
            return ui.badge("locked: sign-in is blocked for a while", "bad")
        if u["state"] == "active":
            return ui.badge("Active", "ok")
        if u["state"] == "invited":
            inv, exp = app.auth.invite_state(u["id"])
            if inv == "open":
                return ui.badge("Waiting for them to accept (link valid until " + exp[:16].replace("T", " ") + ")", "warn")
            if inv == "expired":
                return ui.badge("Link expired: send a new invite", "bad")
            return ui.badge("No active link: send a new invite", "warn")
        return ui.badge(u["state"], "warn")

    @app.route("customer", "GET", "/team", perm="access.view", module="tenant-access")
    def team(ctx):
        us = app.db.all("SELECT * FROM users WHERE customer_id=? ORDER BY name", (ctx.customer["id"],))
        can = ctx.can("access.edit")
        intro = ("<p>These are the people who sign in to this portal. Each has a <strong>role</strong> that decides what they can see and change.</p>"
                 + ("<p>" + str(ui.link("/team/new", "Invite a person", "btn primary")) + "</p>" if can else
                    "<p class='muted'>Only an administrator can invite people or change their role.</p>"))
        steps = Raw(
            "<ol class='howto'>"
            "<li><strong>Press Invite a person.</strong> Enter their name and e-mail address and choose what they may do. If you are unsure, choose <em>Read only</em>.</li>"
            "<li><strong>They get an e-mail</strong> with a link. The link works once and for 72 hours.</li>"
            "<li><strong>They choose a password</strong>"
            + (" and set up a second sign-in step with an authenticator app" if _mfa_required() else "") + ".</li>"
            "<li><strong>They sign in.</strong> Their status on this page changes from <em>Waiting for them to accept</em> to <em>Active</em>.</li>"
            "<li><strong>Change your mind at any time.</strong> Press <em>Manage</em> on a person to change their role, send a new link, sign them out or remove them.</li>"
            "</ol>")
        rows = []
        for u in us:
            me = u["id"] == ctx.sess.user_id
            rows.append([u["name"] + (" (you)" if me else ""), u["email"], ROLE_TITLE.get(u["role"], u["role"]), _status(u),
                         (u["last_login"] or "never")[:16].replace("T", " "), ui.badge("on", "ok") if u["mfa_enabled"] else "-",
                         ui.link("/team/person?uid=" + u["id"], "Manage" if can and not me else "Details", "btn small")])
        tbl = ui.card("People who can sign in to this portal",
                      ui.table(["Name", "E-mail", "Role", "Status", "Last sign-in", "MFA", ""], rows))
        roles = ui.card("What each role can do", ui.table(["Role", "Can"], [[ROLE_TITLE[r], ROLE_TEXT[r]] for r in _roles()]))
        note = ui.card("Good to know", Raw(
            "<ul class='plain'><li>An invitation link works once and for 72 hours. Sending a new one cancels the old one.</li>"
            "<li>Changing a role signs the person out. The new role applies when they sign in again.</li>"
            "<li>You cannot change or remove your own entry, and the last active administrator cannot be demoted or removed.</li>"
            "<li>Changing a role, resetting multi-factor authentication or removing someone asks for your password again.</li>"
            "<li>Every change is written to the activity log.</li></ul>"))
        return ui.page(ctx, "People", Raw(ui.card("Who can sign in", Raw(intro)) + ui.card("How to add someone, in five steps", steps) + tbl + roles + note), "/team")

    # ------------------------------------------------------------------ the guided invitation
    _BEFORE = (
        "<p>You are about to invite one person to this portal. It takes about a minute.</p>"
        "<ol class='howto'>"
        "<li>Answer the three questions below. <strong>Nothing is sent until you press Send invitation.</strong></li>"
        "<li>The person gets an e-mail with a link. The link works <strong>once</strong> and for <strong>72 hours</strong>.</li>"
        "<li>They choose their own password. <strong>You never see or set it.</strong></li>"
        "<li>The next page tells you what to expect and what to do if the e-mail does not arrive.</li>"
        "</ol>"
        "<p class='muted'>Not sure what to choose? Pick <em>Read only</em>. You can change the role later under <em>Manage</em>.</p>")

    def _invite_form(ctx, vals=None, error=""):
        vals = vals or {}
        err = f'<div class="flash bad" role="alert">{esc(error)}</div>' if error else ""
        html = (f'{err}<form method="post" action="/team/new" class="stack steps" autocomplete="off">'
                f'<input type="hidden" name="_csrf" value="{esc(ctx.sess.csrf)}">'
                '<fieldset class="step"><legend><span class="n">1</span> Who are you inviting?</legend>'
                f'<div class="field"><label>Name<input type="text" name="name" value="{esc(vals.get("name", ""))}" required maxlength="120" placeholder="for example Alex Morgan">'
                '</label></div>'
                f'<div class="field"><label>E-mail address<input type="email" name="email" value="{esc(vals.get("email", ""))}" required maxlength="200" placeholder="alex@yourcompany.example">'
                '</label><small class="muted">The invitation goes to this address. Use the address the person reads every day.</small></div></fieldset>'
                '<fieldset class="step"><legend><span class="n">2</span> What may they do?</legend>'
                + _role_radios(vals.get("role", "read-only")) +
                '</fieldset>'
                '<fieldset class="step"><legend><span class="n">3</span> What happens next</legend>'
                '<p>The portal sends the e-mail straight away. The person follows the link, chooses a password'
                + (' and sets up an authenticator app for the second sign-in step' if _mfa_required() else '') +
                '. You can send a new link, cancel the link or change the role at any time under <em>Manage</em>.</p>'
                '<div class="actions"><button class="btn primary">Send invitation</button> '
                '<a class="btn" href="/team">Cancel</a></div></fieldset></form>')
        return Raw(html)

    @app.route("customer", "GET", "/team/new", perm="access.edit", module="tenant-access")
    def invite_form(ctx):
        return ui.page(ctx, "Invite a person", Raw(ui.card("Before you start", Raw(_BEFORE)) + ui.card("Three quick questions", _invite_form(ctx))), "/team",
                       actions=ui.link("/team", "Back", "btn"))

    @app.route("customer", "POST", "/team/new", perm="access.edit", module="tenant-access")
    def invite_post(ctx):
        name, email, role = ctx.f("name").strip(), ctx.f("email").strip().lower(), ctx.f("role")
        vals = {"name": name, "email": email, "role": role if role in CUSTOMER_ROLES else "read-only"}

        def fail(msg):
            return html_response(ui.page(ctx, "Invite a person", Raw(ui.card("Three quick questions", _invite_form(ctx, vals, msg))), "/team",
                                         actions=ui.link("/team", "Back", "btn")), 400)
        if not name:
            return fail("Enter the person's name, so you can recognise them in the list.")
        if not valid_email(email):
            return fail("That e-mail address does not look right. It should look like name@company.example.")
        if role not in CUSTOMER_ROLES:
            return fail("Choose what the person may do.")
        try:
            uid = app.auth.create_user(email, name, role, ctx.customer["id"], actor=ctx.sess.email, ip=ctx.req.ip)
        except AuthError as e:
            if "already exists" in str(e):
                return fail("This e-mail address already has an account on this portal. If the person is on your People list, open them with Manage; "
                            "otherwise use a different address.")
            return fail(str(e))
        mail = _send_invite(ctx, uid)
        u = _person(ctx, uid)
        return html_response(_invited_page(ctx, u, mail))

    _MAIL_NOTE = {
        "sent": ("ok", "The e-mail was sent."),
        "captured": ("warn", "This is a demonstration portal, so the e-mail was captured and not delivered to a real inbox."),
        "not-configured": ("bad", "This portal is not set up to send e-mail yet, so nothing was sent. Ask your service provider to set up e-mail, "
                                  "then press Send new invite on the person&#39;s page."),
        "failed": ("bad", "The e-mail could not be sent. Wait a few minutes and press Send new invite on the person&#39;s page. "
                          "If it fails again, tell your service provider."),
    }

    def _invited_page(ctx, u, mail_id):
        row = app.db.one("SELECT state FROM outbox WHERE id=?", (mail_id,)) if mail_id else None
        kind, text = _MAIL_NOTE.get(row["state"] if row else "", ("warn", "The e-mail has been queued."))
        _, exp = app.auth.invite_state(u["id"])
        top = ui.card(f"Invitation prepared for {u['name']}", Raw(
            f'<div class="flash {"" if kind == "ok" else "bad" if kind == "bad" else "warn"}" role="status">{text}</div>'
            + str(ui.kv([("Name", u["name"]), ("E-mail", u["email"]), ("Role", ROLE_TITLE.get(u["role"], u["role"])),
                         ("Link valid until", exp[:16].replace("T", " ") + " (UTC)" if exp else "-")]))
            + "<p>" + str(ui.link("/team/person?uid=" + u["id"], "Manage this person", "btn primary")) + " "
            + str(ui.link("/team/new", "Invite another person", "btn")) + " " + str(ui.link("/team", "Back to People", "btn")) + "</p>"))
        todo = ui.card("What happens now", Raw(
            "<ol class='howto'>"
            f"<li><strong>{esc(u['name'])} opens the e-mail</strong> and presses the link. Ask them to look in the spam folder if it is not in the inbox.</li>"
            "<li><strong>They choose a password.</strong> The portal tells them what a good password needs. You never see it.</li>"
            + ("<li><strong>They set up the second sign-in step.</strong> They scan a code with an authenticator app on their phone and enter the 6 digits it shows.</li>" if _mfa_required() else "")
            + "<li><strong>They sign in.</strong> Their role is <strong>" + esc(ROLE_TITLE.get(u["role"], u["role"])) + "</strong>: " + esc(ROLE_TEXT.get(u["role"], "")) + "</li>"
            "<li><strong>Check back on the People page.</strong> When the status says <em>Active</em>, they are in.</li>"
            "</ol>"))
        trouble = ui.card("If something does not work", ui.table(["You see", "What it usually means", "What to do"], [
            ["The person says the e-mail did not arrive", "It is in the spam folder, the address has a typo, or the e-mail system is slow", "Check spam. Check the address on the People page. Wait a few minutes, then press Send new invite"],
            ["The link says it is not valid or has expired", "The link works once and for 72 hours, or a newer invitation replaced it", "Open the person with Manage and press Send new invite"],
            ["The address was typed wrongly", "The invitation went to someone else or nowhere", "Cancel the link, remove the person, and invite again with the right address"],
            ["The person cannot sign in later", "A wrong password several times locks the account for a short while", "Open the person with Manage and press Unlock"],
            ["The person lost their phone", "They cannot give the second sign-in code", "Open the person with Manage and press Reset multi-factor authentication"],
        ]))
        return ui.page(ctx, "Invitation sent", Raw(top + todo + trouble), "/team")

    def _send_invite(ctx, uid):
        u = _person(ctx, uid)
        if not u:
            return ""
        tok = app.auth.invite_token(uid)
        return services.send_mail(app, u["email"], f"Your {app.cfg.d['branding']['name']} account",
                                  f"Hello {u['name']},\n\n{ctx.sess.name} invited you. Set your password here:\n"
                                  f"{services.invite_link(app, tok)}\n\nThe link works once and for 72 hours.\n", ctx.customer["id"])

    # ------------------------------------------------------------------ one person
    def _back(u):
        return redirect("/team/person?uid=" + u["id"]) if u else redirect("/team")

    @app.route("customer", "POST", "/team", perm="access.edit", module="tenant-access")
    def team_add(ctx):
        """Kept so that older forms keep working; the guided page is /team/new."""
        try:
            uid = app.auth.create_user(ctx.f("email"), ctx.f("name"), ctx.f("role"), ctx.customer["id"], actor=ctx.sess.email, ip=ctx.req.ip)
        except AuthError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/team/new")
        _send_invite(ctx, uid)
        ctx.flash("Invitation sent.")
        return redirect("/team/person?uid=" + uid)

    @app.route("customer", "GET", "/team/person", perm="access.view", module="tenant-access")
    def person_page(ctx):
        u = _person(ctx, ctx.q("uid"))
        if not u:
            return html_response(ui.page(ctx, "Person not found", Raw(ui.card("Person not found", Raw(
                "<p>There is nobody with that link on your account. They may have been removed. <a href='/team'>Back to People</a></p>"))), "/team"), 404)
        can, me = ctx.can("access.edit"), u["id"] == ctx.sess.user_id
        csrf = ctx.sess.csrf
        only_admin = u["role"] == "administrator" and u["state"] == "active" and _other_admins(ctx, u["id"]) == 0
        inv, exp = app.auth.invite_state(u["id"]) if u["state"] == "invited" else ("", "")
        top = ui.card(u["name"] + (" (you)" if me else ""), Raw(str(ui.kv([
            ("E-mail", u["email"]), ("Role", ROLE_TITLE.get(u["role"], u["role"])), ("Status", _status(u)),
            ("Last sign-in", (u["last_login"] or "never")[:16].replace("T", " ")),
            ("Second sign-in step (MFA)", "on" if u["mfa_enabled"] else "not set up yet")])) +
            f"<p class='muted'>{esc(ROLE_TEXT.get(u['role'], ''))}</p>"), actions=ui.link("/team", "Back to People", "btn"))
        body = top
        if me:
            body += ui.card("This is you", Raw("<p>You cannot change your own role, sign yourself out of other places or remove yourself here. "
                                               "Ask another administrator. To change your password or your authenticator, use <em>Account</em>.</p>"))
        elif not can:
            body += ui.card("View only", Raw("<p>Only an administrator can change people. Ask one of them if something needs to change.</p>"))
        else:
            # 1. role
            if only_admin:
                body += ui.card("Change what they can do", Raw("<p>This person is the only active administrator, so the role cannot be lowered. "
                                                              "Invite or promote another administrator first.</p>"))
            else:
                body += ui.card("Change what they can do", Raw(
                    '<p>Choose the new role and press <em>Change role</em>. The person is signed out straight away and the new role applies '
                    'when they sign in again. The portal asks for your password to confirm.</p>'
                    f'<form method="post" action="/team/role" class="stack"><input type="hidden" name="_csrf" value="{esc(csrf)}">'
                    f'<input type="hidden" name="uid" value="{esc(u["id"])}">' + _role_radios(u["role"]) +
                    '<div class="actions"><button class="btn primary">Change role</button></div></form>'))
            # 2. invitation
            if u["state"] == "invited":
                state_text = {"open": "A link is waiting. It is valid until " + exp[:16].replace("T", " ") + " (UTC).",
                              "expired": "The last link has expired.", "none": "There is no active link."}.get(inv, "")
                cancel = (str(ui.button("Cancel the link", "/team/invite/revoke", csrf, {"uid": u["id"]}, "small",
                                        confirm="Cancel the invitation link? The person stays on the list without a way to sign in until you send a new one."))
                          if inv in ("open", "expired") else "")
                body += ui.card("Invitation", Raw(
                    f"<p>This person has not set a password yet. {esc(state_text)}</p>"
                    "<p>Sending a new invitation e-mails a fresh link and cancels the earlier one.</p><p>"
                    + str(ui.button("Send new invite", "/team/invite", csrf, {"uid": u["id"]}, "primary")) + " " + cancel + "</p>"))
            # 3. sign-in help
            help_ = ""
            if app.auth.is_locked(u):
                help_ += ("<h3>Locked</h3><p>Too many wrong passwords locked the account for a short while. Unlock it if you know the person is trying to sign in.</p><p>"
                          + str(ui.button("Unlock", "/team/unlock", csrf, {"uid": u["id"]}, "small")) + "</p>")
            if u["state"] == "active":
                help_ += ("<h3>Sign out everywhere</h3><p>Ends every session of this person on every device. Use it if a laptop is lost or you are worried about an account. "
                          "They can sign in again.</p><p>" + str(ui.button("Sign out everywhere", "/team/signout", csrf, {"uid": u["id"]}, "small",
                                                                          confirm=f"End every session of {u['email']}?")) + "</p>")
            if u["mfa_enabled"]:
                help_ += ("<h3>Reset the second sign-in step</h3><p>Use this if the person lost their phone or authenticator. They are signed out and set it up again at the next sign-in. "
                          "The portal asks for your password to confirm.</p><p>" + str(ui.button("Reset multi-factor authentication", "/team/mfa-reset", csrf, {"uid": u["id"]}, "small",
                                                                                              confirm="Reset multi-factor authentication for this person?")) + "</p>")
            if help_:
                body += ui.card("Sign-in help", Raw(help_))
            # 4. remove
            if only_admin:
                body += ui.card("Remove this person", Raw("<p>This person is the only active administrator and cannot be removed. Invite or promote another administrator first.</p>"))
            else:
                body += ui.card("Remove this person", Raw(
                    "<p>They lose access at once and any open sessions end. Their name stays in the activity log. "
                    "Access keys they created belong to your account and keep working, so review them under Access keys if they knew a secret. "
                    "The portal asks for your password to confirm.</p><p>"
                    + str(ui.button("Remove " + u["name"], "/team/remove", csrf, {"uid": u["id"]}, "small danger", confirm=f"Remove {u['email']}? This cannot be undone.")) + "</p>"))
        return ui.page(ctx, u["name"], Raw(body), "/team")

    @app.route("customer", "POST", "/team/invite", perm="access.edit", module="tenant-access")
    def team_reinvite(ctx):
        u = _person(ctx, ctx.f("uid"))
        if not u or u["state"] != "invited":
            ctx.flash("Error: That person has already set a password.")
            return _back(u)
        _send_invite(ctx, u["id"])
        ctx.audit("user.reinvite", u["email"])
        ctx.flash("A new invitation was sent. Earlier links no longer work.")
        return _back(u)

    @app.route("customer", "POST", "/team/invite/revoke", perm="access.edit", module="tenant-access")
    def team_revoke(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["state"] == "invited":
            app.auth.revoke_invites(u["id"], ctx.sess.email, ctx.req.ip)
            ctx.flash("Invitation cancelled.")
        return _back(u)

    @app.route("customer", "POST", "/team/role", perm="access.edit", module="tenant-access", reauth=True)
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
        return _back(u)

    @app.route("customer", "POST", "/team/signout", perm="access.edit", module="tenant-access")
    def team_signout(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            app.auth.revoke_user_sessions(u["id"])
            ctx.audit("user.sessions_ended", u["email"])
            ctx.flash("All sessions of that person were ended.")
        return _back(u)

    @app.route("customer", "POST", "/team/unlock", perm="access.edit", module="tenant-access")
    def team_unlock(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u:
            app.auth.unlock(u["id"], ctx.sess.email, ctx.req.ip)
            ctx.flash("Account unlocked.")
        return _back(u)

    @app.route("customer", "POST", "/team/remove", perm="access.edit", module="tenant-access", reauth=True)
    def team_remove(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            if u["role"] == "administrator" and u["state"] == "active" and _other_admins(ctx, u["id"]) == 0:
                ctx.flash("Error: There must be at least one administrator.")
                return _back(u)
            app.auth.revoke_user_sessions(u["id"])
            app.db.run("DELETE FROM invitations WHERE user_id=?", (u["id"],))
            app.db.run("DELETE FROM users WHERE id=?", (u["id"],))
            ctx.audit("user.remove", u["email"])
            ctx.flash(f"{u['name']} was removed.")
        return redirect("/team")

    @app.route("customer", "POST", "/team/mfa-reset", perm="access.edit", module="tenant-access", reauth=True)
    def team_mfa_reset(ctx):
        u = _person(ctx, ctx.f("uid"))
        if u and u["id"] != ctx.sess.user_id:
            app.auth.disable_mfa(u["id"], ctx.sess.email, ctx.req.ip)
            app.auth.revoke_user_sessions(u["id"])
            ctx.flash("Multi-factor authentication reset. The person sets it up again at next sign-in.")
        return _back(u)

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

    @app.route("customer", "POST", "/groups/delete", perm="access.edit", module="tenant-access", reauth=True)
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

    @app.route("customer", "POST", "/users/delete", perm="access.edit", module="tenant-access", reauth=True)
    def user_del(ctx):
        app.backend.delete_user(ctx.ref, ctx.f("user"))
        ctx.audit("storage_user.delete", ctx.f("user"))
        ctx.flash("Storage user deleted.")
        return redirect("/users")
