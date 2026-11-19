"""Core module: sign-in, multi-factor authentication, invitations, own account."""
from __future__ import annotations

import logging
import urllib.parse

from .. import crypto, logs
from ..auth import AuthError
from ..web import ui
from ..web.core import Raw, html_response, redirect, Response
from ..util import esc

MODULE = {"id": "core-accounts", "name": "Accounts and sign-in", "version": "1.0.0", "core": True,
          "surfaces": ["customer", "admin"], "requires": [],
          "description": "Sign-in, multi-factor authentication, invitations and own account.",
          "nav": [{"surface": "customer", "label": "My account", "path": "/account", "perm": "dashboard.view", "group": "Account", "order": 90},
                  {"surface": "admin", "label": "My account", "path": "/account", "perm": "admin.overview", "group": "", "order": 90}]}

slog = logging.getLogger("csportal.security")


def _pre_token(ctx) -> tuple[str, str]:
    """Anti-forgery token for forms shown before sign-in: a random value in a cookie and in the form."""
    tok = ctx.req.cookies.get(ctx.app.pre_cookie_name(ctx.req.surface)) or crypto.token()
    return tok, ctx.app.pre_cookie(ctx.req.surface, tok)


def _safe_next(n: str) -> str:
    n = urllib.parse.unquote(n or "/")
    return n if n.startswith("/") and not n.startswith("//") and "\\" not in n else "/"


def register(app):
    demo_accounts_html = ""

    @app.route("both", "GET", "/login", public=True)
    def login_form(ctx):
        if ctx.sess and ctx.sess.mfa_ok:
            return redirect("/")
        tok, cookie = _pre_token(ctx)
        demo = ""
        if ctx.cfg.demo:
            from ..demo import DEMO_PASSWORD, demo_accounts
            rows = "".join(f"<tr><td>{esc(a['label'])}</td><td class='mono'>{esc(a['email'])}</td></tr>"
                           for a in demo_accounts(ctx.req.surface))
            demo = (f'<section class="card"><h2>Demo accounts</h2><p class="muted">Demo mode only. Password for all: '
                    f'<code>{esc(DEMO_PASSWORD)}</code></p><table><tbody>{rows}</tbody></table></section>')
        b = ui.brand(app)
        title = "Sign in" if ctx.req.surface == "customer" else "Administration sign-in"
        body = (f'<h1>{esc(b["name"])}</h1><p class="muted">{esc(title)}</p><section class="card">' +
                ui.form("/login", [{"name": "email", "label": "E-mail", "type": "email"},
                                   {"name": "password", "label": "Password", "type": "password"},
                                   {"name": "next", "type": "hidden", "value": ctx.q("next", "/"), "label": "", "required": False}],
                        tok, "Sign in") + "</section>" + demo)
        return html_response(ui.bare_page(app, title, body)).header("Set-Cookie", cookie)

    @app.route("both", "POST", "/login", public=True)
    def login_post(ctx):
        try:
            tok, _csrf = app.auth.authenticate(ctx.f("email"), ctx.req.form.get("password", ""), ctx.req.surface, ctx.req.ip)
        except AuthError as e:
            pre, cookie = _pre_token(ctx)
            body = (f'<h1>{esc(ui.brand(app)["name"])}</h1><div class="flash bad" role="alert">{esc(str(e))}</div><section class="card">' +
                    ui.form("/login", [{"name": "email", "label": "E-mail", "type": "email", "value": ctx.f("email")},
                                       {"name": "password", "label": "Password", "type": "password"}], pre, "Sign in") + "</section>")
            return html_response(ui.bare_page(app, "Sign in", body), 401).header("Set-Cookie", cookie)
        r = redirect(_safe_next(ctx.f("next")) if ctx.f("next") else "/")
        r.header("Set-Cookie", app.session_cookie(ctx.req.surface, tok))
        # the session may need MFA; the pipeline redirects to /mfa on the next request
        return r

    @app.route("both", "POST", "/logout", mfa_exempt=True)
    def logout(ctx):
        app.auth.sign_out(ctx.sess, ctx.req.ip)
        return redirect("/login").header("Set-Cookie", app.session_cookie(ctx.req.surface, "", 0))

    @app.route("both", "GET", "/logout", public=True)
    def logout_get(ctx):
        return redirect("/login")

    # ------------------------------------------------------------ MFA
    @app.route("both", "GET", "/mfa", mfa_exempt=True)
    def mfa_form(ctx):
        if ctx.sess.mfa_ok:
            return redirect("/")
        u = app.db.one("SELECT mfa_enabled, totp_sealed, email FROM users WHERE id=?", (ctx.sess.user_id,))
        if u["mfa_enabled"]:
            body = ("<p>Enter the 6-digit code from your authenticator app.</p>" +
                    ui.form("/mfa", [{"name": "code", "label": "Code", "attrs": {"inputmode": "numeric", "maxlength": "6", "autocomplete": "one-time-code"}}],
                            ctx.sess.csrf, "Verify"))
        else:
            secret = app.auth.pending_totp_secret(ctx.sess.user_id) or app.auth.begin_mfa_enrol(ctx.sess.user_id)
            b = ui.brand(app)
            uri = crypto.totp_uri(secret, u["email"], b["name"])
            body = ("<p>Your organisation requires multi-factor authentication. Add this account to an authenticator app "
                    "(any app that supports time-based codes), then enter the 6-digit code.</p>"
                    f'<p>Setup key:</p><div class="secret mono">{esc(secret)}</div><p class="muted"><small>Or open this link on the device with your authenticator: '
                    f'<a href="{esc(uri)}">{esc(uri[:48])}...</a></small></p>' +
                    ui.form("/mfa", [{"name": "code", "label": "Code", "attrs": {"inputmode": "numeric", "maxlength": "6", "autocomplete": "one-time-code"}}],
                            ctx.sess.csrf, "Confirm and continue", extra=Raw('<input type="hidden" name="enrol" value="1">')))
        return html_response(ui.bare_page(app, "Verify your identity", f"<h1>Verify your identity</h1><section class='card'>{body}</section>"))

    @app.route("both", "POST", "/mfa", mfa_exempt=True)
    def mfa_post(ctx):
        try:
            ok = app.auth.verify_mfa(ctx.sess, ctx.f("code"), ctx.req.ip, enrolling=bool(ctx.f("enrol")))
        except AuthError as e:
            ctx.flash("Error: " + str(e))
            return redirect("/mfa")
        if not ok:
            ctx.flash("Error: That code is not correct.")
            return redirect("/mfa")
        return redirect("/")

    # ------------------------------------------------------------ invitation / password set
    @app.route("both", "GET", "/invite/{token}", public=True)
    def invite_form(ctx):
        tok, cookie = _pre_token(ctx)
        body = ("<h1>Set your password</h1><section class='card'>" +
                ui.form("/invite", [{"name": "token", "type": "hidden", "value": ctx.params["token"], "label": "", "required": False},
                                    {"name": "password", "label": "New password", "type": "password",
                                     "help": f"At least {app.auth.min_len} characters. Longer is better."},
                                    {"name": "password2", "label": "Repeat password", "type": "password"}], tok, "Set password") + "</section>")
        return html_response(ui.bare_page(app, "Set your password", body)).header("Set-Cookie", cookie)

    @app.route("both", "POST", "/invite", public=True)
    def invite_post(ctx):
        if ctx.req.form.get("password") != ctx.req.form.get("password2"):
            return html_response(ui.bare_page(app, "Set your password", '<div class="flash bad">The passwords do not match. Go back and try again.</div>'), 400)
        try:
            app.auth.redeem_invite(ctx.f("token"), ctx.req.form.get("password", ""), ctx.req.ip)
        except AuthError as e:
            return html_response(ui.bare_page(app, "Set your password", f'<div class="flash bad">{esc(str(e))}</div>'), 400)
        return redirect("/login")

    # ------------------------------------------------------------ own account
    @app.route("both", "GET", "/account")
    def account(ctx):
        u = app.db.one("SELECT * FROM users WHERE id=?", (ctx.sess.user_id,))
        body = ui.grid(
            ui.card("Profile", ui.kv([("Name", u["name"]), ("E-mail", u["email"]), ("Role", u["role"]),
                                      ("Multi-factor authentication", ui.badge("On", "ok") if u["mfa_enabled"] else ui.badge("Off", "warn")),
                                      ("Last sign-in", u["last_login"] or "-")])),
            ui.card("Change password", ui.form("/account/password", [
                {"name": "current", "label": "Current password", "type": "password"},
                {"name": "new", "label": "New password", "type": "password"}], ctx.sess.csrf, "Change password")), cols=2)
        return ui.page(ctx, "My account", body, "/account")

    @app.route("both", "POST", "/account/password")
    def account_password(ctx):
        try:
            app.auth.change_password(ctx.sess.user_id, ctx.req.form.get("current", ""), ctx.req.form.get("new", ""), ctx.req.ip)
            ctx.flash("Password changed.")
        except AuthError as e:
            ctx.flash("Error: " + str(e))
        return redirect("/account")
