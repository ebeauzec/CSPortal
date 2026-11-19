"""S3 access-key lifecycle. Secrets are shown once and never stored by the portal."""
from __future__ import annotations

import datetime as dt

from ..util import iso, parse_iso, utcnow
from ..web import ui
from ..web.core import Raw, html_response, redirect
from ..backends.base import BackendError

EXPIRY_CHOICES = [("0", "Never expires"), ("30", "30 days"), ("90", "90 days"), ("180", "180 days"), ("365", "1 year")]


def _expiry_cell(exp):
    if not exp:
        return "never"
    try:
        left = (parse_iso(exp) - utcnow()).days
    except Exception:
        return str(exp)[:10]
    if left < 0:
        return ui.badge("expired " + str(exp)[:10], "bad")
    return ui.badge(f"{str(exp)[:10]} ({left} days)", "warn" if left <= 14 else "")

MODULE = {"id": "s3-access", "name": "S3 access keys", "version": "1.0.0", "surfaces": ["customer"],
          "requires": ["tenant-access"], "description": "Create, rotate and revoke S3 access keys; endpoint details.",
          "nav": [{"surface": "customer", "label": "Access keys", "path": "/keys", "perm": "keys.view", "group": "Storage", "order": 20}]}


def register(app):
    @app.route("customer", "GET", "/keys", perm="keys.view", module="s3-access")
    def keys(ctx):
        users = app.backend.list_users(ctx.ref)
        if not users:
            return ui.page(ctx, "Access keys", Raw(ui.card("No storage users yet", Raw(
                '<p>Access keys belong to storage users. <a href="/users">Create a group and a user</a> first.</p>'))), "/keys")
        sel = ctx.q("user") or users[0]["username"]
        if sel not in [u["username"] for u in users]:
            sel = users[0]["username"]
        opts = "".join(f'<option value="{ui.esc(u["username"])}"{" selected" if u["username"] == sel else ""}>{ui.esc(u["username"])}</option>' for u in users)
        picker = Raw(f'<form method="get" action="/keys"><label>Storage user <select name="user" data-autosubmit>{opts}</select></label> '
                     f'<noscript><button class="btn small">Show</button></noscript></form>')
        ks = app.backend.list_keys(ctx.ref, sel)
        can = ctx.can("keys.manage")
        rows = [[Raw(f"<code>{ui.esc(k['id'])}</code>"), k["created"][:10], k.get("last_used") or "never", _expiry_cell(k.get("expires")),
                 ui.button("Delete", "/keys/delete", ctx.sess.csrf, {"user": sel, "key": k["id"]}, "small danger",
                           confirm="Delete this key? Applications using it stop working immediately.") if can else ""] for k in ks]
        body = ui.card("Choose user", picker) + ui.card(f"Access keys for {sel}", ui.table(["Access key ID", "Created", "Last used", "Expires", ""], rows,
                                                                                        "No access keys for this user."))
        if can:
            body += ui.card("Create a new key", Raw(
                "<p>The secret is shown <strong>once</strong>. Copy it to your application's secret store. "
                "To rotate: create a new key, switch your application, then delete the old key. "
                "A key with an expiry date stops working by itself on that day.</p>" +
                ui.form("/keys/create", [{"name": "user", "type": "hidden", "value": sel},
                                         {"name": "expiry", "label": "Expiry", "type": "select", "options": EXPIRY_CHOICES, "value": "0"}],
                        ctx.sess.csrf, "Create access key")))
        ep = app.backend.endpoints(ctx.ref)
        body += ui.card("Endpoint", ui.kv([("S3 endpoint", Raw("<code>" + ", ".join(ep["s3"]) + "</code>")), ("Region", ", ".join(ep["regions"])),
                                           ("Addressing", "Path-style and virtual-hosted-style")]))
        return ui.page(ctx, "Access keys", Raw(body), "/keys")

    @app.route("customer", "POST", "/keys/create", perm="keys.manage", module="s3-access")
    def create(ctx):
        days = int(ctx.f("expiry")) if ctx.f("expiry") in dict(EXPIRY_CHOICES) else 0
        exp = iso(utcnow() + dt.timedelta(days=days)) if days else None
        k = app.backend.create_key(ctx.ref, ctx.f("user"), exp)
        ctx.audit("key.create", ctx.f("user"), f"{k['id']} expires={exp[:10] if exp else 'never'}")
        body = ui.card("New access key created", Raw(
            "<p><strong>Copy the secret now. It will not be shown again.</strong></p>"
            f'<div class="secret"><div>Access key ID</div><code id="kid">{ui.esc(k["id"])}</code> '
            '<button class="btn small" data-copy="kid" type="button">Copy</button></div>'
            f'<div class="secret"><div>Secret access key</div><code id="ksec">{ui.esc(k["secret"])}</code> '
            '<button class="btn small" data-copy="ksec" type="button">Copy</button></div>'
            f'<p><a class="btn primary" href="/keys?user={ui.esc(ctx.f("user"))}">I have saved the secret</a></p>'))
        return html_response(ui.page(ctx, "Access key created", body, "/keys"))

    @app.route("customer", "POST", "/keys/delete", perm="keys.manage", module="s3-access")
    def delete(ctx):
        app.backend.delete_key(ctx.ref, ctx.f("user"), ctx.f("key"))
        ctx.audit("key.delete", ctx.f("user"), ctx.f("key"))
        ctx.flash("Access key deleted.")
        return redirect(f"/keys?user={ctx.f('user')}")
