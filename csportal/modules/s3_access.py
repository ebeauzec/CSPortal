"""S3 access keys: one guided page to create a key with exactly the permissions it needs.

A customer administrator answers four plain questions (what is it for, what may it do, which buckets, how long).
The portal creates the storage user and its own group behind the scenes, then shows the secret once with ready-to-use
connection settings. Secrets are never stored by the portal."""
from __future__ import annotations

import datetime as dt

from ..backends.base import BackendError
from ..util import esc, iso, parse_iso, utcnow
from ..web import ui
from ..web.core import Raw, html_response, redirect
from .tenant_access import _NAME

EXPIRY_CHOICES = [("90", "90 days (recommended)"), ("30", "30 days"), ("180", "180 days"), ("365", "1 year"), ("0", "Never expires")]
MAX_NAME = 26                     # the key's group is named "key-<name>" and group names are at most 31 characters


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


MODULE = {"id": "s3-access", "name": "S3 access keys", "version": "2.0.0", "surfaces": ["customer"],
          "requires": ["tenant-access"], "description": "Guided creation, rotation and removal of S3 access keys; connection details.",
          "nav": [{"surface": "customer", "label": "Access keys", "path": "/keys", "perm": "keys.view", "group": "Storage", "order": 20}]}


def _summary(user, groups_by_name):
    """Plain-words description of what a storage user may do, from its groups."""
    gs = [groups_by_name[g] for g in user["groups"] if g in groups_by_name]
    if not gs:
        return "Nothing yet (no group)", "No buckets"
    rw = any(g["access"] == "read-write" for g in gs)
    what = "Read and write" if rw else "Read only"
    if any(not g.get("buckets") for g in gs):
        where = "All buckets"
    else:
        names = sorted({b for g in gs for b in g["buckets"]})
        where = ", ".join(names)
    return what, where


_BEFORE = (
    '<p>You are about to create a key for <strong>one</strong> application, tool or person. It takes about a minute.</p>'
    '<ol class="howto">'
    '<li>Answer the four questions below. Nothing is created until you press <em>Create access key</em>.</li>'
    '<li>The next page shows the key and its secret <strong>once</strong>. Have a place ready to keep it (a password manager, or your application&#39;s secret store).</li>'
    '<li>Then you enter the key in your application and run one test command. The next page walks you through it.</li>'
    '</ol>'
    '<p class="muted">Not sure what to choose? Pick <em>Read only</em>, tick only the buckets the application needs, and keep the 90-day expiry. '
    'You can change the permissions later with <em>Change permissions</em> on the Access keys page.</p>')

_STEPS = (
    '<ol class="howto">'
    '<li><strong>Create a key.</strong> Press <em>Create an access key</em>, name it after what will use it, and choose what it may do and on which buckets.</li>'
    '<li><strong>Copy the secret.</strong> The portal shows the secret access key once. Copy both codes straight into your application&#39;s settings or secret store.</li>'
    '<li><strong>Enter the connection details.</strong> Your application needs four things: the endpoint address, the region, the access key ID and the secret access key. The portal shows all four.</li>'
    '<li><strong>Test it.</strong> The portal gives you a one-line command that lists your buckets. If it answers, the key works.</li>'
    '<li><strong>Replace it from time to time.</strong> Add a second key to the same name, switch your application to it, then delete the old one. Nothing stops working in between.</li>'
    '</ol>')


def _own_group(user):
    return user["groups"] == ["key-" + user["username"]]


def register(app):
    def _bucket_names(ctx):
        return [b["name"] for b in app.backend.list_buckets(ctx.ref)]

    # ------------------------------------------------------------------ the list
    @app.route("customer", "GET", "/keys", perm="keys.view", module="s3-access")
    def keys(ctx):
        users = app.backend.list_users(ctx.ref)
        groups = {g["name"]: g for g in app.backend.list_groups(ctx.ref)}
        can_keys, can_new = ctx.can("keys.manage"), ctx.can("access.edit")
        intro = ("<p>An <strong>access key</strong> is a pair of codes that lets an application, a backup tool or a person's "
                 "software use your storage. Each key has its own permissions, so you can give it only what it needs.</p>")
        if can_new:
            intro += "<p>" + str(ui.link("/keys/new", "Create an access key", "btn primary")) + "</p>"
        elif can_keys:
            intro += ("<p class='muted'>Creating a new key also sets its permissions, which needs an administrator. "
                      "You can add a replacement key to an existing one below.</p>")
        body = ui.card("Access keys", Raw(intro))
        body += ui.card("How to connect an application, in five steps", Raw(_STEPS))
        if not users:
            body += ui.card("No keys yet", Raw("<p>Nothing uses your storage through a key yet. "
                                               + ("Press <strong>Create an access key</strong> to start.</p>" if can_new else
                                                  "Ask an administrator of your account to create one.</p>")))
        for u in users:
            ks = app.backend.list_keys(ctx.ref, u["username"])
            what, where = _summary(u, groups)
            own = _own_group(u)
            rows = []
            for k in ks:
                last = len(ks) == 1 and own and can_new
                msg = ("Delete this key? Applications using it stop working immediately. It is this key's only key, so its permissions are removed too."
                       if last else "Delete this key? Applications using it stop working immediately.")
                rows.append([Raw(f"<code>{esc(k['id'])}</code>"), k["created"][:10], k.get("last_used") or "never", _expiry_cell(k.get("expires")),
                             ui.button("Delete", "/keys/delete", ctx.sess.csrf, {"user": u["username"], "key": k["id"]}, "small danger", confirm=msg)
                             if can_keys else ""])
            state = ui.badge("disabled", "warn") if u["disabled"] else ""
            head = (f'<p><span class="badge {"ok" if what == "Read and write" else ""}">{esc(what)}</span> '
                    f'<span class="muted">on</span> {esc(where)} {state}</p>' + (f"<p class='muted'>{esc(u['full_name'])}</p>" if u["full_name"] and not own else ""))
            more = ""
            if can_keys and not u["disabled"] and len(ks) < 5:
                opts = "".join(f'<option value="{v}">{esc(t)}</option>' for v, t in EXPIRY_CHOICES)
                more = (f'<form method="post" action="/keys/create" class="inline"><input type="hidden" name="_csrf" value="{esc(ctx.sess.csrf)}">'
                        f'<input type="hidden" name="user" value="{esc(u["username"])}"><label>Add another key, valid for <select name="expiry">{opts}</select></label> '
                        f'<button class="btn small">Add key</button></form>'
                        "<p class='muted'>To replace a key without downtime: add a new one, switch your application to it, then delete the old one.</p>")
            elif len(ks) >= 5:
                more = "<p class='muted'>This user holds the maximum of 5 keys. Delete one before adding another.</p>"
            edit = ""
            if can_new:
                edit = " " + str(ui.link(f"/users/edit?user={u['username']}", "Groups", "btn small")) if not own else \
                       " " + str(ui.link(f"/groups/edit?group=key-{u['username']}", "Change permissions", "btn small"))
            body += ui.card(u["username"], Raw(head + str(ui.table(["Access key ID", "Created", "Last used", "Expires", ""], rows, "No keys. Add one below.")) + more),
                            actions=Raw(edit.strip()) if edit else None)
        ep = app.backend.endpoints(ctx.ref)
        body += ui.card("Where to connect", ui.kv([("S3 endpoint", Raw("<code>" + ", ".join(esc(x) for x in ep["s3"]) + "</code>")),
                                                  ("Region", ", ".join(ep["regions"])),
                                                  ("Addressing", "Path-style and virtual-hosted-style")]))
        return ui.page(ctx, "Access keys", Raw(body), "/keys")

    # ------------------------------------------------------------------ the guided page
    def _form(ctx, vals=None, error=""):
        vals = vals or {}
        buckets = _bucket_names(ctx)
        chosen = set(vals.get("buckets", []))
        scope = vals.get("scope", "selected" if buckets else "all")
        access = vals.get("access", "read-only")
        expiry = vals.get("expiry", "90")

        def radio(name, value, label, hint, checked):
            return (f'<label class="option"><input type="radio" name="{name}" value="{value}"{" checked" if checked else ""}> '
                    f'<span><strong>{esc(label)}</strong><small class="muted">{esc(hint)}</small></span></label>')
        bx = "".join(f'<label class="check"><input type="checkbox" name="b_{esc(b)}" value="1"{" checked" if b in chosen else ""}> {esc(b)}</label>' for b in buckets)
        if not buckets:
            bx = "<p class='muted'>You have no buckets yet. The key will work on every bucket, including ones you create later.</p>"
        opts = "".join(f'<option value="{v}"{" selected" if v == expiry else ""}>{esc(t)}</option>' for v, t in EXPIRY_CHOICES)
        err = f'<div class="flash bad" role="alert">{esc(error)}</div>' if error else ""
        html = (f'{err}<form method="post" action="/keys/new" class="stack steps" autocomplete="off">'
                f'<input type="hidden" name="_csrf" value="{esc(ctx.sess.csrf)}">'
                '<fieldset class="step"><legend><span class="n">1</span> What is this key for?</legend>'
                f'<div class="field"><label>Name<input type="text" name="name" value="{esc(vals.get("name", ""))}" required maxlength="{MAX_NAME}" placeholder="for example nightly-backup">'
                '</label><small class="muted">Letters, numbers, dot, hyphen and underscore. You will see this name in the list of keys.</small></div>'
                f'<div class="field"><label>Note (optional)<input type="text" name="note" value="{esc(vals.get("note", ""))}" maxlength="100" placeholder="for example the backup server in the office">'
                '</label></div></fieldset>'
                '<fieldset class="step"><legend><span class="n">2</span> What may it do?</legend>'
                + radio("access", "read-only", "Read only", "Download and list objects. Cannot change or delete anything.", access == "read-only")
                + radio("access", "read-write", "Read and write", "Upload, replace and delete objects too.", access == "read-write") +
                '</fieldset>'
                '<fieldset class="step"><legend><span class="n">3</span> Which buckets?</legend>'
                + radio("scope", "selected", "Only the buckets I tick", "Safest. The key cannot see your other buckets.", scope == "selected") + f'<div class="indent">{bx}</div>'
                + radio("scope", "all", "All buckets", "Including buckets you create later.", scope == "all") +
                '</fieldset>'
                '<fieldset class="step"><legend><span class="n">4</span> How long should it work?</legend>'
                f'<div class="field"><label>Valid for<select name="expiry">{opts}</select></label>'
                '<small class="muted">The key stops working by itself on that day. Shorter is safer; replacing a key is easy.</small></div></fieldset>'
                '<div class="actions"><button class="btn primary">Create access key</button> '
                '<a class="btn" href="/keys">Cancel</a></div></form>')
        return Raw(html)

    @app.route("customer", "GET", "/keys/new", perm="keys.manage", module="s3-access")
    def new_form(ctx):
        if not ctx.can("access.edit"):
            return html_response(ui.page(ctx, "Create an access key", Raw(ui.card("An administrator is needed", Raw(
                "<p>A new key comes with its own permissions, and only an administrator of your account can set those. "
                "You can add a replacement key to an existing one on the <a href='/keys'>Access keys</a> page.</p>"))), "/keys"), 403)
        pre = ctx.q("bucket")
        vals = {"scope": "selected", "buckets": [pre], "access": "read-write"} if pre in _bucket_names(ctx) else None
        return ui.page(ctx, "Create an access key", Raw(ui.card("Before you start", Raw(_BEFORE)) + ui.card("Four quick questions", _form(ctx, vals))), "/keys",
                       actions=ui.link("/keys", "Back", "btn"))

    @app.route("customer", "POST", "/keys/new", perm="access.edit", module="s3-access")
    def new_post(ctx):
        buckets = _bucket_names(ctx)
        name, note = ctx.f("name"), ctx.f("note")[:100]
        access = ctx.f("access") if ctx.f("access") in ("read-only", "read-write") else "read-only"
        scope = "all" if ctx.f("scope") == "all" else "selected"
        picked = [b for b in buckets if ctx.f("b_" + b)]
        vals = {"name": name, "note": note, "access": access, "scope": scope, "buckets": picked, "expiry": ctx.f("expiry") or "90"}

        def fail(msg):
            return html_response(ui.page(ctx, "Create an access key", Raw(ui.card("Four quick questions", _form(ctx, vals, msg))), "/keys",
                                         actions=ui.link("/keys", "Back", "btn")), 400)
        if not _NAME.match(name) or len(name) > MAX_NAME:
            return fail(f"Give the key a name of 2 to {MAX_NAME} letters, numbers, dots, hyphens or underscores, starting with a letter or number.")
        if scope == "selected" and buckets and not picked:
            return fail("Tick at least one bucket, or choose All buckets.")
        if any(u["username"] == name for u in app.backend.list_users(ctx.ref)):
            return fail("A key with this name already exists. Choose another name, or add a key to the existing one on the Access keys page.")
        days = int(ctx.f("expiry")) if ctx.f("expiry") in dict(EXPIRY_CHOICES) else 90
        exp = iso(utcnow() + dt.timedelta(days=days)) if days else None
        scoped = picked if scope == "selected" else []
        group = "key-" + name
        made_group = made_user = False
        try:
            app.backend.create_group(ctx.ref, group, access, scoped)
            made_group = True
            app.backend.create_user(ctx.ref, name, note or f"Access key {name}", [group])
            made_user = True
            k = app.backend.create_key(ctx.ref, name, exp)
        except BackendError:
            if made_user:                                   # do not leave half of a key behind
                _quiet(lambda: app.backend.delete_user(ctx.ref, name))
            if made_group:
                _quiet(lambda: app.backend.delete_group(ctx.ref, group))
            raise
        ctx.audit("key.create", name, f"{k['id']} {access} buckets={','.join(scoped) or 'all'} expires={exp[:10] if exp else 'never'}")
        return html_response(_created_page(ctx, name, k, access, scoped, exp))

    # ------------------------------------------------------------------ the result
    def _created_page(ctx, user, k, access, scoped, exp):
        ep = app.backend.endpoints(ctx.ref)
        url, region = (ep["s3"] or ["https://s3.example.net"])[0], (ep["regions"] or ["us-east-1"])[0]
        what = "read and write" if access == "read-write" else "read only"
        where = ", ".join(scoped) if scoped else "all buckets"
        snippet = (f"export AWS_ACCESS_KEY_ID={k['id']}\nexport AWS_SECRET_ACCESS_KEY={k['secret']}\nexport AWS_DEFAULT_REGION={region}\n"
                   f"aws s3 ls --endpoint-url {url}")
        top = ui.card(f"Your new access key: {user}", Raw(
            '<div class="flash bad" role="alert"><strong>Copy the secret now.</strong> It is shown only once and cannot be recovered. '
            'If you lose it, create a new key.</div>'
            f'<div class="secret"><div>Access key ID</div><code id="kid">{esc(k["id"])}</code> <button class="btn small" data-copy="kid" type="button">Copy</button></div>'
            f'<div class="secret"><div>Secret access key</div><code id="ksec">{esc(k["secret"])}</code> <button class="btn small" data-copy="ksec" type="button">Copy</button></div>'
            f'<p>This key can <strong>{esc(what)}</strong> on <strong>{esc(where)}</strong>. '
            + (f'It stops working on <strong>{esc(exp[:10])}</strong>.' if exp else 'It does not expire.') + '</p>'
            '<p><a class="btn primary" href="/keys">I have saved the secret</a></p>'))
        todo = ui.card("What to do now", Raw(
            '<ol class="howto">'
            '<li><strong>Copy the secret access key</strong> with the Copy button above and keep it somewhere safe. This page is the only time it is shown.</li>'
            '<li><strong>Open your application&#39;s storage settings.</strong> Look for "S3", "object storage", "custom endpoint" or "S3-compatible storage".</li>'
            f'<li><strong>Enter the four details:</strong> endpoint <code>{esc(url)}</code>, region <code>{esc(region)}</code>, the access key ID and the secret access key. '
            'If the tool asks for an addressing style, choose <em>path-style</em>.</li>'
            '<li><strong>Test the connection.</strong> Run the command in the box below, or use the application&#39;s "test connection" button. '
            'A list of your buckets (or an empty list) means it works.</li>'
            f'<li><strong>Put a reminder in your calendar</strong>{" for a few days before " + esc(exp[:10]) if exp else " to replace this key every few months"}. '
            'To replace it: open <em>Access keys</em>, press <em>Add key</em> under this name, switch the application to the new key, then delete the old one.</li>'
            '</ol>'))
        trouble = ui.card("If something does not work", ui.table(["You see", "What it usually means", "What to do"], [
            ["AccessDenied or 403 when listing", "The key may not use that bucket, or it is read only and you tried to write", "On Access keys press Change permissions and tick the bucket or choose Read and write"],
            ["SignatureDoesNotMatch", "The secret was copied with a missing or extra character, or the clock on your computer is wrong", "Copy the secret again with the Copy button; if you lost it, create a new key"],
            ["InvalidAccessKeyId", "The access key ID is mistyped, or the key was deleted or expired", "Check the ID in the Access keys list; create a new key if it is gone"],
            ["Cannot connect, timeout or certificate error", "Wrong endpoint, or your network blocks it", "Use the endpoint exactly as shown here and ask your network team to allow it"],
            ["NoSuchBucket", "The bucket name is mistyped, or it is in another account", "Check the name on the Buckets page"],
        ]))
        use = ui.card("Connection details and test command", Raw(
            ui.kv([("Endpoint", Raw(f"<code>{esc(url)}</code>")), ("Region", region), ("Access key ID", Raw(f"<code>{esc(k['id'])}</code>")),
                   ("Addressing", "Path-style or virtual-hosted-style")]).__str__() +
            "<p>For the AWS command line, paste these four lines into a terminal. The last one lists your buckets and proves the key works.</p>"
            f'<pre class="log" id="snip">{esc(snippet)}</pre><p><button class="btn small" data-copy="snip" type="button">Copy</button></p>'
            "<p class='muted'>Other tools ask for the same four things: endpoint, region, access key ID and secret access key. "
            "Keep the secret in your application&#39;s secret store, not in source code.</p>"))
        return ui.page(ctx, "Access key created", Raw(top + todo + use + trouble), "/keys")

    # ------------------------------------------------------------------ add a key to an existing user, delete
    @app.route("customer", "POST", "/keys/create", perm="keys.manage", module="s3-access")
    def create(ctx):
        user = ctx.f("user")
        days = int(ctx.f("expiry")) if ctx.f("expiry") in dict(EXPIRY_CHOICES) else 90
        exp = iso(utcnow() + dt.timedelta(days=days)) if days else None
        k = app.backend.create_key(ctx.ref, user, exp)
        ctx.audit("key.create", user, f"{k['id']} expires={exp[:10] if exp else 'never'}")
        users = {u["username"]: u for u in app.backend.list_users(ctx.ref)}
        groups = {g["name"]: g for g in app.backend.list_groups(ctx.ref)}
        what, where = _summary(users[user], groups) if user in users else ("", "")
        access = "read-write" if what == "Read and write" else "read-only"
        scoped = [] if where == "All buckets" else [b.strip() for b in where.split(",") if b.strip()]
        return html_response(_created_page(ctx, user, k, access, scoped, exp))

    @app.route("customer", "POST", "/keys/delete", perm="keys.manage", module="s3-access", reauth=True)
    def delete(ctx):
        user = ctx.f("user")
        app.backend.delete_key(ctx.ref, user, ctx.f("key"))
        ctx.audit("key.delete", user, ctx.f("key"))
        msg = "Access key deleted."
        u = next((x for x in app.backend.list_users(ctx.ref) if x["username"] == user), None)
        if u and _own_group(u) and not app.backend.list_keys(ctx.ref, user) and ctx.can("access.edit"):
            app.backend.delete_user(ctx.ref, user)
            _quiet(lambda: app.backend.delete_group(ctx.ref, "key-" + user))
            ctx.audit("key.remove_all", user, "last key deleted: storage user and its group removed")
            msg = "Access key deleted, and its permissions were removed."
        ctx.flash(msg)
        return redirect("/keys")


def _quiet(fn):
    try:
        fn()
    except BackendError:
        pass
