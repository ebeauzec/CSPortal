"""UC3: bucket lifecycle, access, cross-origin rules and data-protection self-service."""
from __future__ import annotations

import re

from .. import policy, services
from ..backends import s3xml
from ..backends.base import BackendError
from ..util import esc, human_bytes, valid_bucket_name
from ..web import ui
from ..web.core import Raw, html_response, redirect

MODULE = {"id": "buckets", "name": "Buckets and data protection", "version": "1.2.0", "surfaces": ["customer"],
          "requires": [], "description": "Guided bucket creation; protect buckets: versioning, lifecycle, Object Lock, access policy, CORS.",
          "nav": [{"surface": "customer", "label": "Buckets", "path": "/buckets", "perm": "buckets.view", "group": "Storage", "order": 10}]}

_RULE_ID = re.compile(r"[^A-Za-z0-9_.-]")


def name_problem(n: str) -> tuple[str, str]:
    """(plain-words problem, suggested name) for a bucket name; ("", "") when the name is fine."""
    sug = re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9.-]", "-", n.strip().lower())).strip("-.")
    sug = sug.replace("..", ".")
    if len(n) < 3:
        return "A bucket name needs at least 3 characters.", ""
    if len(n) > 63:
        return "A bucket name can have at most 63 characters.", sug[:63]
    if n != n.lower():
        return "Use lowercase letters only.", sug
    if re.search(r"[^a-z0-9.-]", n):
        return "Use only lowercase letters, numbers, dots and hyphens. No spaces or underscores.", sug
    if not re.match(r"^[a-z0-9]", n) or not re.search(r"[a-z0-9]$", n):
        return "The name must start and end with a letter or number.", sug
    if ".." in n or re.match(r"^\d+\.\d+\.\d+\.\d+$", n):
        return "Two dots in a row, or a name that looks like an IP address, is not allowed.", sug
    return "", ""


_PURPOSE_HELP = {
    "keep-versions": ("Keep old versions (recommended)", "If a file is deleted or overwritten by mistake, you can get the earlier copy back."),
    "latest-only": ("Keep only the latest version", "Uses less space. A deleted or overwritten file cannot be recovered."),
    "locked": ("Lock objects so nobody can delete or change them", "For records that must be kept unchanged for a set time. This choice cannot be undone later."),
}


def _int(v: str, hi: int) -> int:
    return min(max(int(v), 1), hi) if v.strip().isdigit() else 0


def register(app):
    def _plan(ctx):
        return services.customer_plan(app, ctx.customer)

    def _back(name, section=""):
        return redirect(f"/buckets/{name}{section}")

    # ------------------------------------------------------------------ list, create
    @app.route("customer", "GET", "/buckets", perm="buckets.view", module="buckets")
    def list_(ctx):
        bs = app.backend.list_buckets(ctx.ref)
        plan = _plan(ctx)
        rows = []
        for b in bs:
            good = sum(1 for _, ok, _ in services.bucket_posture(b) if ok)
            access = ui.badge("public", "bad") if b["public"] else ui.badge("private", "ok") if b["public"] is False else "-"
            ver = ui.badge("versioned", "ok") if b["versioning"] == "enabled" else ui.badge("off", "warn") if b["versioning"] in ("off", "suspended") else "-"
            rows.append([ui.link(f"/buckets/{b['name']}", b["name"]), b["region"], human_bytes(b["bytes"]), f"{b['objects']:,}",
                         ver, ui.badge("locked", "ok") if b["object_lock"] else "-", access,
                         f"{good}/4" if b["versioning"] != "unknown" else "-"])
        tbl = ui.card("Your buckets", ui.table(["Name", "Region", "Size", "Objects", "Versioning", "Object Lock", "Access", "Protection"],
                                               rows, "No buckets yet."))
        fields = [{"name": "name", "label": "Bucket name", "help": "3-63 characters: lowercase letters, numbers, dots and hyphens. Must be unique across the service.",
                   "attrs": {"pattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", "maxlength": "63"}},
                  {"name": "region", "label": "Region", "type": "select", "options": [(r, r) for r in app.backend.endpoints(ctx.ref)["regions"]]},
                  {"name": "versioning", "label": "Keep old versions of objects (recommended)", "type": "checkbox", "value": True}]
        if plan["allow_object_lock"]:
            fields.append({"name": "object_lock", "label": "Enable Object Lock (cannot be changed later)", "type": "checkbox",
                           "help": "Protects objects from deletion or change for a retention period you choose."})
        create = ""
        if ctx.can("buckets.edit"):
            full = len(bs) >= plan["max_buckets"]
            create = ui.card(f"Create a bucket ({len(bs)} of {plan['max_buckets']} used)", Raw(
                "<p>A <strong>bucket</strong> is a top-level folder for your files. Creating one takes about a minute:</p>"
                '<ol class="howto"><li>Choose a name and a region.</li><li>Choose how the data is protected.</li>'
                "<li>Optionally let old data clean itself up.</li><li>Create an access key so an application can use the bucket.</li></ol>" +
                ("<p class='muted'>Your plan's bucket limit is reached. Delete an empty bucket or ask your provider for more.</p>" if full else
                 "<p>" + str(ui.link("/buckets/new", "Create a bucket", "btn primary")) + "</p>")))
        return ui.page(ctx, "Buckets", Raw((create if not bs else "") + tbl + (create if bs else "")), "/buckets")

    @app.route("customer", "POST", "/buckets", perm="buckets.edit", module="buckets")
    def create(ctx):
        name, plan = ctx.f("name").lower(), _plan(ctx)
        if not valid_bucket_name(name):
            ctx.flash("Error: That bucket name is not valid.")
            return redirect("/buckets")
        if len(app.backend.list_buckets(ctx.ref)) >= plan["max_buckets"]:
            ctx.flash(f"Error: Your plan allows {plan['max_buckets']} buckets.")
            return redirect("/buckets")
        lock = bool(ctx.f("object_lock")) and bool(plan["allow_object_lock"])
        app.backend.create_bucket(ctx.ref, name, ctx.f("region") or "us-east-1", bool(ctx.f("versioning")), lock)
        ctx.audit("bucket.create", name, f"versioning={bool(ctx.f('versioning')) or lock} lock={lock}")
        ctx.flash(f"Bucket {name} created.")
        return redirect(f"/buckets/{name}")

    # ------------------------------------------------------------------ guided creation
    _BEFORE = (
        "<p>You are about to create a <strong>bucket</strong>: a top-level folder that holds your files (objects). It takes about a minute.</p>"
        '<ol class="howto"><li>Answer the questions below. Nothing is created until you press <em>Create bucket</em>.</li>'
        "<li>The next page confirms what was created and lists what to do next, including how to give an application access.</li></ol>"
        '<p class="muted">Not sure? Keep the suggested choice: old versions kept. '
        "You can change versioning, clean-up and access rules later on the bucket's page. A bucket's name cannot be changed.</p>")

    def _new_form(ctx, v=None, error="", suggestion=""):
        v = v or {}
        plan = _plan(ctx)
        regions = app.backend.endpoints(ctx.ref)["regions"]
        purpose = v.get("purpose", "keep-versions")
        lock_ok = bool(plan["allow_object_lock"])

        def radio(val, checked, disabled=False):
            t, h = _PURPOSE_HELP[val]
            return (f'<label class="option"><input type="radio" name="purpose" value="{val}"{" checked" if checked else ""}{" disabled" if disabled else ""}> '
                    f'<span><strong>{esc(t)}</strong><small class="muted">{esc(h)}</small></span></label>')
        reg = (f'<div class="field"><label>Region<select name="region">' + "".join(
            f'<option value="{esc(r)}"{" selected" if r == v.get("region") else ""}>{esc(r)}</option>' for r in regions) + "</select></label>"
            "<small class='muted'>Where the data is stored. It cannot be changed later.</small></div>") if len(regions) > 1 else             f'<input type="hidden" name="region" value="{esc(regions[0])}"><p class="muted">Region: <strong>{esc(regions[0])}</strong> (the only one your service offers).</p>'
        err = ""
        if error:
            err = f'<div class="flash bad" role="alert">{esc(error)}' + (
                f' Try <strong>{esc(suggestion)}</strong>.' if suggestion else "") + "</div>"
        lock_block = ""
        if lock_ok:
            lock_block = ('<details class="indent"><summary>Settings for locking (only used if you choose to lock)</summary><div class="field"><label>Keep each object for<input type="number" name="lock_amount" min="1" max="36500" '
                          f'value="{esc(v.get("lock_amount", "365"))}"></label></div>'
                          '<div class="field"><label>Unit<select name="lock_unit"><option value="days">days</option><option value="years">years (up to 100)</option></select></label></div>'
                          '<div class="field"><label>Strictness<select name="lock_mode"><option value="GOVERNANCE">Standard: a user with special permission can still shorten it</option>'
                          '<option value="COMPLIANCE">Strict: nobody, not even the provider, can shorten or remove it</option></select></label></div>'
                          '<label class="check"><input type="checkbox" name="lock_ack" value="1"> I understand that strict retention cannot be shortened or removed</label></details>')
        else:
            lock_block = '<p class="muted indent">Locking is not part of your plan. Ask your provider if you need it.</p>'
        html = (f'{err}<form method="post" action="/buckets/new" class="stack steps" autocomplete="off">'
                f'<input type="hidden" name="_csrf" value="{esc(ctx.sess.csrf)}">'
                '<fieldset class="step"><legend><span class="n">1</span> Name and place</legend>'
                f'<div class="field"><label>Bucket name<input type="text" name="name" value="{esc(v.get("name", ""))}" required maxlength="63" placeholder="for example acme-backups-2026"></label>'
                '<small class="muted">3 to 63 characters: lowercase letters, numbers, dots and hyphens. It must be unique across the whole service and cannot be changed later.</small></div>'
                + reg + '</fieldset>'
                '<fieldset class="step"><legend><span class="n">2</span> How should the data be protected?</legend>'
                + radio("keep-versions", purpose == "keep-versions") + radio("latest-only", purpose == "latest-only")
                + radio("locked", purpose == "locked", disabled=not lock_ok) + lock_block + '</fieldset>'
                '<fieldset class="step"><legend><span class="n">3</span> Clean-up (optional)</legend>'
                f'<div class="field"><label>Delete objects automatically after (days)<input type="number" name="c_expire" min="1" max="36500" value="{esc(v.get("c_expire", ""))}"></label>'
                '<small class="muted">Leave empty to keep objects until you delete them. Not combined with locking.</small></div>'
                f'<div class="field"><label>Delete old versions after (days)<input type="number" name="c_old" min="1" max="36500" value="{esc(v.get("c_old", ""))}"></label>'
                '<small class="muted">Only for buckets that keep old versions. Leave empty to keep them.</small></div></fieldset>'
                '<fieldset class="step"><legend><span class="n">4</span> Who can use it?</legend>'
                '<p>Only you at first. A new bucket is <strong>private</strong>. In the next step you can create an access key for an application. '
                'Public access and finer rules are on the bucket\'s <em>Manage access</em> page later.</p></fieldset>'
                '<div class="actions"><button class="btn primary">Create bucket</button> <a class="btn" href="/buckets">Cancel</a></div></form>')
        return Raw(html)

    def _guided_page(ctx, v=None, error="", suggestion="", status=200):
        plan = _plan(ctx)
        n = len(app.backend.list_buckets(ctx.ref))
        body = ui.card("Before you start", Raw(_BEFORE)) + ui.card(f"Create a bucket ({n} of {plan['max_buckets']} used)", _new_form(ctx, v, error, suggestion))
        return html_response(ui.page(ctx, "Create a bucket", Raw(body), "/buckets", actions=ui.link("/buckets", "Back", "btn")), status)

    @app.route("customer", "GET", "/buckets/new", perm="buckets.edit", module="buckets")
    def new_form(ctx):
        return _guided_page(ctx)

    @app.route("customer", "POST", "/buckets/new", perm="buckets.edit", module="buckets")
    def new_post(ctx):
        plan = _plan(ctx)
        v = {k: ctx.f(k) for k in ("name", "region", "purpose", "lock_amount", "lock_unit", "lock_mode", "c_expire", "c_old")}
        name = v["name"]
        if v["purpose"] not in _PURPOSE_HELP:
            v["purpose"] = "keep-versions"
        purpose = v["purpose"]

        def fail(msg, sug=""):
            return _guided_page(ctx, v, msg, sug, 400)
        prob, sug = name_problem(name)
        if prob:
            return fail(prob, sug)
        if len(app.backend.list_buckets(ctx.ref)) >= plan["max_buckets"]:
            return fail(f"Your plan allows {plan['max_buckets']} buckets. Delete an empty bucket or ask your provider for more.")
        regions = app.backend.endpoints(ctx.ref)["regions"]
        region = v["region"] if v["region"] in regions else regions[0]
        lock = None
        if purpose == "locked":
            if not plan["allow_object_lock"]:
                return fail("Locking is not part of your plan.")
            lock = {"mode": v["lock_mode"] if v["lock_mode"] in ("GOVERNANCE", "COMPLIANCE") else "GOVERNANCE",
                    "amount": int(v["lock_amount"]) if v["lock_amount"].isdigit() else 0, "unit": "years" if v["lock_unit"] == "years" else "days"}
            bad = s3xml.lock_problems(lock)
            if bad:
                return fail(bad[0])
            if lock["mode"] == "COMPLIANCE" and not ctx.f("lock_ack"):
                return fail("Tick the box to confirm that strict retention cannot be shortened or removed.")
        versioning = purpose in ("keep-versions", "locked")
        rules = []
        exp, old = _int(v["c_expire"], 36500), _int(v["c_old"], 36500)
        if v["c_expire"].strip() and not exp or v["c_old"].strip() and not old:
            return fail("Enter whole numbers of days, or leave the clean-up fields empty.")
        if exp and lock:
            return fail("Automatic deletion cannot be combined with locking. Leave the clean-up days empty.")
        if exp:
            rules.append({"id": "auto-expire", "prefix": "", "expire_days": exp, "noncurrent_days": 0})
        if old and versioning:
            rules.append({"id": "old-versions", "prefix": "", "expire_days": 0, "noncurrent_days": old})
        elif old:
            return fail("Old versions are only kept when you choose to keep versions. Clear that field, or choose to keep old versions.")
        app.backend.create_bucket(ctx.ref, name, region, versioning, bool(lock))
        try:
            if lock:
                app.backend.update_bucket(ctx.ref, name, lock_default=lock)
            if rules:
                app.backend.update_bucket(ctx.ref, name, lifecycle=rules)
        except BackendError:
            try:                                                # the bucket is empty: do not leave a half-set-up one behind
                app.backend.delete_bucket(ctx.ref, name)
            except BackendError:
                pass
            raise
        ctx.audit("bucket.create", name, f"versioning={versioning} lock={lock['mode'] + ' ' + str(lock['amount']) + ' ' + lock['unit'] if lock else 'no'} "
                                         f"cleanup={','.join(r['id'] for r in rules) or 'none'}")
        return html_response(_created(ctx, name, region, purpose, lock, rules))

    def _created(ctx, name, region, purpose, lock, rules):
        ep = app.backend.endpoints(ctx.ref)
        url = (ep["s3"] or ["https://s3.example.net"])[0]
        prot = {"keep-versions": "Old versions are kept", "latest-only": "Only the latest version is kept", "locked": "Locked"}[purpose]
        if lock:
            prot += f": each object is kept {lock['amount']} {lock['unit']} ({'strict' if lock['mode'] == 'COMPLIANCE' else 'standard'})"
        names = {"auto-expire": "objects deleted automatically",
                 "old-versions": "old versions deleted automatically"}
        clean = ", ".join(names[r["id"]] for r in rules) or "none"
        done = ui.card(f"Bucket {name} is ready", ui.kv([("Name", Raw(f"<code>{esc(name)}</code>")), ("Region", region), ("Protection", prot),
                                                        ("Clean-up", clean), ("Who can use it", "Only you, for now (private)")]))
        key_btn = ui.link(f"/keys/new?bucket={name}", "Create an access key for this bucket", "btn primary") if ctx.can("access.edit") else ""
        todo = ui.card("What to do now", Raw(
            '<ol class="howto">'
            "<li><strong>Give an application access.</strong> Create an access key limited to this bucket. It takes a minute and the portal explains each step. "
            + (f"<br>{key_btn}" if key_btn else "Ask an administrator of your account to create one.") + "</li>"
            f"<li><strong>Test it.</strong> After you have a key, upload a small file with the AWS command line: <code>aws s3 cp hello.txt s3://{esc(name)}/ --endpoint-url {esc(url)}</code></li>"
            "<li><strong>Check the protection.</strong> Open the bucket to review versioning, clean-up rules and who has access.</li>"
            "<li><strong>Optional:</strong> let a website read it, or limit access to one folder, on the bucket's <em>Manage access</em> page.</li></ol>"
            f'<p>{ui.link(f"/buckets/{name}", "Open the bucket", "btn")} {ui.link("/buckets/new", "Create another bucket", "btn")}</p>'))
        trouble = ui.card("Good to know", ui.table(["Question", "Answer"], [
            ["Can I rename the bucket?", "No. Create a new bucket and copy the data across."],
            ["Can I change the protection later?", "Versioning and clean-up rules: yes, on the bucket's page. Locking can only be chosen when the bucket is created."],
            ["Is my data visible to anyone else?", "No. The bucket is private until you change its access rules."],
            ["How do I delete the bucket?", "Empty it first, then use Delete bucket on its page."]]))
        return ui.page(ctx, "Bucket created", Raw(done + todo + trouble), "/buckets")

    # ------------------------------------------------------------------ detail
    @app.route("customer", "GET", "/buckets/{name}", perm="buckets.view", module="buckets")
    def detail(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        n, csrf = b["name"], ctx.sess.csrf
        edit = ctx.can("buckets.edit")
        warn = "".join(f'<div class="notice">Could not read a setting: {esc(x)}</div>' for x in b.get("notes", []))
        posture = "".join(
            f'<li>{ui.badge("OK", "ok") if ok else ui.badge("Review", "warn")} <strong>{label}</strong>' +
            ("" if ok else f' <span class="muted">{advice}</span>') + "</li>"
            for label, ok, advice in services.bucket_posture(b))
        facts = ui.card("Bucket", ui.kv([("Name", b["name"]), ("Region", b["region"]), ("Created", b["created"][:10]),
                                         ("Size", human_bytes(b["bytes"])), ("Objects", f"{b['objects']:,}"),
                                         ("Consistency", b["consistency"])]))
        post = ui.card("Protection", Raw(f'<ul class="plain">{posture}</ul>'))
        # versioning
        vcard = ""
        if edit:
            if b["versioning"] == "enabled" and not b["object_lock"]:
                vcard = ui.button("Suspend versioning", f"/buckets/{n}/versioning", csrf, {"state": "suspended"},
                                  confirm="Suspend versioning? New changes will no longer keep old versions.")
            elif b["versioning"] in ("off", "suspended"):
                vcard = ui.button("Turn on versioning", f"/buckets/{n}/versioning", csrf, {"state": "enabled"}, "primary")
        vc = ui.card("Versioning", Raw(f"<p>Status: <strong>{b['versioning']}</strong>. Versioning keeps earlier copies of objects so you can "
                                       f"recover from accidental deletes and overwrites.</p>{vcard}"))
        # access summary
        rows = policy.describe(b.get("policy"), n, ctx.ref)
        summary = (f"<p>This bucket is <strong>{'public' if b['public'] else 'private' if b['public'] is False else 'of unknown access'}</strong>. "
                   f"{len(rows)} access rule{'s' if len(rows) != 1 else ''} in its policy"
                   f"{'; connections without encryption are refused' if policy.requires_tls(b.get('policy')) else ''}.</p>")
        ac = ui.card("Access", Raw(summary + ui.link(f"/buckets/{n}/access", "Manage access" if ctx.can("access.edit") else "View access", "btn primary" if ctx.can("access.edit") else "btn")))
        # lifecycle
        lrows = []
        for r in b["lifecycle"]:
            if r.get("custom"):
                desc = "custom rule set with the S3 API (kept as it is)"
            else:
                desc = ", ".join(x for x in [f"expire after {r['expire_days']} days" if r.get("expire_days") else "",
                                             f"delete old versions after {r['noncurrent_days']} days" if r.get("noncurrent_days") else ""] if x)
            lrows.append([r["id"], r.get("prefix") or "all objects", desc,
                          ui.button("Remove", f"/buckets/{n}/lifecycle/delete", csrf, {"rule": r["id"]}, "small danger",
                                    confirm="Remove this rule?") if edit else ""])
        lform = ui.form(f"/buckets/{n}/lifecycle", [
            {"name": "rule_id", "label": "Rule name", "attrs": {"maxlength": "40"}},
            {"name": "prefix", "label": "Applies to keys starting with", "required": False, "help": "Leave empty for every object."},
            {"name": "expire_days", "label": "Delete objects after (days)", "type": "number", "required": False, "attrs": {"min": "1", "max": "36500"}},
            {"name": "noncurrent_days", "label": "Delete old versions after (days)", "type": "number", "required": False, "attrs": {"min": "1", "max": "36500"}},
        ], csrf, "Add rule") if edit else ""
        lc = ui.card("Lifecycle rules", Raw(ui.table(["Rule", "Applies to", "Action", ""], lrows, "No rules. Objects are kept until you delete them.") + lform))
        # Object Lock
        ol = ui.card("Object Lock", Raw(_lock_body(ctx, b, edit)))
        # CORS
        cc = ui.card("Cross-origin access (CORS)", Raw(_cors_body(ctx, b, edit)))
        # delete
        dele = ""
        if ctx.can("buckets.delete"):
            dele = ui.card("Delete bucket", Raw("<p class='muted'>A bucket must be empty before it can be deleted.</p>" +
                           ui.button("Delete bucket", f"/buckets/{n}/delete", csrf, {}, "danger",
                                     confirm=f"Delete bucket {n}? This cannot be undone.")))
        return ui.page(ctx, n, Raw(warn + ui.grid(facts, post, cols=2) + ui.grid(vc, ac, cols=2) + lc + ol + cc + dele),
                       "/buckets", actions=ui.link("/buckets", "All buckets", "btn"))

    def _lock_body(ctx, b, edit):
        n = b["name"]
        if not b["object_lock"]:
            return "<p>Not enabled. Object Lock can only be chosen when a bucket is created.</p>"
        d = b.get("lock_default")
        cur = (f"<p>Default retention: <strong>{esc(d['mode'].lower())}</strong> for <strong>{d['amount']} {esc(d['unit'])}</strong> "
               f"on every new object. Applications can set a longer period on single objects with the S3 API.</p>") if d else \
              "<p>No default retention. Objects are protected only when an application sets a retention period on them.</p>"
        info = ("<p class='muted'><strong>Governance</strong>: users with special permission can still shorten or remove the lock. "
                "<strong>Compliance</strong>: nobody, including the service provider, can delete or change an object until its retention ends.</p>")
        if not edit:
            return cur + info
        form = ui.form(f"/buckets/{n}/lock", [
            {"name": "mode", "label": "Mode", "type": "select", "value": (d or {}).get("mode", "GOVERNANCE"),
             "options": [("GOVERNANCE", "Governance"), ("COMPLIANCE", "Compliance (cannot be undone)")]},
            {"name": "amount", "label": "Keep each new object for", "type": "number", "value": (d or {}).get("amount", 30), "attrs": {"min": "1", "max": "36500"}},
            {"name": "unit", "label": "Unit", "type": "select", "value": (d or {}).get("unit", "days"), "options": [("days", "days"), ("years", "years (up to 100)")]},
            {"name": "ack", "label": "I understand that compliance retention cannot be shortened or removed", "type": "checkbox",
             "help": "Needed only for compliance mode."}], ctx.sess.csrf, "Save default retention")
        clear = ui.button("Remove default retention", f"/buckets/{n}/lock/clear", ctx.sess.csrf, {}, "small",
                          confirm="Stop applying a default retention to new objects? Objects already locked stay locked.") if d else ""
        return cur + info + form + clear

    def _cors_body(ctx, b, edit):
        n = b["name"]
        rows = [[", ".join(r["origins"]), ", ".join(r["methods"]), ", ".join(r["headers"]) or "-", r.get("max_age") or "-",
                 ui.button("Remove", f"/buckets/{n}/cors/delete", ctx.sess.csrf, {"index": str(i)}, "small danger", confirm="Remove this rule?") if edit else ""]
                for i, r in enumerate(b.get("cors", []))]
        t = ui.table(["Allowed origins", "Methods", "Allowed headers", "Max age (s)", ""], rows,
                     "No rules. Browsers on other websites cannot read this bucket.")
        if not edit:
            return t
        meth = "".join(f'<label class="check"><input type="checkbox" name="m_{m}" value="1"{" checked" if m == "GET" else ""}> {m}</label>'
                       for m in s3xml.CORS_METHODS)
        form = ui.form(f"/buckets/{n}/cors", [
            {"name": "origins", "label": "Allowed origins (one per line)", "type": "textarea", "attrs": {}, "help": "For example https://app.example.com. Avoid * unless the content is public."},
            {"name": "headers", "label": "Allowed request headers (comma separated)", "required": False, "help": "For example Content-Type, Authorization. Leave empty for none."},
            {"name": "max_age", "label": "Browsers may cache the answer for (seconds)", "type": "number", "required": False, "attrs": {"min": "0", "max": "86400"}}],
            ctx.sess.csrf, "Add rule", extra=Raw(f'<div class="field"><strong>Methods</strong>{meth}</div>'))
        return t + form

    # ------------------------------------------------------------------ simple settings
    @app.route("customer", "POST", "/buckets/{name}/versioning", perm="buckets.edit", module="buckets")
    def versioning(ctx):
        state = "enabled" if ctx.f("state") == "enabled" else "suspended"
        app.backend.update_bucket(ctx.ref, ctx.params["name"], versioning=state)
        ctx.audit("bucket.versioning", ctx.params["name"], state)
        ctx.flash(f"Versioning {state}.")
        return _back(ctx.params["name"])

    @app.route("customer", "POST", "/buckets/{name}/public", perm="access.edit", module="buckets", reauth=True)
    def public(ctx):
        want = ctx.f("public") == "1"
        name = ctx.params["name"]
        if want and not _plan(ctx)["allow_public_buckets"]:
            ctx.flash("Error: Public buckets are not part of your plan.")
            return _back(name, "/access")
        app.backend.update_bucket(ctx.ref, name, public=want)
        ctx.audit("bucket.public" if want else "bucket.private", name)
        ctx.flash("Bucket is now public." if want else "Bucket is now private.")
        return _back(name, "/access")

    @app.route("customer", "POST", "/buckets/{name}/lifecycle", perm="buckets.edit", module="buckets")
    def lifecycle_add(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        rid = _RULE_ID.sub("-", ctx.f("rule_id"))[:40]
        rule = {"id": rid, "prefix": ctx.f("prefix")[:200], "expire_days": _int(ctx.f("expire_days"), 36500),
                "noncurrent_days": _int(ctx.f("noncurrent_days"), 36500)}
        if not rid or not (rule["expire_days"] or rule["noncurrent_days"]):
            ctx.flash("Error: Give the rule a name and at least one action.")
            return _back(b["name"])
        rules = [r for r in b["lifecycle"] if r["id"] != rid] + [rule]
        app.backend.update_bucket(ctx.ref, b["name"], lifecycle=rules)
        ctx.audit("bucket.lifecycle_add", b["name"], rid)
        ctx.flash("Lifecycle rule saved.")
        return _back(b["name"])

    @app.route("customer", "POST", "/buckets/{name}/lifecycle/delete", perm="buckets.edit", module="buckets")
    def lifecycle_del(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        app.backend.update_bucket(ctx.ref, b["name"], lifecycle=[r for r in b["lifecycle"] if r["id"] != ctx.f("rule")])
        ctx.audit("bucket.lifecycle_remove", b["name"], ctx.f("rule"))
        ctx.flash("Rule removed.")
        return _back(b["name"])

    # ------------------------------------------------------------------ Object Lock default retention
    @app.route("customer", "POST", "/buckets/{name}/lock", perm="buckets.edit", module="buckets", reauth=True)
    def lock_set(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        d = {"mode": ctx.f("mode"), "amount": int(ctx.f("amount")) if ctx.f("amount").isdigit() else 0,
             "unit": "years" if ctx.f("unit") == "years" else "days"}
        bad = s3xml.lock_problems(d)
        if not b["object_lock"]:
            bad = ["Object Lock is not enabled on this bucket."]
        elif d["mode"] == "COMPLIANCE" and not ctx.f("ack"):
            bad = ["Tick the box to confirm that compliance retention cannot be shortened or removed."]
        if bad:
            ctx.flash("Error: " + bad[0])
            return _back(name)
        app.backend.update_bucket(ctx.ref, name, lock_default=d)
        ctx.audit("bucket.lock_default", name, f"{d['mode']} {d['amount']} {d['unit']}")
        ctx.flash("Default retention saved. It applies to objects written from now on.")
        return _back(name)

    @app.route("customer", "POST", "/buckets/{name}/lock/clear", perm="buckets.edit", module="buckets")
    def lock_clear(ctx):
        name = ctx.params["name"]
        app.backend.update_bucket(ctx.ref, name, lock_default=None)
        ctx.audit("bucket.lock_default_clear", name)
        ctx.flash("Default retention removed.")
        return _back(name)

    # ------------------------------------------------------------------ CORS
    @app.route("customer", "POST", "/buckets/{name}/cors", perm="buckets.edit", module="buckets")
    def cors_add(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        rule = {"id": "", "origins": [o.strip() for o in ctx.f("origins").replace(",", "\n").splitlines() if o.strip()],
                "methods": [m for m in s3xml.CORS_METHODS if ctx.f("m_" + m)],
                "headers": [h.strip() for h in ctx.f("headers").split(",") if h.strip()], "expose": [],
                "max_age": int(ctx.f("max_age")) if ctx.f("max_age").isdigit() else 0}
        bad = s3xml.cors_problems(rule)
        if len(b.get("cors", [])) >= 20:
            bad.append("A bucket may have at most 20 CORS rules.")
        if bad:
            ctx.flash("Error: " + bad[0])
            return _back(name)
        app.backend.update_bucket(ctx.ref, name, cors=list(b.get("cors", [])) + [rule])
        ctx.audit("bucket.cors_add", name, ", ".join(rule["origins"])[:200])
        ctx.flash("CORS rule added.")
        return _back(name)

    @app.route("customer", "POST", "/buckets/{name}/cors/delete", perm="buckets.edit", module="buckets")
    def cors_del(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        rules = list(b.get("cors", []))
        i = int(ctx.f("index")) if ctx.f("index").isdigit() else -1
        if 0 <= i < len(rules):
            gone = rules.pop(i)
            app.backend.update_bucket(ctx.ref, name, cors=rules)
            ctx.audit("bucket.cors_remove", name, ", ".join(gone["origins"])[:200])
            ctx.flash("CORS rule removed.")
        return _back(name)

    # ------------------------------------------------------------------ access policy
    def _access_page(ctx, name, text=None, errors=None, status=200):
        b = app.backend.get_bucket(ctx.ref, name)
        plan, edit, csrf = _plan(ctx), ctx.can("access.edit"), ctx.sess.csrf
        doc = b.get("policy")
        rows = []
        for r in policy.describe(doc, name, ctx.ref):
            who = Raw(esc(r["who"]) + (' <span class="badge bad">public</span>' if r["public"] else ""))
            if not edit:
                act = ""
            elif r["gid"]:
                act = ui.button("Remove", f"/buckets/{name}/access/revoke", csrf, {"gid": r["gid"]}, "small danger", confirm="Remove this grant?")
            else:
                act = ui.button("Remove", f"/buckets/{name}/access/revoke", csrf, {"index": str(r["index"]), "sid": r["sid"]}, "small danger",
                                confirm="Remove this statement from the policy?")
            rows.append([r["kind"], r["effect"], who, r["what"] + (" (with conditions)" if r["conditions"] else ""), r["scope"], Raw(act)])
        table = ui.table(["Rule", "Effect", "Who", "What", "Where", ""], rows,
                         "No access rules. Only the storage users whose groups allow it can use this bucket.")
        users = app.backend.list_users(ctx.ref)
        groups = app.backend.list_groups(ctx.ref)
        opts = [("account:", "Everyone in this storage account")] + [(f"group:{g['name']}", f"Group {g['name']}") for g in groups] + \
               [(f"user:{u['username']}", f"User {u['username']}") for u in users]
        grant = ui.card("Give access to a user or group", ui.form(f"/buckets/{name}/access/grant", [
            {"name": "who", "label": "Who", "type": "select", "options": opts},
            {"name": "level", "label": "What they may do", "type": "select",
             "options": [(k, v[0]) for k, v in policy.LEVELS.items()]},
            {"name": "prefix", "label": "Only inside this folder (optional)", "required": False,
             "help": "A key prefix such as reports/2026/. Leave empty for the whole bucket."}], csrf, "Add access")) if edit else ""
        state = []
        if edit:
            if b["public"]:
                state.append(ui.button("Make private", f"/buckets/{name}/public", csrf, {"public": "0"}, "primary"))
            elif plan["allow_public_buckets"]:
                state.append(ui.button("Allow public read", f"/buckets/{name}/public", csrf, {"public": "1"}, "danger",
                                       confirm="Anyone on the internet will be able to read every object in this bucket. Continue?"))
            tls = policy.requires_tls(doc)
            state.append(ui.button("Allow unencrypted connections" if tls else "Require encrypted connections (HTTPS)",
                                   f"/buckets/{name}/access/tls", csrf, {"on": "0" if tls else "1"}, "" if tls else "primary"))
        pub_note = "" if plan["allow_public_buckets"] else "<p class='muted'>Public buckets are not part of your plan.</p>"
        status_card = ui.card("Status", Raw(
            f"<p>Public access: <strong>{'on' if b['public'] else 'off' if b['public'] is False else 'unknown'}</strong>. "
            f"Encrypted connections only: <strong>{'yes' if policy.requires_tls(doc) else 'no'}</strong>.</p>{pub_note}" + " ".join(state)))
        err = ""
        if errors:
            err = '<div class="flash bad" role="alert"><strong>The policy was not saved:</strong><ul class="plain">' + \
                  "".join(f"<li>{esc(e)}</li>" for e in errors) + "</ul></div>"
        sample = text if text is not None else (policy.dump(doc) if doc else policy.dump(policy.empty()))
        adv = ui.card("Advanced: edit the policy", Raw(
            err + "<p class='muted'>The policy is the S3 bucket policy as stored by the storage service. Only this bucket, this storage account and, "
                  "if your plan allows it, read-only public access are accepted. Conditions are limited to aws:SecureTransport, aws:SourceIp and s3:prefix.</p>" +
            (ui.form(f"/buckets/{name}/access/policy", [{"name": "policy", "label": "Policy (JSON)", "type": "textarea", "rows": 14, "value": sample}],
                     csrf, "Validate and save") if edit else f"<pre class='log'>{esc(sample)}</pre>")))
        body = Raw(status_card + ui.card("Access rules", Raw(table)) + grant + adv)
        out = ui.page(ctx, f"Access: {name}", body, "/buckets", actions=ui.link(f"/buckets/{name}", "Back to bucket", "btn"))
        return html_response(out, status) if status != 200 else out

    @app.route("customer", "GET", "/buckets/{name}/access", perm="buckets.view", module="buckets")
    def access(ctx):
        return _access_page(ctx, ctx.params["name"])

    def _principal(ctx, token):
        kind, _, nm = token.partition(":")
        if kind == "account":
            return policy.principal_arn(ctx.ref, "root")
        if kind == "user" and nm in [u["username"] for u in app.backend.list_users(ctx.ref)]:
            return policy.principal_arn(ctx.ref, "user", nm)
        if kind == "group" and nm in [g["name"] for g in app.backend.list_groups(ctx.ref)]:
            return policy.principal_arn(ctx.ref, "group", nm)
        return ""

    @app.route("customer", "POST", "/buckets/{name}/access/grant", perm="access.edit", module="buckets")
    def grant(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        arn = _principal(ctx, ctx.f("who"))
        if not arn or ctx.f("level") not in policy.LEVELS:
            ctx.flash("Error: Choose who gets access and what they may do.")
            return _back(name, "/access")
        new, gid = policy.add_grant(b.get("policy"), name, [arn], ctx.f("level"), ctx.f("prefix"))
        added = {"Version": "2012-10-17", "Statement": [s for s in new["Statement"] if str(s.get("Sid", "")).startswith(policy.SID_GRANT + gid)]}
        bad = policy.validate(added, name, ctx.ref, _plan(ctx)["allow_public_buckets"])
        if not bad and len(policy.dump(new).encode()) > policy.MAX_BYTES:
            bad = ["The policy would become larger than the storage service allows. Remove a rule first."]
        if bad:
            ctx.flash("Error: " + bad[0])
            return _back(name, "/access")
        app.backend.update_bucket(ctx.ref, name, policy=new)
        ctx.audit("bucket.access_grant", name, f"{ctx.f('who') or 'account'} {ctx.f('level')} prefix={policy.clean_prefix(ctx.f('prefix')) or '-'}")
        ctx.flash("Access added.")
        return _back(name, "/access")

    @app.route("customer", "POST", "/buckets/{name}/access/revoke", perm="access.edit", module="buckets")
    def revoke(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        doc = b.get("policy")
        if ctx.f("gid"):
            new, what = policy.remove_grant(doc, ctx.f("gid")), "grant " + ctx.f("gid")
        else:
            i = int(ctx.f("index")) if ctx.f("index").isdigit() else -1
            sts = policy.statements(doc)
            if not (0 <= i < len(sts)) or (sts[i].get("Sid") or "") != ctx.f("sid"):
                ctx.flash("Error: The policy changed in the meantime. Review it and try again.")
                return _back(name, "/access")
            new, what = policy.remove_statement(doc, i), "statement " + (ctx.f("sid") or str(i))
        app.backend.update_bucket(ctx.ref, name, policy=new)
        ctx.audit("bucket.access_revoke", name, what)
        ctx.flash("Access removed.")
        return _back(name, "/access")

    @app.route("customer", "POST", "/buckets/{name}/access/tls", perm="access.edit", module="buckets")
    def tls(ctx):
        name = ctx.params["name"]
        b = app.backend.get_bucket(ctx.ref, name)
        on = ctx.f("on") == "1"
        app.backend.update_bucket(ctx.ref, name, policy=policy.set_tls_only(b.get("policy"), name, on))
        ctx.audit("bucket.require_tls" if on else "bucket.allow_plain", name)
        ctx.flash("Unencrypted connections are now refused." if on else "Unencrypted connections are allowed again.")
        return _back(name, "/access")

    @app.route("customer", "POST", "/buckets/{name}/access/policy", perm="access.edit", module="buckets", reauth=True)
    def policy_save(ctx):
        name = ctx.params["name"]
        text = ctx.f("policy")
        doc, bad = policy.parse(text)
        if doc is not None:
            bad = policy.validate(doc, name, ctx.ref, _plan(ctx)["allow_public_buckets"])
        if bad:
            return _access_page(ctx, name, text=text, errors=bad, status=400)
        app.backend.update_bucket(ctx.ref, name, policy=doc)
        ctx.audit("bucket.policy_set", name, f"{len(policy.statements(doc))} statements")
        ctx.flash("Policy saved.")
        return _back(name, "/access")

    @app.route("customer", "POST", "/buckets/{name}/delete", perm="buckets.delete", module="buckets", reauth=True)
    def delete(ctx):
        app.backend.delete_bucket(ctx.ref, ctx.params["name"])
        ctx.audit("bucket.delete", ctx.params["name"])
        ctx.flash(f"Bucket {ctx.params['name']} deleted.")
        return redirect("/buckets")
