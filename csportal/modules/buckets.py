"""UC3: bucket lifecycle and data-protection self-service."""
from __future__ import annotations

import re

from .. import services
from ..util import human_bytes, valid_bucket_name
from ..web import ui
from ..web.core import Raw, redirect
from ..backends.base import BackendError

MODULE = {"id": "buckets", "name": "Buckets and data protection", "version": "1.0.0", "surfaces": ["customer"],
          "requires": [], "description": "Create and protect buckets: versioning, lifecycle, Object Lock, access.",
          "nav": [{"surface": "customer", "label": "Buckets", "path": "/buckets", "perm": "buckets.view", "group": "Storage", "order": 10}]}


def register(app):
    def _plan(ctx):
        return services.customer_plan(app, ctx.customer)

    @app.route("customer", "GET", "/buckets", perm="buckets.view", module="buckets")
    def list_(ctx):
        bs = app.backend.list_buckets(ctx.ref)
        plan = _plan(ctx)
        rows = []
        for b in bs:
            good = sum(1 for _, ok, _ in services.bucket_posture(b) if ok)
            rows.append([ui.link(f"/buckets/{b['name']}", b["name"]), b["region"], human_bytes(b["bytes"]), f"{b['objects']:,}",
                         ui.badge("versioned", "ok") if b["versioning"] == "enabled" else ui.badge("off", "warn"),
                         ui.badge("locked", "ok") if b["object_lock"] else "-",
                         ui.badge("public", "bad") if b["public"] else ui.badge("private", "ok"),
                         f"{good}/4"])
        tbl = ui.card("Your buckets", ui.table(["Name", "Region", "Size", "Objects", "Versioning", "Object Lock", "Access", "Protection"],
                                               rows, "No buckets yet."))
        fields = [{"name": "name", "label": "Bucket name", "help": "3-63 characters: lowercase letters, numbers, dots and hyphens. Must be unique across the service.",
                   "attrs": {"pattern": "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", "maxlength": "63"}},
                  {"name": "region", "label": "Region", "type": "select", "options": [(r, r) for r in app.backend.endpoints(ctx.ref)["regions"]]},
                  {"name": "versioning", "label": "Keep old versions of objects (recommended)", "type": "checkbox", "value": True}]
        if plan["allow_object_lock"]:
            fields.append({"name": "object_lock", "label": "Enable Object Lock (cannot be changed later)", "type": "checkbox",
                           "help": "Protects objects from deletion or change for a retention period you choose."})
        create = ui.card(f"Create a bucket ({len(bs)} of {plan['max_buckets']} used)",
                         ui.form("/buckets", fields, ctx.sess.csrf, "Create bucket")) if ctx.can("buckets.edit") else ""
        return ui.page(ctx, "Buckets", Raw(tbl + create), "/buckets")

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

    @app.route("customer", "GET", "/buckets/{name}", perm="buckets.view", module="buckets")
    def detail(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        plan = _plan(ctx)
        edit = ctx.can("buckets.edit")
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
                vcard = ui.button("Suspend versioning", f"/buckets/{b['name']}/versioning", ctx.sess.csrf, {"state": "suspended"},
                                  confirm="Suspend versioning? New changes will no longer keep old versions.")
            elif b["versioning"] in ("off", "suspended"):
                vcard = ui.button("Turn on versioning", f"/buckets/{b['name']}/versioning", ctx.sess.csrf, {"state": "enabled"}, "primary")
        vc = ui.card("Versioning", Raw(f"<p>Status: <strong>{b['versioning']}</strong>. Versioning keeps earlier copies of objects so you can "
                                       f"recover from accidental deletes and overwrites.</p>{vcard}"))
        # access
        acc = ""
        if edit:
            if b["public"]:
                acc = ui.button("Make private", f"/buckets/{b['name']}/public", ctx.sess.csrf, {"public": "0"}, "primary")
            elif plan["allow_public_buckets"]:
                acc = ui.button("Allow public read", f"/buckets/{b['name']}/public", ctx.sess.csrf, {"public": "1"}, "danger",
                                confirm="Anyone on the internet will be able to read every object in this bucket. Continue?")
            else:
                acc = '<p class="muted">Public buckets are not part of your plan.</p>'
        ac = ui.card("Access", Raw(f"<p>This bucket is <strong>{'public' if b['public'] else 'private'}</strong>.</p>{acc}"))
        # lifecycle
        lrows = []
        for i, r in enumerate(b["lifecycle"]):
            desc = ", ".join(x for x in [f"expire after {r['expire_days']} days" if r.get("expire_days") else "",
                                         f"delete old versions after {r['noncurrent_days']} days" if r.get("noncurrent_days") else "",
                                         f"clean incomplete uploads after {r['abort_multipart_days']} days" if r.get("abort_multipart_days") else ""] if x)
            lrows.append([r["id"], r.get("prefix") or "all objects", desc,
                          ui.button("Remove", f"/buckets/{b['name']}/lifecycle/delete", ctx.sess.csrf, {"rule": r["id"]}, "small danger",
                                    confirm="Remove this rule?") if edit else ""])
        lform = ui.form(f"/buckets/{b['name']}/lifecycle", [
            {"name": "rule_id", "label": "Rule name", "attrs": {"maxlength": "40"}},
            {"name": "prefix", "label": "Applies to keys starting with", "required": False, "help": "Leave empty for every object."},
            {"name": "expire_days", "label": "Delete objects after (days)", "type": "number", "required": False, "attrs": {"min": "1", "max": "36500"}},
            {"name": "noncurrent_days", "label": "Delete old versions after (days)", "type": "number", "required": False, "attrs": {"min": "1", "max": "36500"}},
            {"name": "abort_multipart_days", "label": "Clean incomplete uploads after (days)", "type": "number", "required": False, "attrs": {"min": "1", "max": "365"}},
        ], ctx.sess.csrf, "Add rule") if edit else ""
        lc = ui.card("Lifecycle rules", Raw(ui.table(["Rule", "Applies to", "Action", ""], lrows, "No rules. Objects are kept until you delete them.") + lform))
        # Object Lock
        ol = ui.card("Object Lock", Raw("<p>" + ("Enabled on this bucket. Objects can be protected from deletion or change for a retention period "
                                                  "set by your applications with the S3 API." if b["object_lock"] else
                                                  "Not enabled. Object Lock can only be chosen when a bucket is created.") + "</p>"))
        # delete
        dele = ""
        if ctx.can("buckets.delete"):
            dele = ui.card("Delete bucket", Raw("<p class='muted'>A bucket must be empty before it can be deleted.</p>" +
                           ui.button("Delete bucket", f"/buckets/{b['name']}/delete", ctx.sess.csrf, {}, "danger",
                                     confirm=f"Delete bucket {b['name']}? This cannot be undone.")))
        return ui.page(ctx, b["name"], Raw(ui.grid(facts, post, cols=2) + ui.grid(vc, ac, cols=2) + lc + ol + dele),
                       "/buckets", actions=ui.link("/buckets", "All buckets", "btn"))

    @app.route("customer", "POST", "/buckets/{name}/versioning", perm="buckets.edit", module="buckets")
    def versioning(ctx):
        state = "enabled" if ctx.f("state") == "enabled" else "suspended"
        app.backend.update_bucket(ctx.ref, ctx.params["name"], versioning=state)
        ctx.audit("bucket.versioning", ctx.params["name"], state)
        ctx.flash(f"Versioning {state}.")
        return redirect(f"/buckets/{ctx.params['name']}")

    @app.route("customer", "POST", "/buckets/{name}/public", perm="buckets.edit", module="buckets")
    def public(ctx):
        want = ctx.f("public") == "1"
        if want and not _plan(ctx)["allow_public_buckets"]:
            ctx.flash("Error: Public buckets are not part of your plan.")
            return redirect(f"/buckets/{ctx.params['name']}")
        app.backend.update_bucket(ctx.ref, ctx.params["name"], public=want)
        ctx.audit("bucket.public" if want else "bucket.private", ctx.params["name"])
        ctx.flash("Bucket is now public." if want else "Bucket is now private.")
        return redirect(f"/buckets/{ctx.params['name']}")

    def _int(v: str, hi: int) -> int:
        return min(max(int(v), 1), hi) if v.strip().isdigit() else 0

    @app.route("customer", "POST", "/buckets/{name}/lifecycle", perm="buckets.edit", module="buckets")
    def lifecycle_add(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        rid = re.sub(r"[^A-Za-z0-9_.-]", "-", ctx.f("rule_id"))[:40]
        rule = {"id": rid, "prefix": ctx.f("prefix")[:200], "expire_days": _int(ctx.f("expire_days"), 36500),
                "noncurrent_days": _int(ctx.f("noncurrent_days"), 36500), "abort_multipart_days": _int(ctx.f("abort_multipart_days"), 365)}
        if not rid or not (rule["expire_days"] or rule["noncurrent_days"] or rule["abort_multipart_days"]):
            ctx.flash("Error: Give the rule a name and at least one action.")
            return redirect(f"/buckets/{b['name']}")
        rules = [r for r in b["lifecycle"] if r["id"] != rid] + [rule]
        app.backend.update_bucket(ctx.ref, b["name"], lifecycle=rules)
        ctx.audit("bucket.lifecycle_add", b["name"], rid)
        ctx.flash("Lifecycle rule saved.")
        return redirect(f"/buckets/{b['name']}")

    @app.route("customer", "POST", "/buckets/{name}/lifecycle/delete", perm="buckets.edit", module="buckets")
    def lifecycle_del(ctx):
        b = app.backend.get_bucket(ctx.ref, ctx.params["name"])
        app.backend.update_bucket(ctx.ref, b["name"], lifecycle=[r for r in b["lifecycle"] if r["id"] != ctx.f("rule")])
        ctx.audit("bucket.lifecycle_remove", b["name"], ctx.f("rule"))
        ctx.flash("Rule removed.")
        return redirect(f"/buckets/{b['name']}")

    @app.route("customer", "POST", "/buckets/{name}/delete", perm="buckets.delete", module="buckets")
    def delete(ctx):
        app.backend.delete_bucket(ctx.ref, ctx.params["name"])
        ctx.audit("bucket.delete", ctx.params["name"])
        ctx.flash(f"Bucket {ctx.params['name']} deleted.")
        return redirect("/buckets")
