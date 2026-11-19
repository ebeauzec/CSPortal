"""Server-side HTML toolkit. Everything is escaped unless wrapped in Raw. No external assets."""
from __future__ import annotations

import re

from .. import COPYRIGHT, PRODUCT, __version__
from ..util import esc
from .core import Raw

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def brand(app) -> dict:
    d = app.cfg.d["branding"]
    g = app.db.setting
    color = g("brand.color", d["color"])
    return {"name": g("brand.name", d["name"]), "product": g("brand.product", d["product"]),
            "color": color if _COLOR.match(color or "") else "#0b5fff",
            "support_email": g("brand.support_email", d["support_email"]),
            "support_url": g("brand.support_url", d["support_url"]),
            "legal": g("brand.legal", d["legal_text"])}


def brand_css(app) -> str:
    c = brand(app)["color"]
    return f":root{{--brand:{c};}}\n"


def _h(v) -> str:
    return v if isinstance(v, Raw) else esc(v)


# ------------------------------------------------------------------ building blocks
def badge(text: str, kind: str = "") -> Raw:
    return Raw(f'<span class="badge {esc(kind)}">{esc(text)}</span>')


def link(href: str, text: str, cls: str = "") -> Raw:
    return Raw(f'<a href="{esc(href)}"' + (f' class="{esc(cls)}"' if cls else "") + f">{esc(text)}</a>")


def table(headers: list, rows: list[list], empty: str = "Nothing to show yet.", cls: str = "") -> Raw:
    if not rows:
        return Raw(f'<p class="muted">{esc(empty)}</p>')
    th = "".join(f"<th>{_h(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{_h(c)}</td>" for c in r) + "</tr>" for r in rows)
    return Raw(f'<div class="tablewrap"><table class="{esc(cls)}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>')


def kv(pairs: list[tuple]) -> Raw:
    return Raw('<dl class="kv">' + "".join(f"<dt>{esc(k)}</dt><dd>{_h(v)}</dd>" for k, v in pairs) + "</dl>")


def card(title: str, body, cls: str = "", actions=None) -> Raw:
    act = f'<div class="card-actions">{_h(actions)}</div>' if actions else ""
    return Raw(f'<section class="card {esc(cls)}"><header><h2>{esc(title)}</h2>{act}</header>{_h(body)}</section>')


def meter(value: float, maximum: float, label: str = "") -> Raw:
    pct = 0 if not maximum else min(100, value / maximum * 100)
    kind = "ok" if pct < 70 else "warn" if pct < 90 else "bad"
    return Raw(f'<div class="meter {kind}"><progress max="100" value="{pct:.1f}"></progress>'
               f'<span>{esc(label or f"{pct:.0f}%")}</span></div>')


def stat(label: str, value: str, sub: str = "") -> Raw:
    return Raw(f'<div class="stat"><div class="stat-v">{esc(value)}</div><div class="stat-l">{esc(label)}</div>'
               + (f'<div class="stat-s">{esc(sub)}</div>' if sub else "") + "</div>")


def grid(*items, cols: int = 3) -> Raw:
    return Raw(f'<div class="grid c{cols}">' + "".join(_h(i) for i in items) + "</div>")


def button(label: str, action: str, csrf: str, fields: dict | None = None, cls: str = "", confirm: str = "") -> Raw:
    hid = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in (fields or {}).items())
    conf = f' data-confirm="{esc(confirm)}"' if confirm else ""
    return Raw(f'<form method="post" action="{esc(action)}" class="inline"><input type="hidden" name="_csrf" value="{esc(csrf)}">'
               f'{hid}<button class="btn {esc(cls)}"{conf}>{esc(label)}</button></form>')


def form(action: str, fields: list[dict], csrf: str, submit: str = "Save", cls: str = "", extra=None) -> Raw:
    out = [f'<form method="post" action="{esc(action)}" class="stack {esc(cls)}" autocomplete="off">',
           f'<input type="hidden" name="_csrf" value="{esc(csrf)}">']
    for f in fields:
        n, t = f["name"], f.get("type", "text")
        lab = f.get("label", n)
        req = " required" if f.get("required", True) and t != "checkbox" else ""
        help_ = f'<small class="muted">{esc(f["help"])}</small>' if f.get("help") else ""
        v = f.get("value", "")
        if t == "hidden":
            out.append(f'<input type="hidden" name="{esc(n)}" value="{esc(v)}">')
            continue
        if t == "select":
            opts = "".join(f'<option value="{esc(o[0])}"{" selected" if str(o[0]) == str(v) else ""}>{esc(o[1])}</option>'
                           for o in f["options"])
            ctl = f'<select name="{esc(n)}"{req}>{opts}</select>'
        elif t == "textarea":
            ctl = f'<textarea name="{esc(n)}" rows="{f.get("rows", 4)}"{req}>{esc(v)}</textarea>'
        elif t == "checkbox":
            ctl = (f'<label class="check"><input type="checkbox" name="{esc(n)}" value="1"{" checked" if v else ""}> '
                   f'{esc(lab)}</label>')
            out.append(f'<div class="field">{ctl}{help_}</div>')
            continue
        else:
            extra_attr = "".join(f' {k}="{esc(val)}"' for k, val in f.get("attrs", {}).items())
            ctl = f'<input type="{esc(t)}" name="{esc(n)}" value="{esc(v)}"{req}{extra_attr}' + \
                  (f' placeholder="{esc(f["placeholder"])}"' if f.get("placeholder") else "") + \
                  (' autocomplete="new-password"' if t == "password" else "") + ">"
        out.append(f'<div class="field"><label>{esc(lab)}{ctl}</label>{help_}</div>')
    if extra:
        out.append(_h(extra))
    out.append(f'<div class="actions"><button class="btn primary">{esc(submit)}</button></div></form>')
    return Raw("".join(out))


def line_chart(points: list[tuple[str, float]], unit: str = "", quota: float | None = None, width: int = 640, height: int = 220) -> Raw:
    """Server-drawn SVG line chart. No script, no external library."""
    if len(points) < 2:
        return Raw('<p class="muted">Not enough data for a chart yet.</p>')
    pad_l, pad_r, pad_t, pad_b = 54, 12, 14, 28
    vals = [p[1] for p in points] + ([quota] if quota else [])
    vmax = max(vals) * 1.08 or 1
    w, h = width - pad_l - pad_r, height - pad_t - pad_b
    xs = [pad_l + i * w / (len(points) - 1) for i in range(len(points))]
    ys = [pad_t + h - (p[1] / vmax) * h for p in points]
    path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(zip(xs, ys)))
    area = path + f" L{xs[-1]:.1f},{pad_t + h:.1f} L{xs[0]:.1f},{pad_t + h:.1f} Z"
    grid_lines = ""
    for i in range(5):
        gy = pad_t + h - i * h / 4
        grid_lines += (f'<line class="gl" x1="{pad_l}" x2="{width - pad_r}" y1="{gy:.1f}" y2="{gy:.1f}"/>'
                       f'<text class="ax" x="{pad_l - 6}" y="{gy + 4:.1f}" text-anchor="end">{vmax * i / 4:.0f}{esc(unit)}</text>')
    step = max(1, len(points) // 6)
    xl = "".join(f'<text class="ax" x="{xs[i]:.1f}" y="{height - 8}" text-anchor="middle">{esc(points[i][0])}</text>'
                 for i in range(0, len(points), step))
    q = ""
    if quota:
        qy = pad_t + h - (quota / vmax) * h
        q = (f'<line class="ql" x1="{pad_l}" x2="{width - pad_r}" y1="{qy:.1f}" y2="{qy:.1f}"/>'
             f'<text class="ax" x="{width - pad_r}" y="{qy - 4:.1f}" text-anchor="end">Quota</text>')
    desc = f"Line chart, {len(points)} points, from {points[0][1]:.0f} to {points[-1][1]:.0f} {unit}"
    return Raw(f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{esc(desc)}">{grid_lines}{q}'
               f'<path class="area" d="{area}"/><path class="ln" d="{path}"/>{xl}</svg>')


def bar_chart(items: list[tuple[str, float]], unit: str = "", width: int = 640) -> Raw:
    if not items:
        return Raw('<p class="muted">Nothing to chart yet.</p>')
    mx = max(v for _, v in items) or 1
    row_h = 26
    h = row_h * len(items) + 6
    rows = ""
    for i, (lab, v) in enumerate(items):
        y = i * row_h + 4
        bw = (width - 230) * v / mx
        rows += (f'<text class="ax" x="0" y="{y + 15}">{esc(lab[:26])}</text>'
                 f'<rect class="bar" x="170" y="{y + 3}" width="{bw:.1f}" height="14" rx="3"/>'
                 f'<text class="ax" x="{175 + bw:.1f}" y="{y + 15}">{v:,.1f}{esc(unit)}</text>')
    return Raw(f'<svg class="chart" viewBox="0 0 {width} {h}" role="img" aria-label="Bar chart">{rows}</svg>')


# ------------------------------------------------------------------ page shells
_ICON = '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">'


def bare_page(app, title: str, body: str, ctx=None) -> str:
    b = brand(app)
    demo = '<div class="demo-banner">DEMO MODE: simulated storage and sample data. No real systems are used.</div>' if app.cfg.demo else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} - {esc(b["name"])}</title>{_ICON}<link rel="stylesheet" href="/static/app.css">'
            f'<link rel="stylesheet" href="/brand.css"></head><body class="bare">{demo}<main class="narrow">{body}</main>'
            f'<footer class="foot">{esc(COPYRIGHT)}</footer><script src="/static/app.js" defer></script></body></html>')


def reauth_page(ctx, path: str, form_data: dict | None = None, error: str = "", nxt: str = "") -> str:
    """Ask for the password (and the code) again. The original form is carried along and replayed after success."""
    sess = ctx.sess
    keep = "".join(f'<input type="hidden" name="r_{esc(k)}" value="{esc(v)}">'
                   for k, v in (form_data or {}).items() if k != "_csrf")
    fields = [{"name": "password", "label": "Your password", "type": "password"}]
    if sess.mfa_enabled:
        fields.append({"name": "code", "label": "Code from your authenticator app",
                       "attrs": {"inputmode": "numeric", "maxlength": "6", "autocomplete": "one-time-code"}})
    err = f'<div class="flash bad" role="alert">{esc(error)}</div>' if error else ""
    extra = Raw(f'<input type="hidden" name="_replay_path" value="{esc(path if form_data is not None else "")}">'
                f'<input type="hidden" name="_next" value="{esc(nxt)}">{keep}')
    intro = Raw("<p>This action changes access or data. Confirm your identity to continue. Nothing has been changed yet.</p>"
                + form("/reauth", fields, sess.csrf, "Confirm and continue", extra=extra))
    return page(ctx, "Confirm it is you", Raw(err + str(card("Re-enter your credentials", intro))), "")


def page(ctx, title: str, body, active: str = "", actions=None) -> str:
    app, sess = ctx.app, ctx.sess
    b = brand(app)
    surface = ctx.req.surface
    nav_groups: dict[str, list] = {}
    for mid, m in app.modules.items():
        for n in m.get("nav", []):
            if n["surface"] != surface:
                continue
            if sess is None or n.get("perm") not in sess.perms:
                continue
            if surface == "customer" and ctx.customer and not app.customer_has_module(ctx.customer, mid):
                continue
            if surface == "admin" and not app.module_globally_on(mid):
                continue
            nav_groups.setdefault(n.get("group", ""), []).append(n)
    nav = ""
    for g in ["", "Storage", "Account", "Service", "Customers", "Finance", "Platform", "System"]:
        items = sorted(nav_groups.get(g, []), key=lambda n: n.get("order", 50))
        if not items:
            continue
        if g:
            nav += f'<div class="nav-g">{esc(g)}</div>'
        for n in items:
            cur = ' aria-current="page"' if n["path"] == active else ""
            nav += f'<a href="{esc(n["path"])}"{cur}>{esc(n["label"])}</a>'
    demo = ('<div class="demo-banner">DEMO MODE: simulated storage and sample data. No real systems are used.</div>'
            if app.cfg.demo else "")
    flash = ""
    if sess and sess.flash:
        kind = "bad" if sess.flash.startswith("Error") else "ok"
        flash = f'<div class="flash {kind}" role="status">{esc(sess.flash)}</div>'
    notices = ""
    if surface == "customer":
        from .. import services
        for n in services.active_notices(app):
            notices += f'<div class="notice {esc(n["kind"])}"><strong>{esc(n["title"])}</strong> {esc(n["body"] or "")}</div>'
    who = ""
    if sess:
        who = (f'<span class="who">{esc(sess.name)} <small>({esc(sess.role)})</small></span>'
               f'<form method="post" action="/logout" class="inline"><input type="hidden" name="_csrf" value="{esc(sess.csrf)}">'
               f'<button class="btn small">Sign out</button></form>')
    sub = b["product"] if surface == "customer" else "Administration"
    act = f'<div class="page-actions">{_h(actions)}</div>' if actions else ""
    legal = f'<span>{esc(b["legal"])}</span> ' if b["legal"] else ""
    support = f'<a href="mailto:{esc(b["support_email"])}">{esc(b["support_email"])}</a>' if b["support_email"] else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(title)} - {esc(b["name"])}</title>{_ICON}<link rel="stylesheet" href="/static/app.css">'
            f'<link rel="stylesheet" href="/brand.css"></head><body class="{esc(surface)}">'
            f'<a class="skip" href="#main">Skip to content</a>{demo}'
            f'<header class="top"><div class="brandname"><span class="logo"></span><strong>{esc(b["name"])}</strong>'
            f'<small>{esc(sub)}</small></div><div class="user">{who}</div></header>'
            f'<div class="shell"><nav class="side" aria-label="Main">{nav}</nav>'
            f'<main id="main"><div class="titlebar"><h1>{esc(title)}</h1>{act}</div>{flash}{notices}{_h(body)}</main></div>'
            f'<footer class="foot">{legal}{support} &middot; {esc(COPYRIGHT)} &middot; {esc(PRODUCT)} {esc(__version__)}</footer>'
            f'<script src="/static/app.js" defer></script></body></html>')
