"""XML bodies for the S3 bucket settings the portal manages: versioning, lifecycle, CORS, Object Lock.

Rules the portal can not describe (tags, transitions, date-based expiry, other filters) are kept as the
original XML in a `raw` member and written back unchanged, so saving a change never removes them.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def esc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _strip(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def parse(raw: bytes) -> ET.Element | None:
    try:
        return _strip(ET.fromstring(raw))
    except ET.ParseError:
        return None


def _t(el: ET.Element | None, name: str) -> str:
    x = el.find(name) if el is not None else None
    return (x.text or "").strip() if x is not None else ""


# ------------------------------------------------------------------ versioning
def versioning_xml(state: str) -> bytes:
    st = "Enabled" if state == "enabled" else "Suspended"
    return f'<VersioningConfiguration xmlns="{NS}"><Status>{st}</Status></VersioningConfiguration>'.encode()


def versioning_from(raw: bytes) -> str:
    r = parse(raw)
    return {"Enabled": "enabled", "Suspended": "suspended"}.get(_t(r, "Status"), "off") if r is not None else "unknown"


# ------------------------------------------------------------------ lifecycle
def lifecycle_xml(rules: list[dict]) -> bytes:
    out = []
    for r in rules:
        if r.get("raw"):
            out.append(r["raw"])
            continue
        x = f"<Rule><ID>{esc(r['id'])}</ID><Filter><Prefix>{esc(r.get('prefix', ''))}</Prefix></Filter><Status>Enabled</Status>"
        if r.get("expire_days"):
            x += f"<Expiration><Days>{int(r['expire_days'])}</Days></Expiration>"
        if r.get("noncurrent_days"):
            x += f"<NoncurrentVersionExpiration><NoncurrentDays>{int(r['noncurrent_days'])}</NoncurrentDays></NoncurrentVersionExpiration>"
        if r.get("abort_multipart_days"):
            x += f"<AbortIncompleteMultipartUpload><DaysAfterInitiation>{int(r['abort_multipart_days'])}</DaysAfterInitiation></AbortIncompleteMultipartUpload>"
        out.append(x + "</Rule>")
    return f'<LifecycleConfiguration xmlns="{NS}">{"".join(out)}</LifecycleConfiguration>'.encode()


_SIMPLE_RULE_CHILDREN = {"ID", "Filter", "Prefix", "Status", "Expiration", "NoncurrentVersionExpiration", "AbortIncompleteMultipartUpload"}


def lifecycle_from(raw: bytes) -> list[dict]:
    r = parse(raw)
    if r is None:
        return []
    rules = []
    for rule in r.findall("Rule"):
        kids = {c.tag for c in rule}
        flt = rule.find("Filter")
        prefix = _t(flt, "Prefix") if flt is not None else _t(rule, "Prefix")
        simple = (kids <= _SIMPLE_RULE_CHILDREN and _t(rule, "Status") == "Enabled" and
                  (flt is None or {c.tag for c in flt} <= {"Prefix"}) and
                  (rule.find("Expiration") is None or {c.tag for c in rule.find("Expiration")} <= {"Days"}))
        rid = _t(rule, "ID") or "rule"
        if simple:
            def num(parent, child):
                v = _t(rule.find(parent), child)
                return int(v) if v.isdigit() else 0
            rules.append({"id": rid, "prefix": prefix, "expire_days": num("Expiration", "Days"),
                          "noncurrent_days": num("NoncurrentVersionExpiration", "NoncurrentDays"),
                          "abort_multipart_days": num("AbortIncompleteMultipartUpload", "DaysAfterInitiation")})
        else:
            rules.append({"id": rid, "prefix": prefix, "expire_days": 0, "noncurrent_days": 0, "abort_multipart_days": 0,
                          "raw": ET.tostring(rule, encoding="unicode"), "custom": True})
    return rules


# ------------------------------------------------------------------ CORS
CORS_METHODS = ("GET", "PUT", "POST", "DELETE", "HEAD")


def cors_xml(rules: list[dict]) -> bytes:
    out = []
    for r in rules:
        x = "<CORSRule>"
        if r.get("id"):
            x += f"<ID>{esc(r['id'])}</ID>"
        x += "".join(f"<AllowedOrigin>{esc(o)}</AllowedOrigin>" for o in r["origins"])
        x += "".join(f"<AllowedMethod>{esc(m)}</AllowedMethod>" for m in r["methods"])
        x += "".join(f"<AllowedHeader>{esc(h)}</AllowedHeader>" for h in r.get("headers", []))
        x += "".join(f"<ExposeHeader>{esc(h)}</ExposeHeader>" for h in r.get("expose", []))
        if r.get("max_age"):
            x += f"<MaxAgeSeconds>{int(r['max_age'])}</MaxAgeSeconds>"
        out.append(x + "</CORSRule>")
    return f'<CORSConfiguration xmlns="{NS}">{"".join(out)}</CORSConfiguration>'.encode()


def cors_from(raw: bytes) -> list[dict]:
    r = parse(raw)
    if r is None:
        return []
    out = []
    for x in r.findall("CORSRule"):
        age = _t(x, "MaxAgeSeconds")
        out.append({"id": _t(x, "ID"), "origins": [(o.text or "").strip() for o in x.findall("AllowedOrigin")],
                    "methods": [(m.text or "").strip() for m in x.findall("AllowedMethod")],
                    "headers": [(h.text or "").strip() for h in x.findall("AllowedHeader")],
                    "expose": [(h.text or "").strip() for h in x.findall("ExposeHeader")],
                    "max_age": int(age) if age.isdigit() else 0})
    return out


_ORIGIN = re.compile(r"^(\*|https?://(\*\.)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?)$")
_HEADER = re.compile(r"^(\*|[A-Za-z0-9-]{1,64})$")


def cors_problems(rule: dict) -> list[str]:
    out = []
    if not rule.get("origins"):
        out.append("Give at least one origin, for example https://app.example.com.")
    for o in rule.get("origins", []):
        if not _ORIGIN.match(o):
            out.append(f"Origin {o[:60]!r} is not valid. Use https://host, https://*.host or *.")
    if not rule.get("methods"):
        out.append("Choose at least one method.")
    for m in rule.get("methods", []):
        if m not in CORS_METHODS:
            out.append(f"Method {m[:10]!r} is not supported.")
    for h in rule.get("headers", []) + rule.get("expose", []):
        if not _HEADER.match(h):
            out.append(f"Header {h[:40]!r} is not valid.")
    if not (0 <= int(rule.get("max_age") or 0) <= 86400):
        out.append("Max age must be between 0 and 86400 seconds.")
    if len(rule.get("origins", [])) > 20:
        out.append("A rule may name at most 20 origins.")
    return out


# ------------------------------------------------------------------ Object Lock
LOCK_MODES = ("GOVERNANCE", "COMPLIANCE")


def objectlock_xml(default: dict | None) -> bytes:
    x = f'<ObjectLockConfiguration xmlns="{NS}"><ObjectLockEnabled>Enabled</ObjectLockEnabled>'
    if default:
        unit = "Years" if default.get("unit") == "years" else "Days"
        x += (f"<Rule><DefaultRetention><Mode>{esc(default['mode'])}</Mode><{unit}>{int(default['amount'])}</{unit}>"
              f"</DefaultRetention></Rule>")
    return (x + "</ObjectLockConfiguration>").encode()


def objectlock_from(raw: bytes) -> dict | None:
    r = parse(raw)
    if r is None:
        return None
    d = r.find("Rule/DefaultRetention")
    if d is None:
        return None
    years = _t(d, "Years")
    days = _t(d, "Days")
    amt = years or days
    return {"mode": _t(d, "Mode"), "amount": int(amt) if amt.isdigit() else 0, "unit": "years" if years else "days"}


def lock_problems(default: dict | None) -> list[str]:
    if not default:
        return []
    out = []
    if default.get("mode") not in LOCK_MODES:
        out.append("Mode must be governance or compliance.")
    top = 100 if default.get("unit") == "years" else 36500
    if not (1 <= int(default.get("amount") or 0) <= top):
        out.append(f"Retention must be between 1 and {top} {default.get('unit', 'days')}.")
    return out
