"""Bucket policy rules: build, check and describe S3 bucket policies.

One module decides what a customer may put in a bucket policy, so the simulator, the StorageGRID
connector and the pages all agree. The checks are strict on purpose:

  * the policy may only name resources of its own bucket;
  * principals are limited to this storage account (its users, groups and root) or, only where the
    plan allows public buckets, everyone (read actions only);
  * no NotPrincipal, NotAction or NotResource (they are easy to get wrong and hard to review);
  * conditions are limited to a short list of well-understood keys.

Statements made by the portal carry a Sid that starts with "csportal", so they can be shown, changed
and removed as one unit. Statements written by hand (or by an S3 tool) are kept unchanged.
"""
from __future__ import annotations

import copy
import json
import re
import secrets

MAX_BYTES = 20 * 1024                    # StorageGRID accepts bucket policies up to 20 KiB
SID_PUBLIC = "csportalpublicread"
SID_TLS = "csportalrequiretls"
SID_GRANT = "csportalgrant"

PUBLIC_ACTIONS = {"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation"}
LEVELS = {
    "read": ("Read", ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation"]),
    "read-write": ("Read and write", ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation",
                                      "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload",
                                      "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads"]),
    "write-only": ("Upload only", ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]),
}
_OBJECT_ACTIONS = {"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
                   "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"}
_CONDITION_KEYS = {"aws:SecureTransport", "aws:SourceIp", "s3:prefix", "s3:delimiter", "s3:max-keys"}
_CONDITION_OPS = {"Bool", "IpAddress", "NotIpAddress", "StringEquals", "StringLike", "StringNotEquals", "StringNotLike", "NumericLessThanEquals"}
_SID = re.compile(r"^[A-Za-z0-9]{1,64}$")
_PRINCIPAL = re.compile(r"^arn:aws:iam::(\d{1,25}):(root|user/[A-Za-z0-9_.@-]{1,64}|group/[A-Za-z0-9_.@-]{1,64})$")
_ACTION = re.compile(r"^s3:[A-Za-z0-9*?]{1,60}$")
_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}(/\d{1,3})?$")


# ------------------------------------------------------------------ small helpers
def _list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def bucket_arn(bucket: str) -> str:
    return f"arn:aws:s3:::{bucket}"


def principal_arn(account: str, kind: str, name: str = "") -> str:
    return f"arn:aws:iam::{account}:" + ("root" if kind == "root" else f"{kind}/{name}")


def principals(stmt: dict) -> list[str]:
    p = stmt.get("Principal")
    if p == "*":
        return ["*"]
    if isinstance(p, dict):
        return [str(x) for x in _list(p.get("AWS"))]
    return []


def is_public_principal(stmt: dict) -> bool:
    return "*" in principals(stmt)


def empty() -> dict:
    return {"Version": "2012-10-17", "Statement": []}


def parse(text: str) -> tuple[dict | None, list[str]]:
    """Read policy text. Returns (document, problems); the document is None when the text is not usable."""
    text = (text or "").strip()
    if not text:
        return None, ["The policy is empty."]
    if len(text.encode()) > MAX_BYTES:
        return None, [f"The policy is larger than {MAX_BYTES // 1024} KiB, the limit of the storage service."]
    try:
        doc = json.loads(text)
    except ValueError as e:
        return None, [f"The policy is not valid JSON ({e.__class__.__name__}: {str(e)[:80]})."]
    if not isinstance(doc, dict):
        return None, ["The policy must be a JSON object."]
    return doc, []


def dump(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False)


# ------------------------------------------------------------------ checks
def validate(doc: dict, bucket: str, account: str, allow_public: bool) -> list[str]:
    """Return a list of problems in plain words. An empty list means the policy may be saved."""
    out: list[str] = []
    if not isinstance(doc, dict):
        return ["The policy must be a JSON object."]
    if doc.get("Version", "2012-10-17") not in ("2012-10-17", "2008-10-17"):
        out.append("Version must be 2012-10-17.")
    stmts = doc.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list) or not stmts:
        return out + ["The policy needs a Statement list with at least one statement."]
    if len(stmts) > 50:
        out.append("A policy may have at most 50 statements.")
    seen: set[str] = set()
    for i, s in enumerate(stmts, 1):
        w = f"Statement {i}: "
        if not isinstance(s, dict):
            out.append(w + "must be an object.")
            continue
        for bad in ("NotPrincipal", "NotAction", "NotResource"):
            if bad in s:
                out.append(w + f"{bad} is not supported here. List what is allowed or denied.")
        extra = set(s) - {"Sid", "Effect", "Principal", "Action", "Resource", "Condition", "NotPrincipal", "NotAction", "NotResource"}
        if extra:
            out.append(w + "unknown field " + ", ".join(sorted(extra)) + ".")
        sid = s.get("Sid")
        if sid is not None:
            if not isinstance(sid, str) or not _SID.match(sid):
                out.append(w + "Sid may only contain letters and numbers.")
            elif sid in seen:
                out.append(w + f"Sid {sid} is used twice.")
            else:
                seen.add(sid)
        eff = s.get("Effect")
        if eff not in ("Allow", "Deny"):
            out.append(w + "Effect must be Allow or Deny.")
        ps = principals(s)
        if not ps:
            out.append(w + "Principal is missing. Use a user, a group or the account.")
        for p in ps:
            if p == "*":
                if eff == "Allow" and not allow_public:
                    out.append(w + "public access is not part of your plan.")
                continue
            m = _PRINCIPAL.match(p)
            if not m:
                out.append(w + f"principal {p[:80]!r} is not recognised. Use arn:aws:iam::<account>:user/<name> or group/<name>.")
            elif m.group(1) != str(account):
                out.append(w + "principals from other storage accounts are not allowed here.")
        acts = [a for a in _list(s.get("Action"))]
        if not acts:
            out.append(w + "Action is missing.")
        for a in acts:
            if not isinstance(a, str) or not _ACTION.match(a):
                out.append(w + f"action {str(a)[:60]!r} is not valid. Actions start with s3:.")
        if eff == "Allow" and is_public_principal(s):
            odd = [a for a in acts if a not in PUBLIC_ACTIONS]
            if odd:
                out.append(w + "public access may only allow reading (" + ", ".join(sorted(PUBLIC_ACTIONS)) + "). Not allowed: " + ", ".join(map(str, odd[:4])) + ".")
        res = _list(s.get("Resource"))
        if not res:
            out.append(w + "Resource is missing.")
        for r in res:
            if not isinstance(r, str) or not (r == bucket_arn(bucket) or r.startswith(bucket_arn(bucket) + "/")):
                out.append(w + f"resource {str(r)[:90]!r} is not part of bucket {bucket}.")
        cond = s.get("Condition")
        if cond is not None:
            if not isinstance(cond, dict) or len(cond) > 4:
                out.append(w + "Condition must be an object with at most 4 operators.")
            else:
                for op, kv in cond.items():
                    if op not in _CONDITION_OPS or not isinstance(kv, dict):
                        out.append(w + f"condition operator {str(op)[:30]!r} is not supported.")
                        continue
                    for k, v in kv.items():
                        if k not in _CONDITION_KEYS:
                            out.append(w + f"condition key {str(k)[:40]!r} is not supported. Use one of: " + ", ".join(sorted(_CONDITION_KEYS)) + ".")
                        if k == "aws:SourceIp" and not all(isinstance(x, str) and _IP.match(x) for x in _list(v)):
                            out.append(w + "aws:SourceIp needs addresses such as 203.0.113.0/24.")
    return out


# ------------------------------------------------------------------ reading
def statements(doc: dict | None) -> list[dict]:
    if not doc:
        return []
    s = doc.get("Statement")
    return [x for x in (s if isinstance(s, list) else [s] if isinstance(s, dict) else []) if isinstance(x, dict)]


def is_public(doc: dict | None) -> bool:
    """True when an Allow statement without a condition names everyone and lets them read."""
    for s in statements(doc):
        if s.get("Effect") == "Allow" and is_public_principal(s) and not s.get("Condition"):
            acts = _list(s.get("Action"))
            if any(a in ("s3:GetObject", "s3:GetObjectVersion", "s3:*", "*") for a in acts):
                return True
    return False


def requires_tls(doc: dict | None) -> bool:
    for s in statements(doc):
        c = s.get("Condition") or {}
        if (s.get("Effect") == "Deny" and is_public_principal(s) and
                str((c.get("Bool") or {}).get("aws:SecureTransport", "")).lower() == "false"):
            return True
    return False


def _who(stmt: dict, account: str) -> str:
    out = []
    for p in principals(stmt):
        m = _PRINCIPAL.match(p) if p != "*" else None
        if p == "*":
            out.append("everyone (public)")
        elif m and m.group(2) == "root":
            out.append("the whole account")
        elif m:
            kind, _, name = m.group(2).partition("/")
            out.append(f"{kind} {name}" + ("" if m.group(1) == str(account) else " (other account)"))
        else:
            out.append(p)
    return ", ".join(out) or "-"


def _scope(stmt: dict, bucket: str) -> str:
    pref = []
    for r in _list(stmt.get("Resource")):
        if isinstance(r, str) and r.startswith(bucket_arn(bucket) + "/"):
            pref.append(r[len(bucket_arn(bucket)) + 1:].rstrip("*"))
    cond = (stmt.get("Condition") or {}).get("StringLike", {}).get("s3:prefix")
    pref += [str(x).rstrip("*") for x in _list(cond)]
    pref = [p for p in dict.fromkeys(pref) if p]
    return ", ".join(pref) if pref else "whole bucket"


def level_of(actions: list) -> str:
    a = set(map(str, actions))
    if "s3:*" in a or "*" in a:
        return "everything"
    for key in ("read-write", "read", "write-only"):
        if a == set(LEVELS[key][1]) or (key == "read" and a <= set(LEVELS["read"][1]) and a):
            return LEVELS[key][0]
    if a and a <= set(LEVELS["read-write"][1]):
        return "custom read/write"
    return "custom"


def describe(doc: dict | None, bucket: str, account: str) -> list[dict]:
    """One row per statement for the access page. Statements made by the portal are grouped as one grant."""
    rows, seen = [], set()
    for i, s in enumerate(statements(doc)):
        sid = s.get("Sid") or ""
        gid = sid[len(SID_GRANT):-1] if sid.startswith(SID_GRANT) and sid[-1:] in "ol" else ""
        if gid:
            if gid in seen:
                continue
            seen.add(gid)
        kind = ("Public read" if sid == SID_PUBLIC else "Encrypted connections only" if sid == SID_TLS else
                "Grant" if gid else "Custom statement")
        rows.append({"index": i, "sid": sid, "gid": gid, "effect": s.get("Effect", "?"), "kind": kind,
                     "who": _who(s, account), "what": level_of(_list(s.get("Action"))), "scope": _scope(s, bucket),
                     "managed": bool(gid or sid in (SID_PUBLIC, SID_TLS)),
                     "public": s.get("Effect") == "Allow" and is_public_principal(s),
                     "conditions": bool(s.get("Condition"))})
    return rows


# ------------------------------------------------------------------ changing
def _with(doc: dict | None) -> dict:
    d = copy.deepcopy(doc) if doc else empty()
    st = d.get("Statement")
    d["Statement"] = st if isinstance(st, list) else ([st] if isinstance(st, dict) else [])
    d.setdefault("Version", "2012-10-17")
    return d


def _clean(doc: dict) -> dict | None:
    return doc if doc.get("Statement") else None


def set_public(doc: dict | None, bucket: str, on: bool) -> dict | None:
    d = _with(doc)
    d["Statement"] = [s for s in d["Statement"] if s.get("Sid") != SID_PUBLIC]
    if on:
        d["Statement"].append({"Sid": SID_PUBLIC, "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                               "Resource": f"{bucket_arn(bucket)}/*"})
    return _clean(d)


def set_tls_only(doc: dict | None, bucket: str, on: bool) -> dict | None:
    d = _with(doc)
    d["Statement"] = [s for s in d["Statement"] if s.get("Sid") != SID_TLS]
    if on:
        d["Statement"].append({"Sid": SID_TLS, "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                               "Resource": [bucket_arn(bucket), f"{bucket_arn(bucket)}/*"],
                               "Condition": {"Bool": {"aws:SecureTransport": "false"}}})
    return _clean(d)


def clean_prefix(prefix: str) -> str:
    p = (prefix or "").strip().lstrip("/")
    return re.sub(r"[^A-Za-z0-9!_.*'()/ -]", "", p)[:200].rstrip("*")


def add_grant(doc: dict | None, bucket: str, who: list[str], level: str, prefix: str = "") -> tuple[dict, str]:
    """Add a grant for the given principal ARNs. Returns (document, grant id)."""
    if level not in LEVELS:
        raise ValueError("unknown access level")
    gid = secrets.token_hex(4)
    pref = clean_prefix(prefix)
    acts = LEVELS[level][1]
    d = _with(doc)
    obj_res = f"{bucket_arn(bucket)}/{pref}*" if pref else f"{bucket_arn(bucket)}/*"
    obj_acts = [a for a in acts if a in _OBJECT_ACTIONS]
    bkt_acts = [a for a in acts if a not in _OBJECT_ACTIONS]
    base = {"Effect": "Allow", "Principal": {"AWS": list(who)}}
    d["Statement"].append({"Sid": f"{SID_GRANT}{gid}o", **base, "Action": obj_acts, "Resource": obj_res})
    if bkt_acts:
        lst = {"Sid": f"{SID_GRANT}{gid}l", **base, "Action": bkt_acts, "Resource": bucket_arn(bucket)}
        if pref:
            # With a prefix, listing is limited to that prefix and the other bucket-level actions are left out.
            lst["Action"] = ["s3:ListBucket"]
            lst["Condition"] = {"StringLike": {"s3:prefix": [f"{pref}*"]}}
        d["Statement"].append(lst)
    return d, gid


def remove_grant(doc: dict | None, gid: str) -> dict | None:
    d = _with(doc)
    d["Statement"] = [s for s in d["Statement"] if s.get("Sid") not in (f"{SID_GRANT}{gid}o", f"{SID_GRANT}{gid}l")]
    return _clean(d)


def remove_statement(doc: dict | None, index: int) -> dict | None:
    d = _with(doc)
    if 0 <= index < len(d["Statement"]):
        del d["Statement"][index]
    return _clean(d)
