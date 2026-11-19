"""AWS Signature Version 4 for S3 requests, used by the StorageGRID connector for bucket settings.

Kept apart and pure (no network, no clock unless asked) so it can be tested against published examples.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse
from datetime import datetime, timezone


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def canonical_query(query: str) -> str:
    """Sorted key=value pairs, each side percent-encoded; a key with no value becomes `key=`."""
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        pairs.append((_q(urllib.parse.unquote(k)), _q(urllib.parse.unquote(v))))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def content_md5(body: bytes) -> str:
    # MD5 is required by S3 for some settings calls as an integrity check, not for security.
    return base64.b64encode(hashlib.md5(body, usedforsecurity=False).digest()).decode()


def sign(method: str, host: str, path: str, query: str, body: bytes, key: str, secret: str, region: str,
         now: datetime | None = None, md5: bool = False) -> dict:
    """Return the headers to send. `path` must already be percent-encoded as it will be sent."""
    now = now or datetime.now(timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    phash = hashlib.sha256(body).hexdigest()
    hdrs = {"host": host, "x-amz-content-sha256": phash, "x-amz-date": amz}
    if md5 and body:
        hdrs["content-md5"] = content_md5(body)
    names = sorted(hdrs)
    signed = ";".join(names)
    creq = "\n".join([method, path, canonical_query(query), "".join(f"{k}:{hdrs[k]}\n" for k in names), signed, phash])
    scope = f"{day}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (day, region, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    out = {"x-amz-date": amz, "x-amz-content-sha256": phash,
           "Authorization": f"AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders={signed}, Signature={sig}"}
    if "content-md5" in hdrs:
        out["Content-MD5"] = hdrs["content-md5"]
    if body:
        out["Content-Type"] = "application/xml"
    return out
