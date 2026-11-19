"""Native StorageGRID connector (Grid Management API, Tenant Management API, S3 API).

STATUS: UNVERIFIED. The calls below follow the public StorageGRID documentation as understood when
this was written, but they have NOT been run against a real grid. Before production use:

  1. run `python -m csportal conformance`, which compares every path used here with the OpenAPI
     document the grid itself publishes and lists anything that does not exist on that release;
  2. run the connector test plan in docs/STORAGEGRID_INTEGRATION.md against a non-production grid;
  3. record the verified release range in the CHANGELOG.

Design rules (see docs/STORAGEGRID_INTEGRATION.md): documented endpoints only, strict TLS, short-lived
tokens, back-off, no private endpoints, no screen scraping.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

from .. import logs
from .. import policy as bpolicy
from . import s3sign, s3xml
from .base import BackendError, StorageBackend

log = logging.getLogger("csportal.backend")

# Every management API call this connector makes, as (method, path template). The conformance check
# compares this table with the grid's own OpenAPI document.
CALLS = [
    ("POST", "/authorize"),
    ("GET", "/grid/accounts"), ("POST", "/grid/accounts"),
    ("GET", "/grid/accounts/{id}"), ("PUT", "/grid/accounts/{id}"), ("DELETE", "/grid/accounts/{id}"),
    ("GET", "/grid/accounts/{id}/usage"),
    ("GET", "/grid/health"), ("GET", "/grid/alerts"),
    ("GET", "/org/containers"), ("POST", "/org/containers"), ("DELETE", "/org/containers/{bucketName}"),
    ("GET", "/org/groups"), ("POST", "/org/groups"), ("PUT", "/org/groups/{id}"), ("DELETE", "/org/groups/{id}"),
    ("GET", "/org/users"), ("POST", "/org/users"), ("PATCH", "/org/users/{id}"), ("DELETE", "/org/users/{id}"),
    ("GET", "/org/users/{id}/s3-access-keys"), ("POST", "/org/users/{id}/s3-access-keys"),
    ("DELETE", "/org/users/{id}/s3-access-keys/{accessKey}"),
    ("GET", "/org/usage"),
]


class StorageGridBackend(StorageBackend):
    name = "storagegrid"
    verified = False
    description = "StorageGRID Grid Management API, Tenant Management API and S3 API (unverified)"

    def __init__(self, conn, grid_password: Callable[[], str],
                 get_creds: Callable[[str], dict | None] | None = None,
                 put_creds: Callable[[str, dict], None] | None = None):
        """`conn` is a settings.GridConn: admin nodes (the first is the primary), API version, grid account and user,
        trusted certificates and the S3 gateway endpoints. Certificate checking is always on."""
        from .gridcheck import tls_context
        self.bases = conn.base_urls()                     # empty until an administrator enters the admin nodes
        self._active = 0                                  # index of the admin node that answered last
        self.ver = conn.api_version
        self.grid_account, self.grid_user, self._grid_pw = conn.account_id, conn.username, grid_password
        self.s3_endpoints = list(conn.endpoints)
        self.s3_endpoint = self.s3_endpoints[0].url.rstrip("/") if self.s3_endpoints else ""      # used for bucket settings
        self.s3_region = self.s3_endpoints[0].region if self.s3_endpoints else "us-east-1"
        self.timeout = float(conn.timeout)
        self.get_creds, self.put_creds = get_creds, put_creds
        self.ctx = tls_context(conn)
        self._tokens: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._fails = 0
        self._open_until = 0.0

    @property
    def base(self) -> str:
        return self.bases[self._active] if self.bases else ""

    def _mgmt(self, method: str, path: str, headers: dict, body: bytes | None = None):
        """Call the management API on the admin nodes in order, starting with the one that answered last.
        Moves to the next node only when a node can not be reached."""
        if not self.bases:
            raise BackendError("not_configured", "The storage grid connection is not set up yet. An administrator must enter it under Storage grid.", 503)
        last: BackendError | None = None
        for i in range(len(self.bases)):
            idx = (self._active + i) % len(self.bases)
            try:
                res = self._http(method, self.bases[idx] + path, headers, body, self.timeout)
            except BackendError as e:
                if e.code != "backend_unavailable":
                    raise
                last = e
                continue
            if idx != self._active:
                logs.event(log, logging.WARNING, "storage admin node changed", node=self.bases[idx])
                self._active = idx
            return res
        raise last or BackendError("backend_unavailable", "The storage service could not be reached.", 503)

    # ------------------------------------------------------------------ http
    def _http(self, method: str, url: str, headers: dict, body: bytes | None = None, timeout: float = 20):
        if time.monotonic() < self._open_until:
            raise BackendError("backend_unavailable", "The storage service is not responding. Try again shortly.", 503)
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        last: Exception | None = None
        for attempt in range(3 if method in ("GET", "HEAD") else 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
                    self._fails = 0
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                data = e.read()
                if e.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(0.5 * 2 ** attempt)
                    last = e
                    continue
                return e.code, data
            except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as e:
                last = e
                time.sleep(0.3 * 2 ** attempt)
        self._fails += 1
        if self._fails >= 5:
            self._open_until = time.monotonic() + 30          # circuit breaker
        raise BackendError("backend_unavailable", "The storage service could not be reached.", 503) from last

    def _api(self, scope: str, method: str, path: str, body: Any = None, params: dict | None = None):
        """scope is 'grid' or a tenant reference. Returns the 'data' member of the response."""
        url = f"/api/{self.ver}{path}" + (("?" + urllib.parse.urlencode(params)) if params else "")
        for retry in (0, 1):
            tok = self._token(scope, force=bool(retry))
            hdrs = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                hdrs["Content-Type"] = "application/json"
            status, raw = self._mgmt(method, url, hdrs, data)
            if status == 401 and not retry:
                continue
            break
        return self._unwrap(status, raw)

    @staticmethod
    def _unwrap(status: int, raw: bytes):
        try:
            doc = json.loads(raw.decode() or "{}")
        except ValueError:
            doc = {}
        if 200 <= status < 300:
            return doc.get("data", doc) if isinstance(doc, dict) else doc
        msg = ""
        if isinstance(doc, dict):
            msg = (doc.get("message") or {}).get("text", "") if isinstance(doc.get("message"), dict) else str(doc.get("message", ""))
        code = {400: "invalid", 401: "auth_failed", 403: "forbidden", 404: "not_found", 409: "conflict",
                422: "invalid"}.get(status, "backend_error")
        raise BackendError(code, logs.scrub(msg) or f"The storage service returned an error ({status}).", status)

    def _token(self, scope: str, force: bool = False) -> str:
        with self._lock:
            tok = self._tokens.get(scope)
            if tok and not force and tok[1] > time.monotonic() + 60:
                return tok[0]
        if scope == "grid":
            acct, user, pw = self.grid_account, self.grid_user, self._grid_pw()
        else:
            c = self.get_creds(scope) if self.get_creds else None
            if not c:
                raise BackendError("no_credentials", "No service credentials are stored for this storage account.", 500)
            acct, user, pw = scope, c["username"], c["password"]
        status, raw = self._mgmt("POST", f"/api/{self.ver}/authorize",
                                 {"Content-Type": "application/json", "Accept": "application/json"},
                                 json.dumps({"accountId": acct, "username": user, "password": pw,
                                             "cookie": False, "csrfToken": False}).encode())
        tok_v = self._unwrap(status, raw)
        if not isinstance(tok_v, str):
            raise BackendError("auth_failed", "Sign-in to the storage service failed.", 401)
        with self._lock:
            self._tokens[scope] = (tok_v, time.monotonic() + 3600)       # refreshed early; 401 forces renewal
        return tok_v

    # ------------------------------------------------------------------ S3 (bucket configuration)
    def _s3(self, ref: str, method: str, bucket: str, query: str = "", body: bytes = b"") -> tuple[int, bytes]:
        """One signed S3 request on the first gateway endpoint (path-style). Settings calls carry Content-MD5."""
        c = self.get_creds(ref) if self.get_creds else None
        if not c or not c.get("s3_key"):
            raise BackendError("no_credentials", "No S3 service key is stored for this storage account.", 500)
        if not self.s3_endpoint:
            raise BackendError("not_configured", "No S3 gateway endpoint is set up yet. An administrator must enter one under Storage grid.", 503)
        host = urllib.parse.urlparse(self.s3_endpoint).netloc
        path = "/" + urllib.parse.quote(bucket)
        hdrs = s3sign.sign(method, host, path, query, body, c["s3_key"], c["s3_secret"], self.s3_region, md5=method == "PUT")
        return self._http(method, f"{self.s3_endpoint}{path}" + (f"?{query}" if query else ""), hdrs, body or None, self.timeout)

    def _s3_read(self, ref: str, name: str, sub: str, notes: list) -> bytes | None:
        """Read one bucket setting. Returns b"" when it is not set, None when it could not be read (noted)."""
        try:
            st, raw = self._s3(ref, "GET", name, sub)
        except BackendError as e:
            notes.append(f"{sub}: {e.message}")
            return None
        if st == 200:
            return raw
        if st == 404:
            return b""
        notes.append(f"{sub}: the storage service answered {st}")
        return None

    def _s3_write(self, ref: str, name: str, sub: str, method: str, body: bytes, what: str):
        st, raw = self._s3(ref, method, name, sub, body)
        if st >= 300 and not (method == "DELETE" and st == 404):
            logs.event(log, logging.WARNING, "bucket setting rejected", setting=sub, status=st)
            raise BackendError("backend_error", f"The {what} change was rejected by the storage service ({st}).", st)

    # ------------------------------------------------------------------ service
    def health(self) -> dict:
        try:
            status, raw = self._mgmt("GET", "/api/versions", {"Accept": "application/json"})
            doc = json.loads(raw.decode() or "{}")
            versions = doc.get("data", doc) if isinstance(doc, dict) else doc
            ok = status == 200 and (self.ver.lstrip("v") in [str(v).lstrip("v") for v in (versions or [])] or self.ver in str(versions))
            return {"ok": bool(ok), "release": f"API {self.ver}",
                    "detail": "Reachable." if ok else f"Grid does not list API {self.ver} (supported: {versions})."}
        except BackendError as e:
            return {"ok": False, "release": "unknown", "detail": e.message}

    def grid_overview(self) -> dict:
        h = self._api("grid", "GET", "/grid/health")
        a = self._api("grid", "GET", "/grid/alerts")
        return {"capacity_bytes": 0, "used_bytes": 0, "nodes_total": 0, "nodes_ok": 0,
                "alerts": [{"severity": x.get("severity", "?"), "title": x.get("name", "alert")} for x in (a or [])][:20],
                "raw_health": h}

    def endpoints(self, ref: str) -> dict:
        regions = list(dict.fromkeys(e.region for e in self.s3_endpoints)) or ["us-east-1"]
        return {"s3": [e.url for e in self.s3_endpoints], "regions": regions,
                "details": [{"name": e.name, "url": e.url, "region": e.region, "note": e.note} for e in self.s3_endpoints]}

    # ------------------------------------------------------------------ tenants
    def create_tenant(self, name, quota_bytes, features) -> str:
        root_pw = secrets.token_urlsafe(24)
        acct = self._api("grid", "POST", "/grid/accounts", {
            "name": name, "capabilities": ["s3"], "password": root_pw,
            "policy": {"useAccountIdentitySource": bool(features.get("own_identity")),
                       "allowPlatformServices": bool(features.get("platform_services")),
                       "quotaObjectBytes": int(quota_bytes)}})
        ref = str(acct["id"])
        # Service identity for the portal, in a dedicated group. The root password is used once and kept
        # only in encrypted storage as break-glass.
        if self.put_creds:
            self.put_creds(ref, {"username": "root", "password": root_pw})
        self._tokens.pop(ref, None)
        try:
            g = self._api(ref, "POST", "/org/groups", {"displayName": "csportal-service", "uniqueName": "group/csportal-service",
                                                      "policies": {"management": {"manageAllContainers": True, "manageEndpoints": True,
                                                                                  "manageOwnS3Credentials": True, "rootAccess": False}}})
            svc_pw = secrets.token_urlsafe(24)
            u = self._api(ref, "POST", "/org/users", {"fullName": "CSPortal service", "uniqueName": "user/csportal-service",
                                                     "memberOf": [g["id"]], "disable": False})
            key = self._api(ref, "POST", f"/org/users/{u['id']}/s3-access-keys", {})
            if self.put_creds:
                self.put_creds(ref, {"username": "csportal-service", "password": svc_pw, "s3_key": key.get("accessKey"),
                                     "s3_secret": key.get("secretAccessKey"), "root_password_note": "stored under root"})
        except BackendError:
            self.delete_tenant(ref)         # do not leave half-created accounts behind
            raise
        return ref

    def update_tenant(self, ref, quota_bytes=None, features=None):
        cur = self._api("grid", "GET", f"/grid/accounts/{ref}")
        pol = cur.get("policy", {})
        if quota_bytes is not None:
            pol["quotaObjectBytes"] = int(quota_bytes)
        if features is not None:
            pol["allowPlatformServices"] = bool(features.get("platform_services"))
            pol["useAccountIdentitySource"] = bool(features.get("own_identity"))
        cur["policy"] = pol
        self._api("grid", "PUT", f"/grid/accounts/{ref}", cur)

    def set_suspended(self, ref, suspended):
        # StorageGRID has no suspend flag on accounts; the portal blocks sign-in and disables the keys.
        for u in self.list_users(ref):
            self.update_user(ref, u["username"], disabled=bool(suspended))

    def delete_tenant(self, ref):
        self._api("grid", "DELETE", f"/grid/accounts/{ref}")

    # ------------------------------------------------------------------ usage and buckets
    def usage(self, ref):
        u = self._api("grid", "GET", f"/grid/accounts/{ref}/usage")
        acct = self._api("grid", "GET", f"/grid/accounts/{ref}")
        bs = [{"name": b["name"], "bytes": b.get("dataBytes", 0), "objects": b.get("objectCount", 0)}
              for b in (u.get("buckets") or [])]
        return {"bytes_used": u.get("dataBytes", 0), "objects": u.get("objectCount", 0),
                "quota_bytes": acct.get("policy", {}).get("quotaObjectBytes", 0), "buckets": bs}

    def list_buckets(self, ref):
        """Cheap listing: settings that need one S3 call each (versioning, access) are read on the bucket page."""
        use = {b["name"]: b for b in self.usage(ref)["buckets"]}
        out = []
        for b in self._api(ref, "GET", "/org/containers") or []:
            n = b["name"]
            out.append({"name": n, "region": b.get("region", "us-east-1"), "created": b.get("creationTime", ""),
                        "bytes": use.get(n, {}).get("bytes", 0), "objects": use.get(n, {}).get("objects", 0),
                        "versioning": "unknown", "object_lock": bool(b.get("objectLock") or b.get("s3ObjectLock")), "public": None,
                        "lifecycle": [], "consistency": b.get("consistency", ""), "policy": None, "cors": [],
                        "lock_default": None, "notes": []})
        return out

    def get_bucket(self, ref, name):
        for b in self.list_buckets(ref):
            if b["name"] != name:
                continue
            notes = b["notes"]
            raw = self._s3_read(ref, name, "versioning", notes)
            b["versioning"] = s3xml.versioning_from(raw) if raw else ("off" if raw == b"" else "unknown")
            raw = self._s3_read(ref, name, "lifecycle", notes)
            b["lifecycle"] = s3xml.lifecycle_from(raw) if raw else []
            raw = self._s3_read(ref, name, "policy", notes)
            if raw:
                try:
                    b["policy"] = json.loads(raw.decode())
                except ValueError:
                    notes.append("policy: the storage service returned a policy that could not be read")
            b["public"] = bpolicy.is_public(b["policy"]) if raw is not None else None
            raw = self._s3_read(ref, name, "cors", notes)
            b["cors"] = s3xml.cors_from(raw) if raw else []
            if b["object_lock"]:
                raw = self._s3_read(ref, name, "object-lock", notes)
                b["lock_default"] = s3xml.objectlock_from(raw) if raw else None
            return b
        raise BackendError("bucket_not_found", "The bucket was not found.", 404)

    def create_bucket(self, ref, name, region, versioning, object_lock):
        body = {"name": name, "region": region}
        if object_lock:
            body["s3ObjectLock"] = {"enabled": True}
        self._api(ref, "POST", "/org/containers", body)
        if versioning and not object_lock:
            self.update_bucket(ref, name, versioning="enabled")

    def delete_bucket(self, ref, name):
        self._api(ref, "DELETE", f"/org/containers/{urllib.parse.quote(name)}")

    def update_bucket(self, ref, name, **ch):
        if "versioning" in ch:
            self._s3_write(ref, name, "versioning", "PUT", s3xml.versioning_xml(ch["versioning"]), "versioning")
        if "lifecycle" in ch:
            if ch["lifecycle"]:
                self._s3_write(ref, name, "lifecycle", "PUT", s3xml.lifecycle_xml(ch["lifecycle"]), "lifecycle")
            else:
                self._s3_write(ref, name, "lifecycle", "DELETE", b"", "lifecycle")
        if "public" in ch:
            notes: list = []
            raw = self._s3_read(ref, name, "policy", notes)
            cur = None
            if raw is None:
                raise BackendError("backend_error", "The current access policy could not be read, so it was not changed.", 502)
            if raw:
                try:
                    cur = json.loads(raw.decode())
                except ValueError:
                    raise BackendError("backend_error", "The current access policy could not be read, so it was not changed.", 502)
            ch["policy"] = bpolicy.set_public(cur, name, bool(ch["public"]))
        if "policy" in ch:
            if ch["policy"]:
                self._s3_write(ref, name, "policy", "PUT", json.dumps(ch["policy"]).encode(), "access policy")
            else:
                self._s3_write(ref, name, "policy", "DELETE", b"", "access policy")
        if "cors" in ch:
            if ch["cors"]:
                self._s3_write(ref, name, "cors", "PUT", s3xml.cors_xml(ch["cors"]), "CORS")
            else:
                self._s3_write(ref, name, "cors", "DELETE", b"", "CORS")
        if "lock_default" in ch:
            self._s3_write(ref, name, "object-lock", "PUT", s3xml.objectlock_xml(ch["lock_default"]), "Object Lock")

    # ------------------------------------------------------------------ users, groups, keys
    def list_groups(self, ref):
        return [{"name": g.get("displayName", g.get("uniqueName")), "access": _access(g), "buckets": _scope(g), "id": g["id"],
                 "created": ""} for g in self._api(ref, "GET", "/org/groups") or []
                if g.get("uniqueName") != "group/csportal-service"]

    def create_group(self, ref, name, access, buckets=None):
        self._api(ref, "POST", "/org/groups", {"displayName": name, "uniqueName": f"group/{name}",
                                              "policies": {"s3": {"Statement": _s3_policy(access, buckets)}}})

    def update_group(self, ref, name, access=None, buckets=None):
        for g in self._api(ref, "GET", "/org/groups") or []:
            if g.get("displayName") == name:
                acc = access if access is not None else _access(g)
                scope = buckets if buckets is not None else _scope(g)
                g.setdefault("policies", {})["s3"] = {"Statement": _s3_policy(acc, scope)}
                self._api(ref, "PUT", f"/org/groups/{g['id']}", g)
                return
        raise BackendError("not_found", "The group was not found.", 404)

    def delete_group(self, ref, name):
        for g in self._api(ref, "GET", "/org/groups") or []:
            if g.get("displayName") == name:
                self._api(ref, "DELETE", f"/org/groups/{g['id']}")
                return
        raise BackendError("not_found", "The group was not found.", 404)

    def _user(self, ref, username):
        for u in self._api(ref, "GET", "/org/users") or []:
            if u.get("uniqueName") == f"user/{username}":
                return u
        raise BackendError("user_not_found", "The user was not found.", 404)

    def list_users(self, ref):
        gm = {g["id"]: g.get("displayName") for g in self._api(ref, "GET", "/org/groups") or []}
        return [{"username": u["uniqueName"].split("/", 1)[-1], "full_name": u.get("fullName", ""),
                 "groups": [gm.get(i, i) for i in u.get("memberOf", [])], "disabled": bool(u.get("disable")), "keys": 0}
                for u in self._api(ref, "GET", "/org/users") or [] if u.get("uniqueName") != "user/csportal-service"]

    def create_user(self, ref, username, full_name, groups):
        gm = {g.get("displayName"): g["id"] for g in self._api(ref, "GET", "/org/groups") or []}
        self._api(ref, "POST", "/org/users", {"fullName": full_name, "uniqueName": f"user/{username}",
                                              "memberOf": [gm[g] for g in groups if g in gm], "disable": False})

    def update_user(self, ref, username, groups=None, disabled=None):
        u = self._user(ref, username)
        body: dict = {}
        if disabled is not None:
            body["disable"] = bool(disabled)
        if groups is not None:
            gm = {g.get("displayName"): g["id"] for g in self._api(ref, "GET", "/org/groups") or []}
            body["memberOf"] = [gm[g] for g in groups if g in gm]
        self._api(ref, "PATCH", f"/org/users/{u['id']}", body)

    def delete_user(self, ref, username):
        self._api(ref, "DELETE", f"/org/users/{self._user(ref, username)['id']}")

    def list_keys(self, ref, username):
        u = self._user(ref, username)
        return [{"id": k.get("accessKey", k.get("id")), "created": k.get("creationTime", ""), "last_used": None,
                 "expires": k.get("expires")}
                for k in self._api(ref, "GET", f"/org/users/{u['id']}/s3-access-keys") or []]

    def create_key(self, ref, username, expires=None):
        k = self._api(ref, "POST", f"/org/users/{self._user(ref, username)['id']}/s3-access-keys", {"expires": expires} if expires else {})
        return {"id": k["accessKey"], "secret": k["secretAccessKey"]}

    def delete_key(self, ref, username, key_id):
        self._api(ref, "DELETE", f"/org/users/{self._user(ref, username)['id']}/s3-access-keys/{key_id}")

    # ------------------------------------------------------------------ conformance
    def conformance(self) -> list[dict]:
        """Compare CALLS with the OpenAPI document the grid publishes. Returns one row per call."""
        doc = None
        for p in ("/api/docs/swagger.json", "/api/docs/openapi.json", f"/api/{self.ver}/docs/swagger.json"):
            try:
                st, raw = self._mgmt("GET", p, {"Accept": "application/json"})
                if st == 200:
                    doc = json.loads(raw.decode())
                    break
            except Exception:
                continue
        if not doc:
            return [{"method": m, "path": p, "status": "unknown", "detail": "OpenAPI document not found"} for m, p in CALLS]
        paths = {k.replace(f"/api/{self.ver}", ""): v for k, v in (doc.get("paths") or {}).items()}
        have = {(m.upper(), norm(p)) for p, ops in paths.items() for m in ops}
        return [{"method": m, "path": p, "status": "ok" if (m, norm(p)) in have else "MISSING", "detail": ""}
                for m, p in CALLS]


def norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _x(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _s3_policy(access: str, buckets: list[str] | None = None) -> list[dict]:
    """Group policy statements. With buckets named, the group can use only those buckets and can not list the others."""
    act = {"read-write": ["s3:*"], "read-only": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:GetBucketLocation"]}.get(access, [])
    if not act:
        return [{"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "arn:aws:s3:::*"}]
    if not buckets:
        if access == "read-only":
            act = act + ["s3:ListAllMyBuckets"]
        return [{"Effect": "Allow", "Action": act, "Resource": "arn:aws:s3:::*"}]
    res = [r for b in buckets for r in (f"arn:aws:s3:::{b}", f"arn:aws:s3:::{b}/*")]
    return [{"Effect": "Allow", "Action": act, "Resource": res}]


def _access(g: dict) -> str:
    st = (g.get("policies", {}).get("s3", {}) or {}).get("Statement", [])
    acts = [a for s in st for a in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")])]
    return "read-write" if "s3:*" in acts else ("read-only" if acts else "none")


def _scope(g: dict) -> list[str]:
    """The buckets a group is limited to; an empty list means every bucket."""
    names: list[str] = []
    for st in (g.get("policies", {}).get("s3", {}) or {}).get("Statement", []):
        for r in (st.get("Resource") if isinstance(st.get("Resource"), list) else [st.get("Resource")]):
            if not isinstance(r, str):
                continue
            if r in ("arn:aws:s3:::*", "*"):
                return []
            if r.startswith("arn:aws:s3:::"):
                n = r[len("arn:aws:s3:::"):].split("/", 1)[0]
                if n and n not in names:
                    names.append(n)
    return names
