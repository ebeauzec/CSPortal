"""Step-by-step check of the storage grid connection, used by the admin console's "Test connection".

Each step reports ok, warn, fail or skipped, with a plain-English hint for what to fix. Nothing secret is
returned. The password is sent only after the grid's certificate has been verified. To help diagnose a
certificate problem the checker may open one extra connection that does NOT verify the certificate, only to read
the certificate the server presents; it sends no data and no credentials on that connection.
"""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from .. import logs

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skipped"


def tls_context(conn) -> ssl.SSLContext:
    """Verifying TLS context. Trust: the CA file named in the configuration, CA certificates saved in the console,
    or the system store when neither is set. TLS 1.2 or newer. Verification can not be switched off."""
    ctx = ssl.create_default_context(cafile=conn.ca_file or None, cadata=conn.ca_pem or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _step(area: str, target: str, check: str, status: str, detail: str = "", hint: str = "") -> dict:
    return {"area": area, "target": target, "check": check, "status": status, "detail": logs.scrub(detail)[:400], "hint": hint}


def _presented_cert(host: str, port: int, timeout: float) -> dict | None:
    """The certificate the server shows, read without verifying it (diagnostics only; nothing is sent)."""
    from cryptography import x509
    from ..settings import describe_cert
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s, c.wrap_socket(s, server_hostname=host) as t:
            return describe_cert(x509.load_der_x509_certificate(t.getpeercert(binary_form=True)))
    except (OSError, ValueError):
        return None


def _tls_hint(msg: str, host: str) -> str:
    m = msg.lower()
    if "hostname" in m or "doesn't match" in m or "ip address mismatch" in m:
        return (f"The certificate does not list '{host}'. Connect with a name or address the certificate lists, or ask the grid "
                "administrator for a certificate that includes it.")
    if "expired" in m:
        return "The certificate has expired. The grid administrator must replace it."
    if "self-signed" in m or "self signed" in m or "unable to get local issuer" in m or "unknown ca" in m:
        return ("The portal does not trust the certificate's issuer. Ask the grid administrator for the CA certificate that signed "
                "it and add it under CA certificates.")
    return "Check the certificate chain with the grid administrator."


def _check_tls(area: str, host: str, port: int, ctx, timeout: float, steps: list) -> bool:
    """TCP connect and verified TLS handshake. Appends steps; returns True when both pass."""
    from cryptography import x509
    from ..settings import describe_cert
    target = f"{host}:{port}"
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        steps.append(_step(area, target, "Network connection", FAIL, f"{type(e).__name__}: {e}",
                           "Check the address and port, the route from the portal host, and that a firewall allows HTTPS from the portal to this address."))
        return False
    steps.append(_step(area, target, "Network connection", OK, f"Connected in {int((time.monotonic() - t0) * 1000)} ms."))
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
            ver = t.version()
    except ssl.SSLCertVerificationError as e:
        sock.close()
        shown = _presented_cert(host, port, timeout)
        extra = f" It presents: {shown['subject']}, issued by {shown['issuer']}, SHA-256 {shown['sha256']}." if shown else ""
        steps.append(_step(area, target, "Certificate check", FAIL, f"{e.verify_message}.{extra}", _tls_hint(e.verify_message, host)))
        return False
    except (ssl.SSLError, OSError) as e:
        sock.close()
        steps.append(_step(area, target, "Secure connection (TLS 1.2 or newer)", FAIL, f"{type(e).__name__}: {e}",
                           "The server did not complete a TLS 1.2 or newer handshake. Check that this is the HTTPS port of the service."))
        return False
    info = describe_cert(x509.load_der_x509_certificate(der))
    status = WARN if info["days_left"] < 30 else OK
    steps.append(_step(area, target, "Certificate check", status,
                       f"{ver}. {info['subject']}, issued by {info['issuer']}, valid until {info['not_after']} ({info['days_left']} days). "
                       f"SHA-256 {info['sha256']}.", "The certificate expires soon. Ask the grid administrator to renew it." if status == WARN else ""))
    return True


def _json_request(host, port, ctx, timeout, method, path, body=None, token=""):
    c = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    try:
        h = {"Accept": "application/json"}
        data = None
        if body is not None:
            data, h["Content-Type"] = json.dumps(body).encode(), "application/json"
        if token:
            h["Authorization"] = f"Bearer {token}"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read(1_000_000)
        try:
            doc = json.loads(raw.decode() or "{}")
        except ValueError:
            doc = {}
        return r.status, doc
    finally:
        c.close()


def _grid_message(doc) -> str:
    m = doc.get("message") if isinstance(doc, dict) else ""
    return (m.get("text", "") if isinstance(m, dict) else str(m or ""))[:200]


def diagnose(conn, password: str) -> list[dict]:
    """Run every check against the given settings. Used before saving (nothing is stored) and after."""
    ctx, timeout = tls_context(conn), min(conn.timeout, 15)
    steps: list[dict] = []
    authed = False
    for node in conn.nodes:
        area, target = f"Admin node {node.name}", f"{node.host}:{node.port}"
        if not _check_tls(area, node.host, node.port, ctx, timeout, steps):
            continue
        try:
            st, doc = _json_request(node.host, node.port, ctx, timeout, "GET", "/api/versions")
            versions = doc.get("data", doc) if isinstance(doc, dict) else doc
            vs = [str(v) for v in (versions or [])] if isinstance(versions, list) else []
            if st == 200 and any(v.lstrip("v") == conn.api_version.lstrip("v") for v in vs):
                steps.append(_step(area, target, "Management API version", OK, f"{conn.api_version} is supported. The grid offers: {', '.join(vs)}."))
            else:
                steps.append(_step(area, target, "Management API version", FAIL, f"HTTP {st}. The grid offers: {', '.join(vs) or 'nothing readable'}.",
                                   "Set the API version to one the grid offers, or check that this is the grid's admin node address."))
                continue
        except (OSError, http.client.HTTPException) as e:
            steps.append(_step(area, target, "Management API version", FAIL, f"{type(e).__name__}: {e}", "The service did not answer as a StorageGRID admin node."))
            continue
        if authed:
            steps.append(_step(area, target, "Sign-in", SKIP, "Already checked on an earlier admin node; not repeated to avoid extra sign-ins."))
            continue
        if not password:
            steps.append(_step(area, target, "Sign-in", FAIL, "No password is set for the portal's grid user.",
                               "Enter the password in the form (stored encrypted), or set the environment variable named in the configuration."))
            continue
        try:
            st, doc = _json_request(node.host, node.port, ctx, timeout, "POST", f"/api/{conn.api_version}/authorize",
                                    {"accountId": conn.account_id, "username": conn.username, "password": password,
                                     "cookie": False, "csrfToken": False})
        except (OSError, http.client.HTTPException) as e:
            steps.append(_step(area, target, "Sign-in", FAIL, f"{type(e).__name__}: {e}", "The sign-in request did not complete."))
            continue
        token = doc.get("data") if st == 200 and isinstance(doc, dict) and isinstance(doc.get("data"), str) else ""
        if not token:
            steps.append(_step(area, target, "Sign-in", FAIL, f"HTTP {st}. {_grid_message(doc)}",
                               "The grid rejected the sign-in. Check the account ID, user name and password, and that the user is not locked or disabled."))
            continue
        authed = True
        steps.append(_step(area, target, "Sign-in", OK, f"Signed in as '{conn.username}' on account {conn.account_id}."))
        for label, path, hint in (("Read grid health", f"/api/{conn.api_version}/grid/health", "Give the portal's grid group the permission to read health and metrics."),
                                  ("List tenant accounts", f"/api/{conn.api_version}/grid/accounts?limit=1", "Give the portal's grid group the 'Tenant accounts' permission.")):
            try:
                st, doc = _json_request(node.host, node.port, ctx, timeout, "GET", path, token=token)
            except (OSError, http.client.HTTPException) as e:
                steps.append(_step(area, target, label, FAIL, f"{type(e).__name__}: {e}", ""))
                continue
            if st == 200:
                steps.append(_step(area, target, label, OK, "Allowed."))
            elif st in (401, 403):
                steps.append(_step(area, target, label, FAIL, f"HTTP {st}. {_grid_message(doc)}", hint))
            else:
                steps.append(_step(area, target, label, WARN, f"HTTP {st}. {_grid_message(doc)}",
                                   "Unexpected answer. Run the API conformance check to see whether this call exists on your release."))
    for ep in conn.endpoints:
        u = urlparse(ep.url)
        host, port = u.hostname, u.port or 443
        area, target = f"S3 endpoint {ep.name}", f"{host}:{port}"
        if not _check_tls(area, host, port, ctx, timeout, steps):
            continue
        try:
            c = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
            c.request("GET", "/", headers={"Accept": "application/xml"})
            r = c.getresponse()
            r.read(100_000)
            hdrs = {k.lower() for k, _ in r.getheaders()}
            c.close()
            if any(h.startswith("x-amz-") for h in hdrs) or r.status in (200, 403):
                steps.append(_step(area, target, "Answers as an S3 service", OK,
                                   f"HTTP {r.status} without credentials, which is expected." if r.status == 403 else f"HTTP {r.status}."))
            else:
                steps.append(_step(area, target, "Answers as an S3 service", WARN, f"HTTP {r.status}, no S3 headers.",
                                   "Check that this address is the S3 gateway (load balancer) endpoint and not another service."))
        except (OSError, http.client.HTTPException) as e:
            steps.append(_step(area, target, "Answers as an S3 service", FAIL, f"{type(e).__name__}: {e}", "The endpoint did not answer."))
    if not conn.nodes:
        steps.append(_step("Configuration", "", "Admin nodes", FAIL, "No admin node is set.", "Enter at least one admin node."))
    return steps


def simulate(conn) -> list[dict]:
    """Demo mode: illustrative results. Nothing is contacted."""
    steps = []
    for n in conn.nodes:
        a, t = f"Admin node {n.name}", f"{n.host}:{n.port}"
        steps += [_step(a, t, "Network connection", OK, "Simulated."), _step(a, t, "Certificate check", OK, "Simulated: TLSv1.3, valid for 400 days."),
                  _step(a, t, "Management API version", OK, f"{conn.api_version} is supported (simulated).")]
    if conn.nodes:
        steps += [_step(f"Admin node {conn.nodes[0].name}", f"{conn.nodes[0].host}:{conn.nodes[0].port}", "Sign-in", OK, "Simulated."),
                  _step(f"Admin node {conn.nodes[0].name}", "", "List tenant accounts", OK, "Simulated.")]
    for e in conn.endpoints:
        u = urlparse(e.url)
        steps.append(_step(f"S3 endpoint {e.name}", f"{u.hostname}:{u.port or 443}", "Answers as an S3 service", OK, "Simulated."))
    return steps


def summary(steps: list[dict]) -> dict:
    bad = sum(1 for s in steps if s["status"] == FAIL)
    warn = sum(1 for s in steps if s["status"] == WARN)
    return {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ok": bad == 0, "failed": bad, "warnings": warn,
            "checks": len(steps), "steps": steps}
