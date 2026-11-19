"""HTTP layer: request/response, router, security pipeline, two surfaces, access log.

Security pipeline for every request (see docs/SECURITY.md): host and origin checks, session lookup,
MFA gate, CSRF check on every POST, permission check, module entitlement, then the handler.
"""
from __future__ import annotations

import hmac
import http.server
import json
import logging
import re
import socketserver
import ssl
import threading
import time
import traceback
import urllib.parse
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Callable

from .. import logs
from ..backends.base import BackendError
from ..util import esc, new_id

log = logging.getLogger("csportal")
alog = logging.getLogger("csportal.access")
seclog = logging.getLogger("csportal.security")

STATIC_DIR = Path(__file__).parent / "static"
_STATIC_OK = {"app.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8",
              "favicon.svg": "image/svg+xml"}
MAX_BODY = 1024 * 1024


class Raw(str):
    """Marks a string as trusted HTML. Everything else is escaped on output."""


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    headers: list = field(default_factory=list)
    ctype: str = "text/html; charset=utf-8"

    def header(self, k: str, v: str) -> "Response":
        self.headers.append((k, v))
        return self


def html_response(body: str, status: int = 200) -> Response:
    return Response(status, body.encode("utf-8"))


def redirect(loc: str, status: int = 303) -> Response:
    return Response(status, b"", [("Location", loc)])


def json_response(obj, status: int = 200) -> Response:
    return Response(status, json.dumps(obj).encode(), ctype="application/json")


def text_response(s: str, ctype: str = "text/plain; charset=utf-8", status: int = 200, filename: str = "") -> Response:
    r = Response(status, s.encode("utf-8"), ctype=ctype)
    if filename:
        r.header("Content-Disposition", f'attachment; filename="{filename}"')
    return r


@dataclass
class Request:
    method: str
    path: str
    query: dict
    form: dict
    headers: dict
    cookies: dict
    ip: str
    surface: str
    rid: str
    host: str = ""


class Ctx:
    """Everything a handler needs. Customer-surface handlers get a customer-scoped data accessor."""

    def __init__(self, app, req: Request, sess, params: dict, customer, route):
        self.app, self.req, self.sess, self.params, self.customer, self.route = app, req, sess, params, customer, route
        self.cfg, self.db, self.auth, self.backend = app.cfg, app.db, app.auth, app.backend
        self._scoped = None

    @property
    def scoped(self):
        if self.customer is None:
            raise PermissionError("no customer in scope")
        if self._scoped is None:
            self._scoped = self.db.for_customer(self.customer["id"])
        return self._scoped

    @property
    def ref(self) -> str:
        return self.customer["tenant_ref"]

    def f(self, name: str, default: str = "") -> str:
        return (self.req.form.get(name, default) or "").strip()

    def q(self, name: str, default: str = "") -> str:
        return self.req.query.get(name, default)

    def can(self, perm: str) -> bool:
        return bool(self.sess) and perm in self.sess.perms

    def flash(self, msg: str) -> None:
        if self.sess:
            self.auth.set_flash(self.sess, msg)

    def audit(self, action: str, target: str = "", detail: str = "") -> None:
        kind = "user"
        actor = self.sess.email if self.sess else "anonymous"
        cid = self.customer["id"] if self.customer else None
        self.app.audit.record(action, actor, kind, cid, target, detail, self.req.ip)


@dataclass
class Route:
    surface: str
    method: str
    pattern: re.Pattern
    handler: Callable
    perm: str | None
    module: str | None
    public: bool
    mfa_exempt: bool
    raw: str


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", path) + "$")


class Router:
    def __init__(self):
        self.routes: list[Route] = []

    def add(self, surface: str, method: str, path: str, handler, perm=None, module=None, public=False, mfa_exempt=False):
        for s in (["customer", "admin"] if surface == "both" else [surface]):
            self.routes.append(Route(s, method.upper(), _compile(path), handler, perm, module, public, mfa_exempt, path))

    def match(self, surface: str, method: str, path: str):
        path_known = False
        for r in self.routes:
            if r.surface != surface:
                continue
            m = r.pattern.match(path)
            if m:
                path_known = True
                if r.method == method:
                    return r, {k: urllib.parse.unquote(v) for k, v in m.groupdict().items()}, True
        return None, {}, path_known


SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
                                "frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # "same-origin" keeps URLs (which can hold invitation tokens) from ever leaving the site, while still letting
    # browsers send a real Origin header on form posts ("no-referrer" makes them send "null").
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

_TOKEN_PATH = re.compile(r"(/(?:invite|reset)/)[^/?\s]+")


def safe_path(p: str) -> str:
    return _TOKEN_PATH.sub(r"\1[REDACTED]", p)


class App:
    """Holds the services and dispatches requests. One App serves both surfaces."""

    def __init__(self, cfg, db, audit, auth, box, backend):
        self.cfg, self.db, self.audit, self.auth, self.box, self.backend = cfg, db, audit, auth, box, backend
        self.router = Router()
        self.modules: dict[str, dict] = {}
        self.started = time.time()
        self.log_dir = None
        self.job_runner = None

    # ---------------------------------------------------------------- registration
    def route(self, surface, method, path, perm=None, module=None, public=False, mfa_exempt=False):
        def deco(fn):
            self.router.add(surface, method, path, fn, perm, module, public, mfa_exempt)
            return fn
        return deco

    def register_module(self, manifest: dict):
        self.modules[manifest["id"]] = manifest

    # ---------------------------------------------------------------- entitlement
    def module_globally_on(self, mid: str) -> bool:
        m = self.modules.get(mid)
        if not m:
            return False
        if m.get("core"):
            return True
        off = json.loads(self.db.setting("modules_off", "[]"))
        return mid not in off

    def customer_has_module(self, customer, mid: str) -> bool:
        if not self.module_globally_on(mid):
            return False
        if self.modules[mid].get("core"):
            return True
        plan = self.db.one("SELECT modules FROM plans WHERE id=?", (customer["plan_id"],))
        if not plan or mid not in json.loads(plan["modules"]):
            return False
        return mid not in json.loads(customer["modules_off"] or "[]")

    def entitlement_report(self, customer) -> list[dict]:
        plan = self.db.one("SELECT modules FROM plans WHERE id=?", (customer["plan_id"],))
        in_plan = json.loads(plan["modules"]) if plan else []
        off = json.loads(customer["modules_off"] or "[]")
        out = []
        for mid, m in sorted(self.modules.items()):
            if "customer" not in m["surfaces"] or m.get("core"):
                continue
            why = ("disabled by the service provider" if not self.module_globally_on(mid)
                   else "not in the plan" if mid not in in_plan
                   else "switched off for this customer" if mid in off else "")
            out.append({"id": mid, "name": m["name"], "on": not why, "why": why})
        return out

    # ---------------------------------------------------------------- dispatch
    def handle(self, req: Request) -> Response:
        t0 = time.monotonic()
        logs.request_id.set(req.rid)
        try:
            resp = self._dispatch(req)
        except Exception:  # last line of defence
            log.exception("unhandled error", extra={"fields": {"path": safe_path(req.path)}})
            resp = html_response(self.error_page(500, "Something went wrong",
                                 f"The error was recorded. Quote reference {req.rid} when you contact support."), 500)
        for k, v in SECURITY_HEADERS.items():
            if not any(h[0].lower() == k.lower() for h in resp.headers):
                resp.header(k, v)
        if self.cfg.secure_cookies:
            resp.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        resp.header("X-Request-Id", req.rid)
        logs.event(alog, logging.INFO, "request", method=req.method, path=safe_path(req.path), status=resp.status,
                   ms=int((time.monotonic() - t0) * 1000), ip=req.ip, surface=req.surface)
        return resp

    def error_page(self, code: int, title: str, msg: str) -> str:
        from . import ui
        return ui.bare_page(self, f"{code} {title}", f"<h1>{esc(title)}</h1><p>{esc(msg)}</p><p><a href=\"/\">Back to start</a></p>")

    def _dispatch(self, req: Request) -> Response:
        from . import ui
        if req.method == "HEAD":
            req.method = "GET"
        if req.method not in ("GET", "POST"):
            return html_response(self.error_page(405, "Method not allowed", "This request type is not supported."), 405)
        if req.surface == "admin" and any(h.startswith("x-forwarded-") for h in req.headers) \
                and not self.cfg.get("admin_allow_proxy", default=False):
            logs.event(seclog, logging.WARNING, "admin console request via proxy refused", ip=req.ip)
            return html_response(self.error_page(403, "Not available here", "The admin console is not available through this address."), 403)
        if req.path.startswith("/static/"):
            return self._static(req.path[8:])
        if req.path == "/brand.css":
            return Response(200, ui.brand_css(self).encode(), ctype="text/css; charset=utf-8").header("Cache-Control", "no-cache")
        if req.path == "/healthz":
            return json_response({"status": "ok", "surface": req.surface, "uptime_s": int(time.time() - self.started)})

        route, params, path_known = self.router.match(req.surface, req.method, req.path)
        if not route:
            if path_known:
                return html_response(self.error_page(405, "Method not allowed", "This request type is not supported."), 405)
            return html_response(self.error_page(404, "Page not found", "That page does not exist."), 404)

        # Host / origin: a state-changing request must come from the same site.
        if req.method == "POST":
            origin = req.headers.get("origin", "")
            if origin and urllib.parse.urlparse(origin).netloc != req.host:
                logs.event(seclog, logging.WARNING, "cross-origin POST refused", origin=origin, ip=req.ip)
                return html_response(self.error_page(403, "Request refused", "The request did not come from this site."), 403)

        cookie_name = self.cookie_name(req.surface)
        sess = self.auth.session(req.cookies.get(cookie_name), req.surface)
        if not route.public:
            if not sess:
                if req.method == "GET":
                    return redirect("/login?next=" + urllib.parse.quote(req.path))
                return html_response(self.error_page(401, "Signed out", "Your session has ended. Sign in again."), 401)
            if not sess.mfa_ok and not route.mfa_exempt:
                return redirect("/mfa")
        if req.method == "POST":
            if route.public:
                pre = req.cookies.get(self.pre_cookie_name(req.surface), "")
                if not pre or not hmac.compare_digest(pre, req.form.get("_csrf", "")):
                    return html_response(self.error_page(403, "Request refused", "The form has expired. Go back, reload it and try again."), 403)
            elif not hmac.compare_digest(sess.csrf, req.form.get("_csrf", "")):
                logs.event(seclog, logging.WARNING, "csrf check failed", ip=req.ip, path=safe_path(req.path))
                return html_response(self.error_page(403, "Request refused", "The form has expired. Go back, reload it and try again."), 403)

        customer = None
        if req.surface == "customer" and sess:
            customer = self.db.one("SELECT * FROM customers WHERE id=?", (sess.customer_id,))
            if not customer:
                return redirect("/logout")
        if route.perm and (not sess or route.perm not in sess.perms):
            logs.event(seclog, logging.WARNING, "permission denied", perm=route.perm,
                       account=sess.email if sess else "", ip=req.ip, path=safe_path(req.path))
            return html_response(ui.page(Ctx(self, req, sess, params, customer, route), "Not permitted",
                                         "<p>Your role does not allow this action. Ask an administrator of your account.</p>"), 403)
        if route.module and req.surface == "admin" and not self.module_globally_on(route.module):
            return html_response(ui.page(Ctx(self, req, sess, params, customer, route), "Module is off",
                                         "<p>This module is switched off. A super administrator can switch it on under Modules.</p>"), 404)
        if route.module and customer and not self.customer_has_module(customer, route.module):
            return html_response(ui.page(Ctx(self, req, sess, params, customer, route), "Not available",
                                         "<p>This feature is not part of your plan. Contact support to add it.</p>"), 404)
        ctx = Ctx(self, req, sess, params, customer, route)
        try:
            resp = route.handler(ctx)
        except BackendError as e:
            logs.event(log, logging.WARNING, "back-end error", code=e.code, status=e.status, message=e.message,
                       path=safe_path(req.path))
            if req.method == "POST" and sess:
                ctx.flash("Error: " + e.message)
                back = urllib.parse.urlparse(req.headers.get("referer", ""))
                return redirect(back.path if back.netloc == req.host and back.path.startswith("/") else "/")
            return html_response(ui.page(ctx, "Service problem", f"<p>{esc(e.message)}</p><p class=\"muted\">Reference {esc(req.rid)}</p>"),
                                 503 if e.status >= 500 or e.status == 0 else 400)
        if isinstance(resp, str):
            resp = html_response(resp)
        return resp

    def cookie_name(self, surface: str) -> str:
        return ("__Host-" if self.cfg.secure_cookies else "") + ("cp_session" if surface == "customer" else "ap_session")

    def pre_cookie_name(self, surface: str) -> str:
        return ("__Host-" if self.cfg.secure_cookies else "") + ("cp_pre" if surface == "customer" else "ap_pre")

    def session_cookie(self, surface: str, token: str, max_age: int | None = None) -> str:
        parts = [f"{self.cookie_name(surface)}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if self.cfg.secure_cookies:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

    def pre_cookie(self, surface: str, token: str) -> str:
        parts = [f"{self.pre_cookie_name(surface)}={token}", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=3600"]
        if self.cfg.secure_cookies:
            parts.append("Secure")
        return "; ".join(parts)

    def _static(self, name: str) -> Response:
        if name not in _STATIC_OK:
            return html_response(self.error_page(404, "Not found", "No such file."), 404)
        p = STATIC_DIR / name
        r = Response(200, p.read_bytes(), ctype=_STATIC_OK[name])
        r.header("Cache-Control", "public, max-age=3600")
        return r


# -------------------------------------------------------------------------- server
def make_handler(app: App, surface: str, trust_proxy: bool):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "CSPortal"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 30

        def log_message(self, *a):      # replaced by the access log
            pass

        def _serve(self):
            parsed = urllib.parse.urlsplit(self.path)
            headers = {k.lower(): v for k, v in self.headers.items()}
            ip = self.client_address[0]
            if trust_proxy and surface == "customer" and headers.get("x-forwarded-for"):
                ip = headers["x-forwarded-for"].split(",")[0].strip()[:45]
            form: dict = {}
            if self.command == "POST":
                try:
                    n = int(headers.get("content-length", "0"))
                except ValueError:
                    n = -1
                if n < 0 or n > MAX_BODY:
                    self._send(Response(413, b"Request too large", ctype="text/plain"), close=True)
                    return
                body = self.rfile.read(n) if n else b""
                ct = headers.get("content-type", "")
                if ct.startswith("application/x-www-form-urlencoded"):
                    form = {k: v[-1] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace"),
                                                                       keep_blank_values=True, max_num_fields=200).items()}
                elif n:
                    self._send(Response(415, b"Unsupported content type", ctype="text/plain"), close=True)
                    return
            cookies = {}
            if "cookie" in headers:
                sc = SimpleCookie()
                try:
                    sc.load(headers["cookie"])
                    cookies = {k: m.value for k, m in sc.items()}
                except Exception:
                    cookies = {}
            req = Request(self.command, parsed.path or "/", {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()},
                          form, headers, cookies, ip, surface, new_id("r"), headers.get("host", ""))
            resp = app.handle(req)
            self._send(resp, head=self.command == "HEAD")

        def _send(self, resp: Response, close: bool = False, head: bool = False):
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.ctype)
            self.send_header("Content-Length", str(len(resp.body)))
            for k, v in resp.headers:
                self.send_header(k, v)
            if close:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            if not head:
                self.wfile.write(resp.body)

        do_GET = do_POST = do_HEAD = _serve
        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = lambda self: self._send(
            Response(405, b"Method not allowed", ctype="text/plain"), close=True)

    return Handler


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 64
    allow_reuse_address = True


def start_server(app: App, surface: str, host: str, port: int, cert: str = "", key: str = "",
                 trust_proxy: bool = False) -> Server:
    srv = Server((host, port), make_handler(app, surface, trust_proxy))
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, name=f"http-{surface}", daemon=True)
    t.start()
    logs.event(log, logging.INFO, "listening", surface=surface, host=host, port=port, tls=bool(cert))
    return srv
