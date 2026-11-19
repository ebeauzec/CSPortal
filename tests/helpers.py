"""Test helpers: a demo-mode app on free ports and a tiny cookie-aware HTTP client."""
from __future__ import annotations

import http.client
import re
import shutil
import socket
import tempfile
import urllib.parse
from pathlib import Path

from csportal import config
from csportal.bootstrap import build_app
from csportal.web.core import start_server


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Env:
    def __init__(self, overrides=None):
        self.dir = Path(tempfile.mkdtemp(prefix="csportal-test-"))
        self.cport, self.aport = free_port(), free_port()
        ov = {"mode": "demo", "data_dir": str(self.dir), "backend": {"type": "simulator"},
              "customer_listen": {"host": "127.0.0.1", "port": self.cport},
              "admin_listen": {"host": "127.0.0.1", "port": self.aport},
              "log": {"level": "WARNING"}}
        if overrides:
            ov.update(overrides)
        self.cfg = config.load(None, ov)
        self.app = build_app(self.cfg)
        self.servers = [start_server(self.app, "customer", "127.0.0.1", self.cport),
                        start_server(self.app, "admin", "127.0.0.1", self.aport)]

    def client(self, surface="customer") -> "Client":
        return Client("127.0.0.1", self.cport if surface == "customer" else self.aport)

    def close(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        import logging
        for h in list(logging.getLogger("csportal").handlers) + list(logging.getLogger("csportal.access").handlers):
            h.close()
        shutil.rmtree(self.dir, ignore_errors=True)


class Client:
    def __init__(self, host, port):
        self.host, self.port, self.cookies = host, port, {}
        self.last_headers = {}

    def req(self, method, path, form=None, headers=None, follow=True):
        h = {"Host": f"{self.host}:{self.port}"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        h.update(headers or {})
        c = http.client.HTTPConnection(self.host, self.port, timeout=15)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        self.last_headers = {k.lower(): v for k, v in r.getheaders()}
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, rest = v.partition("=")
                val = rest.split(";")[0]
                if val == "" or "Max-Age=0" in v:
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = val
        c.close()
        if follow and r.status in (301, 302, 303) and "location" in self.last_headers:
            return self.req("GET", self.last_headers["location"])
        return r.status, data

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, form, **kw):
        return self.req("POST", path, form=form, **kw)

    @staticmethod
    def csrf(html: str) -> str:
        m = re.search(r'name="_csrf" value="([^"]+)"', html)
        return m.group(1) if m else ""

    def login(self, email, password="Demo-Portal-2026!"):
        _, page = self.get("/login")
        return self.post("/login", {"_csrf": self.csrf(page), "email": email, "password": password})

    def post_form(self, path_page, path_post, extra):
        """Load a page to get a CSRF token, then POST to path_post."""
        _, page = self.get(path_page)
        return self.post(path_post, {"_csrf": self.csrf(page), **extra})
