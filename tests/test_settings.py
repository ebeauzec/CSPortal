"""Admin settings, the storage grid connection page, the connection checker and admin-node failover.

The checker and the connector are run against a fake StorageGRID admin node that speaks real TLS on a local port,
so the network code is exercised (the real grid is not available to the tests)."""
import datetime as dt
import http.server
import io
import json
import ssl
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from csportal import settings as S
from csportal.backends import gridcheck
from csportal.backends.base import BackendError
from csportal.backends.storagegrid import StorageGridBackend

from helpers import Env, free_port

ADMIN = "admin@demo.example"
OPS = "ops@demo.example"
GRID_PW = "Grid-Test-Pw-2026!"      # check-repo-ok: test value for a fake grid


def make_cert(cn="localhost"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


class FakeGrid:
    """A tiny StorageGRID admin node and S3 gateway: just enough of the API for the connection checks."""

    def __init__(self, password=GRID_PW):
        self.cert_pem, key_pem = make_cert()
        self.dir = tempfile.mkdtemp(prefix="fakegrid-")
        cf, kf = Path(self.dir, "c.pem"), Path(self.dir, "k.pem")
        cf.write_text(self.cert_pem)
        kf.write_text(key_pem)
        self.password, self.hits = password, []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, doc=None, headers=None):
                body = json.dumps(doc if doc is not None else {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.hits.append(("GET", self.path))
                if self.path == "/api/versions":
                    return self._send(200, {"data": ["v3", "v4"]})
                if self.path.startswith("/api/v4/grid/health") or self.path.startswith("/api/v4/grid/accounts"):
                    return self._send(200 if self.headers.get("Authorization") == "Bearer tok123" else 401, {"data": []})
                if self.path == "/":
                    return self._send(403, {}, {"x-amz-request-id": "1"})
                self._send(404)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                doc = json.loads(self.rfile.read(n) or b"{}")
                outer.hits.append(("POST", self.path))
                if self.path == "/api/v4/authorize":
                    if doc.get("password") == outer.password and doc.get("username") == "portal":
                        return self._send(200, {"data": "tok123"})
                    return self._send(401, {"message": {"text": "Invalid credentials"}})
                self._send(404)

        self.port = free_port()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def conn(self, **kw):
        base = dict(nodes=[S.AdminNode("fake", "127.0.0.1", self.port)], api_version="v4", account_id="0", username="portal", ca_pem=self.cert_pem,
                    endpoints=[S.S3Endpoint("s3", f"https://127.0.0.1:{self.port}")], timeout=5)
        base.update(kw)
        return S.GridConn(**base)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ParsingTests(unittest.TestCase):
    def test_nodes(self):
        nodes, errs = S.parse_nodes("primary, gw1.example.net:8443\n192.0.2.12\n# comment\n[2001:db8::1]:443")
        self.assertEqual(errs, [])
        self.assertEqual([(n.name, n.host, n.port) for n in nodes], [("primary", "gw1.example.net", 8443), ("admin-node-2", "192.0.2.12", 443),
                                                                     ("admin-node-3", "2001:db8::1", 443)])
        self.assertEqual(S.parse_nodes("")[1][0][:12], "Enter at lea")
        for bad in ("host:99999", "bad host!", "0.0.0.0", "a, b, c d", "x\nx"):
            self.assertTrue(S.parse_nodes(bad)[1], bad)
        self.assertTrue(S.parse_nodes("127.0.0.1")[1])                  # loopback refused outside demo mode
        self.assertFalse(S.parse_nodes("127.0.0.1", demo=True)[1])
        self.assertEqual(S.parse_nodes("169.254.169.254")[1] != [], True)

    def test_endpoints(self):
        eps, errs = S.parse_endpoints("main | https://s3.example.net | us-east-1 | HA group\nhttps://s3b.example.net:8082")
        self.assertEqual(errs, [])
        self.assertEqual([(e.name, e.url, e.region) for e in eps], [("main", "https://s3.example.net", "us-east-1"), ("s3-endpoint-2", "https://s3b.example.net:8082", "us-east-1")])
        for bad in ("http://s3.example.net", "https://s3.example.net/path", "https://user@s3.example.net", "x | https://s3.example.net | Bad Region"):
            self.assertTrue(S.parse_endpoints(bad)[1], bad)

    def test_certificates(self):
        pem, key = make_cert()
        infos, err = S.cert_infos(pem + "\n" + pem)
        self.assertEqual((len(infos), err), (2, ""))
        self.assertTrue(infos[0]["is_ca"] and len(infos[0]["sha256"]) == 95)
        self.assertIn("private key", S.cert_infos(pem + key)[1])
        self.assertTrue(S.cert_infos("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")[1])
        self.assertTrue(S.cert_infos("just some text")[1])

    def test_values(self):
        p = S.BY_KEY["session.idle_minutes"]
        self.assertEqual(S.parse_value(p, "30")[0], 30)
        self.assertTrue(S.parse_value(p, "2")[1] and S.parse_value(p, "abc")[1] and S.parse_value(p, "9999")[1])
        u = S.BY_KEY["public_url"]
        self.assertTrue(S.parse_value(u, "http://portal.example.net")[1])
        self.assertFalse(S.parse_value(u, "http://portal.example.net", demo=True)[1])
        self.assertEqual(S.parse_value(u, "https://portal.example.net/")[0], "https://portal.example.net")


class ConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grid = FakeGrid()

    @classmethod
    def tearDownClass(cls):
        cls.grid.close()

    def status(self, steps, check):
        return [s["status"] for s in steps if s["check"] == check]

    def test_all_checks_pass(self):
        steps = gridcheck.diagnose(self.grid.conn(), GRID_PW)
        self.assertEqual(gridcheck.summary(steps)["failed"], 0, steps)
        for c in ("Network connection", "Certificate check", "Management API version", "Sign-in", "Read grid health", "List tenant accounts", "Answers as an S3 service"):
            self.assertIn("ok", self.status(steps, c), c)

    def test_untrusted_certificate_shows_what_was_presented(self):
        seen = len(self.grid.hits)
        steps = gridcheck.diagnose(self.grid.conn(ca_pem=""), GRID_PW)
        bad = [s for s in steps if s["check"] == "Certificate check" and s["status"] == "fail"]
        self.assertTrue(bad)
        self.assertIn("SHA-256", bad[0]["detail"])
        self.assertIn("CA certificate", bad[0]["hint"])
        self.assertNotIn("Sign-in", [s["check"] for s in steps])
        self.assertEqual(self.grid.hits[seen:], [])        # no request at all reached the server over the unverified path

    def test_wrong_password_and_missing_password(self):
        steps = gridcheck.diagnose(self.grid.conn(), "wrong-password")
        self.assertEqual(self.status(steps, "Sign-in"), ["fail"])
        self.assertNotIn("wrong-password", json.dumps(steps))
        self.assertIn("No password", json.dumps(gridcheck.diagnose(self.grid.conn(), "")))

    def test_dead_node_and_wrong_api_version(self):
        dead = free_port()
        steps = gridcheck.diagnose(self.grid.conn(nodes=[S.AdminNode("dead", "127.0.0.1", dead)], endpoints=[]), GRID_PW)
        self.assertEqual(self.status(steps, "Network connection"), ["fail"])
        steps = gridcheck.diagnose(self.grid.conn(api_version="v9", endpoints=[]), GRID_PW)
        self.assertEqual(self.status(steps, "Management API version"), ["fail"])
        self.assertIn("v3", steps[-1]["detail"])

    def test_connector_fails_over_to_the_next_admin_node(self):
        dead = free_port()
        conn = self.grid.conn(nodes=[S.AdminNode("dead", "127.0.0.1", dead), S.AdminNode("fake", "127.0.0.1", self.grid.port)])
        be = StorageGridBackend(conn, lambda: GRID_PW)
        h = be.health()
        self.assertTrue(h["ok"], h)
        self.assertTrue(be.base.endswith(str(self.grid.port)))             # moved to the second node and stays there
        self.assertEqual(be.endpoints("x")["regions"], ["us-east-1"])
        self.assertEqual(be.endpoints("x")["details"][0]["name"], "s3")
        self.assertTrue(be._token("grid"))                                    # signs in with the stored password

    def test_connector_without_nodes_says_so(self):
        be = StorageGridBackend(S.GridConn(), lambda: "")
        self.assertFalse(be.health()["ok"])
        with self.assertRaises(BackendError) as cm:
            be.grid_overview()
        self.assertEqual(cm.exception.code, "not_configured")


class ConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.app = cls.env.app

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        self.app.auth.limiter._hits.clear()
        self.a = self.env.client("admin")
        self.a.login(ADMIN)

    def audit_has(self, action, text=""):
        return any(r["action"] == action and text in (r["detail"] or "") for r in self.app.db.all("SELECT * FROM audit ORDER BY id DESC LIMIT 50"))

    def test_all_settings_page_lists_everything(self):
        st, page = self.a.get("/settings")
        self.assertEqual(st, 200)
        for text in ("Customer portal address", "Sign out after idle minutes", "Failed sign-ins before lock-out", "Log level", "Mail relay host",
                     "Usage sampling interval", "Storage connector", "Grid connection", "Master key", "Mail relay password", "Configuration file only"):
            self.assertIn(text, page, text)

    def test_change_a_setting_and_reset_it(self):
        self.assertEqual(self.a.post_form("/settings/edit/sessions", "/settings/edit/sessions", {"session__idle_minutes": "20", "session__absolute_hours": "8"})[0], 200)
        self.assertEqual(self.app.cfg.d["session"]["idle_minutes"], 20)
        self.assertTrue(self.audit_has("settings.update", "session.idle_minutes: 30 -> 20"))
        _, page = self.a.get("/settings")
        self.assertIn("console", page)
        _, page = self.a.post_form("/settings", "/settings/reset", {"key": "session.idle_minutes"})
        self.assertEqual(self.app.cfg.d["session"]["idle_minutes"], 30)
        self.assertTrue(self.audit_has("settings.reset"))

    def test_invalid_value_is_refused(self):
        _, page = self.a.post_form("/settings/edit/sessions", "/settings/edit/sessions", {"session__idle_minutes": "1", "session__absolute_hours": "8"})
        self.assertIn("must be between", page)
        self.assertNotEqual(self.app.cfg.d["session"]["idle_minutes"], 1)

    def test_weakening_security_is_flagged_and_audited(self):
        self.a.post_form("/settings/edit/security", "/settings/edit/security",
                         {"security__lockout_attempts": "5", "security__lockout_minutes": "15", "security__min_password_length": "12",
                          "security__audit_retention_days": "2555"})                       # checkbox absent: MFA no longer required
        try:
            self.assertFalse(self.app.cfg.d["security"]["customer_mfa_required"])
            self.assertTrue(self.audit_has("settings.update", "WEAKENED"))
            _, page = self.a.get("/settings")
            self.assertIn("not required to use multi-factor", page)
        finally:
            self.a.post_form("/settings", "/settings/reset", {"key": "security.customer_mfa_required"})
        self.assertTrue(self.app.cfg.d["security"]["customer_mfa_required"])

    def test_live_security_values_reach_the_running_service(self):
        self.a.post_form("/settings/edit/security", "/settings/edit/security",
                         {"security__customer_mfa_required": "1", "security__lockout_attempts": "7", "security__lockout_minutes": "15",
                          "security__min_password_length": "14", "security__audit_retention_days": "2555"})
        try:
            self.assertEqual((self.app.auth.lock_n, self.app.auth.min_len), (7, 14))
        finally:
            for k in ("security.lockout_attempts", "security.min_password_length"):
                self.a.post_form("/settings", "/settings/reset", {"key": k})
        self.assertEqual(self.app.auth.lock_n, 5)

    def test_grid_page_shows_everything_for_the_grid_administrators(self):
        st, page = self.a.get("/grid")
        self.assertEqual(st, 200)
        for text in ("192.0.2.11", "192.0.2.12", "s3.example.net", "For the grid administrators", "Tenant accounts", "Network rules",
                     "csportal-service", "Download this sheet", "Certificates the portal trusts", "used for bucket settings"):
            self.assertIn(text, page, text)
        st, sheet = self.a.get("/grid/handover.txt")
        self.assertEqual(st, 200)
        self.assertIn("STORAGE GRID CONNECTION SHEET", sheet)
        self.assertIn("192.0.2.11", sheet)

    def test_grid_settings_save_password_stays_secret(self):
        form = {"nodes": "main, 192.0.2.50:8443\nbackup, 192.0.2.51", "api_version": "v4", "account_id": "0", "username": "portal",
                "password": GRID_PW, "ca_pem": "", "source_address": "198.51.100.77", "timeout": "15",
                "endpoints": "gw | https://s3.example.org:8082 | eu-west-1 | main gateway"}
        st, page = self.a.post_form("/grid", "/grid", form)
        self.assertEqual(st, 200)
        self.assertIn("192.0.2.50", page)
        conn = S.load_grid(self.app.cfg, self.app.db)
        self.assertEqual([(n.host, n.port) for n in conn.nodes], [("192.0.2.50", 8443), ("192.0.2.51", 443)])
        self.assertEqual(conn.endpoints[0].region, "eu-west-1")
        self.assertEqual(S.grid_password(self.app.cfg, self.app.db, self.app.box), GRID_PW)
        raw = self.app.db.one("SELECT sealed FROM secrets WHERE name=?", (S.GRID_SECRET,))["sealed"]
        self.assertNotIn(GRID_PW, raw)                                               # stored encrypted
        self.assertTrue(self.audit_has("grid.settings.update", "192.0.2.50"))
        self.assertFalse(any(GRID_PW in (r["detail"] or "") for r in self.app.db.all("SELECT detail FROM audit")))
        for path in ("/grid", "/grid/handover.txt", "/settings"):
            self.assertNotIn(GRID_PW, self.a.get(path)[1], path)
        from csportal.modules.system import build_bundle
        z = zipfile.ZipFile(io.BytesIO(build_bundle(self.app)))
        self.assertNotIn(GRID_PW, "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist()))
        self.assertIn("grid_connection.json", z.namelist())
        # leaving the password empty keeps it
        form["password"] = ""
        self.a.post_form("/grid", "/grid", form)
        self.assertEqual(S.grid_password(self.app.cfg, self.app.db, self.app.box), GRID_PW)

    def test_grid_settings_errors_keep_the_typed_values(self):
        st, page = self.a.post_form("/grid", "/grid", {"nodes": "bad host!", "api_version": "v4", "account_id": "0", "username": "portal",
                                                       "password": "", "ca_pem": "", "timeout": "15", "endpoints": "http://insecure.example.net"})
        self.assertIn("Admin node line 1", page)
        self.assertIn("Endpoint line 1", page)
        self.assertIn("bad host!", page)

    def test_a_private_key_is_never_accepted_as_a_certificate(self):
        pem, key = make_cert()
        _, page = self.a.post_form("/grid", "/grid", {"nodes": "a, 192.0.2.60", "api_version": "v4", "account_id": "0", "username": "portal", "password": "",
                                                      "ca_pem": pem + key, "timeout": "15", "endpoints": "https://s3.example.net"})
        self.assertIn("contains a private key", page)

    def test_test_button_in_demo_is_simulated_and_saves_nothing(self):
        before = self.app.db.one("SELECT value FROM settings WHERE key='grid.conn'")
        st, page = self.a.post_form("/grid", "/grid/test", {"nodes": "a, 192.0.2.70", "api_version": "v4", "account_id": "0", "username": "portal", "password": "",
                                                            "ca_pem": "", "timeout": "15", "endpoints": "https://s3.example.net"})
        self.assertIn("have <strong>not</strong> been saved", page)
        self.assertIn("Simulated", page)
        after = self.app.db.one("SELECT value FROM settings WHERE key='grid.conn'")
        self.assertEqual(before and before["value"], after and after["value"])

    def test_only_super_administrators_may_change_settings(self):
        o = self.env.client("admin")
        o.login(OPS)
        self.assertEqual(o.get("/grid")[0], 200)                        # operations can look
        self.assertEqual(o.get("/settings")[0], 200)
        self.assertEqual(o.get("/settings/edit/sessions")[0], 403)
        self.assertEqual(o.post_form("/grid", "/grid", {"nodes": "x"})[0], 403)
        self.assertEqual(o.post_form("/settings", "/settings/reset", {"key": "public_url"})[0], 403)

    def test_console_values_apply_when_the_service_starts(self):
        from csportal import config as cfgmod
        self.app.db.set_setting("cfg.session.idle_minutes", "25")
        cfg = cfgmod.load(None, {"mode": "demo", "data_dir": str(self.app.cfg.data_dir)})
        self.assertEqual(S.apply_overrides(cfg, self.app.db), [])
        self.assertEqual(cfg.d["session"]["idle_minutes"], 25)
        self.assertEqual(S.source_of(cfg, self.app.db, S.BY_KEY["session.idle_minutes"]), "console")
        self.app.db.set_setting("cfg.session.idle_minutes", "9999")        # a bad stored value is skipped, not applied
        cfg2 = cfgmod.load(None, {"mode": "demo", "data_dir": str(self.app.cfg.data_dir)})
        self.assertTrue(S.apply_overrides(cfg2, self.app.db))
        self.assertEqual(cfg2.d["session"]["idle_minutes"], 30)
        self.app.db.run("DELETE FROM settings WHERE key='cfg.session.idle_minutes'")


if __name__ == "__main__":
    unittest.main()
