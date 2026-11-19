"""Customer controls: bucket access policies, CORS, Object Lock retention, people and roles, scoped groups, key expiry.

Part 1 tests the pure rules. Part 2 runs the StorageGRID connector against a fake TLS grid (simulated: not a real grid).
Part 3 drives the pages of a demo-mode instance.
"""
import base64
import datetime as dt
import hashlib
import http.server
import json
import re
import ssl
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

from csportal import policy
from csportal import settings as S
from csportal.backends import s3sign, s3xml
from csportal.backends.base import BackendError
from csportal.backends.storagegrid import StorageGridBackend

from helpers import Env, free_port
from test_settings import make_cert

ACCT = "12345678901234567890"
ADMIN_C = "dana@riverbend.example"
OTHER_C = "mara@harbourview.example"


class PolicyRules(unittest.TestCase):
    B = "my-bucket"

    def v(self, doc, public=False, acct=ACCT):
        return policy.validate(doc, self.B, acct, public)

    def test_grant_builds_valid_statements_and_removes_cleanly(self):
        who = [policy.principal_arn(ACCT, "group", "analysts")]
        doc, gid = policy.add_grant(None, self.B, who, "read", "reports/2026/")
        self.assertEqual(self.v(doc), [])
        res = [s["Resource"] for s in doc["Statement"]]
        self.assertIn("arn:aws:s3:::my-bucket/reports/2026/*", res)
        listing = [s for s in doc["Statement"] if s["Sid"].endswith("l")][0]
        self.assertEqual(listing["Condition"], {"StringLike": {"s3:prefix": ["reports/2026/*"]}})
        rows = policy.describe(doc, self.B, ACCT)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["who"], rows[0]["what"], rows[0]["scope"]), ("group analysts", "Read", "reports/2026/"))
        self.assertIsNone(policy.remove_grant(doc, gid))

    def test_write_only_has_no_bucket_level_statement(self):
        doc, _ = policy.add_grant(None, self.B, [policy.principal_arn(ACCT, "user", "uploader")], "write-only")
        self.assertEqual(len(doc["Statement"]), 1)
        self.assertNotIn("s3:GetObject", doc["Statement"][0]["Action"])

    def test_rules_refuse_unsafe_policies(self):
        base = {"Effect": "Allow", "Principal": {"AWS": [policy.principal_arn(ACCT, "root")]}, "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"}
        self.assertEqual(self.v({"Statement": [base]}), [])
        other_bucket = dict(base, Resource="arn:aws:s3:::other-bucket/*")
        self.assertTrue(any("not part of bucket" in p for p in self.v({"Statement": [other_bucket]})))
        sneaky = dict(base, Resource="arn:aws:s3:::my-bucket-evil/*")
        self.assertTrue(self.v({"Statement": [sneaky]}))
        foreign = dict(base, Principal={"AWS": "arn:aws:iam::99999999999999999999:root"})
        self.assertTrue(any("other storage accounts" in p for p in self.v({"Statement": [foreign]})))
        self.assertTrue(self.v({"Statement": [dict(base, NotPrincipal={"AWS": "x"})]}))
        self.assertTrue(self.v({"Statement": [dict(base, Action="*")]}))
        self.assertTrue(self.v({"Statement": [dict(base, Condition={"StringEquals": {"aws:PrincipalTag/x": "y"}})]}))
        self.assertTrue(self.v({"Statement": []}))
        self.assertTrue(self.v({"Statement": [dict(base, Effect="Maybe")]}))

    def test_public_access_needs_the_plan_and_is_read_only(self):
        pub = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}
        self.assertTrue(any("not part of your plan" in p for p in self.v({"Statement": [pub]}, public=False)))
        self.assertEqual(self.v({"Statement": [pub]}, public=True), [])
        write = dict(pub, Action=["s3:GetObject", "s3:PutObject"])
        self.assertTrue(any("only allow reading" in p for p in self.v({"Statement": [write]}, public=True)))
        deny = dict(pub, Effect="Deny", Action="s3:*")
        self.assertEqual(self.v({"Statement": [deny]}, public=False), [])         # denying everyone is always fine

    def test_public_and_tls_toggles_keep_other_statements(self):
        doc, _ = policy.add_grant(None, self.B, [policy.principal_arn(ACCT, "user", "a")], "read")
        doc = policy.set_public(doc, self.B, True)
        doc = policy.set_tls_only(doc, self.B, True)
        self.assertTrue(policy.is_public(doc))
        self.assertTrue(policy.requires_tls(doc))
        self.assertEqual(len(doc["Statement"]), 4)
        doc = policy.set_public(doc, self.B, False)
        self.assertFalse(policy.is_public(doc))
        self.assertTrue(policy.requires_tls(doc))
        self.assertEqual(self.v(doc), [])
        self.assertFalse(policy.is_public(policy.set_public(None, self.B, False)))

    def test_parse_limits(self):
        self.assertIsNone(policy.parse("")[0])
        self.assertIsNone(policy.parse("{not json")[0])
        self.assertIsNone(policy.parse("[1]")[0])
        self.assertIsNone(policy.parse('{"a": "' + "x" * (policy.MAX_BYTES + 5) + '"}')[0])
        self.assertEqual(policy.parse('{"Statement": []}')[1], [])

    def test_prefix_is_cleaned(self):
        self.assertEqual(policy.clean_prefix("/a b/<script>*"), "a b/script")


class SignerAndXml(unittest.TestCase):
    def test_signature_matches_the_published_aws_example(self):
        # "GET Bucket lifecycle" from the AWS Signature Version 4 documentation (examplebucket, 2013-05-24).
        h = s3sign.sign("GET", "examplebucket.s3.amazonaws.com", "/", "lifecycle", b"", "AKIAIOSFODNN7EXAMPLE",  # check-repo-ok: published AWS documentation example key
                        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1",  # check-repo-ok: published AWS documentation example key
                        now=dt.datetime(2013, 5, 24, tzinfo=dt.timezone.utc))
        self.assertIn("Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", h["Authorization"])
        self.assertEqual(h["x-amz-content-sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_canonical_query(self):
        self.assertEqual(s3sign.canonical_query("versioning"), "versioning=")
        self.assertEqual(s3sign.canonical_query("b=2&a=1&c"), "a=1&b=2&c=")
        self.assertEqual(s3sign.canonical_query("prefix=a b"), "prefix=a%20b")

    def test_lifecycle_keeps_rules_it_cannot_describe(self):
        xml = (b'<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
               b'<Rule><ID>simple</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>'
               b'<Rule><ID>tiering</ID><Filter><Tag><Key>a</Key><Value>b</Value></Tag></Filter><Status>Enabled</Status>'
               b'<Transition><Days>5</Days><StorageClass>X</StorageClass></Transition></Rule></LifecycleConfiguration>')
        rules = s3xml.lifecycle_from(xml)
        self.assertEqual([r["id"] for r in rules], ["simple", "tiering"])
        self.assertEqual(rules[0]["expire_days"], 30)
        self.assertTrue(rules[1].get("custom"))
        back = s3xml.lifecycle_xml(rules + [{"id": "new", "prefix": "", "noncurrent_days": 7}])
        self.assertIn(b"<Transition>", back)
        self.assertIn(b"<NoncurrentDays>7</NoncurrentDays>", back)
        self.assertEqual([r["id"] for r in s3xml.lifecycle_from(back)], ["simple", "tiering", "new"])

    def test_cors_and_lock_round_trip_and_checks(self):
        rule = {"id": "", "origins": ["https://app.example.com"], "methods": ["GET", "PUT"], "headers": ["Content-Type"], "expose": [], "max_age": 600}
        self.assertEqual(s3xml.cors_from(s3xml.cors_xml([rule]))[0]["origins"], ["https://app.example.com"])
        self.assertEqual(s3xml.cors_problems(rule), [])
        self.assertTrue(s3xml.cors_problems(dict(rule, origins=["javascript:alert(1)"])))
        self.assertTrue(s3xml.cors_problems(dict(rule, methods=["TRACE"])))
        d = {"mode": "COMPLIANCE", "amount": 2, "unit": "years"}
        self.assertEqual(s3xml.objectlock_from(s3xml.objectlock_xml(d)), d)
        self.assertTrue(s3xml.lock_problems({"mode": "COMPLIANCE", "amount": 101, "unit": "years"}))
        self.assertTrue(s3xml.lock_problems({"mode": "NONE", "amount": 1, "unit": "days"}))


class FakeS3Grid:
    """A fake grid: management API for containers and groups, and S3 settings calls that check the signature."""
    KEY, SECRET = "AKTESTKEY", "test-secret-value"      # check-repo-ok: test values for a fake grid

    def __init__(self):
        self.cert_pem, key_pem = make_cert()
        d = tempfile.mkdtemp(prefix="fakes3-")
        cf, kf = Path(d, "c.pem"), Path(d, "k.pem")
        cf.write_text(self.cert_pem)
        kf.write_text(key_pem)
        self.settings: dict[tuple, bytes] = {}
        self.groups: list[dict] = []
        self.bad_signatures = 0
        self.bad_md5 = 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, doc):
                b = json.dumps({"data": doc}).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _raw(self, code, body=b""):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))

            def _s3(self, method):
                body = self._body()
                u = urllib.parse.urlparse(self.path)
                bucket, sub = u.path.strip("/"), u.query
                want = s3sign.sign(method, self.headers["Host"], u.path, u.query, body, outer.KEY, outer.SECRET, "us-east-1",
                                   now=dt.datetime.strptime(self.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc),
                                   md5="Content-MD5" in self.headers)
                if want["Authorization"] != self.headers.get("Authorization"):
                    outer.bad_signatures += 1
                    return self._raw(403)
                if body and self.headers.get("Content-MD5") != base64.b64encode(hashlib.md5(body).digest()).decode():
                    outer.bad_md5 += 1
                    return self._raw(400)
                if method == "PUT":
                    outer.settings[(bucket, sub)] = body
                    return self._raw(200)
                if method == "DELETE":
                    outer.settings.pop((bucket, sub), None)
                    return self._raw(204)
                got = outer.settings.get((bucket, sub))
                return self._raw(200, got) if got is not None else self._raw(404)

            def _mgmt(self, method):
                body = self._body()
                doc = json.loads(body or b"{}")
                p = self.path.split("?")[0]
                if p.endswith("/authorize"):
                    return self._json(200, "tok")
                if p.endswith("/org/containers"):
                    return self._json(200, [{"name": "bkt", "region": "us-east-1", "creationTime": "2026-01-01T00:00:00Z", "s3ObjectLock": {"enabled": True}}])
                if "/grid/accounts/" in p and p.endswith("/usage"):
                    return self._json(200, {"dataBytes": 0, "objectCount": 0, "buckets": []})
                if "/grid/accounts/" in p:
                    return self._json(200, {"policy": {"quotaObjectBytes": 0}})
                if p.endswith("/org/groups") and method == "GET":
                    return self._json(200, outer.groups)
                if p.endswith("/org/groups") and method == "POST":
                    doc["id"] = f"g{len(outer.groups) + 1}"
                    outer.groups.append(doc)
                    return self._json(201, doc)
                if "/org/groups/" in p and method == "PUT":
                    gid = p.rsplit("/", 1)[1]
                    outer.groups[:] = [doc if g["id"] == gid else g for g in outer.groups]
                    return self._json(200, doc)
                self._json(404, {})

            def do_GET(self):
                self._s3("GET") if "x-amz-date" in self.headers else self._mgmt("GET")

            def do_PUT(self):
                self._s3("PUT") if "x-amz-date" in self.headers else self._mgmt("PUT")

            def do_DELETE(self):
                self._s3("DELETE") if "x-amz-date" in self.headers else self._mgmt("DELETE")

            def do_POST(self):
                self._mgmt("POST")

        self.port = free_port()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def backend(self):
        conn = S.GridConn(nodes=[S.AdminNode("fake", "127.0.0.1", self.port)], api_version="v4", account_id="0", username="portal",
                          ca_pem=self.cert_pem, endpoints=[S.S3Endpoint("s3", f"https://127.0.0.1:{self.port}")], timeout=5)
        creds = {"username": "svc", "password": "pw", "s3_key": self.KEY, "s3_secret": self.SECRET}
        return StorageGridBackend(conn, lambda: "pw", lambda ref: creds)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ConnectorSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grid = FakeS3Grid()
        cls.be = cls.grid.backend()

    @classmethod
    def tearDownClass(cls):
        cls.grid.close()

    def test_bucket_settings_round_trip_with_valid_signatures(self):
        be, ref = self.be, ACCT
        doc, _ = policy.add_grant(None, "bkt", [policy.principal_arn(ref, "group", "g")], "read")
        be.update_bucket(ref, "bkt", policy=doc)
        be.update_bucket(ref, "bkt", cors=[{"id": "", "origins": ["https://a.example"], "methods": ["GET"], "headers": [], "expose": [], "max_age": 60}])
        be.update_bucket(ref, "bkt", lifecycle=[{"id": "r", "prefix": "x/", "expire_days": 9}], versioning="enabled")
        be.update_bucket(ref, "bkt", lock_default={"mode": "GOVERNANCE", "amount": 5, "unit": "days"})
        b = be.get_bucket(ref, "bkt")
        self.assertEqual(b["policy"], doc)
        self.assertFalse(b["public"])
        self.assertEqual(b["cors"][0]["origins"], ["https://a.example"])
        self.assertEqual(b["lifecycle"][0]["expire_days"], 9)
        self.assertEqual(b["versioning"], "enabled")
        self.assertEqual(b["lock_default"], {"mode": "GOVERNANCE", "amount": 5, "unit": "days"})
        self.assertEqual(b["notes"], [])
        self.assertEqual((self.grid.bad_signatures, self.grid.bad_md5), (0, 0))

    def test_public_toggle_keeps_the_rest_of_the_policy_and_removing_all_deletes_it(self):
        be, ref = self.be, ACCT
        be.update_bucket(ref, "bkt", policy=policy.set_tls_only(None, "bkt", True))
        be.update_bucket(ref, "bkt", public=True)
        b = be.get_bucket(ref, "bkt")
        self.assertTrue(b["public"] and policy.requires_tls(b["policy"]))
        be.update_bucket(ref, "bkt", public=False)
        be.update_bucket(ref, "bkt", policy=None)
        self.assertNotIn(("bkt", "policy"), self.grid.settings)
        self.assertFalse(be.get_bucket(ref, "bkt")["public"])

    def test_unreadable_settings_are_reported_not_hidden(self):
        bad = self.grid.backend()
        bad.get_creds = lambda ref: {"username": "svc", "password": "pw", "s3_key": "wrong", "s3_secret": "wrong"}
        b = bad.get_bucket(ACCT, "bkt")
        self.assertTrue(b["notes"])
        self.assertIsNone(b["public"])

    def test_group_scope_is_written_and_read_back(self):
        be, ref = self.be, ACCT
        be.create_group(ref, "team", "read-write", ["bkt", "other"])
        be.create_group(ref, "all", "read-only")
        g = {x["name"]: x for x in be.list_groups(ref)}
        self.assertEqual(g["team"]["buckets"], ["bkt", "other"])
        self.assertEqual(g["all"]["buckets"], [])
        self.assertEqual(g["team"]["access"], "read-write")
        stmts = [x for x in self.grid.groups if x["displayName"] == "team"][0]["policies"]["s3"]["Statement"]
        self.assertNotIn("s3:ListAllMyBuckets", json.dumps(stmts))                 # a scoped group can not list the other buckets
        be.update_group(ref, "team", buckets=["bkt"])
        self.assertEqual({x["name"]: x for x in be.list_groups(ref)}["team"]["buckets"], ["bkt"])
        be.update_group(ref, "team", access="read-only")
        t = {x["name"]: x for x in be.list_groups(ref)}["team"]
        self.assertEqual((t["access"], t["buckets"]), ("read-only", ["bkt"]))


class PortalControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.app = cls.env.app

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        self.app.auth.limiter._hits.clear()

    def ref(self, slug):
        return self.app.db.one("SELECT tenant_ref FROM customers WHERE slug=?", (slug,))["tenant_ref"]

    def login(self, email=ADMIN_C):
        c = self.env.client()
        c.login(email)
        return c

    def bucket(self, slug="riverbend", name="riverbend-curated"):
        return self.app.backend.get_bucket(self.ref(slug), name)

    # ------------------------------------------------------------ access policy
    def test_grant_then_revoke_access_to_a_group_inside_a_folder(self):
        c = self.login()
        st, page = c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/grant",
                               {"who": "group:readonly", "level": "read", "prefix": "reports/"})
        self.assertIn("group readonly", page)
        self.assertIn("reports/", page)
        pol = self.bucket()["policy"]
        self.assertEqual(len(pol["Statement"]), 2)
        gid = policy.describe(pol, "riverbend-curated", self.ref("riverbend"))[0]["gid"]
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/revoke", {"gid": gid})
        self.assertIsNone(self.bucket()["policy"])

    def test_grant_to_an_unknown_user_is_refused(self):
        c = self.login()
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/grant", {"who": "user:nobody", "level": "read", "prefix": ""})
        self.assertIsNone(self.bucket()["policy"])

    def test_policy_editor_validates_and_keeps_the_text(self):
        c = self.login()
        evil = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999:root"}, "Action": "s3:*",
                                           "Resource": "arn:aws:s3:::someone-elses-bucket/*"}]})
        st, page = c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/policy", {"policy": evil})
        self.assertEqual(st, 400)
        self.assertIn("The policy was not saved", page)
        self.assertIn("someone-elses-bucket", page)
        self.assertIsNone(self.bucket()["policy"])
        ok = json.dumps({"Statement": [{"Sid": "ro", "Effect": "Allow", "Principal": {"AWS": policy.principal_arn(self.ref("riverbend"), "group", "readonly")},
                                         "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::riverbend-curated/*"}]})
        st, page = c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/policy", {"policy": ok})
        self.assertEqual(st, 200)
        self.assertEqual(self.bucket()["policy"]["Statement"][0]["Sid"], "ro")
        # a statement written by hand can be removed from the page; the check on the Sid stops a stale click
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/revoke", {"index": "0", "sid": "other"})
        self.assertIsNotNone(self.bucket()["policy"])
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/revoke", {"index": "0", "sid": "ro"})
        self.assertIsNone(self.bucket()["policy"])

    def test_starter_plan_cannot_publish_through_the_policy_editor(self):
        c = self.login(OTHER_C)
        c.post_form("/buckets", "/buckets", {"name": "hv-policy-try", "region": "us-east-1"})
        pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::hv-policy-try/*"}]})
        st, page = c.post_form("/buckets/hv-policy-try/access", "/buckets/hv-policy-try/access/policy", {"policy": pub})
        self.assertEqual(st, 400)
        self.assertFalse(self.app.backend.get_bucket(self.ref("harbourview"), "hv-policy-try")["public"])

    def test_public_and_encryption_toggles(self):
        c = self.login()
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/public", {"public": "1"})
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/tls", {"on": "1"})
        b = self.bucket()
        self.assertTrue(b["public"])
        self.assertTrue(policy.requires_tls(b["policy"]))
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/public", {"public": "0"})
        c.post_form("/buckets/riverbend-curated/access", "/buckets/riverbend-curated/access/tls", {"on": "0"})
        b = self.bucket()
        self.assertFalse(b["public"])
        self.assertIsNone(b["policy"])

    def test_access_page_is_not_reachable_across_customers_or_by_read_only_users(self):
        c = self.login(OTHER_C)
        st, _ = c.get("/buckets/riverbend-curated/access")
        self.assertIn(st, (400, 403, 404))
        c.post_form("/buckets", "/buckets/riverbend-curated/access/tls", {"on": "1"})
        self.assertIsNone(self.bucket()["policy"])
        ro = self.login("lee@riverbend.example")
        st, _ = ro.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/access/tls", {"on": "1"})
        self.assertEqual(st, 403)
        st, page = ro.get("/buckets/riverbend-curated/access")
        self.assertEqual(st, 200)
        self.assertNotIn("Validate and save", page)
        # an operator manages buckets and keys, but not who may use them
        op = self.login("omar@riverbend.example")
        st, _ = op.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/access/tls", {"on": "1"})
        self.assertEqual(st, 403)
        st, _ = op.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/public", {"public": "1"})
        self.assertEqual(st, 403)
        st, _ = op.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/cors", {"origins": "https://o.example", "m_GET": "1"})
        self.assertIn(st, (200, 303))
        self.assertIsNone(self.bucket()["policy"])
        self.app.backend.update_bucket(self.ref("riverbend"), "riverbend-curated", cors=[])

    # ------------------------------------------------------------ CORS and Object Lock
    def test_cors_rules(self):
        c = self.login()
        c.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/cors", {"origins": "ftp://nope", "m_GET": "1"})
        self.assertEqual(self.bucket()["cors"], [])
        c.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/cors",
                    {"origins": "https://app.example.com\nhttps://*.example.org", "m_GET": "1", "m_PUT": "1", "headers": "Content-Type, X-Token", "max_age": "300"})
        r = self.bucket()["cors"]
        self.assertEqual((r[0]["origins"], r[0]["methods"], r[0]["headers"], r[0]["max_age"]),
                         (["https://app.example.com", "https://*.example.org"], ["GET", "PUT"], ["Content-Type", "X-Token"], 300))
        c.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/cors/delete", {"index": "0"})
        self.assertEqual(self.bucket()["cors"], [])

    def test_object_lock_default_retention(self):
        c = self.login()
        n = "riverbend-backups"
        c.post_form(f"/buckets/{n}", f"/buckets/{n}/lock", {"mode": "COMPLIANCE", "amount": "1", "unit": "years"})
        self.assertIsNone(self.bucket(name=n)["lock_default"])                       # compliance needs the acknowledgement
        c.post_form(f"/buckets/{n}", f"/buckets/{n}/lock", {"mode": "COMPLIANCE", "amount": "1", "unit": "years", "ack": "1"})
        self.assertEqual(self.bucket(name=n)["lock_default"], {"mode": "COMPLIANCE", "amount": 1, "unit": "years"})
        c.post_form(f"/buckets/{n}", f"/buckets/{n}/lock", {"mode": "GOVERNANCE", "amount": "0", "unit": "days"})
        self.assertEqual(self.bucket(name=n)["lock_default"]["mode"], "COMPLIANCE")  # an invalid change leaves it alone
        c.post_form(f"/buckets/{n}", f"/buckets/{n}/lock/clear", {})
        self.assertIsNone(self.bucket(name=n)["lock_default"])
        c.post_form("/buckets/riverbend-curated", "/buckets/riverbend-curated/lock", {"mode": "GOVERNANCE", "amount": "5", "unit": "days"})
        self.assertIsNone(self.bucket()["lock_default"])                              # not a locked bucket

    # ------------------------------------------------------------ people
    def person(self, email):
        return self.app.db.one("SELECT * FROM users WHERE email=?", (email,))

    def test_roles_invitations_and_sessions(self):
        c = self.login()
        c.post_form("/team", "/team", {"name": "New Person", "email": "new.person@riverbend.example", "role": "read-only"})
        u = self.person("new.person@riverbend.example")
        self.assertEqual((u["role"], u["state"]), ("read-only", "invited"))
        self.assertEqual(self.app.auth.invite_state(u["id"])[0], "open")
        # a second invitation cancels the first link
        c.post_form("/team", "/team/invite", {"uid": u["id"]})
        self.assertEqual(self.app.db.one("SELECT COUNT(*) n FROM invitations WHERE user_id=? AND used=0", (u["id"],))["n"], 1)
        c.post_form("/team", "/team/invite/revoke", {"uid": u["id"]})
        self.assertEqual(self.app.auth.invite_state(u["id"])[0], "none")
        self.assertIn("no link", c.get("/team")[1])
        # change the role of an active person; their sessions end
        ro = self.env.client()
        ro.login("lee@riverbend.example")
        lee = self.person("lee@riverbend.example")
        self.assertEqual(ro.get("/buckets")[0], 200)
        c.post_form("/team", "/team/role", {"uid": lee["id"], "role": "operator"})
        self.assertEqual(self.person("lee@riverbend.example")["role"], "operator")
        self.assertIn("Sign in", ro.get("/buckets")[1])
        c.post_form("/team", "/team/role", {"uid": lee["id"], "role": "read-only"})                     # put the demo user back
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='user.role_change' AND detail LIKE '%read-only -> operator%'"))

    def test_nobody_changes_their_own_role_or_the_role_of_another_customers_person(self):
        c = self.login()
        me = self.person(ADMIN_C)
        c.post_form("/team", "/team/role", {"uid": me["id"], "role": "read-only"})
        self.assertEqual(self.person(ADMIN_C)["role"], "administrator")
        mara = self.person(OTHER_C)
        c.post_form("/team", "/team/role", {"uid": mara["id"], "role": "read-only"})
        self.assertEqual(self.person(OTHER_C)["role"], "administrator")
        c.post_form("/team", "/team/role", {"uid": self.person("lee@riverbend.example")["id"], "role": "superuser"})
        self.assertEqual(self.person("lee@riverbend.example")["role"], "read-only")

    def test_locked_person_can_be_unlocked_and_sessions_ended(self):
        c = self.login()
        lee = self.person("lee@riverbend.example")
        self.app.db.run("UPDATE users SET failed=9, locked_until=? WHERE id=?",
                        ((dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), lee["id"]))
        self.assertIn("locked", c.get("/team")[1])
        c.post_form("/team", "/team/unlock", {"uid": lee["id"]})
        self.assertIsNone(self.person("lee@riverbend.example")["locked_until"])
        ro = self.env.client()
        ro.login("lee@riverbend.example")
        c.post_form("/team", "/team/signout", {"uid": lee["id"]})
        self.assertIn("Sign in", ro.get("/buckets")[1])

    # ------------------------------------------------------------ groups, users, keys
    def test_scoped_group_and_membership(self):
        c = self.login()
        ref = self.ref("riverbend")
        c.post_form("/users", "/groups", {"name": "curated-only", "access": "read-only", "scope_riverbend-curated": "1"})
        g = {x["name"]: x for x in self.app.backend.list_groups(ref)}["curated-only"]
        self.assertEqual((g["access"], g["buckets"]), ("read-only", ["riverbend-curated"]))
        c.post_form("/groups/edit?group=curated-only", "/groups/update",
                    {"group": "curated-only", "access": "read-write", "scope_riverbend-curated": "1", "scope_riverbend-backups": "1"})
        g = {x["name"]: x for x in self.app.backend.list_groups(ref)}["curated-only"]
        self.assertEqual((g["access"], g["buckets"]), ("read-write", ["riverbend-backups", "riverbend-curated"]))
        c.post_form("/users", "/groups", {"name": "bad-scope", "access": "read-only", "scope_not-a-bucket": "1"})
        self.assertEqual({x["name"]: x for x in self.app.backend.list_groups(ref)}["bad-scope"]["buckets"], [])   # unknown names are dropped
        user = self.app.backend.list_users(ref)[0]["username"]
        c.post_form(f"/users/edit?user={user}", "/users/groups", {"user": user, "g_curated-only": "1", "g_readonly": "1"})
        self.assertEqual(sorted({u["username"]: u for u in self.app.backend.list_users(ref)}[user]["groups"]), ["curated-only", "readonly"])
        for gn in ("curated-only", "bad-scope"):
            self.app.backend.update_user(ref, user, groups=["readwrite"])
            c.post_form("/users", "/groups/delete", {"group": gn})

    def test_access_key_expiry(self):
        c = self.login()
        ref = self.ref("riverbend")
        user = self.app.backend.list_users(ref)[0]["username"]
        before = {k["id"] for k in self.app.backend.list_keys(ref, user)}
        c.post_form(f"/keys?user={user}", "/keys/create", {"user": user, "expiry": "30"})
        new = [k for k in self.app.backend.list_keys(ref, user) if k["id"] not in before]
        self.assertEqual(len(new), 1)
        left = (dt.datetime.fromisoformat(new[0]["expires"].replace("Z", "+00:00")) - dt.datetime.now(dt.timezone.utc)).days
        self.assertIn(left, (29, 30))
        self.assertIn("days)", c.get(f"/keys?user={user}")[1])
        self.app.backend.delete_key(ref, user, new[0]["id"])

    # ------------------------------------------------------------ guided access key
    def test_guided_key_creates_user_group_and_shows_the_secret_once(self):
        c = self.login()
        ref = self.ref("riverbend")
        st, page = c.get("/keys/new")
        self.assertEqual(st, 200)
        for text in ("What is this key for?", "What may it do?", "Which buckets?", "How long should it work?", "Before you start"):
            self.assertIn(text, page)
        buckets = [b["name"] for b in self.app.backend.list_buckets(ref)]
        st, page = c.post_form("/keys/new", "/keys/new", {"name": "nightly-backup", "note": "office backup server", "access": "read-only",
                                                           "scope": "selected", "b_" + buckets[0]: "1", "expiry": "30"})
        self.assertEqual(st, 200)
        for text in ("Secret access key", "What to do now", "If something does not work", "AWS_ACCESS_KEY_ID", "path-style"):
            self.assertIn(text, page)
        g = next(x for x in self.app.backend.list_groups(ref) if x["name"] == "key-nightly-backup")
        self.assertEqual((g["access"], g["buckets"]), ("read-only", [buckets[0]]))
        u = next(x for x in self.app.backend.list_users(ref) if x["username"] == "nightly-backup")
        self.assertEqual(u["groups"], ["key-nightly-backup"])
        listing = c.get("/keys")[1]
        self.assertIn("nightly-backup", listing)
        self.assertIn("Read only", listing)
        self.assertIn("How to connect an application, in five steps", listing)
        self.assertNotIn("Secret access key", listing)                          # shown once
        key = self.app.backend.list_keys(ref, "nightly-backup")[0]
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='key.create' AND target='nightly-backup'"))
        # deleting the only key also removes the key's own user and group
        _, page = c.get("/keys")
        c.post("/keys/delete", {"_csrf": c.csrf(page), "user": "nightly-backup", "key": key["id"]})
        self.assertFalse([x for x in self.app.backend.list_users(ref) if x["username"] == "nightly-backup"])
        self.assertFalse([x for x in self.app.backend.list_groups(ref) if x["name"] == "key-nightly-backup"])

    def test_guided_key_asks_again_when_the_answers_are_incomplete(self):
        c = self.login()
        ref = self.ref("riverbend")
        users_before = len(self.app.backend.list_users(ref))
        st, page = c.post_form("/keys/new", "/keys/new", {"name": "x", "access": "read-only", "scope": "all", "expiry": "90"})
        self.assertEqual(st, 400)
        self.assertIn("2 to 26", page)
        st, page = c.post_form("/keys/new", "/keys/new", {"name": "needs-bucket", "access": "read-only", "scope": "selected", "expiry": "90"})
        self.assertEqual(st, 400)
        self.assertIn("Tick at least one bucket", page)
        self.assertIn('value="needs-bucket"', page)                              # what was typed is kept
        existing = self.app.backend.list_users(ref)[0]["username"]
        st, page = c.post_form("/keys/new", "/keys/new", {"name": existing, "access": "read-only", "scope": "all", "expiry": "90"})
        self.assertEqual(st, 400)
        self.assertIn("already exists", page)
        self.assertEqual(len(self.app.backend.list_users(ref)), users_before)

    def test_guided_key_leaves_nothing_behind_when_the_grid_refuses(self):
        c = self.login()
        ref = self.ref("riverbend")
        real = self.app.backend.create_key

        def refuse(*a, **k):
            from csportal.backends.base import BackendError
            raise BackendError("grid", "The grid refused.", 500)
        self.app.backend.create_key = refuse
        try:
            c.post_form("/keys/new", "/keys/new", {"name": "will-fail", "access": "read-write", "scope": "all", "expiry": "0"})
        finally:
            self.app.backend.create_key = real
        self.assertFalse([x for x in self.app.backend.list_users(ref) if x["username"] == "will-fail"])
        self.assertFalse([x for x in self.app.backend.list_groups(ref) if x["name"] == "key-will-fail"])

    def test_an_operator_can_replace_a_key_but_not_create_permissions(self):
        op = self.login("omar@riverbend.example")
        st, page = op.get("/keys/new")
        self.assertEqual(st, 403)
        self.assertIn("administrator", page)
        st, page = op.get("/keys")
        self.assertNotIn("Create an access key</a>", page)
        self.assertIn("Add another key", page)
        st, _ = op.post_form("/keys", "/keys/new", {"name": "sneaky", "access": "read-write", "scope": "all", "expiry": "90"})
        self.assertEqual(st, 403)

    # ------------------------------------------------------------ guided bucket creation
    def test_name_problems_are_explained_with_a_suggestion(self):
        from csportal.modules.buckets import name_problem
        self.assertEqual(name_problem("good-name.1"), ("", ""))
        self.assertIn("lowercase", name_problem("My Bucket")[0])
        self.assertEqual(name_problem("My Bucket_1")[1], "my-bucket-1")
        self.assertIn("at least 3", name_problem("ab")[0])
        self.assertIn("63", name_problem("a" * 64)[0])
        self.assertIn("start and end", name_problem("-abc-")[0])
        self.assertIn("IP address", name_problem("203.0.113.9")[0])

    def test_guided_bucket_with_cleanup_and_the_follow_up_steps(self):
        c = self.login()
        ref = self.ref("riverbend")
        st, page = c.get("/buckets/new")
        self.assertEqual(st, 200)
        for text in ("Before you start", "Name and place", "How should the data be protected?", "Clean-up (optional)", "Who can use it?"):
            self.assertIn(text, page)
        st, page = c.post_form("/buckets/new", "/buckets/new", {"name": "guided-one", "region": "us-east-1", "purpose": "keep-versions",
                                                               "c_uploads": "1", "c_old": "30"})
        self.assertEqual(st, 200)
        for text in ("Bucket guided-one is ready", "What to do now", "/keys/new?bucket=guided-one", "aws s3 cp"):
            self.assertIn(text, page)
        b = self.app.backend.get_bucket(ref, "guided-one")
        self.assertEqual(b["versioning"], "enabled")
        self.assertEqual({r["id"] for r in b["lifecycle"]}, {"cleanup-uploads", "old-versions"})
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='bucket.create' AND target='guided-one'"))
        # the key page opens with that bucket already ticked
        st, page = c.get("/keys/new?bucket=guided-one")
        self.assertRegex(page, r'name="b_guided-one" value="1" checked')
        self.app.backend.delete_bucket(ref, "guided-one")

    def test_guided_bucket_refuses_with_plain_words_and_keeps_the_answers(self):
        c = self.login()
        ref = self.ref("riverbend")
        n = len(self.app.backend.list_buckets(ref))
        st, page = c.post_form("/buckets/new", "/buckets/new", {"name": "Bad Name_1", "purpose": "keep-versions"})
        self.assertEqual(st, 400)
        self.assertIn("lowercase", page)
        self.assertIn("bad-name-1", page)                         # the suggestion
        st, page = c.post_form("/buckets/new", "/buckets/new", {"name": "ok-name-two", "purpose": "latest-only", "c_old": "10"})
        self.assertEqual(st, 400)
        self.assertIn("Old versions are only kept", page)
        st, page = c.post_form("/buckets/new", "/buckets/new", {"name": "ok-name-two", "purpose": "keep-versions", "c_expire": "abc"})
        self.assertEqual(st, 400)
        self.assertIn('value="ok-name-two"', page)
        st, page = c.post_form("/buckets/new", "/buckets/new", {"name": "riverbend-curated", "purpose": "keep-versions"})   # already taken
        self.assertEqual(len(self.app.backend.list_buckets(ref)), n)

    def test_guided_locked_bucket_needs_the_acknowledgement_and_sets_default_retention(self):
        c = self.login()
        ref = self.ref("riverbend")
        base = {"name": "locked-records", "purpose": "locked", "lock_amount": "2", "lock_unit": "years", "lock_mode": "COMPLIANCE"}
        st, page = c.post_form("/buckets/new", "/buckets/new", base)
        self.assertEqual(st, 400)
        self.assertIn("cannot be shortened", page)
        self.assertFalse([b for b in self.app.backend.list_buckets(ref) if b["name"] == "locked-records"])
        st, page = c.post_form("/buckets/new", "/buckets/new", {**base, "lock_ack": "1", "c_expire": "30"})
        self.assertEqual(st, 400)
        self.assertIn("cannot be combined", page)
        st, page = c.post_form("/buckets/new", "/buckets/new", {**base, "lock_ack": "1"})
        self.assertEqual(st, 200)
        b = self.app.backend.get_bucket(ref, "locked-records")
        self.assertTrue(b["object_lock"])
        self.assertEqual((b["lock_default"]["mode"], b["lock_default"]["amount"], b["lock_default"]["unit"]), ("COMPLIANCE", 2, "years"))

    def test_guided_bucket_is_for_people_who_may_edit_buckets(self):
        ro = self.login("lee@riverbend.example")
        self.assertEqual(ro.get("/buckets/new")[0], 403)
        st, _ = ro.post_form("/buckets", "/buckets/new", {"name": "sneaky-bucket", "purpose": "latest-only"})
        self.assertEqual(st, 403)


if __name__ == "__main__":
    unittest.main()
