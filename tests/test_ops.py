"""Operations: audit checkpoints and retention, backups, drift, key rotation, personal data, re-authentication,
approval by a second administrator, and the tenant credentials written when a grid account is created."""
import json
import os
import secrets
import unittest

from csportal import approvals, crypto, ops, settings as S
from csportal.auth import AuthError
from csportal.backends.storagegrid import StorageGridBackend
from csportal.util import GB

from helpers import Env

ADMIN = "admin@demo.example"
PW = "Demo-Portal-2026!"             # check-repo-ok: demo account password used by the tests
PW2 = "Quartz-Harbor-Lamp-2026!"        # check-repo-ok: test value


def admin_client(env):
    c = env.client("admin")
    st, page = c.login(ADMIN)
    assert st == 200, page[:300]
    return c


class AuditAndBackups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.app = cls.env.app

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def test_truncation_and_forged_checkpoint_are_detected(self):
        a = self.app.audit
        for i in range(6):
            a.record("test.event", "t", "system", None, f"n{i}")
        self.assertTrue(a.checkpoint())
        self.assertTrue(a.verify_full()["ok"])
        last = self.app.db.one("SELECT MAX(id) m FROM audit")["m"]
        self.app.db.run("DELETE FROM audit WHERE id > ?", (last - 2,))           # cut the newest records off
        v = a.verify_full()
        self.assertFalse(v["ok"])
        self.assertTrue(any("missing" in p for p in v["problems"]))
        # a forged checkpoint (wrong signature) is refused too
        self.app.db.run("UPDATE audit_checkpoints SET mac='00'")
        self.assertTrue(any("signature" in p for p in a.verify_full()["problems"]))

    def test_retention_archives_and_the_rest_still_verifies(self):
        env = Env()
        try:
            a = env.app.audit
            for i in range(30):
                a.record("test.event", "t", "system", None, f"n{i}")
            before = a.verify_full()
            self.assertTrue(before["ok"])
            r = a.prune(-1, env.dir / "audit-archive", keep_last=5)       # a retention of -1 days puts the cut-off in the future
            self.assertGreater(r["pruned"], 20)
            self.assertTrue((env.dir / "audit-archive" / r["archive"]).exists())
            self.assertTrue((env.dir / "audit-archive" / (r["archive"] + ".sha256")).exists())
            after = a.verify_full()
            self.assertTrue(after["ok"], after["problems"])
            self.assertIsNotNone(after["anchor_id"])
            a.record("test.after", "t")                                     # the chain continues from the anchor
            self.assertTrue(a.verify_full()["ok"])
            env.app.db.run("UPDATE audit_anchor SET hash='ff' || substr(hash,3)")     # forged anchor
            self.assertFalse(a.verify_full()["ok"])
        finally:
            env.close()

    def test_prune_refuses_a_broken_chain(self):
        env = Env()
        try:
            a = env.app.audit
            for i in range(10):
                a.record("test.event", "t", "system", None, f"n{i}")
            env.app.db.run("UPDATE audit SET detail='changed' WHERE id=3")
            r = a.prune(-1, env.dir / "arch", keep_last=1)
            self.assertEqual(r["pruned"], 0)
            self.assertIn("does not verify", r["refused"])
        finally:
            env.close()

    def test_backups_are_checked_and_old_ones_removed(self):
        for _ in range(4):
            ops.backup_now(self.app, keep=2)
        self.assertEqual(len(ops.list_backups(self.app)), 2)
        newest = ops.backup_dir(self.app) / ops.list_backups(self.app)[0]["name"]
        self.assertEqual(ops.check_backup(newest), "ok")
        bad = ops.backup_dir(self.app) / "csportal-20200101T000000Z.db"
        bad.write_bytes(b"this is not a database" * 50)
        self.assertNotEqual(ops.check_backup(bad), "ok")

    def test_drift_is_reported_and_quota_can_be_aligned(self):
        rep = ops.drift_report(self.app)
        self.assertTrue(rep["ok"], rep)
        c = self.app.db.one("SELECT * FROM customers WHERE slug='riverbend'")
        self.app.backend.update_tenant(c["tenant_ref"], quota_bytes=1 * GB)
        rep = ops.drift_report(self.app)
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["quota_mismatch"][0]["customer_id"], c["id"])
        self.assertTrue(ops.align_quota(self.app, c["id"], "tester"))
        self.assertTrue(ops.drift_report(self.app)["ok"])
        self.assertFalse(ops.align_quota(self.app, "c_missing", "tester"))
        ref = self.app.backend.create_tenant("Stray Account", 5 * GB, {})        # on the grid, unknown to the portal
        self.assertEqual([u["ref"] for u in ops.drift_report(self.app)["not_in_portal"]], [ref])
        self.app.backend.delete_tenant(ref)


class PersonalData(unittest.TestCase):
    def test_export_and_erase_keep_the_audit_chain_intact(self):
        env = Env()
        try:
            app = env.app
            who = "omar@riverbend.example"
            app.audit.record("test.touch", who, "user", None, who)
            exp = ops.person_export(app, who.upper())
            self.assertEqual(len(exp["accounts"]), 1)
            self.assertTrue(exp["audit_records"])
            self.assertNotIn("pw_hash", json.dumps(exp))
            r = ops.person_erase(app, who, "tester")
            self.assertEqual(r["accounts"], 1)
            self.assertEqual(ops.person_export(app, who)["accounts"], [])
            self.assertTrue(app.audit.verify_full()["ok"])
            last = app.db.one("SELECT * FROM audit WHERE action='privacy.erase'")
            self.assertNotIn(who, last["target"] + last["detail"])
            with self.assertRaises(ValueError):                            # the last active administrator of a customer
                ops.person_erase(app, "dana@riverbend.example", "tester")
        finally:
            env.close()


class KeyRotation(unittest.TestCase):
    def test_everything_sealed_moves_to_the_new_key(self):
        env = Env()
        try:
            app = env.app
            uid = app.db.one("SELECT id FROM users WHERE email='admin@demo.example'")["id"]
            secret = app.auth.begin_mfa_enrol(uid)
            S.secret_put(app.db, app.box, S.GRID_SECRET, "grid-password-value")      # check-repo-ok: test value
            app.audit.checkpoint()
            old_box = app.box
            out = ops.rotate_master_key(app, secrets.token_bytes(32))
            self.assertGreaterEqual(out["secrets"], 1)
            self.assertEqual(out["totp"], 1)
            self.assertEqual(S.secret_get(app.db, app.box, S.GRID_SECRET), "grid-password-value")
            self.assertEqual(app.auth.pending_totp_secret(uid), secret)
            with self.assertRaises(Exception):
                S.secret_get(app.db, old_box, S.GRID_SECRET)                    # the old key no longer opens anything
            self.assertTrue(app.audit.verify_full()["ok"])
            with self.assertRaises(ValueError):
                ops.rotate_master_key(app, b"short")
        finally:
            env.close()

    def test_a_value_that_cannot_be_opened_changes_nothing(self):
        env = Env()
        try:
            app = env.app
            S.secret_put(app.db, app.box, S.GRID_SECRET, "keep-me")                  # check-repo-ok: test value
            app.db.run("UPDATE secrets SET sealed='AAAA' WHERE name=?", (S.GRID_SECRET,))
            with self.assertRaises(Exception):
                ops.rotate_master_key(app, secrets.token_bytes(32))
            self.assertIs(app.box.__class__, crypto.SecretBox)
        finally:
            env.close()


class TenantCredentials(unittest.TestCase):
    def test_root_credentials_are_kept_and_only_the_s3_key_is_added_later(self):
        calls, stored = [], {}

        def put(ref, c):
            calls.append((ref, dict(c)))
            stored.setdefault(ref, {}).update(c)

        b = StorageGridBackend(S.GridConn(nodes=[S.AdminNode("a", "127.0.0.1", 9)], username="portal"), lambda: "x", put_creds=put)

        def fake_api(scope, method, path, body=None):
            if path == "/grid/accounts" and method == "POST":
                self.assertTrue(body["password"])                       # the root password is set, not left empty
                fake_api.pw = body["password"]
                return {"id": "1234"}
            if path == "/org/groups":
                return {"id": "g1"}
            if path == "/org/users":
                return {"id": "u1"}
            if path.endswith("/s3-access-keys"):
                return {"accessKey": "AK", "secretAccessKey": "SK"}
            return {}
        b._api = fake_api
        ref = b.create_tenant("Acme", 10 * GB, {})
        self.assertEqual(ref, "1234")
        self.assertEqual(calls[0][1], {"username": "root", "password": fake_api.pw})
        self.assertEqual(stored["1234"], {"username": "root", "password": fake_api.pw, "s3_key": "AK", "s3_secret": "SK"})


class TenantPassword(unittest.TestCase):
    def test_new_password_is_tested_before_it_is_kept(self):
        env = Env()
        try:
            app = env.app
            ref = app.db.one("SELECT tenant_ref FROM customers WHERE slug='riverbend'")["tenant_ref"]
            from csportal import services
            services.grid_creds_putter(app)(ref, {"username": "root", "password": "old-value"})        # check-repo-ok: test value
            ops.set_tenant_password(app, "riverbend", "new-value", "tester")                           # check-repo-ok: test value
            self.assertEqual(services.grid_creds_getter(app)(ref)["password"], "new-value")
            real = app.backend.list_users

            def refuse(r):
                from csportal.backends.base import BackendError
                raise BackendError("auth", "bad credentials", 401)
            app.backend.list_users = refuse
            with self.assertRaises(ValueError):
                ops.set_tenant_password(app, "riverbend", "wrong-value", "tester")                      # check-repo-ok: test value
            app.backend.list_users = real
            self.assertEqual(services.grid_creds_getter(app)(ref)["password"], "new-value")             # the old value stays
            with self.assertRaises(ValueError):
                ops.set_tenant_password(app, "nobody", "x", "tester")
        finally:
            env.close()


class ReauthAndApprovals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.app = cls.env.app

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        self.app.auth.limiter._hits.clear()
        self.app.cfg.d["security"]["four_eyes"] = False

    def _staff(self, email, name):
        uid = self.app.auth.create_user(email, name, "operations", None, PW)
        return uid

    def _age_sessions(self):
        self.app.db.run("UPDATE sessions SET created_at='2020-01-01T00:00:00Z', reauth_at=NULL")

    def test_an_old_session_must_confirm_the_password_and_the_action_then_runs_once(self):
        uid = self._staff("temp1@demo.example", "Temp One")
        c = admin_client(self.env)
        self._age_sessions()
        _, page = c.get("/staff")
        csrf = c.csrf(page)
        st, page = c.post("/staff/remove", {"_csrf": csrf, "uid": uid})
        self.assertIn("Confirm it is you", page)
        self.assertIsNotNone(self.app.db.one("SELECT 1 FROM users WHERE id=?", (uid,)))        # nothing changed yet
        st, page = c.post("/reauth", {"_csrf": csrf, "password": "wrong-password-1234", "_replay_path": "/staff/remove", "r_uid": uid})
        self.assertEqual(st, 401)
        self.assertIsNotNone(self.app.db.one("SELECT 1 FROM users WHERE id=?", (uid,)))
        st, page = c.post("/reauth", {"_csrf": csrf, "password": PW, "_replay_path": "/staff/remove", "r_uid": uid})
        self.assertIsNone(self.app.db.one("SELECT 1 FROM users WHERE id=?", (uid,)))           # the original request was replayed
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='user.reauth'"))
        # a second removal straight afterwards needs no new prompt
        uid2 = self._staff("temp2@demo.example", "Temp Two")
        _, page = c.get("/staff")
        c.post("/staff/remove", {"_csrf": c.csrf(page), "uid": uid2})
        self.assertIsNone(self.app.db.one("SELECT 1 FROM users WHERE id=?", (uid2,)))

    def test_only_routes_that_ask_for_it_can_be_replayed(self):
        c = admin_client(self.env)
        _, page = c.get("/staff")
        before = self.app.db.one("SELECT COUNT(*) n FROM users")["n"]
        c.post("/reauth", {"_csrf": c.csrf(page), "password": PW, "_replay_path": "/staff", "r_name": "X", "r_email": "x@demo.example", "r_role": "support"})
        self.assertEqual(self.app.db.one("SELECT COUNT(*) n FROM users")["n"], before)

    def test_reauth_get_redirects_with_a_safe_next(self):
        c = admin_client(self.env)
        self._age_sessions()
        st, page = c.get("/reauth?next=//evil.example/x")
        self.assertIn("Confirm it is you", page)
        self.assertNotIn("evil.example", page)

    def test_four_eyes_needs_a_different_super_administrator(self):
        self.app.cfg.d["security"]["four_eyes"] = True
        a = self.app.db.one("SELECT id FROM users WHERE email=?", (ADMIN,))["id"]
        # with one super administrator the action simply runs: nobody else could approve it
        self.assertFalse(approvals.required(self.app))
        self.app.auth.create_user("second@demo.example", "Second Admin", "super-administrator", None, PW2)
        b = self.app.db.one("SELECT id FROM users WHERE email='second@demo.example'")["id"]
        self.assertTrue(approvals.required(self.app))
        cust = self.app.db.one("SELECT * FROM customers WHERE slug='harbourview'")
        done, msg = approvals.submit(self.app, "customer.close", cust["id"], "Close Harbourview", {"cid": cust["id"]}, ADMIN, a, "198.51.100.1")
        self.assertFalse(done)
        self.assertEqual(self.app.db.one("SELECT state FROM customers WHERE id=?", (cust["id"],))["state"], "active")
        with self.assertRaises(approvals.ApprovalError):                  # asking twice
            approvals.submit(self.app, "customer.close", cust["id"], "again", {"cid": cust["id"]}, ADMIN, a, "")
        aid = self.app.db.one("SELECT id FROM approvals WHERE state='pending'")["id"]
        with self.assertRaises(approvals.ApprovalError):                  # not by the person who asked
            approvals.decide(self.app, aid, True, ADMIN, a, "")
        approvals.decide(self.app, aid, True, "second@demo.example", b, "198.51.100.2")
        self.assertEqual(self.app.db.one("SELECT state FROM customers WHERE id=?", (cust["id"],))["state"], "closed")
        self.assertEqual(self.app.db.one("SELECT state FROM approvals WHERE id=?", (aid,))["state"], "approved")
        with self.assertRaises(approvals.ApprovalError):                  # it cannot be run a second time
            approvals.decide(self.app, aid, True, "second@demo.example", b, "")
        actions = [r["action"] for r in self.app.db.all("SELECT action FROM audit WHERE action LIKE 'approval.%' OR action='customer.close'")]
        self.assertIn("approval.requested", actions)
        self.assertIn("approval.approved", actions)

    def test_rejection_expiry_and_the_secret_in_a_waiting_request(self):
        self.app.cfg.d["security"]["four_eyes"] = True
        if not self.app.db.one("SELECT 1 FROM users WHERE email='second@demo.example'"):
            self.app.auth.create_user("second@demo.example", "Second Admin", "super-administrator", None, PW2)
        a = self.app.db.one("SELECT id FROM users WHERE email=?", (ADMIN,))["id"]
        b = self.app.db.one("SELECT id FROM users WHERE email='second@demo.example'")["id"]
        conn = S.load_grid(self.app.cfg, self.app.db)
        payload = {"conn": conn.to_json(), "password": "super-secret-grid-pw", "clear_password": False}     # check-repo-ok: test value
        done, _ = approvals.submit(self.app, "grid.settings", "grid", "Change grid", payload, ADMIN, a, "")
        self.assertFalse(done)
        row = self.app.db.one("SELECT * FROM approvals WHERE target='grid' AND state='pending'")
        self.assertNotIn("super-secret", row["payload"])                 # stored encrypted
        approvals.decide(self.app, row["id"], False, "second@demo.example", b, "", "not now")
        self.assertEqual(self.app.db.one("SELECT state FROM approvals WHERE id=?", (row["id"],))["state"], "rejected")
        done, _ = approvals.submit(self.app, "staff.remove", b, "Remove second", {"uid": b}, ADMIN, a, "")
        self.app.db.run("UPDATE approvals SET expires_at='2020-01-01T00:00:00Z' WHERE state='pending'")
        self.assertEqual(approvals.expire(self.app), 1)
        with self.assertRaises(approvals.ApprovalError):
            approvals.decide(self.app, self.app.db.one("SELECT id FROM approvals WHERE kind='staff.remove'")["id"], True, "second@demo.example", b, "")

    def test_the_approvals_page_and_operations_pages_load(self):
        c = admin_client(self.env)
        for path, text in [("/approvals", "How it works"), ("/operations", "Audit log integrity"), ("/privacy", "Personal data")]:
            st, page = c.get(path)
            self.assertEqual(st, 200, path)
            self.assertIn(text, page)

    def test_customer_users_cannot_reach_staff_pages(self):
        c = self.env.client()
        c.login("dana@riverbend.example")
        for path in ("/approvals", "/operations", "/privacy", "/reauth"):
            st, page = c.get(path)
            self.assertNotIn("Audit log integrity", page)


if __name__ == "__main__":
    unittest.main()
