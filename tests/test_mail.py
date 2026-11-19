"""Outgoing mail and invitations: a real exchange with a small fake mail relay, and what the inviter is told."""
from __future__ import annotations

import re
import smtplib
import socketserver
import threading
import unittest

from csportal import services
from helpers import Env, free_port

ADMIN_C = "dana@riverbend.example"
PW = "Demo-Portal-2026!"             # check-repo-ok: demo account password used by the tests
PW_NEW = "Quartz-Harbor-Lamp-2026!"  # check-repo-ok: test value


class FakeRelay:
    """Speaks just enough SMTP to receive messages; keeps each one as text."""

    def __init__(self):
        self.messages: list[str] = []
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                def w(s):
                    self.wfile.write((s + "\r\n").encode())
                    self.wfile.flush()
                w("220 fake ESMTP")
                data, buf = False, []
                while True:
                    line = self.rfile.readline()
                    if not line:
                        break
                    t = line.decode().rstrip("\r\n")
                    if data:
                        if t == ".":
                            data = False
                            outer.messages.append("\n".join(buf))
                            w("250 queued")
                        else:
                            buf.append(t)
                        continue
                    u = t.upper()
                    if u.startswith(("EHLO", "HELO")):
                        w("250-fake")
                        w("250 8BITMIME")
                    elif u == "DATA":
                        data, buf = True, []
                        w("354 go")
                    elif u == "QUIT":
                        w("221 bye")
                        break
                    else:
                        w("250 ok")

        self.port = free_port()
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Mail(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.app = self.env.app
        self.relay = FakeRelay()

    def tearDown(self):
        self.relay.close()
        self.env.close()

    def real_mail(self, port=None):
        self.app.cfg.d["mode"] = "production"          # the relay is used only outside demo mode
        self.app.cfg.d["smtp"].update({"host": "127.0.0.1", "port": port or self.relay.port, "starttls": False, "from": "portal@example.net"})

    def login(self, email=ADMIN_C):
        c = self.env.client()
        st, page = c.login(email)
        self.assertEqual(st, 200, page[:200])
        return c

    # ------------------------------------------------------------ the relay
    def test_a_message_reaches_the_relay_complete_and_the_stored_copy_loses_its_link(self):
        self.real_mail()
        mid = services.send_mail(self.app, "x@riverbend.example", "Hi", "Open https://portal.example.net/invite/SECRETTOKEN123 now\n")
        row = self.app.db.one("SELECT state, body FROM outbox WHERE id=?", (mid,))
        self.assertEqual(row["state"], "sent")
        self.assertNotIn("SECRETTOKEN123", row["body"])
        msg = self.relay.messages[0]
        self.assertIn("SECRETTOKEN123", msg)                                          # the person gets the real link
        self.assertRegex(msg, r"(?m)^Date: .+")                                       # without these many mail systems refuse or junk it
        self.assertRegex(msg, r"(?m)^Message-ID: <.+@example\.net>")

    def test_port_465_uses_implicit_tls(self):
        used = []

        class FakeSSL:
            def __init__(self, host, port, timeout=None, context=None):
                used.append(("ssl", host, port, context is not None))

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def login(self, *a):
                pass

            def send_message(self, msg):
                used.append(("sent", msg["To"]))

        real = smtplib.SMTP_SSL
        smtplib.SMTP_SSL = FakeSSL
        try:
            self.real_mail(port=465)
            self.app.cfg.d["smtp"]["starttls"] = True                                   # must not start TLS a second time
            mid = services.send_mail(self.app, "x@riverbend.example", "Hi", "Hello\n")
        finally:
            smtplib.SMTP_SSL = real
        self.assertEqual(used[0], ("ssl", "127.0.0.1", 465, True))
        self.assertEqual(self.app.db.one("SELECT state FROM outbox WHERE id=?", (mid,))["state"], "sent")

    # ------------------------------------------------------------ what the inviter is told
    def test_invitation_through_a_working_relay_says_sent(self):
        c = self.login()
        self.real_mail()
        st, page = c.post_form("/team/new", "/team/new", {"name": "Real Mail", "email": "real.mail@riverbend.example", "role": "read-only"})
        self.assertEqual(st, 200)
        self.assertIn("The e-mail was sent.", page)
        self.assertNotIn("Demonstration only", page)                                   # the link is never shown outside demo mode
        self.assertNotRegex(page, r"/invite/[A-Za-z0-9_-]{20,}")
        self.assertIn("real.mail@riverbend.example", self.relay.messages[0])
        self.assertIn("/invite/", self.relay.messages[0])

    def test_invitation_with_a_broken_relay_says_so_and_keeps_the_person(self):
        c = self.login()
        self.real_mail(port=free_port())                                               # nothing listens there
        st, page = c.post_form("/team/new", "/team/new", {"name": "No Mail", "email": "no.mail@riverbend.example", "role": "read-only"})
        self.assertEqual(st, 200)
        self.assertIn("could not be sent", page)
        self.assertIn("Send new invite", page)
        row = self.app.db.one("SELECT state FROM outbox WHERE to_addr='no.mail@riverbend.example'")
        self.assertEqual(row["state"], "failed")
        self.assertTrue(self.app.db.one("SELECT 1 FROM users WHERE email='no.mail@riverbend.example'"))

    def test_invitation_without_a_relay_says_mail_is_not_set_up(self):
        c = self.login()
        self.app.cfg.d["mode"] = "production"
        st, page = c.post_form("/team/new", "/team/new", {"name": "Nobody", "email": "nobody@riverbend.example", "role": "read-only"})
        self.assertIn("not set up to send e-mail", page)

    # ------------------------------------------------------------ the demonstration
    def test_demo_shows_the_link_and_it_sets_a_password(self):
        c = self.login()
        st, page = c.post_form("/team/new", "/team/new", {"name": "Demo Person", "email": "demo.person@riverbend.example", "role": "read-only"})
        self.assertIn("Demonstration only", page)
        link = re.search(r'href="([^"]*?/invite/[A-Za-z0-9_-]+)"', page)
        self.assertTrue(link, "the page shows the invitation link in demo mode")
        path = "/invite/" + link.group(1).rsplit("/invite/", 1)[1]
        # the same link is on the person's page while the invitation is open
        uid = self.app.db.one("SELECT id FROM users WHERE email='demo.person@riverbend.example'")["id"]
        self.assertIn("Open the invitation link", c.get("/team/person?uid=" + uid)[1])
        guest = self.env.client()
        st, form = guest.get(path)
        self.assertEqual(st, 200)
        st, _ = guest.post("/invite", {"_csrf": guest.csrf(form), "token": path.rsplit("/", 1)[1], "password": PW_NEW, "password2": PW_NEW})
        self.assertEqual(st, 200)                                                       # redirected on to the sign-in page
        self.assertEqual(self.app.db.one("SELECT state FROM users WHERE id=?", (uid,))["state"], "active")
        self.assertNotIn("Open the invitation link", c.get("/team/person?uid=" + uid)[1])   # no longer open, nothing to show

    # ------------------------------------------------------------ the test message in the admin console
    def test_admin_can_send_a_test_message_and_sees_the_result(self):
        a = self.env.client("admin")
        self.assertEqual(a.login("admin@demo.example", PW)[0], 200)
        page = a.get("/outbox")[1]
        self.assertIn("Send a test message", page)
        st, page = a.post_form("/outbox", "/outbox/test", {"to": "me@example.net"})
        self.assertIn("captured below", page)                                          # demo mode
        self.real_mail()
        st, page = a.post_form("/outbox", "/outbox/test", {"to": "me@example.net"})
        self.assertIn("Test message sent", page)
        self.assertIn("me@example.net", self.relay.messages[0])
        self.relay.close()
        self.relay = FakeRelay()
        self.real_mail(port=free_port())
        st, page = a.post_form("/outbox", "/outbox/test", {"to": "me@example.net"})
        self.assertIn("could not be sent", page)
        st, page = a.post_form("/outbox", "/outbox/test", {"to": "not-an-address"})
        self.assertIn("valid e-mail address", page)
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='mail.test'"))


if __name__ == "__main__":
    unittest.main()
