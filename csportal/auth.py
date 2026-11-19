"""Identity, sessions, MFA, roles and permissions.

Customer users and CSP staff share one table but are separated by `customer_id` (NULL = CSP staff),
use different cookies and sessions, and can only sign in on their own surface.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from . import crypto, logs
from .util import iso, parse_iso, utcnow, valid_email, new_id
import datetime as dt

slog = logging.getLogger("csportal.security")

# ------------------------------------------------------------------ roles and permissions
CUSTOMER_ROLES = ["administrator", "operator", "billing", "read-only"]
CSP_ROLES = ["super-administrator", "operations", "finance", "support"]

_ALL_VIEW = {"dashboard.view", "buckets.view", "access.view", "usage.view", "alerts.view", "activity.view",
             "status.view", "keys.view"}
CUSTOMER_PERMS: dict[str, set[str]] = {
    "administrator": _ALL_VIEW | {"buckets.edit", "buckets.delete", "access.edit", "keys.manage", "billing.view",
                                  "alerts.edit", "quota.request", "account.manage"},
    "operator": _ALL_VIEW | {"buckets.edit", "keys.manage"},
    "billing": {"dashboard.view", "usage.view", "billing.view", "alerts.view", "alerts.edit", "quota.request",
                "status.view"},
    "read-only": set(_ALL_VIEW),
}
_CSP_VIEW = {"admin.overview", "customers.view", "plans.view", "billing.view", "quota.view", "audit.view",
             "notices.view", "modules.view"}
CSP_PERMS: dict[str, set[str]] = {
    "super-administrator": _CSP_VIEW | {"customers.edit", "customers.provision", "customers.delete", "plans.edit",
                                        "billing.edit", "quota.decide", "notices.edit", "modules.edit",
                                        "users.manage", "logs.view", "system.view", "system.edit",
                                        "settings.edit", "demo.reset"},
    "operations": _CSP_VIEW | {"customers.edit", "customers.provision", "quota.decide", "notices.edit",
                               "logs.view", "system.view"},
    "finance": {"admin.overview", "customers.view", "plans.view", "billing.view", "billing.edit", "quota.view"},
    "support": {"admin.overview", "customers.view", "plans.view", "quota.view", "audit.view", "notices.view"},
}


def role_perms(kind: str, role: str) -> set[str]:
    return (CUSTOMER_PERMS if kind == "customer" else CSP_PERMS).get(role, set())


@dataclass
class Session:
    id_hash: str
    user_id: str
    surface: str
    csrf: str
    mfa_ok: bool
    customer_id: str | None
    email: str
    name: str
    role: str
    flash: str
    mfa_enabled: bool

    @property
    def perms(self) -> set[str]:
        return role_perms("customer" if self.surface == "customer" else "csp", self.role)


class RateLimiter:
    """Sliding-window limiter by key (address or account)."""

    def __init__(self):
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 20000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < window}
            return allowed


class AuthError(Exception):
    pass


class Auth:
    def __init__(self, cfg, db, box: crypto.SecretBox, audit):
        self.cfg, self.db, self.box, self.audit = cfg, db, box, audit
        self.limiter = RateLimiter()
        sc = cfg.d["security"]
        self.lock_n, self.lock_min, self.min_len = sc["lockout_attempts"], sc["lockout_minutes"], sc["min_password_length"]

    # ---------------------------------------------------------- users
    def create_user(self, email: str, name: str, role: str, customer_id: str | None, password: str | None = None,
                    actor: str = "system", ip: str = "") -> str:
        email = email.strip().lower()
        if not valid_email(email):
            raise AuthError("Enter a valid e-mail address.")
        roles = CUSTOMER_ROLES if customer_id else CSP_ROLES
        if role not in roles:
            raise AuthError("Unknown role.")
        uid = new_id("u_")
        pw = None
        state = "invited"
        if password:
            bad = crypto.password_problems(password, email, self.min_len)
            if bad:
                raise AuthError("Password needs: " + "; ".join(bad))
            pw, state = crypto.hash_password(password), "active"
        try:
            self.db.run("INSERT INTO users(id,customer_id,email,name,role,pw_hash,state,created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (uid, customer_id, email, name.strip()[:120] or email, role, pw, state, iso()))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise AuthError("A user with this e-mail address already exists.")
            raise
        self.audit.record("user.create", actor, "user", customer_id, email, f"role={role}", ip)
        return uid

    def invite_token(self, user_id: str, purpose: str = "set-password", hours: int = 72) -> str:
        t = crypto.token()
        self.db.run("INSERT INTO invitations(token_hash,user_id,purpose,expires_at) VALUES (?,?,?,?)",
                    (crypto.hash_token(t), user_id, purpose, iso(utcnow() + dt.timedelta(hours=hours))))
        return t

    def redeem_invite(self, token: str, password: str, ip: str = "") -> str:
        h = crypto.hash_token(token)
        r = self.db.one("SELECT i.*, u.email, u.customer_id FROM invitations i JOIN users u ON u.id=i.user_id "
                        "WHERE token_hash=? AND used=0", (h,))
        if not r or parse_iso(r["expires_at"]) < utcnow():
            raise AuthError("This link is not valid or has expired. Ask your administrator for a new one.")
        bad = crypto.password_problems(password, r["email"], self.min_len)
        if bad:
            raise AuthError("Password needs: " + "; ".join(bad))
        with self.db.tx() as c:
            c.execute("UPDATE users SET pw_hash=?, state='active', failed=0, locked_until=NULL WHERE id=?",
                      (crypto.hash_password(password), r["user_id"]))
            c.execute("UPDATE invitations SET used=1 WHERE token_hash=?", (h,))
            c.execute("DELETE FROM sessions WHERE user_id=?", (r["user_id"],))
        self.audit.record("user.password_set", r["email"], "user", r["customer_id"], r["email"], r["purpose"], ip)
        return r["user_id"]

    def change_password(self, user_id: str, current: str, new: str, ip: str = "") -> None:
        u = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        if not u or not crypto.verify_password(current, u["pw_hash"] or ""):
            raise AuthError("Current password is not correct.")
        bad = crypto.password_problems(new, u["email"], self.min_len)
        if bad:
            raise AuthError("Password needs: " + "; ".join(bad))
        self.db.run("UPDATE users SET pw_hash=? WHERE id=?", (crypto.hash_password(new), user_id))
        self.audit.record("user.password_change", u["email"], "user", u["customer_id"], u["email"], "", ip)

    # ---------------------------------------------------------- sign in
    def mfa_required(self, user) -> bool:
        if user["customer_id"] is None:
            return not self.cfg.demo or bool(user["mfa_enabled"])
        if self.cfg.demo and not user["mfa_enabled"]:
            return False
        return bool(self.cfg.d["security"]["customer_mfa_required"]) or bool(user["mfa_enabled"])

    def authenticate(self, email: str, password: str, surface: str, ip: str) -> tuple[str, str]:
        """Return (session_token, csrf). Raises AuthError with a generic message on any failure."""
        email = (email or "").strip().lower()
        generic = AuthError("E-mail or password is not correct.")
        if not self.limiter.hit("ip:" + ip, 30, 300) or not self.limiter.hit("acct:" + email, 10, 300):
            logs.event(slog, logging.WARNING, "signin rate limited", ip=ip, account=email)
            raise AuthError("Too many attempts. Wait a few minutes and try again.")
        if surface == "customer":
            u = self.db.one("SELECT u.*, c.state cstate FROM users u JOIN customers c ON c.id=u.customer_id "
                            "WHERE u.email=? AND u.customer_id IS NOT NULL", (email,))
        else:
            u = self.db.one("SELECT u.*, 'active' cstate FROM users u WHERE u.email=? AND u.customer_id IS NULL",
                            (email,))
        # Always spend the same hashing time, so unknown accounts cannot be told apart by timing.
        stored = (u["pw_hash"] if u and u["pw_hash"] else _DUMMY_HASH)
        ok = crypto.verify_password(password or "", stored)
        if not u or not ok or u["state"] != "active":
            if u:
                self._fail(u, ip)
            else:
                logs.event(slog, logging.WARNING, "signin failed", reason="unknown account", ip=ip, account=email)
            raise generic
        if u["locked_until"] and parse_iso(u["locked_until"]) > utcnow():
            logs.event(slog, logging.WARNING, "signin blocked: locked", ip=ip, account=email)
            raise AuthError("This account is temporarily locked. Try again later or contact your administrator.")
        if u["cstate"] in ("suspended", "closed", "pending"):
            raise AuthError("This account is not active. Contact support.")
        self.db.run("UPDATE users SET failed=0, locked_until=NULL WHERE id=?", (u["id"],))
        return self._new_session(u, surface, ip, mfa_ok=not self.mfa_required(u))

    def _fail(self, u, ip: str) -> None:
        n = (u["failed"] or 0) + 1
        locked = None
        if n >= self.lock_n:
            locked = iso(utcnow() + dt.timedelta(minutes=self.lock_min))
            n = 0
            self.audit.record("user.locked", u["email"], "user", u["customer_id"], u["email"], "too many failures", ip)
        self.db.run("UPDATE users SET failed=?, locked_until=COALESCE(?, locked_until) WHERE id=?", (n, locked, u["id"]))
        logs.event(slog, logging.WARNING, "signin failed", reason="bad credentials", ip=ip, account=u["email"])

    def _new_session(self, u, surface: str, ip: str, mfa_ok: bool) -> tuple[str, str]:
        tok, csrf = crypto.token(), crypto.token()
        now = utcnow()
        sc = self.cfg.d["session"]
        self.db.run("INSERT INTO sessions(id,user_id,surface,csrf,mfa_ok,created_at,last_seen,expires_at,ip) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (crypto.hash_token(tok), u["id"], surface, csrf, int(mfa_ok), iso(now), iso(now),
                     iso(now + dt.timedelta(hours=sc["absolute_hours"])), ip))
        if mfa_ok:
            self.db.run("UPDATE users SET last_login=? WHERE id=?", (iso(now), u["id"]))
            self.audit.record("user.signin", u["email"], "user", u["customer_id"], u["email"], "", ip)
        return tok, csrf

    # ---------------------------------------------------------- MFA
    def begin_mfa_enrol(self, user_id: str) -> str:
        secret = crypto.new_totp_secret()
        self.db.run("UPDATE users SET totp_sealed=?, mfa_enabled=0, totp_last_step=0 WHERE id=?",
                    (self.box.seal(secret, "totp:" + user_id), user_id))
        return secret

    def pending_totp_secret(self, user_id: str) -> str | None:
        u = self.db.one("SELECT totp_sealed FROM users WHERE id=?", (user_id,))
        return self.box.open(u["totp_sealed"], "totp:" + user_id) if u and u["totp_sealed"] else None

    def verify_mfa(self, sess: Session, code: str, ip: str, enrolling: bool = False) -> bool:
        if not self.limiter.hit("mfa:" + sess.user_id, 8, 300):
            raise AuthError("Too many attempts. Wait a few minutes and try again.")
        u = self.db.one("SELECT * FROM users WHERE id=?", (sess.user_id,))
        if not u or not u["totp_sealed"]:
            return False
        secret = self.box.open(u["totp_sealed"], "totp:" + u["id"])
        step = crypto.totp_verify(secret, code, u["totp_last_step"] or 0)
        if not step:
            logs.event(slog, logging.WARNING, "mfa failed", account=u["email"], ip=ip)
            return False
        self.db.run("UPDATE users SET totp_last_step=?, mfa_enabled=1, last_login=? WHERE id=?", (step, iso(), u["id"]))
        self.db.run("UPDATE sessions SET mfa_ok=1 WHERE id=?", (sess.id_hash,))
        self.audit.record("user.mfa_enrolled" if enrolling else "user.signin", u["email"], "user", u["customer_id"],
                          u["email"], "mfa", ip)
        return True

    def disable_mfa(self, user_id: str, actor: str, ip: str = "") -> None:
        u = self.db.one("SELECT * FROM users WHERE id=?", (user_id,))
        self.db.run("UPDATE users SET totp_sealed=NULL, mfa_enabled=0 WHERE id=?", (user_id,))
        self.audit.record("user.mfa_disabled", actor, "user", u["customer_id"], u["email"], "", ip)

    # ---------------------------------------------------------- session lookup
    def session(self, token: str | None, surface: str) -> Session | None:
        if not token:
            return None
        h = crypto.hash_token(token)
        r = self.db.one("SELECT s.*, u.customer_id, u.email, u.name, u.role, u.state ustate, u.mfa_enabled, "
                        "c.state cstate FROM sessions s JOIN users u ON u.id=s.user_id "
                        "LEFT JOIN customers c ON c.id=u.customer_id WHERE s.id=?", (h,))
        if not r or r["surface"] != surface or r["ustate"] != "active":
            return None
        now = utcnow()
        idle = dt.timedelta(minutes=self.cfg.d["session"]["idle_minutes"])
        if parse_iso(r["expires_at"]) < now or parse_iso(r["last_seen"]) + idle < now:
            self.db.run("DELETE FROM sessions WHERE id=?", (h,))
            return None
        if surface == "customer" and r["cstate"] in ("suspended", "closed"):
            return None
        self.db.run("UPDATE sessions SET last_seen=? WHERE id=?", (iso(now), h))
        flash = r["flash"]
        if flash:
            self.db.run("UPDATE sessions SET flash='' WHERE id=?", (h,))
        return Session(h, r["user_id"], surface, r["csrf"], bool(r["mfa_ok"]), r["customer_id"], r["email"],
                       r["name"], r["role"], flash, bool(r["mfa_enabled"]))

    def set_flash(self, sess: Session, msg: str) -> None:
        self.db.run("UPDATE sessions SET flash=? WHERE id=?", (msg[:300], sess.id_hash))

    def sign_out(self, sess: Session, ip: str = "") -> None:
        self.db.run("DELETE FROM sessions WHERE id=?", (sess.id_hash,))
        self.audit.record("user.signout", sess.email, "user", sess.customer_id, sess.email, "", ip)

    def revoke_user_sessions(self, user_id: str) -> None:
        self.db.run("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def purge_expired(self) -> int:
        return self.db.run("DELETE FROM sessions WHERE expires_at < ?", (iso(),)).rowcount


_DUMMY_HASH = crypto.hash_password("not-a-real-password-just-for-timing")
