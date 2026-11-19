"""Settings: every configuration parameter in one registry, changes made in the admin console, and the
storage grid connection (admin nodes, S3 gateway endpoints, credentials, certificates).

Where a value comes from, lowest to highest priority:  built-in default < configuration file / environment <
saved in the admin console. Secrets (grid and mail passwords) are stored encrypted, are write-only in the
console, and are never shown, logged or put in the diagnostic bundle.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import config as cfgmod
from .util import iso

# ------------------------------------------------------------------ the registry of parameters
GROUPS = [("general", "General"), ("network", "Network and TLS"), ("sessions", "Sessions"), ("security", "Security"),
          ("logging", "Logging"), ("mail", "Outgoing mail"), ("jobs", "Background jobs"), ("storage", "Storage grid")]

APPLY_TEXT = {"live": "Immediately", "restart": "After a restart", "file": "Configuration file only", "grid": "On the Storage grid page"}


@dataclass(frozen=True)
class Param:
    key: str                  # dotted path inside the configuration
    label: str
    group: str
    kind: str = "text"        # text, int, bool, choice, url, email
    help: str = ""
    apply: str = "file"       # live, restart, file (not editable here) or grid (edited on the Storage grid page)
    lo: int = 0
    hi: int = 0
    choices: tuple = ()
    maxlen: int = 200


PARAMS: list[Param] = [
    Param("mode", "Mode", "general", help="production or demo. Demo uses the built-in simulator and sample data.", apply="file"),
    Param("data_dir", "Data directory", "general", help="Database, logs and backups live here.", apply="file"),
    Param("public_url", "Customer portal address", "general", "url", "Used in invitation and reset links.", "live"),
    Param("admin_public_url", "Admin console address", "general", "url", "Used in staff invitation links. Keep it private.", "live"),
    Param("behind_proxy", "TLS ends at a reverse proxy", "network", "bool", "True when a proxy or load balancer provides HTTPS.", "file"),
    Param("customer_listen.host", "Customer portal listens on (address)", "network", apply="file"),
    Param("customer_listen.port", "Customer portal port", "network", "int", apply="file", lo=1, hi=65535),
    Param("admin_listen.host", "Admin console listens on (address)", "network", help="Must be a private address in production.", apply="file"),
    Param("admin_listen.port", "Admin console port", "network", "int", apply="file", lo=1, hi=65535),
    Param("admin_allow_proxy", "Admin console accepts proxy headers", "network", "bool", "Off is safest. Turn on only if a trusted internal proxy fronts the console.", "file"),
    Param("tls.customer_cert", "Customer portal certificate file", "network", apply="file"),
    Param("tls.customer_key", "Customer portal key file", "network", apply="file"),
    Param("tls.admin_cert", "Admin console certificate file", "network", apply="file"),
    Param("tls.admin_key", "Admin console key file", "network", apply="file"),
    Param("master_key_file", "Master key file", "network", help="The key itself is never shown. It can also come from the environment.", apply="file"),
    Param("session.idle_minutes", "Sign out after idle minutes", "sessions", "int", apply="live", lo=5, hi=720),
    Param("session.absolute_hours", "Sign out after hours (maximum session length)", "sessions", "int", apply="live", lo=1, hi=72),
    Param("security.customer_mfa_required", "Customers must use multi-factor authentication", "security", "bool", "Turning this off weakens security and is recorded in the audit log.", "live"),
    Param("security.lockout_attempts", "Failed sign-ins before lock-out", "security", "int", apply="live", lo=3, hi=50),
    Param("security.lockout_minutes", "Lock-out minutes", "security", "int", apply="live", lo=1, hi=1440),
    Param("security.min_password_length", "Minimum password length", "security", "int", apply="live", lo=8, hi=128),
    Param("security.audit_retention_days", "Audit log retention (days)", "security", "int", "Records older than this are written to an archive file in the data folder and removed, once a day. The chain keeps verifying.", "live", lo=30, hi=36500),
    Param("security.reauth_minutes", "Ask for the password again after (minutes)", "security", "int", "Sensitive actions (removing people, changing roles, deleting buckets, changing the grid connection) need a password confirmation when the last one is older than this.", "live", lo=1, hi=120),
    Param("security.four_eyes", "Second administrator must approve dangerous actions", "security", "bool", "When on, closing a customer, changing the grid connection and removing staff wait for approval by a different super administrator. Turning this off is recorded in the audit log.", "live"),
    Param("security.approval_hours", "Approval request lifetime (hours)", "security", "int", "A request that nobody approves in this time expires.", "live", lo=1, hi=720),
    Param("log.level", "Log level", "logging", "choice", apply="live", choices=("DEBUG", "INFO", "WARNING", "ERROR")),
    Param("log.dir", "Log directory", "logging", help="Empty means the logs folder inside the data directory.", apply="restart"),
    Param("log.max_mb", "Size of each log file (MB)", "logging", "int", apply="restart", lo=1, hi=1024),
    Param("log.backups", "Rotated log files kept", "logging", "int", apply="restart", lo=1, hi=200),
    Param("log.json", "Write logs as JSON", "logging", "bool", apply="restart"),
    Param("log.syslog", "Forward logs to syslog (host:port)", "logging", help="Empty means no forwarding.", apply="restart"),
    Param("smtp.host", "Mail relay host", "mail", help="Empty means the portal sends no mail; messages wait in the outbox.", apply="live"),
    Param("smtp.port", "Mail relay port", "mail", "int", apply="live", lo=1, hi=65535),
    Param("smtp.username", "Mail relay user name", "mail", apply="live"),
    Param("smtp.from", "Sender address", "mail", "email", apply="live"),
    Param("smtp.starttls", "Use STARTTLS", "mail", "bool", apply="live"),
    Param("jobs.usage_sample_minutes", "Usage sampling interval (minutes)", "jobs", "int", apply="restart", lo=1, hi=1440),
    Param("jobs.alert_check_minutes", "Alert check interval (minutes)", "jobs", "int", apply="restart", lo=1, hi=1440),
    Param("jobs.backup_hours", "Automatic database backup interval (hours, 0 = off)", "jobs", "int", "Each backup is checked after it is written. Copy backups off the host; keep the master key apart.", "restart", lo=0, hi=720),
    Param("jobs.backup_keep", "Automatic backups to keep", "jobs", "int", "Older automatic backups are removed.", "live", lo=1, hi=365),
    Param("jobs.drift_hours", "Grid comparison interval (hours, 0 = off)", "jobs", "int", "Compares customers and quotas with the tenant accounts on the grid and reports differences. Changes nothing.", "restart", lo=0, hi=720),
    Param("jobs.audit_checkpoint_minutes", "Audit checkpoint interval (minutes)", "jobs", "int", "Signs the newest audit record so removal of recent records is detected.", "restart", lo=5, hi=1440),
    Param("backend.type", "Storage connector", "storage", help="simulator (demo) or storagegrid.", apply="file"),
]
BY_KEY = {p.key: p for p in PARAMS}
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def get_path(d: dict, key: str, default=None):
    cur = d
    for k in key.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def set_path(d: dict, key: str, value) -> None:
    parts = key.split(".")
    cur = d
    for k in parts[:-1]:
        cur = cur.setdefault(k, {})
    cur[parts[-1]] = value


def parse_value(p: Param, raw, demo: bool = False):
    """Return (typed value, error). `raw` comes from a form, so it is text."""
    s = "" if raw is None else str(raw).strip()
    if p.kind == "bool":
        return (s.lower() in ("1", "true", "on", "yes")), ""
    if p.kind == "int":
        if not re.fullmatch(r"-?\d{1,9}", s):
            return None, f"{p.label}: enter a whole number."
        v = int(s)
        if not p.lo <= v <= p.hi:
            return None, f"{p.label}: must be between {p.lo} and {p.hi}."
        return v, ""
    if p.kind == "choice":
        if s not in p.choices:
            return None, f"{p.label}: choose one of {', '.join(p.choices)}."
        return s, ""
    if _CTRL.search(s) or len(s) > p.maxlen:
        return None, f"{p.label}: too long or contains control characters."
    if p.kind == "url":
        u = urlparse(s)
        if u.scheme not in (("https", "http") if demo else ("https",)) or not u.hostname or u.username or u.query or u.fragment:
            return None, f"{p.label}: enter an https:// address such as https://portal.example.net."
        return s.rstrip("/"), ""
    if p.kind == "email" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", s):
        return None, f"{p.label}: enter an e-mail address."
    return s, ""


def effective(cfg, p: Param):
    return get_path(cfg.d, p.key)


def source_of(cfg, db, p: Param) -> str:
    """'console', 'file' or 'default'."""
    if p.apply in ("live", "restart") and db.one("SELECT 1 FROM settings WHERE key=?", ("cfg." + p.key,)):
        return "console"
    return "file" if get_path(cfg.file_d, p.key) != get_path(cfgmod.DEFAULTS, p.key) else "default"


def apply_overrides(cfg, db) -> list[str]:
    """Put values saved in the console onto the configuration at start-up. Returns problems (bad values are skipped)."""
    problems = []
    for p in PARAMS:
        if p.apply not in ("live", "restart"):
            continue
        row = db.one("SELECT value FROM settings WHERE key=?", ("cfg." + p.key,))
        if not row:
            continue
        try:
            v, err = parse_value(p, json.loads(row["value"]), cfg.demo)
        except ValueError:
            v, err = None, f"{p.label}: stored value unreadable"
        if err:
            problems.append(err)
            continue
        set_path(cfg.d, p.key, v)
    return problems


def refresh_live(app) -> None:
    """Make running components pick up changed values that they copied at start-up."""
    import logging
    sc = app.cfg.d["security"]
    app.auth.lock_n, app.auth.lock_min, app.auth.min_len = sc["lockout_attempts"], sc["lockout_minutes"], sc["min_password_length"]
    logging.getLogger("csportal").setLevel(getattr(logging, str(app.cfg.d["log"]["level"]).upper(), logging.INFO))


def change_param(app, key: str, raw) -> tuple[bool, str, str, str]:
    """Validate and save one parameter. Returns (changed, error, old text, new text)."""
    p = BY_KEY.get(key)
    if not p or p.apply not in ("live", "restart"):
        return False, "This setting is not editable here.", "", ""
    v, err = parse_value(p, raw, app.cfg.demo)
    if err:
        return False, err, "", ""
    old = get_path(app.cfg.d, key)
    if v == old:
        return False, "", str(old), str(v)
    trial = copy.deepcopy(app.cfg.d)
    set_path(trial, key, v)
    problems = cfgmod.validate(cfgmod.Config(trial))
    if problems:
        return False, f"{p.label}: " + "; ".join(problems), "", ""
    app.db.set_setting("cfg." + key, json.dumps(v))
    set_path(app.cfg.d, key, v)
    refresh_live(app)
    return True, "", str(old), str(v)


def reset_param(app, key: str) -> bool:
    """Remove the console value so the file value applies again (live values take effect at once)."""
    p = BY_KEY.get(key)
    if not p or p.apply not in ("live", "restart"):
        return False
    app.db.run("DELETE FROM settings WHERE key=?", ("cfg." + key,))
    set_path(app.cfg.d, key, copy.deepcopy(get_path(app.cfg.file_d, key)))
    refresh_live(app)
    return True


def weakened(cfg) -> list[str]:
    """Settings that are weaker than the recommended defaults. Shown in the console; changes are audited."""
    d, out = cfg.d, []
    if not d["security"]["customer_mfa_required"]:
        out.append("Customers are not required to use multi-factor authentication.")
    if d["security"]["min_password_length"] < 12:
        out.append(f"Minimum password length is {d['security']['min_password_length']} (recommended: 12 or more).")
    if d["security"]["lockout_attempts"] > 10:
        out.append(f"Lock-out only after {d['security']['lockout_attempts']} failed sign-ins (recommended: 10 or fewer).")
    if not d["security"].get("four_eyes"):
        out.append("Dangerous provider actions (closing a customer, changing the grid connection, removing staff) do not need a second approver.")
    if d["security"].get("reauth_minutes", 10) > 30:
        out.append(f"Sensitive actions only ask for the password again after {d['security']['reauth_minutes']} minutes (recommended: 30 or fewer).")
    if d["session"]["idle_minutes"] > 60:
        out.append(f"Idle sessions last {d['session']['idle_minutes']} minutes (recommended: 60 or fewer).")
    if d["session"]["absolute_hours"] > 12:
        out.append(f"Sessions last up to {d['session']['absolute_hours']} hours (recommended: 12 or fewer).")
    return out


# ------------------------------------------------------------------ encrypted secrets (write-only in the console)
def secret_put(db, box, name: str, value: str) -> None:
    db.run("INSERT INTO secrets(name,sealed,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET "
           "sealed=excluded.sealed, updated_at=excluded.updated_at", (name, box.seal(value, name), iso()))


def secret_get(db, box, name: str) -> str:
    r = db.one("SELECT sealed FROM secrets WHERE name=?", (name,))
    return box.open(r["sealed"], name) if r else ""


def secret_updated(db, name: str) -> str:
    r = db.one("SELECT updated_at FROM secrets WHERE name=?", (name,))
    return r["updated_at"] if r else ""


def secret_clear(db, name: str) -> None:
    db.run("DELETE FROM secrets WHERE name=?", (name,))


def smtp_password(app) -> str:
    return secret_get(app.db, app.box, "smtp:password") or os.environ.get(app.cfg.d["smtp"]["password_env"], "")


# ------------------------------------------------------------------ storage grid connection
GRID_SECRET = "grid:provisioning"
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{1,29}$")
MAX_NODES, MAX_ENDPOINTS, MAX_CERTS = 8, 16, 50


@dataclass
class AdminNode:
    name: str
    host: str
    port: int = 443


@dataclass
class S3Endpoint:
    name: str
    url: str
    region: str = "us-east-1"
    note: str = ""


@dataclass
class GridConn:
    nodes: list = field(default_factory=list)          # AdminNode, the first is the primary and is tried first
    api_version: str = "v4"
    account_id: str = "0"                              # 0 is the grid itself
    username: str = ""
    ca_pem: str = ""                                   # CA certificates saved in the console
    ca_file: str = ""                                  # CA file named in the configuration file (read-only here)
    source_address: str = ""                           # how the grid sees the portal; for the grid's firewall rules
    timeout: int = 20
    endpoints: list = field(default_factory=list)      # S3Endpoint, the first is used by the portal for bucket settings

    def base_urls(self) -> list[str]:
        out = []
        for n in self.nodes:
            h = f"[{n.host}]" if ":" in n.host else n.host
            out.append(f"https://{h}" + ("" if n.port == 443 else f":{n.port}"))
        return out

    def to_json(self) -> str:
        d = {"nodes": [vars(n) for n in self.nodes], "api_version": self.api_version, "account_id": self.account_id,
             "username": self.username, "ca_pem": self.ca_pem, "source_address": self.source_address,
             "timeout": self.timeout, "endpoints": [vars(e) for e in self.endpoints]}
        return json.dumps(d)

    @staticmethod
    def from_json(text: str, ca_file: str = "") -> "GridConn":
        d = json.loads(text)
        return GridConn([AdminNode(**n) for n in d.get("nodes", [])], d.get("api_version", "v4"), d.get("account_id", "0"),
                        d.get("username", ""), d.get("ca_pem", ""), ca_file, d.get("source_address", ""),
                        int(d.get("timeout", 20)), [S3Endpoint(**e) for e in d.get("endpoints", [])])


def _split_host_port(addr: str) -> tuple[str, int, str]:
    addr = addr.strip()
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif addr.count(":") == 1:
        host, _, port = addr.partition(":")
    else:
        host, port = addr, ""
    if port and not (port.isdigit() and 1 <= int(port) <= 65535):
        return host, 0, "the port must be a number from 1 to 65535"
    return host, int(port or 443), ""


def host_problem(h: str, demo: bool) -> str:
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "" if _HOST.match(h) else "not a valid host name or IP address"
    if ip.is_unspecified or ip.is_multicast:
        return "not a usable address"
    if not demo and (ip.is_loopback or ip.is_link_local):
        return "loopback and link-local addresses are not allowed"
    return ""


def parse_nodes(text: str, demo: bool = False) -> tuple[list, list[str]]:
    """One admin node per line: 'name, address[:port]' or 'address[:port]'. The first line is the primary."""
    nodes, errs = [], []
    for n, line in enumerate([l.strip() for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")], 1):
        name, _, addr = line.partition(",") if "," in line else ("", "", line)
        name, addr = name.strip() or f"admin-node-{n}", addr.strip()
        host, port, perr = _split_host_port(addr)
        bad = perr or host_problem(host, demo)
        if bad:
            errs.append(f"Admin node line {n} ({addr}): {bad}.")
        elif not _NAME.match(name):
            errs.append(f"Admin node line {n}: the name may use letters, numbers, space, dot, hyphen and underscore.")
        else:
            nodes.append(AdminNode(name, host, port))
    if len(nodes) > MAX_NODES:
        errs.append(f"At most {MAX_NODES} admin nodes.")
    if len({(x.host, x.port) for x in nodes}) != len(nodes):
        errs.append("The same admin node is listed twice.")
    if not nodes and not errs:
        errs.append("Enter at least one admin node (the primary first).")
    return nodes, errs


def parse_endpoints(text: str, demo: bool = False) -> tuple[list, list[str]]:
    """One gateway endpoint per line: 'name | https://host[:port] | region | note' (only the address is required)."""
    eps, errs = [], []
    for n, line in enumerate([l.strip() for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")], 1):
        parts = [p.strip() for p in line.split("|")]
        if parts[0].lower().startswith(("http://", "https://")):      # address only: give it a name
            parts = [f"s3-endpoint-{n}"] + parts
        name, url = parts[0], (parts[1] if len(parts) > 1 else "")
        region = (parts[2] if len(parts) > 2 and parts[2] else "us-east-1")
        note = parts[3] if len(parts) > 3 else ""
        u = urlparse(url)
        if u.scheme != "https" or not u.hostname or u.username or u.path not in ("", "/") or u.query or u.fragment or u.params:
            errs.append(f"Endpoint line {n}: the address must look like https://s3.example.net or https://s3.example.net:8082 (no path).")
            continue
        try:
            port = u.port
        except ValueError:
            errs.append(f"Endpoint line {n}: invalid port.")
            continue
        bad = host_problem(u.hostname, demo)
        if bad:
            errs.append(f"Endpoint line {n} ({u.hostname}): {bad}.")
        elif not _NAME.match(name):
            errs.append(f"Endpoint line {n}: the name may use letters, numbers, space, dot, hyphen and underscore.")
        elif not _REGION.match(region):
            errs.append(f"Endpoint line {n}: the region name must be lower-case letters, numbers and hyphens.")
        elif _CTRL.search(note) or len(note) > 200:
            errs.append(f"Endpoint line {n}: the note is too long.")
        else:
            h = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
            eps.append(S3Endpoint(name, f"https://{h}" + (f":{port}" if port and port != 443 else ""), region, note))
    if len(eps) > MAX_ENDPOINTS:
        errs.append(f"At most {MAX_ENDPOINTS} endpoints.")
    if len({e.url for e in eps}) != len(eps):
        errs.append("The same endpoint is listed twice.")
    return eps, errs


def format_nodes(nodes) -> str:
    out = []
    for n in nodes:
        addr = f"[{n.host}]:{n.port}" if ":" in n.host else (n.host if n.port == 443 else f"{n.host}:{n.port}")
        out.append(f"{n.name}, {addr}")
    return "\n".join(out)


def format_endpoints(eps) -> str:
    return "\n".join(" | ".join([e.name, e.url, e.region] + ([e.note] if e.note else [])) for e in eps)


def cert_infos(pem: str) -> tuple[list[dict], str]:
    """Check pasted CA certificates. Returns (details per certificate, error). Rejects private keys."""
    from cryptography import x509
    if not pem.strip():
        return [], ""
    if "PRIVATE KEY" in pem:
        return [], "That text contains a private key. Paste only certificates (BEGIN CERTIFICATE)."
    if len(pem) > 200_000:
        return [], "The certificate text is too large."
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.S)
    leftover = re.sub(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", "", pem, flags=re.S).strip()
    if not blocks or (leftover and not all(l.startswith("#") for l in leftover.splitlines() if l.strip())):
        return [], "Paste one or more certificates, each from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----."
    if len(blocks) > MAX_CERTS:
        return [], f"At most {MAX_CERTS} certificates."
    out = []
    for b in blocks:
        try:
            c = x509.load_pem_x509_certificate(b.encode())
        except ValueError:
            return [], "One of the certificates could not be read. Check that it was copied completely."
        out.append(describe_cert(c))
    return out, ""


def describe_cert(c) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    na = c.not_valid_after_utc if hasattr(c, "not_valid_after_utc") else c.not_valid_after.replace(tzinfo=timezone.utc)
    nb = c.not_valid_before_utc if hasattr(c, "not_valid_before_utc") else c.not_valid_before.replace(tzinfo=timezone.utc)
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(x.value) for x in san]
    except x509.ExtensionNotFound:
        names = []
    try:
        is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    days = (na - datetime.now(timezone.utc)).days
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "not_before": nb.strftime("%Y-%m-%d"), "not_after": na.strftime("%Y-%m-%d"), "days_left": days,
            "sha256": c.fingerprint(hashes.SHA256()).hex(":").upper(), "names": names[:12], "is_ca": bool(is_ca)}


def demo_conn() -> GridConn:
    """Illustrative values shown in demo mode (documentation address range). Nothing here is contacted."""
    return GridConn([AdminNode("admin-primary", "192.0.2.11", 443), AdminNode("admin-secondary", "192.0.2.12", 443)],
                    "v4", "0", "csportal-provisioning", "", "", "198.51.100.20", 20,
                    [S3Endpoint("s3-primary", "https://s3.example.net", "us-east-1", "Load balancer endpoint, HA group of the gateway nodes"),
                     S3Endpoint("s3-secondary-site", "https://s3-b.example.net:8082", "us-east-1", "Second site gateway")])


def conn_from_file(cfg) -> GridConn:
    sg = cfg.d["backend"]["storagegrid"]
    nodes = []
    if sg.get("base_url"):
        u = urlparse(sg["base_url"])
        if u.hostname:
            nodes = [AdminNode("admin-node-1", u.hostname, u.port or 443)]
    eps = [S3Endpoint("s3-endpoint-1", sg["s3_endpoint"].rstrip("/"))] if sg.get("s3_endpoint") else []
    return GridConn(nodes, sg["api_version"], str(sg["account_id"]), sg["username"], "", sg.get("ca_file", ""), "", 20, eps)


def load_grid(cfg, db) -> GridConn:
    row = db.one("SELECT value FROM settings WHERE key='grid.conn'")
    ca_file = cfg.d["backend"]["storagegrid"].get("ca_file", "")
    if row:
        try:
            return GridConn.from_json(row["value"], ca_file)
        except (ValueError, TypeError, KeyError):
            pass
    return demo_conn() if cfg.demo else conn_from_file(cfg)


def save_grid(db, conn: GridConn) -> None:
    db.set_setting("grid.conn", conn.to_json())


def grid_password(cfg, db, box) -> str:
    """The password saved in the console wins; otherwise the environment variable named in the configuration."""
    return secret_get(db, box, GRID_SECRET) or os.environ.get(cfg.d["backend"]["storagegrid"]["password_env"], "")


def grid_password_source(cfg, db) -> str:
    env = cfg.d["backend"]["storagegrid"]["password_env"]
    if secret_updated(db, GRID_SECRET):
        return "saved in the console (encrypted)"
    if os.environ.get(env, ""):
        return f"environment variable {env}"
    return "not set"


def validate_conn(conn: GridConn, demo: bool = False) -> list[str]:
    errs = []
    if not re.fullmatch(r"v\d{1,2}", conn.api_version):
        errs.append("API version must look like v4.")
    if not re.fullmatch(r"\d{1,20}", conn.account_id):
        errs.append("Account ID must be a number (0 is the grid itself).")
    if not conn.username or _CTRL.search(conn.username) or len(conn.username) > 100:
        errs.append("Enter the grid user name the portal signs in with.")
    if not 3 <= conn.timeout <= 120:
        errs.append("Timeout must be between 3 and 120 seconds.")
    if conn.source_address and (_CTRL.search(conn.source_address) or len(conn.source_address) > 200):
        errs.append("Portal source address is too long.")
    if not conn.endpoints:
        errs.append("Enter at least one S3 gateway endpoint: customers need it to reach their data.")
    return errs


def save_test(db, result: dict) -> None:
    db.set_setting("grid.last_test", json.dumps(result))


def last_test(db) -> dict | None:
    r = db.one("SELECT value FROM settings WHERE key='grid.last_test'")
    try:
        return json.loads(r["value"]) if r else None
    except ValueError:
        return None


# What the grid administrators must prepare. Indicative: checked against the grid's own documentation for your
# release before use (the connector is not yet verified on a real grid).
GRID_PERMISSIONS = [
    ("Tenant accounts", "Create, change and delete tenant accounts and set their quotas and permissions."),
    ("Metrics query", "Read usage and health figures for the portal's dashboards and alerts."),
    ("Read-write access mode", "The group must not be read-only: the portal creates and changes tenant accounts."),
    ("Not needed", "Root access, maintenance, ILM and any other administrator permission. Do not grant them."),
]
TENANT_SERVICE_ACCOUNT = [
    "Group csportal-service with: manage all containers (buckets), manage endpoints, manage own S3 credentials; no root access.",
    "User csportal-service in that group, and one S3 access key used only to apply bucket settings that S3 alone can set.",
    "Their credentials are stored encrypted in the portal. Do not delete them in the tenant; the portal would lose control of the tenant.",
]
