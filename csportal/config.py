"""Configuration: one JSON file, optional environment overrides. Secure defaults."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

DEFAULTS: dict = {
    "mode": "production",              # "production" or "demo"
    "data_dir": "./data",
    "customer_listen": {"host": "0.0.0.0", "port": 8443},
    "admin_listen": {"host": "127.0.0.1", "port": 8444},   # private by default
    "tls": {"customer_cert": "", "customer_key": "", "admin_cert": "", "admin_key": ""},
    "behind_proxy": False,             # true when a reverse proxy terminates TLS
    "public_url": "https://portal.example.net",        # customer portal, used in invitation links
    "admin_public_url": "https://admin.example.net",   # admin console (private), used in staff invitation links
    "master_key_file": "",             # or env CSPORTAL_MASTER_KEY (base64, 32 bytes)
    "session": {"idle_minutes": 30, "absolute_hours": 8},
    "security": {
        "customer_mfa_required": True,
        "lockout_attempts": 5,
        "lockout_minutes": 15,
        "min_password_length": 12,
        "audit_retention_days": 2555,
    },
    "log": {
        "level": "INFO", "dir": "", "max_mb": 20, "backups": 10,
        "json": True, "syslog": "",    # "host:port" for UDP syslog forwarding
    },
    "backend": {
        "type": "simulator",           # "simulator" or "storagegrid"
        "storagegrid": {
            "base_url": "", "api_version": "v4", "account_id": "0",
            "username": "", "password_env": "CSPORTAL_GRID_PASSWORD",
            "ca_file": "", "verify_tls": True, "s3_endpoint": "",
        },
    },
    "smtp": {"host": "", "port": 587, "username": "", "password_env": "CSPORTAL_SMTP_PASSWORD",
             "from": "portal@example.net", "starttls": True},
    "branding": {"name": "Example Cloud Storage", "product": "Object Storage",
                 "color": "#0b5fff", "support_email": "support@example.net",
                 "support_url": "", "legal_text": ""},
    "jobs": {"usage_sample_minutes": 15, "alert_check_minutes": 15},
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict, path: str = ""):
        self.d = data
        self.path = path
        self.file_d = copy.deepcopy(data)      # what the file, environment and defaults say, before console changes

    def __getitem__(self, k):
        return self.d[k]

    def get(self, *keys, default=None):
        cur = self.d
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    @property
    def demo(self) -> bool:
        return self.d["mode"] == "demo"

    @property
    def data_dir(self) -> Path:
        return Path(self.d["data_dir"]).resolve()

    @property
    def secure_cookies(self) -> bool:
        return bool(self.d["behind_proxy"] or self.d["tls"].get("customer_cert"))


def load(path: str | None = None, overrides: dict | None = None) -> Config:
    path = path or os.environ.get("CSPORTAL_CONFIG", "")
    data = copy.deepcopy(DEFAULTS)
    if path and Path(path).exists():
        data = _merge(data, json.loads(Path(path).read_text(encoding="utf-8")))
    env_map = {"CSPORTAL_MODE": ("mode",), "CSPORTAL_DATA_DIR": ("data_dir",),
               "CSPORTAL_LOG_LEVEL": ("log", "level")}
    for env, keys in env_map.items():
        if os.environ.get(env):
            cur = data
            for k in keys[:-1]:
                cur = cur[k]
            cur[keys[-1]] = os.environ[env]
    if overrides:
        data = _merge(data, overrides)
    cfg = Config(data, path or "")
    problems = validate(cfg)
    if problems:
        raise SystemExit("Configuration error:\n  - " + "\n  - ".join(problems))
    return cfg


def validate(cfg: Config) -> list[str]:
    p = []
    d = cfg.d
    if d["mode"] not in ("production", "demo"):
        p.append("mode must be 'production' or 'demo'")
    if d["backend"]["type"] not in ("simulator", "storagegrid"):
        p.append("backend.type must be 'simulator' or 'storagegrid'")
    if d["mode"] == "demo" and d["backend"]["type"] != "simulator":
        p.append("demo mode only runs against the simulator; it can never be pointed at a real grid")
    if d["mode"] == "production":
        if d["backend"]["type"] == "simulator":
            p.append("production mode needs backend.type 'storagegrid'")
        if not cfg.secure_cookies:
            p.append("production mode needs TLS (tls.customer_cert) or behind_proxy=true")
        if d["backend"]["type"] == "storagegrid":
            sg = d["backend"]["storagegrid"]
            if sg["base_url"] and not sg["base_url"].startswith("https://"):
                p.append("backend.storagegrid.base_url must be an https:// URL (or leave it empty and enter the admin nodes in the admin console)")
            if not sg["verify_tls"]:
                p.append("backend.storagegrid.verify_tls cannot be false in production mode")
        if d["admin_listen"]["host"] in ("0.0.0.0", "::") and not d["behind_proxy"]:
            p.append("admin_listen must be a private address (not 0.0.0.0) in production mode")
        if d["admin_listen"]["port"] == d["customer_listen"]["port"]:
            p.append("admin and customer surfaces must use different ports")
    return p
