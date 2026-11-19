"""Small shared helpers. No third-party imports."""
from __future__ import annotations

import datetime as _dt
import html
import re
import secrets

_UTC = _dt.timezone.utc


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_UTC)


def iso(ts: _dt.datetime | None = None) -> str:
    return (ts or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_UTC)


def new_id(prefix: str = "") -> str:
    return prefix + secrets.token_hex(8)


def esc(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


GB = 1000 ** 3
TB = 1000 ** 4
_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"]


def human_bytes(n: float) -> str:
    n = float(n or 0)
    i = 0
    while n >= 1000 and i < len(_UNITS) - 1:
        n /= 1000
        i += 1
    return f"{n:.0f} {_UNITS[i]}" if i == 0 else f"{n:.2f} {_UNITS[i]}"


def money(amount: float, currency: str = "USD") -> str:
    sym = {"USD": "$", "EUR": "€", "GBP": "£", "AED": "AED "}.get(currency, currency + " ")
    return f"{sym}{amount:,.2f}"


_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(s: str) -> str:
    return _SLUG.sub("-", s.lower()).strip("-")[:40] or "customer"


_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def valid_bucket_name(n: str) -> bool:
    return bool(_BUCKET.match(n)) and ".." not in n and not re.match(r"^\d+\.\d+\.\d+\.\d+$", n)


_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def valid_email(e: str) -> bool:
    return bool(_EMAIL.match(e or "")) and len(e) <= 254


def month_of(ts: _dt.datetime) -> str:
    return ts.strftime("%Y-%m")
