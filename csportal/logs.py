"""Structured logging: JSON lines, secret scrubbing, rotation, optional syslog, request ids.

Loggers:  csportal (application), csportal.access (HTTP access), csportal.security (sign-in and
policy events), csportal.job (background jobs).  The audit log of business changes is separate
and lives in the database (see audit.py).
"""
from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import re
import sys
from pathlib import Path

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_SECRET_KEYS = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|cookie|api[_-]?key|access[_-]?key|csrf|totp|otp)"
    r"(\"?\s*[:=]\s*\"?)([^\s\",;&]+)")


def scrub(text: str) -> str:
    return _SECRET_KEYS.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)


class Secret(str):
    """A string that never prints its value."""
    def __repr__(self):
        return "Secret([REDACTED])"

    def __str__(self):
        return "[REDACTED]"

    def reveal(self) -> str:
        return str.__str__(self)


class ScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = scrub(record.getMessage())
            record.args = ()
            fields = getattr(record, "fields", None)
            if isinstance(fields, dict):
                record.fields = {k: (scrub(v) if isinstance(v, str) else v) for k, v in fields.items()}
        except Exception:
            pass
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
            "level": record.levelname, "logger": record.name,
            "request_id": request_id.get(), "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            out.update(fields)
        if record.exc_info:
            out["exc"] = scrub(self.formatException(record.exc_info))
        return json.dumps(out, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s %(levelname)-7s %(name)s [%(rid)s] %(message)s")

    def format(self, record):
        record.rid = request_id.get()
        s = super().format(record)
        fields = getattr(record, "fields", None)
        return s + (" " + json.dumps(fields, default=str) if fields else "")


def event(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"fields": fields})


def setup(cfg) -> Path | None:
    import time
    logging.Formatter.converter = time.gmtime
    lc = cfg.d["log"]
    level = getattr(logging, str(lc["level"]).upper(), logging.INFO)
    fmt: logging.Formatter = JsonFormatter() if lc["json"] else TextFormatter()
    log_dir = Path(lc["dir"]) if lc["dir"] else cfg.data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("csportal")
    root.handlers.clear()
    root.setLevel(level)
    root.propagate = False
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    handlers.append(logging.handlers.RotatingFileHandler(
        log_dir / "csportal.log", maxBytes=int(lc["max_mb"]) * 1024 * 1024,
        backupCount=int(lc["backups"]), encoding="utf-8"))
    if lc["syslog"]:
        host, _, port = lc["syslog"].partition(":")
        handlers.append(logging.handlers.SysLogHandler(address=(host, int(port or 514))))
    for h in handlers:
        h.setFormatter(fmt)
        h.addFilter(ScrubFilter())
        root.addHandler(h)
    # access log to its own file as well (it also reaches the handlers above through propagation)
    acc = logging.getLogger("csportal.access")
    acc.handlers.clear()
    ah = logging.handlers.RotatingFileHandler(
        log_dir / "access.log", maxBytes=int(lc["max_mb"]) * 1024 * 1024,
        backupCount=int(lc["backups"]), encoding="utf-8")
    ah.setFormatter(JsonFormatter())
    ah.addFilter(ScrubFilter())
    acc.addHandler(ah)
    acc.propagate = False
    return log_dir


def tail(path: Path, lines: int = 200, contains: str = "", level: str = "") -> list[str]:
    """Last lines of a log file, optionally filtered. Reads at most the last 2 MB."""
    if not path.exists():
        return []
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 2 * 1024 * 1024))
        data = f.read().decode("utf-8", "replace").splitlines()
    out = []
    for ln in data:
        if contains and contains.lower() not in ln.lower():
            continue
        if level and f'"level": "{level.upper()}"' not in ln and f" {level.upper()} " not in ln:
            continue
        out.append(ln)
    return out[-lines:]
