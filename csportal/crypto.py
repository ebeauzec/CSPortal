"""Cryptography helpers: master key, secret box (AES-256-GCM), password hashing (scrypt), TOTP.

Only the standard library and the `cryptography` package are used.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------- master key
def load_master_key(cfg) -> bytes:
    """Master key from env CSPORTAL_MASTER_KEY or a key file. Demo mode may create its own."""
    raw = os.environ.get("CSPORTAL_MASTER_KEY", "").strip()
    if not raw and cfg.d["master_key_file"]:
        raw = Path(cfg.d["master_key_file"]).read_text(encoding="utf-8").strip()
    if not raw and cfg.demo:
        kf = cfg.data_dir / "demo-master.key"
        if not kf.exists():
            kf.parent.mkdir(parents=True, exist_ok=True)
            kf.write_text(base64.b64encode(secrets.token_bytes(32)).decode(), encoding="utf-8")
        raw = kf.read_text(encoding="utf-8").strip()
    if not raw:
        raise SystemExit("No master key. Set CSPORTAL_MASTER_KEY (base64, 32 bytes) or master_key_file. "
                         "Generate one with: python -m csportal genkey")
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise SystemExit("The master key must be exactly 32 bytes (base64 encoded).")
    return key


def generate_master_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


class SecretBox:
    """Authenticated encryption for stored secrets. The `aad` binds a value to its purpose."""

    def __init__(self, key: bytes):
        self._aes = AESGCM(key)

    def seal(self, plaintext: str, aad: str = "") -> str:
        nonce = secrets.token_bytes(12)
        ct = self._aes.encrypt(nonce, plaintext.encode("utf-8"), aad.encode())
        return "v1." + base64.urlsafe_b64encode(nonce + ct).decode()

    def open(self, sealed: str, aad: str = "") -> str:
        if not sealed.startswith("v1."):
            raise ValueError("unknown secret format")
        raw = base64.urlsafe_b64decode(sealed[3:])
        return self._aes.decrypt(raw[:12], raw[12:], aad.encode()).decode("utf-8")


# ---------------------------------------------------------------- passwords
_N, _R, _P = 2 ** 15, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


# A short list of very common passwords, checked locally (no outside call).
_COMMON = {
    "password", "password1", "123456789012", "qwertyuiop12", "letmein12345", "welcome12345",
    "administrator", "changeme1234", "passw0rd1234", "iloveyou1234", "abc123456789", "000000000000",
    "111111111111", "password1234", "passwordpassword", "qwerty123456", "storagegrid1",
}


def password_problems(password: str, email: str = "", min_len: int = 12) -> list[str]:
    out = []
    if len(password) < min_len:
        out.append(f"at least {min_len} characters")
    if len(password) > 256:
        out.append("at most 256 characters")
    if password.lower() in _COMMON:
        out.append("not a commonly used password")
    local = email.split("@")[0].lower() if email else ""
    if local and len(local) >= 4 and local in password.lower():
        out.append("must not contain your e-mail name")
    if len(set(password)) < 5:
        out.append("use a wider mix of characters")
    return out


# ---------------------------------------------------------------- tokens
def token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // 30))


def totp_verify(secret_b32: str, code: str, last_step: int = 0, at: float | None = None) -> int:
    """Return the matched time step (> last_step) or 0. Accepts one step either side."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return 0
    step = int((at or time.time()) // 30)
    for s in (step - 1, step, step + 1):
        if s > last_step and hmac.compare_digest(_hotp(secret_b32, s), code):
            return s
    return 0


def totp_uri(secret_b32: str, account: str, issuer: str) -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}&issuer={quote(issuer)}&digits=6&period=30"
