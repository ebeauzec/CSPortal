"""Simulated StorageGRID. Used for demo mode, development and automated tests.

It mimics the semantics the portal depends on (quota, bucket rules, versioning that cannot be
turned off once on, Object Lock only at creation, non-empty buckets cannot be deleted). Anything
proven only against this simulator is *not verified on a real grid*.
"""
from __future__ import annotations

import json
import random
import secrets
import threading
from pathlib import Path

from ..util import GB, TB, iso
from .base import BackendError, StorageBackend


class Simulator(StorageBackend):
    name = "simulator"
    verified = False
    description = "Built-in simulated StorageGRID (demo and test)"

    def __init__(self, state_file: Path | None = None, seed: int | None = None):
        self._file = Path(state_file) if state_file else None
        self._lock = threading.RLock()
        self._rnd = random.Random(seed)
        self.s: dict = {"next": 1000, "tenants": {}, "fail_next": None}
        if self._file and self._file.exists():
            self.s = json.loads(self._file.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ plumbing
    def _save(self):
        if self._file:
            self._file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.s), encoding="utf-8")
            tmp.replace(self._file)

    def _t(self, ref: str) -> dict:
        t = self.s["tenants"].get(ref)
        if not t:
            raise BackendError("tenant_not_found", "The storage account was not found.", 404)
        return t

    def _maybe_fail(self):
        if self.s.get("fail_next"):
            msg, self.s["fail_next"] = self.s["fail_next"], None
            raise BackendError("backend_unavailable", msg, 503)

    def fail_next(self, message: str = "Simulated back-end failure"):
        with self._lock:
            self.s["fail_next"] = message

    def reset(self):
        with self._lock:
            self.s = {"next": 1000, "tenants": {}, "fail_next": None}
            self._save()

    # ------------------------------------------------------------ service
    def health(self) -> dict:
        return {"ok": True, "release": "simulator", "detail": "Simulated grid; no real storage is used."}

    def grid_overview(self) -> dict:
        used = sum(b["bytes"] for t in self.s["tenants"].values() for b in t["buckets"].values())
        return {"capacity_bytes": 2000 * TB, "used_bytes": used + 612 * TB, "nodes_total": 12, "nodes_ok": 12,
                "alerts": [{"severity": "minor", "title": "Simulated: scheduled maintenance on site B"}] if self.s["tenants"] else []}

    def endpoints(self, ref: str) -> dict:
        self._t(ref)
        return {"s3": ["https://s3.example.net"], "regions": ["us-east-1"]}

    # ------------------------------------------------------------ tenants
    def create_tenant(self, name, quota_bytes, features) -> str:
        with self._lock:
            self._maybe_fail()
            if any(t["name"] == name for t in self.s["tenants"].values()):
                raise BackendError("tenant_exists", "A storage account with this name already exists.", 409)
            self.s["next"] += 1
            ref = str(self.s["next"] * 7919 % 10 ** 19).zfill(19)
            self.s["tenants"][ref] = {"name": name, "quota": quota_bytes, "features": features, "suspended": False,
                                      "buckets": {}, "groups": {}, "users": {}}
            self._save()
            return ref

    def update_tenant(self, ref, quota_bytes=None, features=None):
        with self._lock:
            self._maybe_fail()
            t = self._t(ref)
            if quota_bytes is not None:
                t["quota"] = quota_bytes
            if features is not None:
                t["features"] = features
            self._save()

    def set_suspended(self, ref, suspended):
        with self._lock:
            self._t(ref)["suspended"] = bool(suspended)
            self._save()

    def delete_tenant(self, ref):
        with self._lock:
            t = self._t(ref)
            if any(b["objects"] for b in t["buckets"].values()):
                raise BackendError("tenant_not_empty", "The storage account still holds objects.", 409)
            del self.s["tenants"][ref]
            self._save()

    # ------------------------------------------------------------ usage
    def usage(self, ref) -> dict:
        with self._lock:
            self._maybe_fail()
            t = self._t(ref)
            bs = [{"name": n, "bytes": b["bytes"], "objects": b["objects"]} for n, b in sorted(t["buckets"].items())]
            return {"bytes_used": sum(b["bytes"] for b in bs), "objects": sum(b["objects"] for b in bs),
                    "quota_bytes": t["quota"], "buckets": bs}

    def advance(self, factor: float = 1.0):
        """Demo only: grow data a little, as a live tenant would."""
        with self._lock:
            for t in self.s["tenants"].values():
                if t["suspended"]:
                    continue
                room = max(0, t["quota"] - sum(b["bytes"] for b in t["buckets"].values()))
                for b in t["buckets"].values():
                    add = int(self._rnd.uniform(0.0, 0.0015) * factor * max(b["bytes"], GB))
                    add = min(add, room)
                    room -= add
                    b["bytes"] += add
                    b["objects"] += add // (4 * 1000 ** 2) + (1 if add else 0)
            self._save()

    # ------------------------------------------------------------ buckets
    @staticmethod
    def _bview(name, b) -> dict:
        return {"name": name, "region": b["region"], "created": b["created"], "bytes": b["bytes"], "objects": b["objects"],
                "versioning": b["versioning"], "object_lock": b["object_lock"], "public": b["public"],
                "lifecycle": b["lifecycle"], "consistency": b["consistency"]}

    def list_buckets(self, ref):
        with self._lock:
            self._maybe_fail()
            return [self._bview(n, b) for n, b in sorted(self._t(ref)["buckets"].items())]

    def get_bucket(self, ref, name):
        with self._lock:
            b = self._t(ref)["buckets"].get(name)
            if not b:
                raise BackendError("bucket_not_found", "The bucket was not found.", 404)
            return self._bview(name, b)

    def create_bucket(self, ref, name, region, versioning, object_lock):
        with self._lock:
            self._maybe_fail()
            t = self._t(ref)
            if t["suspended"]:
                raise BackendError("suspended", "The storage account is suspended.", 403)
            if any(name in x["buckets"] for x in self.s["tenants"].values()):
                raise BackendError("bucket_exists", "A bucket with this name already exists on the service. Choose another name.", 409)
            if object_lock and not t["features"].get("object_lock", True):
                raise BackendError("feature_off", "Object Lock is not part of this plan.", 403)
            t["buckets"][name] = {"region": region, "created": iso(), "bytes": 0, "objects": 0,
                                  "versioning": "enabled" if (versioning or object_lock) else "off",
                                  "object_lock": bool(object_lock), "public": False, "lifecycle": [],
                                  "consistency": "read-after-new-write"}
            self._save()

    def delete_bucket(self, ref, name):
        with self._lock:
            t = self._t(ref)
            b = t["buckets"].get(name)
            if not b:
                raise BackendError("bucket_not_found", "The bucket was not found.", 404)
            if b["objects"]:
                raise BackendError("bucket_not_empty", "The bucket still holds objects. Empty it first.", 409)
            del t["buckets"][name]
            self._save()

    def update_bucket(self, ref, name, **ch):
        with self._lock:
            self._maybe_fail()
            b = self._t(ref)["buckets"].get(name)
            if not b:
                raise BackendError("bucket_not_found", "The bucket was not found.", 404)
            if "versioning" in ch:
                want = ch["versioning"]            # "enabled" or "suspended"
                if want == "suspended" and b["object_lock"]:
                    raise BackendError("locked", "Versioning cannot be suspended on a bucket with Object Lock.", 409)
                if want == "suspended" and b["versioning"] == "off":
                    raise BackendError("not_enabled", "Versioning was never enabled on this bucket.", 409)
                b["versioning"] = want
            if "lifecycle" in ch:
                if b["versioning"] == "off" and any(r.get("noncurrent_days") for r in ch["lifecycle"]):
                    raise BackendError("needs_versioning", "Rules for old versions need versioning on.", 409)
                b["lifecycle"] = ch["lifecycle"]
            if "public" in ch:
                b["public"] = bool(ch["public"])
            if "consistency" in ch:
                b["consistency"] = ch["consistency"]
            self._save()

    # ------------------------------------------------------------ users, groups, keys
    def list_groups(self, ref):
        with self._lock:
            return [{"name": n, **g} for n, g in sorted(self._t(ref)["groups"].items())]

    def create_group(self, ref, name, access):
        with self._lock:
            g = self._t(ref)["groups"]
            if name in g:
                raise BackendError("group_exists", "A group with this name already exists.", 409)
            g[name] = {"access": access, "created": iso()}
            self._save()

    def delete_group(self, ref, name):
        with self._lock:
            t = self._t(ref)
            if any(name in u["groups"] for u in t["users"].values()):
                raise BackendError("group_in_use", "Remove the users from this group first.", 409)
            t["groups"].pop(name, None)
            self._save()

    def list_users(self, ref):
        with self._lock:
            return [{"username": n, "full_name": u["full_name"], "groups": u["groups"], "disabled": u["disabled"],
                     "keys": len(u["keys"])} for n, u in sorted(self._t(ref)["users"].items())]

    def create_user(self, ref, username, full_name, groups):
        with self._lock:
            t = self._t(ref)
            if username in t["users"]:
                raise BackendError("user_exists", "A user with this name already exists.", 409)
            for g in groups:
                if g not in t["groups"]:
                    raise BackendError("group_not_found", f"Group {g} does not exist.", 404)
            t["users"][username] = {"full_name": full_name, "groups": groups, "disabled": False, "keys": {}}
            self._save()

    def update_user(self, ref, username, groups=None, disabled=None):
        with self._lock:
            t = self._t(ref)
            u = t["users"].get(username)
            if not u:
                raise BackendError("user_not_found", "The user was not found.", 404)
            if groups is not None:
                for g in groups:
                    if g not in t["groups"]:
                        raise BackendError("group_not_found", f"Group {g} does not exist.", 404)
                u["groups"] = groups
            if disabled is not None:
                u["disabled"] = bool(disabled)
            self._save()

    def delete_user(self, ref, username):
        with self._lock:
            self._t(ref)["users"].pop(username, None)
            self._save()

    def list_keys(self, ref, username):
        with self._lock:
            u = self._t(ref)["users"].get(username)
            if not u:
                raise BackendError("user_not_found", "The user was not found.", 404)
            return [{"id": k, "created": v["created"], "last_used": v.get("last_used")} for k, v in sorted(u["keys"].items())]

    def create_key(self, ref, username):
        with self._lock:
            u = self._t(ref)["users"].get(username)
            if not u:
                raise BackendError("user_not_found", "The user was not found.", 404)
            if u["disabled"]:
                raise BackendError("user_disabled", "The user is disabled.", 409)
            if len(u["keys"]) >= 5:
                raise BackendError("too_many_keys", "A user can hold at most 5 access keys. Delete one first.", 409)
            kid = "AK" + secrets.token_hex(9).upper()
            secret = secrets.token_urlsafe(30)
            u["keys"][kid] = {"created": iso(), "last_used": None}
            self._save()
            return {"id": kid, "secret": secret}      # the secret is returned once and not kept

    def delete_key(self, ref, username, key_id):
        with self._lock:
            u = self._t(ref)["users"].get(username)
            if u:
                u["keys"].pop(key_id, None)
            self._save()
