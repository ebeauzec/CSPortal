"""The storage back-end interface. Modules call this, never a vendor API directly."""
from __future__ import annotations

from typing import Any


class BackendError(Exception):
    """A back-end failure with a stable portal code and a message safe to show."""

    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class StorageBackend:
    name = "base"
    verified = False            # True only once checked against a real grid
    description = ""

    # --- service
    def health(self) -> dict:                           # {ok, release, detail}
        raise NotImplementedError

    def grid_overview(self) -> dict:                    # CSP only: capacity, nodes, alerts
        raise NotImplementedError

    def endpoints(self, ref: str) -> dict:              # {s3: [url], regions: [name]}
        raise NotImplementedError

    # --- tenants (CSP side)
    def list_tenants(self) -> list[dict]:
        """Every tenant account on the grid: [{ref, name, quota_bytes}]. Used by the drift check."""
        raise NotImplementedError
    def create_tenant(self, name: str, quota_bytes: int, features: dict) -> str: raise NotImplementedError
    def update_tenant(self, ref: str, quota_bytes: int | None = None, features: dict | None = None) -> None: raise NotImplementedError
    def set_suspended(self, ref: str, suspended: bool) -> None: raise NotImplementedError
    def delete_tenant(self, ref: str) -> None: raise NotImplementedError

    # --- tenant self-management
    def usage(self, ref: str) -> dict: raise NotImplementedError       # {bytes_used, objects, quota_bytes, buckets:[]}
    def list_buckets(self, ref: str) -> list[dict]: raise NotImplementedError
    def get_bucket(self, ref: str, name: str) -> dict: raise NotImplementedError
    def create_bucket(self, ref: str, name: str, region: str, versioning: bool, object_lock: bool) -> None: raise NotImplementedError
    def delete_bucket(self, ref: str, name: str) -> None: raise NotImplementedError
    def update_bucket(self, ref: str, name: str, **changes: Any) -> None:
        """Changes: versioning ("enabled"/"suspended"), lifecycle (rules), public (bool), policy (document or None),
        cors (rules), lock_default ({mode, amount, unit} or None)."""
        raise NotImplementedError

    def list_groups(self, ref: str) -> list[dict]: raise NotImplementedError
    def create_group(self, ref: str, name: str, access: str, buckets: list[str] | None = None) -> None:
        """`buckets` limits the group to the named buckets; None or an empty list means every bucket."""
        raise NotImplementedError
    def update_group(self, ref: str, name: str, access: str | None = None, buckets: list[str] | None = None) -> None:
        """Change access and/or scope. `buckets` None keeps the scope; a list (empty = every bucket) replaces it."""
        raise NotImplementedError
    def delete_group(self, ref: str, name: str) -> None: raise NotImplementedError
    def list_users(self, ref: str) -> list[dict]: raise NotImplementedError
    def create_user(self, ref: str, username: str, full_name: str, groups: list[str]) -> None: raise NotImplementedError
    def update_user(self, ref: str, username: str, groups: list[str] | None = None, disabled: bool | None = None) -> None: raise NotImplementedError
    def delete_user(self, ref: str, username: str) -> None: raise NotImplementedError
    def list_keys(self, ref: str, username: str) -> list[dict]: raise NotImplementedError
    def create_key(self, ref: str, username: str, expires: str | None = None) -> dict: raise NotImplementedError    # {id, secret}
    def delete_key(self, ref: str, username: str, key_id: str) -> None: raise NotImplementedError
