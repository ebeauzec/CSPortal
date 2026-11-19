# Modules

CSPortal is built from modules. The core provides identity, permissions, settings, audit, jobs and
notifications; everything a user sees as a feature is a module. The CSP turns modules on and off in the
admin console (Modules), per plan (Plans) and per customer (Customer, Features).

## Module contract

A module is one Python file in `csportal/modules/` with two parts:

```python
MODULE = {
    "id": "usage-billing", "name": "Usage and billing", "version": "1.0.0",
    "surfaces": ["customer", "admin"],      # which surfaces it adds screens to
    "requires": [],                         # other module ids it needs
    "core": False,                          # core modules cannot be switched off
    "description": "...",
    "nav": [{"surface": "customer", "label": "Usage", "path": "/usage", "perm": "usage.view", "group": "Service", "order": 10}],
}

def register(app):
    @app.route("customer", "GET", "/usage", perm="usage.view", module="usage-billing")
    def usage(ctx): ...
```

Rules, each enforced by the framework or by a test:
1. **Permission on every route.** A route without `perm` is reachable by any signed-in user, so only account
   pages use that. Roles and permissions are in `csportal/auth.py`.
2. **Customer data only through the scoped accessor.** Customer-surface code reads and writes through
   `ctx.scoped`, which adds the customer id to every query and refuses tables that are not customer-scoped.
   Back-end calls use `ctx.ref`, the signed-in customer's own storage account, never a value from the request.
3. **Storage only through the connector interface** (`app.backend`), never a vendor API directly.
4. **Dependencies are declared** in `requires`. The module registry refuses to start with a missing
   dependency, and the admin console refuses to switch off a module that others need.
5. **Entitlement is checked by the framework.** A customer reaches a module's routes only when the module
   is on, in the customer's plan, and not switched off for that customer. Otherwise the page answers 404.
6. **Every change is audited** with `ctx.audit(...)`.
7. **Every module has tests** and a section in this file.

## Entitlement

A feature is available to a customer when all of these are true: the module is installed, the module is
switched on, the customer's plan includes it, and the customer has no override switching it off. The admin
console shows the result per customer, with the reason when something is missing.

## Modules in version 0.1.0

| Id | Surfaces | Purpose | Use case | State |
|---|---|---|---|---|
| `core-accounts` (core) | both | Sign-in, multi-factor authentication, invitations, own account | UC1 | Built |
| `tenant-dashboard` (core) | both | Customer dashboard; provider overview | all | Built |
| `system` (core) | admin | Health, logs, diagnostic bundle, backup, staff users, branding, demo reset | all | Built |
| `operations` (core) | admin | Approvals by a second super administrator, drift check, backups, audit integrity, personal-data export and erasure | all | Built |
| `catalogue` | admin | Plans, rate cards, feature switches, module switchboard | UC1, UC2 | Built |
| `tenant-onboarding` | admin | Create, suspend, resume, close customers and their grid tenants | UC1 | Built |
| `tenant-access` | customer | Portal users, roles, invitations, sessions; storage users and groups scoped to buckets | UC1 | Built (1.2.0) |
| `s3-access` | customer | Guided key creation (name, permissions, buckets, expiry), secret shown once, connection details and test command, replacement and removal | UC1 | Built (2.0.0) |
| `buckets` | customer | Guided bucket creation (1.2.0), buckets, versioning, lifecycle, access policy, CORS, Object Lock and default retention, protection posture | UC3 | Built (1.1.0) |
| `usage-billing` | both | Usage trends, monthly statements, adjustments, CSV export | UC2 | Built |
| `capacity-alerts` | both | Quota meter, alerts, quota requests, status notices | UC4 | Built |
| `audit-reports` | both | Customer activity history; provider audit with chain check | UC6 (part) | Built |

"Built" means implemented and tested against the built-in simulator. It does not mean verified on a real
StorageGRID; see [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md).

## Planned modules

| Id | Release | Purpose | Use case |
|---|---|---|---|
| `platform-services` | 2 | Replication, notifications, search integration, grid federation | UC3 |
| `federation` | 2 | Customer-managed identity provider | UC7 |
| `object-browser` | 2 | Browse and transfer objects with time-limited links | parity |
| `support` | 2 | Requests and ticketing hand-off | UC5 |
| `reseller` | 3 | Sub-accounts and partner model | UC10 |

## Adding a module

1. Create `csportal/modules/<name>.py` with `MODULE` and `register(app)`, and add it to `ORDER` in
   `csportal/modules/__init__.py`.
2. Declare permissions in `csportal/auth.py` and decide which roles get them.
3. Add tests, including one that shows a customer cannot reach another customer's data through it.
4. Add the module to the tables above and update [TENANT_PARITY.md](TENANT_PARITY.md) and
   [CHANGELOG.md](../CHANGELOG.md).
