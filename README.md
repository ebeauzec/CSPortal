# CSPortal

A white-label, self-service portal for cloud service providers (CSPs) that sell object storage on
**NetApp StorageGRID**. The CSP's customers sign in to the CSP's own branded portal and manage their own
tenant: buckets, access keys, users, lifecycle and data protection, usage and invoices, quota and alerts. The
CSP configures everything in a separate, internal admin console.

- **Customer portal** (external): self-service for the end customer.
- **Admin console** (internal, private network): customers, plans and rate cards, modules, branding, quota
  approvals, audit, logs, diagnostics.
- **Modular:** every capability is a module the CSP switches on or off per plan and per customer.
- **Secure by design, simple, self-contained:** one process, an embedded database, no outside calls, no CDN.
- **Native:** talks to StorageGRID only through its documented Grid Management, Tenant Management and S3 APIs.
- **Demo mode:** a pre-populated simulated service for presentations and evaluation.

Copyright © 2026 Obi1 - FZCO. All Rights Reserved. Proprietary; see [LICENSE](LICENSE) and [LEGAL.md](LEGAL.md).
CSPortal is an independent product, not affiliated with or endorsed by NetApp, Inc. NetApp and StorageGRID are
trademarks of NetApp, Inc.

## Try it in two minutes

```
pip install -r requirements.txt
python -m csportal demo
```

Open <http://127.0.0.1:8443/> (customer portal) and <http://127.0.0.1:8444/> (admin console). The sign-in pages list the demo
accounts. See [docs/DEMO.md](docs/DEMO.md).

## Use cases (Release 1)

| | Use case | Customer sees | CSP controls |
|---|---|---|---|
| UC1 | Tenant onboarding and access | Invitation (cancel, resend), sign-in with MFA, people and role changes, storage users and groups scoped to buckets, S3 keys (shown once, optional expiry) | Plans, create/suspend/close customers, feature switches |
| UC2 | Usage, metering, billing | Usage trends, by-bucket view, month-to-date estimate, monthly statements, CSV | Rate cards, month close, adjustments, exports |
| UC3 | Buckets and data protection | Create buckets, versioning, lifecycle, per-bucket access rules and policy editor, public-access guard, encrypted-connections-only, CORS, Object Lock default retention, protection panel | Per-plan limits on buckets, public access, Object Lock |
| UC4 | Capacity and alerts | Quota meter, e-mail alerts, quota requests, service notices | Approval queue, auto-approve rules, notices |

Details: [docs/USE_CASES.md](docs/USE_CASES.md). What a tenant can do on StorageGRID and where it lives in the portal:
[docs/TENANT_PARITY.md](docs/TENANT_PARITY.md).

## Status

Version 0.1.0, a release candidate for Release 1. Be clear about what that means:

| Area | State |
|---|---|
| Core, both surfaces, 11 modules, demo mode, logging, audit | Built and tested (automated end-to-end tests against the simulator) |
| StorageGRID connector | **Written, not yet verified on a real grid.** Run `python -m csportal conformance` against your grid first; see [docs/STORAGEGRID_INTEGRATION.md](docs/STORAGEGRID_INTEGRATION.md) |
| Security | Designed per [docs/SECURITY.md](docs/SECURITY.md); implementation status listed there. **Not yet independently penetration tested** |
| Scale and availability | Single node, embedded database. No clustering yet |
| Release 2 features (platform services, own identity provider, object browser, support, default encryption) | Planned; see [docs/ROADMAP.md](docs/ROADMAP.md) |

Verify on a non-production grid, run your own security review and test restores before serving customers.

## Documentation

| | |
|---|---|
| [docs/README.md](docs/README.md) | Index of all documentation |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production install, hardening checklist, backup, upgrade |
| [docs/DEMO.md](docs/DEMO.md) | Demo mode and a demonstration path |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MODULES.md](docs/MODULES.md) | Design and module contract |
| [docs/SECURITY.md](docs/SECURITY.md), [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | Security design and compliance |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Run, log, diagnose, recover |

## Layout

```
csportal/            application (Python 3.12; only direct third-party package: cryptography)
  backends/          storage connector interface, simulator, StorageGRID connector
  modules/           one file per module
  web/               HTTP layer, security pipeline, UI toolkit, static files (no external assets)
docs/                documentation (kept true with the code; see docs/DOCUMENTATION_POLICY.md)
deploy/              example configuration
tests/               end-to-end and unit tests:  PYTHONPATH=. python -m unittest discover -s tests
tools/               repository rules check
```

## Commands

```
python -m csportal serve | demo | genkey | init-admin | conformance | bundle | backup | verify-audit
```
