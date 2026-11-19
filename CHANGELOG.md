# Changelog

Neutral release notes. Each entry says what changed and what is **not verified**.

## Unreleased

**Added**
- `docs/compliance/CONTROL_MAP.md`: control map for ISO/IEC 27001:2022 Annex A and SOC 2 (security, availability,
  confidentiality), with the state of each control and the gaps that matter most.

**Changed**
- ADR-007 accepted: compliance scope is ISO/IEC 27001 and SOC 2 (owner decision, 2026-11-19).

**Not verified**
- The control map is a mapping of the product's own design to the controls. No audit, certificate or independent
  review has been done. Control numbering should be checked against the edition the auditor uses.

## 0.1.0 - 2026-11-19

First release candidate of Release 1.

**Added**
- Core: configuration with safe production rules, structured JSON logging (rotating files, optional syslog,
  secret scrubbing, request ids), embedded database with migrations, hash-chained audit log, accounts with
  scrypt password hashing, TOTP multi-factor authentication, lock-out and rate limiting, invitations.
- Two surfaces from one process: customer portal and private admin console, with a request pipeline that
  applies host and origin checks, anti-forgery tokens, role permissions, module entitlement and strict
  security headers (no inline script, no external origins).
- Modules: accounts, dashboard, system, catalogue (plans, modules), tenant onboarding, tenant access
  (portal users, storage users and groups), S3 access keys, buckets and data protection, usage and billing,
  capacity and alerts, activity and audit.
- Storage connector interface, a simulated StorageGRID, and a StorageGRID connector that uses the Grid
  Management, Tenant Management and S3 APIs, with a conformance check against the grid's own API description.
- Demo mode with pre-populated customers, buckets, usage history, statements, alerts and notices.
- Diagnostic bundle, database backup, log viewer, mail outbox, white-label branding.
- Docker image, compose file, example configuration, CI workflow, repository rules check and git hooks.
- Documentation set (see docs/README.md) and licence files.

**Not verified / known limits**
- The StorageGRID connector has not been run against a real grid. Endpoint paths and field names follow the
  public documentation and are checked at run time by `conformance`; treat results on your release as the
  authority.
- No independent penetration test or accessibility audit has been done.
- Single node; embedded database; no clustering.
- Not built yet: platform services, customer identity provider, object browser, support module, CORS and
  default-encryption settings, four-eyes approval for destructive actions, WebAuthn keys, PDF statements,
  webhook alert channel, master-key rotation command.
