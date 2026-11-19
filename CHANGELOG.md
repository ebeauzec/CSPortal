# Changelog

Neutral release notes. Each entry says what changed and what is **not verified**.

## Unreleased

**Added**
- `docs/compliance/CONTROL_MAP.md`: control map for ISO/IEC 27001:2022 Annex A and SOC 2 (security, availability,
  confidentiality), with the state of each control and the gaps that matter most.

- CI job `dependency-scan`: `pip-audit` on `requirements.txt` (fails the build on a known vulnerability), a
  CycloneDX software bill of materials published as a build artifact, and a weekly scheduled run.
- Dependabot configuration for Python packages, the base image and workflow actions.
- CI job `image-scan`: builds the production image and scans it (operating-system and Python packages) with
  Trivy 0.76.2, run as a container pinned by digest. A HIGH or CRITICAL finding with a fix available fails the
  build; the JSON report is kept as a build artifact. The same job proves the Dockerfile builds.

**Changed**
- ADR-007 accepted: compliance scope is ISO/IEC 27001 and SOC 2 (owner decision, 2026-11-19).
- `requirements.txt` now pins the two packages `cryptography` needs (`cffi` 2.1.1, `pycparser` 3.12), and
  THIRD_PARTY_NOTICES.md lists them. Earlier text saying "one third-party package" was incomplete.

- Dependency updates reviewed from Dependabot: `cryptography` 50.0.2, `actions/checkout` 7,
  `actions/setup-python` 7, `actions/upload-artifact` 7. Dependabot no longer proposes new Python minor or
  major versions for the base image (a Python 3.15 proposal was declined: not tested on 3.15).

**Not verified**
- The image scan has not been seen to run yet (Docker is not available on the development machine). It does not
  cover the host or the grid, and findings with no fix available yet do not fail it.
- The product has not been run on Python 3.15. The supported version stays 3.12.
- The dependency scan found no known vulnerabilities, locally and in its first GitHub Actions run (2026-11-19).
  It covers Python packages only, not the base image or host.
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
