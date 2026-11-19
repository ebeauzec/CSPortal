# Roadmap

Order of work. Dates are not promised; each release ends when its "done" test passes (see
[USE_CASES.md](USE_CASES.md)).

## Release 0. Foundations (done)

- Documentation, licence and ownership, repository rules and hooks.
- Stack decided (ADR-001).

## Release 1. Provision and self-manage (0.1.0 built; verification open)

Built in 0.1.0: core (accounts, MFA, roles, audit, jobs, notifications, module registry, logging), simulator,
StorageGRID connector, demo mode, and the modules `catalogue`, `tenant-onboarding`, `tenant-dashboard`,
`tenant-access`, `s3-access`, `buckets`, `usage-billing`, `capacity-alerts`, `audit-reports`, `system`
(including branding).

**Still open before Release 1 is closed:**
- Verify the connector on a real grid and record the supported release range (see the verification plan in
  [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md)). Use cases UC1 to UC4 are done only when their
  "done when" tests pass against a real grid.
- Owner decision: identity model (ADR-004). Compliance scope is decided (ISO/IEC 27001 and SOC 2, ADR-007).
- Independent penetration test and accessibility review.
- Hardening items marked Planned in [SECURITY.md](SECURITY.md): re-authentication for dangerous actions,
  four-eyes approval, key rotation commands, data export and deletion.

## Release 2. Full tenant parity

`federation`, `platform-services` (including grid federation), `object-browser`, `audit-reports`,
`support`, remaining bucket features (CORS, default encryption, access-time updates).
Close the gaps listed in [compliance/CONTROL_MAP.md](compliance/CONTROL_MAP.md) (dependency scan, audit retention,
four-eyes approval, key rotation, personal-data export and deletion), then map processing integrity and privacy.

## Release 3. Scale and reach

`reseller`, SLA reporting, budgets and forecasts, multi-grid and multi-region choice, server
database option, remaining rows of [TENANT_PARITY.md](TENANT_PARITY.md).

## Always

Security tests, accessibility checks, documentation kept true, and every claim of "verified" backed by
a run against a real grid.
