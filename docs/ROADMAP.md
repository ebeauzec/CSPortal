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
- Hardening items still marked Planned in [SECURITY.md](SECURITY.md): security keys (WebAuthn) and single sign-on for staff.
  Re-authentication, four-eyes approval, key rotation, audit retention and personal-data export and deletion were
  built after 0.1.0 (see [CHANGELOG.md](../CHANGELOG.md)).

## Release 2. Full tenant parity

`federation`, `platform-services` (including grid federation), `object-browser`, `audit-reports`,
`support`, remaining bucket features (default encryption, access-time updates). CORS was built early (unreleased,
after 0.1.0) together with bucket access policies, Object Lock default retention, scoped groups, role changes,
invitation management and access key expiry; see [CUSTOMER_CONTROLS.md](CUSTOMER_CONTROLS.md).
Close the gaps listed in [compliance/CONTROL_MAP.md](compliance/CONTROL_MAP.md), then map processing integrity and privacy.

## What code cannot close

These items need people, a real grid or an outside party. Each has an exact closing step.

| Item | Why code cannot close it | Closing step |
|---|---|---|
| Connector verified on a real grid | The simulator and the fake grid only prove the portal agrees with itself and with the documented API | Run the 17-step plan in [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md#test-plan-for-a-real-grid) on a non-production grid; record the release and every result in the changelog; fix what differs; change the status words in the README, TENANT_PARITY and CUSTOMER_CONTROLS |
| Independent penetration test | It must be done by someone who did not write the code | Give a tester the demo mode build and the architecture and security pages; scope: both listeners, session handling, the policy editor, replay after re-authentication, the approval workflow; fix findings; publish the summary under docs/compliance |
| Identity model (ADR-004) | An owner decision | The owner confirms or changes ADR-004 in [DECISIONS.md](DECISIONS.md); if changed, update the architecture and security pages and the tests in the same commit |
| Host and grid scanning, patching, firewall | They belong to the CSP's own environment | Add the scan reports and the patch cadence to the CSP's evidence folder; see the control map's CSP column |
| Archive custody and restore proof | Needs the CSP's storage | Copy `data/backups` and `data/audit-archive` off the host; run [runbooks/RESTORE.md](runbooks/RESTORE.md) on another host once per quarter and file the result |
| Redundancy | Single node by design | Run the one replica under a virtualisation cluster or an orchestrator that restarts it; see [DEPLOYMENT.md](DEPLOYMENT.md) |

## Release 3. Scale and reach

`reseller`, SLA reporting, budgets and forecasts, multi-grid and multi-region choice, server
database option, remaining rows of [TENANT_PARITY.md](TENANT_PARITY.md).

## Always

Security tests, accessibility checks, documentation kept true, and every claim of "verified" backed by
a run against a real grid.
