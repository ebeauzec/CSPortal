# Changelog

Neutral release notes. Each entry says what changed and what is **not verified**.

## Unreleased

**Fixed (invitations and outgoing mail)**
- Messages now carry `Date` and `Message-ID` headers; many mail systems refuse or junk a message without them. Port 465 now
  uses TLS from the first byte (it hung before).
- The admin console's Mail outbox has **Send a test message**, which reports the relay's answer, so mail can be proved before
  invitations rely on it.
- In demo mode, where no mail is delivered, the invitation result page and the person's Manage page show the link. It is never
  shown outside demo mode.
- Tests with a fake mail relay cover a working relay, a broken one, no relay, port 465 and the demo link.
- Not tested against a real mail provider.

**Fixed (StorageGRID connector, after a check against NetApp's published documentation; see `docs/API_VERIFICATION.md`)**
- New tenants are created with the `management` capability. Without it the tenant sign-in the portal uses would very
  probably have been refused.
- No quota is sent as `null`, not `0`. The grid sign-in no longer sends an account id.
- Access keys are listed and deleted by the grid's own key id and shown with the grid's masked label.
- A user change is a full `PUT`; group and tenant changes send only writable fields; the bucket list asks for the region and
  reads Object Lock correctly; long lists are read page by page; a key answer without a secret is removed.
- **Removed the "clean incomplete uploads" rule** (on by default for new buckets, and in the lifecycle form).
  StorageGRID does not support `AbortIncompleteMultipartUpload`, so the grid would very probably have refused it.
- Paper check only. The connector is still not run against a real grid.

**Changed (people and invitations; see `docs/PEOPLE_GUIDE.md`)**
- **Guided invitation** for customer administrators: three plain questions (who, what role, what happens next), the safe
  role preselected, problems explained in words with the answers kept. The result page says whether the e-mail was sent,
  what the person will do, and what to try if the e-mail does not arrive.
- **Manage a person** page: one page per person with only the actions that apply (change role, send a new invitation, cancel
  the link, unlock, sign out everywhere, reset MFA, remove), each explained before the button. The People list shows status
  in words, last sign-in and a five-step summary. Existing actions, guards and password confirmations are unchanged.
- Customer guide `docs/PEOPLE_GUIDE.md`. Module `tenant-access` 1.2.0. Not verified on a real e-mail system.

**Changed (bucket creation; see `docs/BUCKETS_GUIDE.md`)**
- **Guided bucket creation**: four plain questions on one page (name and region; protection; clean-up; who can use it).
  Name problems are explained with a suggested fix. Protection choices: keep old versions, latest only, or lock with a
  retention time (standard or strict, strict needs a confirmation). Optional clean-up rules are created with the bucket.
  If the grid refuses part of the set-up the empty bucket is removed again.
- Result page with what was created, next steps (including an access key limited to the new bucket, opened with the bucket
  already ticked), and short answers to common questions. The Buckets page explains the process in four steps.
- Customer guide `docs/BUCKETS_GUIDE.md`. Not verified on a real grid.

**Changed (access keys; see `docs/ACCESS_KEYS_GUIDE.md`)**
- **Guided key creation** for customer administrators: four plain questions, one button; the portal creates the storage
  user, its own group and the key, and rolls back if the grid refuses a step.
- Result page: secret shown once with copy buttons, what the key can do, connection details, a copy-and-paste test command,
  a five-step "what to do now" list and a troubleshooting table. The Access keys page opens with a five-step summary.
- Keys are listed with their permissions in words; *Add another key* supports replacement without downtime; deleting the
  last key of a guided key removes its permissions too. The default expiry is now 90 days.
- Operators can still add replacement keys but not create new permissions.
- Customer guide `docs/ACCESS_KEYS_GUIDE.md`. Not verified on a real grid.

**Added (operations and hardening; see `docs/OPERATIONS.md`, `docs/SECURITY.md`)**
- **Re-authentication** for sensitive actions: the password (and code) is asked again when the last confirmation is
  older than `security.reauth_minutes`; the original request is kept and run once after success.
- **Approval by a second super administrator** (`security.four_eyes`) for closing a customer, changing the grid
  connection and removing staff; Approvals page; requests expire; request body stored encrypted.
- **Audit log**: signed checkpoints that expose cut-off or rebuilt logs; daily retention that archives old records to
  checksummed files and keeps a signed anchor; refuses to act on a chain that does not verify.
- **Backups**: automatic, integrity-checked when made, oldest removed; Operations page with a check button.
- **Drift check** between portal and grid (quota differences, accounts missing on the grid or not managed by the
  portal), daily job, page, command and one-click quota alignment.
- **Master-key rotation** command (all or nothing; re-encrypts secrets, multi-factor secrets and waiting requests;
  renews audit signatures; backs up first).
- **Personal data**: export and erase by e-mail address (page and commands); audit records stay until retention ends.
- New admin pages: Approvals, Operations, Privacy. New settings: `security.reauth_minutes`, `security.four_eyes`,
  `security.approval_hours`, `jobs.backup_hours`, `jobs.backup_keep`, `jobs.drift_hours`, `jobs.audit_checkpoint_minutes`.
- Tests: `tests/test_ops.py`.
- Runbooks in `docs/runbooks/`.

**Fixed**
- Creating a grid account never set the password of the portal's service user and then overwrote the stored tenant
  credentials, so management calls for a new tenant would very probably have failed. The tenant root password is now
  set and stored, and the S3 key is added to it.

**Added (customer controls; see `docs/CUSTOMER_CONTROLS.md`)**
- **Bucket access page**: readable list of the bucket policy; guided grants to a group, a storage user or the whole
  storage account (read, read and write, upload only; whole bucket or one folder); public read on or off (plan
  permitting); require encrypted connections; a policy editor with checks (own bucket and own account only, public
  read only, no negated fields, short condition list, 20 KiB limit). Statements written by hand are kept. Needs the
  administrator permission.
- **CORS rules** and **Object Lock default retention** (governance or compliance, days or years) per bucket.
- **Groups limited to named buckets**, changeable later; **storage users can change groups**. A scoped group cannot
  list the account's other buckets.
- **People**: change a role (ends the person's sessions), cancel an invitation, resend one (cancels the old link),
  invitation status and expiry, sign out everywhere, unlock a locked account, role descriptions. Nobody changes
  their own role.
- **Access keys** can have an expiry (30, 90, 180 days, 1 year); the list shows the date and days left.
- Connector reads versioning, lifecycle, policy, CORS and Object Lock on the bucket page and says when a setting
  could not be read. Lifecycle rules the portal cannot describe are kept unchanged.
- New unit and end-to-end tests (`tests/test_access.py`), including a fake TLS grid that checks S3 signatures.

**Changed**
- **Appearance**: a flatter, denser administrative look (dark top bar, small corner radius, bordered status tags, no
  shadows). Branding colour and white-label settings work as before.
- Changing a bucket's public access now needs the administrator permission (operators keep versioning, lifecycle,
  Object Lock, CORS and keys).
- Bucket list shows "-" for versioning and access on a real grid (one S3 call per bucket would be slow); the bucket
  page shows them.

**Fixed**
- S3 requests for bucket settings sent sub-resource queries such as `?versioning` without the `=` that Signature V4
  requires, so a real S3 endpoint would very probably have refused them. Now signed correctly and tested against the
  AWS documentation example.
- An invitation resent to a person left the older link working; only the newest link works now.

**Not verified (customer controls)**
- None of the above has run against a real StorageGRID. The group policy format, bucket policy principals, S3
  settings calls with the tenant service key and access key expiry are the points most likely to differ by release.
  The test plan is in `docs/STORAGEGRID_INTEGRATION.md`.
- The CSS change was checked in a browser on the demo data only; no accessibility audit has been done.

**Added**
- `docs/compliance/CONTROL_MAP.md`: control map for ISO/IEC 27001:2022 Annex A and SOC 2 (security, availability,
  confidentiality), with the state of each control and the gaps that matter most.

- CI job `dependency-scan`: `pip-audit` on `requirements.txt` (fails the build on a known vulnerability), a
  CycloneDX software bill of materials published as a build artifact, and a weekly scheduled run.
- Dependabot configuration for Python packages, the base image and workflow actions.
- **Admin console settings** (`/settings`): every configuration parameter in one place with its value, source
  (default, file or console) and when a change takes effect. Session, security, logging, mail and job settings
  can be changed by a super administrator; start-up settings (addresses, ports, certificates, master key) are shown
  and edited in the file. Values are validated, changes are audited, weaker-than-recommended settings are flagged.
- **Storage grid connection page** (`/grid`): admin nodes (primary and failover), management API version, grid
  account and user, write-only encrypted password, trusted CA certificates (with fingerprints and expiry), S3 gateway
  endpoints with regions and notes, request timeout. Step-by-step **connection test** (before and after saving),
  and a **sheet for the grid administrators** (permissions, network rules, per-tenant objects, certificates, last
  test) as a page and a text download. The connector now supports several admin nodes with failover and uses the
  configured endpoints and regions. The portal starts without grid details and says so. Mail password can be saved
  encrypted in the console. `grid_connection.json` added to the diagnostic bundle. See `docs/ADMIN_CONSOLE.md`.
- CI job `image-scan`: builds the production image and scans it (operating-system and Python packages) with
  Trivy 0.76.2, run as a container pinned by digest. A HIGH or CRITICAL finding with a fix available fails the
  build; the JSON report is kept as a build artifact. The same job proves the Dockerfile builds.
- The first image scan failed on one fixable HIGH finding (`zlib1g` in the Debian 13 base image). The Dockerfile
  now applies operating-system security updates at build time. Because of that, two builds of the same commit
  can differ in operating-system package versions; the bill of materials and the scan report record what was built.

**Changed**
- ADR-007 accepted: compliance scope is ISO/IEC 27001 and SOC 2 (owner decision, 2026-11-19).
- `requirements.txt` now pins the two packages `cryptography` needs (`cffi` 2.1.1, `pycparser` 3.12), and
  THIRD_PARTY_NOTICES.md lists them. Earlier text saying "one third-party package" was incomplete.

- Dependency updates reviewed from Dependabot: `cryptography` 50.0.2, `actions/checkout` 7,
  `actions/setup-python` 7, `actions/upload-artifact` 7. Dependabot no longer proposes new Python minor or
  major versions for the base image (a Python 3.15 proposal was declined: not tested on 3.15).

**Not verified**
- The image scan passed in GitHub Actions on 2026-11-19, after the zlib1g fix. It does not cover the host or the
  grid, and findings with no fix available yet do not fail it. Docker is not available on the development
  machine, so the image has not been run locally.
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
