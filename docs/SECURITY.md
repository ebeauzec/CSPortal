# Security design

CSPortal is secure by design: the safe behaviour is the default and the only one available without
an explicit, audited decision by the CSP. This page is the design; the threat model is the
reasoning behind it. Both are updated whenever the design changes.

## What is being protected

1. **The grid.** A portal compromise must not become a grid compromise.
2. **Tenant data and tenant configuration.** One customer must never see or change another's.
3. **Credentials and keys.** S3 secret keys, portal service credentials, signing keys.
4. **Billing figures.** Usage and statements must not be altered unnoticed.
5. **The admin console.** It holds the power to create and delete tenants.

## Threats considered

| Threat | Main controls |
|---|---|
| Stolen or guessed customer password | Multi-factor authentication required by default; rate limiting and lock-out; breached-password check done locally against a bundled list, no external call. |
| One customer reaching another customer's tenant | Customer id on every record and every connector call, enforced in the data layer and in the connector, with a test per module (see MODULES.md rule 2). |
| Portal bug that lets a user exceed their role | Deny by default; permissions declared per module; server-side check on every request; no authorisation decisions in the browser. |
| Compromise of the public portal | Public surface has no administrative endpoints; the admin console is a separate listener on a private network; the public surface holds only the credentials it needs. |
| Leaked grid credentials | The portal uses one least-privilege service identity per tenant, plus one provisioning identity for the grid. Secrets are encrypted at rest with a key held apart from the data; rotation is a built-in admin action. |
| Leaked S3 secret key | Shown once, never stored by the portal, rotation and revocation in one click, last-used time shown. |
| Injection, cross-site scripting, request forgery | Parameterised queries only; output escaping by default; strict content security policy that allows no external origins; same-site cookies and anti-forgery tokens. |
| Supply-chain compromise | Few dependencies, pinned and recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md); all front-end assets vendored; no runtime downloads. |
| Tampering with usage and statements | Closed periods are immutable; corrections are linked adjustment records; every change is in the audit log. |
| Insider misuse (CSP staff) | CSP roles split duties; destructive actions (delete tenant, rotate master key) need a second approver; every action audited with who, what, when, from where. |
| Denial of service on sign-in or provisioning | Rate limits per address and per account; provisioning jobs queued with concurrency limits. |

## Design rules

**Identity and sessions**
- Customer users and CSP staff are separate stores, separate sessions, separate cookies.
- Multi-factor authentication (time-based codes or security keys) is on by default for customers and
  mandatory for CSP staff.
- Sessions are short, bound to the browser, rotated on privilege change, and revocable by the user and
  by the CSP.
- Passwords are stored with a modern memory-hard hash. No password is ever logged or shown.

**Authorisation**
- Roles per surface; every module declares permissions; the default is no access.
- Every request is authorised on the server against the customer id, the role and the entitlement.
- Dangerous actions (delete bucket with data, delete user, disable multi-factor) ask for re-authentication.

**Secrets**
- Grid service credentials and any stored token are encrypted with a master key supplied at start-up
  from the environment or a mounted secret, never stored beside the data.
- S3 secret keys are shown once. The portal keeps only what it needs to identify the key.
- Logs and debug bundles are scrubbed of secrets by construction (secret values have a type that
  cannot be printed).

**Network**
- TLS only; modern protocol versions and ciphers; HSTS.
- The admin console binds to a private interface and refuses requests that arrive through the public
  proxy (host and port are both checked).
- The portal's connector calls the grid over TLS and verifies the grid certificate against a CSP-supplied
  trust anchor; certificate checking cannot be turned off in production mode.
- Outbound connections are limited to the configured grid endpoints, the mail relay and configured
  webhooks. There is no telemetry and no call-home.

**Data**
- No customer object data passes through the portal in bulk. Uploads and downloads go to the S3
  endpoint directly with time-limited, scoped links.
- Personal data is limited to what is needed (name, e-mail, role, sign-in events). Export and
  deletion of a customer's portal data is a documented admin action.

**Audit**
- Append-only audit log, hash-chained so tampering is detectable, kept per customer and for the CSP.
- Customers can read their own activity history; only the CSP can read the CSP log.

**Secure development**
- Security tests in the suite: authorisation matrix per module, cross-customer access attempts,
  injection and output-escaping checks, secret-leak scan of logs.
- No debug mode in production builds; configuration that weakens security needs an explicit setting
  that is shown in the admin console and recorded in the audit log.
- Every dependency is reviewed on addition and on update. All runtime dependencies are pinned in
  `requirements.txt`, including the ones `cryptography` needs.
- CI job `dependency-scan` runs `pip-audit` on `requirements.txt` (and everything it pulls in) on every push,
  pull request and weekly; a known vulnerability fails the build. The same job publishes a CycloneDX software
  bill of materials as a build artifact. Dependabot proposes updates to Python packages, the base image and the
  workflow actions. It does not propose a new Python minor or major version: that is a deliberate decision,
  made with tests on the new version, and it changes the Dockerfile, CI and docs together.
- CI job `image-scan` builds the production image (so the Dockerfile is tested on every change) and scans it with
  Trivy for known vulnerabilities in operating-system and Python packages, on every push, pull request and
  weekly. A HIGH or CRITICAL finding that has a fix available fails the build; findings with no fix yet are
  kept in the JSON report (build artifact) but do not fail it. The scanner runs as a container pinned by
  digest, not through a third-party action, and reads the image from a saved file, so it gets no access to the
  build host's Docker. Its vulnerability database is downloaded when the job runs. To update the scanner,
  change the digest in `.github/workflows/ci.yml` after checking the release. The scan covers Python packages only: it does not scan the base image's operating-system
  packages or the host (the CSP does, see [DEPLOYMENT.md](DEPLOYMENT.md)).

## Implementation status (version 0.1.0)

| Control | State |
|---|---|
| Separate customer and staff users, sessions and cookies; admin console on its own listener | Built; tested |
| Admin console refuses requests carrying proxy headers; refuses to start on a public address in production | Built; tested |
| Passwords: scrypt, length rule, common-password list (small, local), no e-mail name | Built; tested |
| TOTP multi-factor authentication, one-time use of each code, mandatory for staff (outside demo), default for customers | Built; tested against the RFC 6238 test vectors |
| Lock-out after failed attempts, per-address and per-account rate limits, same timing for unknown accounts | Built; tested |
| Deny-by-default roles, per-route permissions, server-side checks | Built; tested |
| Customer-scoped data accessor; tables that are not customer-scoped refused | Built; tested |
| Anti-forgery token on every POST; same-origin check; SameSite=Strict cookies; `__Host-` cookies over TLS | Built; tested |
| Strict content security policy (no inline script, no external origins), framing denied, no-store | Built; tested |
| Secrets encrypted with AES-256-GCM under a key held outside the data; bound to purpose | Built; tested |
| S3 secret shown once and not stored by the portal | Built; tested |
| Strict TLS to the grid; certificate checking cannot be turned off in production | Built (connector unverified on a real grid) |
| Secret scrubbing in all logs and in the diagnostic bundle; tokens removed from access-log paths | Built; tested |
| Hash-chained audit log with verification command and page | Built; tested |
| Immutable closed statements; linked adjustments | Built; tested |
| Single-use invitation links; stored mail copy loses the link after delivery | Built; tested |
| Settings and grid connection editable in the admin console by super administrators only; values validated; every change audited with old and new value (never secrets); settings weaker than recommended flagged | Built; tested |
| Grid and mail passwords: encrypted with the master key, write-only in the console, never in logs, audit records, pages or the diagnostic bundle | Built; tested |
| Certificate checking on the grid connection cannot be turned off; the password is sent only after the certificate is verified; a pasted private key is refused; loopback and link-local grid addresses refused outside demo mode | Built; tested |
| Bucket policy checker: only the bucket's own resources, only this storage account's principals, public read only where the plan allows, no negated fields, short condition list, size limit | Built; tested |
| Changing who can use a bucket (policy, public access) needs the administrator permission; operators manage buckets and keys only | Built; tested |
| Role change ends the person's sessions; invitation links are single-use and a new one cancels the old; locked accounts can be unlocked by a customer administrator; nobody changes their own role | Built; tested |
| S3 requests signed with Signature V4, checked against the published AWS example; settings calls carry Content-MD5 | Built; tested |
| Re-authentication before dangerous actions: the password (and the code, when multi-factor is on) is asked again if the last confirmation is older than `security.reauth_minutes`; the original form is kept and run once after success; only routes that ask for it can be replayed | Built; tested |
| Second approver for closing a customer, changing the grid connection and removing staff (`security.four_eyes`): a different super administrator approves or rejects; requests expire; the request is stored encrypted; each step audited | Built; tested |
| WebAuthn security keys; single sign-on for staff | Planned |
| Master-key rotation command (`rotate-key`): all-or-nothing re-encryption of stored secrets, multi-factor secrets and waiting approvals, audit signatures renewed, backup taken first | Built; tested |
| Grid password change on the Storage grid page (write-only, tested before saving, needs approval when four-eyes is on) | Built; tested. Rotating the per-customer tenant credentials is not built: the tenant root password is changed on the grid and re-entered by a runbook (see [runbooks/ROTATE_GRID_CREDENTIALS.md](runbooks/ROTATE_GRID_CREDENTIALS.md)) |
| Export and erasure of a person's portal data (`/privacy`, `person-export`, `person-erase`): accounts, sessions, invitations and stored mail removed; audit records stay until retention ends and the erasure is recorded without the address | Built; tested |
| Audit log checkpoints (HMAC-signed, key derived from the master key) detect records cut off the end or a rebuilt chain; retention archives old records to a file with a checksum and keeps a signed anchor so the rest still verifies; nothing is removed when the chain does not verify | Built; tested |
| Database backups are opened and integrity-checked when made; the oldest beyond `jobs.backup_keep` are removed; a copy that fails its check is deleted and reported | Built; tested |
| Drift check between portal customers and grid accounts (quota differences, missing and unmanaged accounts); nothing changes without a button press | Built; tested on the simulator, not on a real grid |
| Webhook alert channel (e-mail only today) | Planned |
| Independent penetration test | Not done |

## Sensitive actions: re-authentication and approval

**Re-authentication.** Routes marked `reauth` (removing a person, changing a role, resetting multi-factor, deleting a
group, storage user, access key or bucket, changing public access or the policy of a bucket, setting Object Lock,
closing a customer, changing the grid connection, removing staff, approving a request, erasing or exporting personal
data, aligning a grid quota) need a password confirmation that is no older than `security.reauth_minutes` (default 10).
When it is older the page shows "Confirm it is you" and nothing has changed yet. After a correct password (and code),
the original form is run once through the normal checks (session, permission, anti-forgery token). The prompt is rate
limited (6 attempts in 5 minutes per person) and wrong passwords count towards the account lock-out. Confirmation is
recorded as `user.reauth`.

**Approval by a second administrator.** With `security.four_eyes` on and at least two active super administrators, the
three most dangerous provider actions are filed as a request instead of being run. A different super administrator sees
what will happen and approves or rejects it on the Approvals page; the action then runs once with the stored values.
Requests expire after `security.approval_hours` (default 72). The person who asked can withdraw a waiting request but
cannot approve it. The request body (it can hold the new grid password) is stored encrypted and is emptied after use.
With only one active super administrator the action runs at once, because nobody else could approve it; the settings
page lists "no second approver" among the settings that are weaker than recommended while the option is off.
Audit actions: `approval.requested`, `approval.approved`, `approval.rejected`, `approval.expired`, `approval.failed`,
`approval.withdrawn`.

## Audit log: integrity and retention

Each record holds the hash of the previous one, so a change in the middle breaks the chain. A chain alone cannot show
that the newest records were cut off or that the whole chain was rebuilt, so the portal also signs **checkpoints**
(id and hash of the newest record, HMAC-SHA-256, key derived from the master key; hourly by default). Verification
fails when a checkpoint has a bad signature, points past the end of the log, or does not match the record it names.

**Retention.** Once a day, records older than `security.audit_retention_days` (default 2555, about seven years) are
written to `audit-archive/audit-<first>-<last>.jsonl` in the data folder with a `.sha256` checksum file, then removed.
The id and hash of the last removed record are kept in a signed **anchor**, so the remaining records still verify and
new records continue the same chain. Nothing is removed when the chain does not verify first. The newest 1000 records are
never removed. Copy the archive files to long-term storage that matches your retention policy; the portal does not
delete them.

What this does not do: an attacker who holds the master key can sign new checkpoints. Keep the master key away from
the database and its backups. Personal data inside old audit records stays until its retention ends.

## Reporting a vulnerability

Contact the Author through the repository's private security reporting option or the contact
information in the project documentation. Do not open a public issue for a vulnerability.
