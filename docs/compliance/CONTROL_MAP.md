# Control map: ISO/IEC 27001:2022 and SOC 2

This page maps what CSPortal provides to the controls an auditor of a cloud service provider (CSP) will ask
about. Scope was set by the owner on 2026-11-19: **ISO/IEC 27001:2022 (Annex A) and SOC 2 (Trust Services
Criteria 2017, with the 2022 points of focus)**. See ADR-007 in [../DECISIONS.md](../DECISIONS.md).

## How to read this page

- **No certificate or report is claimed.** ISO 27001 certifies an organisation's management system. A SOC 2
  report is an auditor's opinion on a service organisation, here the CSP. CSPortal is one system inside the
  CSP's scope. This map shows what the product contributes as evidence and where the CSP's own work begins.
- **State** values: **Provided** (built and tested), **Partial** (built, with a stated gap), **Planned**
  (not built, on the roadmap), **CSP** (an organisational or infrastructure control that the product cannot
  provide).
- "Where" points to the code, the page or the test that shows it. Security design detail is in
  [../SECURITY.md](../SECURITY.md); build status in [../../CHANGELOG.md](../../CHANGELOG.md).
- Control numbers follow ISO/IEC 27001:2022 Annex A and the AICPA Trust Services Criteria. Check them against
  the editions your auditor uses before quoting them in an audit.

## Honest gaps that matter most

1. **The StorageGRID connector is not verified on a real grid** (affects availability and integrity evidence).
2. **No independent penetration test.** (Python dependencies are now scanned in CI; the base image and host are not.)
3. **Audit retention is not enforced.** `security.audit_retention_days` is a configuration value only; no
   purge or archive job exists. The audit log grows until the CSP archives the database. A purge must keep
   the hash chain verifiable, so it needs a signed checkpoint design first.
4. **No four-eyes approval or re-authentication** for destructive provider actions yet.
5. **Single node:** no redundancy inside the product (ISO 8.14, SOC 2 A1.2). The CSP must provide it around it.

## ISO/IEC 27001:2022 Annex A

### 5. Organisational controls

| Control | What CSPortal provides | Where | State | CSP responsibility |
|---|---|---|---|---|
| 5.1 Policies for information security | Security design and rules documented | docs/SECURITY.md | Partial | Own policy set; approve and publish it |
| 5.2 Roles and responsibilities | Defined provider roles (super administrator, operations, finance, support) and customer roles | auth.py | Provided | Assign people to roles |
| 5.3 Segregation of duties | Finance cannot edit customers; support cannot provision; roles limited per task. Second approver for destructive actions is planned | auth.py | Partial | Operate roles without sharing accounts |
| 5.8 Information security in project management | Repository rules, tests, review checklist in the documentation policy | docs/DOCUMENTATION_POLICY.md | Partial | Own project process |
| 5.9 Inventory of information and assets | Customer, plan, module, user and tenant records; module list; dependency list | database; THIRD_PARTY_NOTICES.md | Partial | Asset register for hosts and grid |
| 5.12 / 5.13 Classification and labelling | Secrets, personal data and audit data are separate record types; personal data limited to name, e-mail, role | db.py | Partial | Classification scheme |
| 5.14 Information transfer | TLS for all transfers; no data leaves the site except configured grid, mail and (planned) webhook | web/core.py, backends/storagegrid.py | Provided | Transfer agreements |
| 5.15 Access control | Deny-by-default roles; per-route permission; customer-scoped data access | auth.py, db.py, tests | Provided | Review role assignments |
| 5.16 Identity management | Unique accounts, invitation flow, removal, separate customer and staff stores | auth.py | Provided | Joiner, mover, leaver process |
| 5.17 Authentication information | scrypt hashing, password rules, single-use invitations, MFA secrets encrypted | crypto.py, auth.py | Provided | Password and key custody |
| 5.18 Access rights | Roles changeable by customer administrators and staff; every change audited | modules/tenant_access.py | Provided | Periodic access review (list users from admin console) |
| 5.19 to 5.22 Supplier relationships | Dependency list and licences; one direct third-party package plus two it needs, all pinned; bill of materials per build | THIRD_PARTY_NOTICES.md | Partial | Supplier assessments (hosting, mail relay, NetApp) |
| 5.23 Cloud services | Product is itself a cloud service component; documents shared responsibility | docs/COMPLIANCE.md | Partial | Cloud-service policy |
| 5.24 to 5.28 Incident management | Request ids, security log, audit log, diagnostic bundle, log viewer support detection and investigation | logs.py, audit.py, modules/system.py | Partial | Incident process, on-call, customer notification |
| 5.29 / 5.30 Continuity and ICT readiness | Backup command, restore steps, health page. No clustering | docs/DEPLOYMENT.md | Partial | Recovery objectives, tested restores, standby host |
| 5.31 Legal and contractual requirements | Licence and notice files; data-protection design | LICENSE, LEGAL.md, docs/COMPLIANCE.md | Partial | Contracts and DPAs with customers |
| 5.32 Intellectual property | Ownership and attribution terms | LICENSE | Provided | Respect licence terms |
| 5.33 Protection of records | Hash-chained audit log; immutable closed statements | audit.py, services.py | Partial | Retention and archive (gap 3) |
| 5.34 Privacy and PII | Data minimisation; no telemetry; no outside calls | docs/COMPLIANCE.md | Partial | Lawful basis, notices, rights handling. Export and deletion of a person's data is planned |
| 5.35 / 5.36 Independent review, compliance with policies | Automated tests, repository rules check, audit-chain verification command | tests/, tools/check_repo.py | Partial | Internal audit; external review |
| 5.37 Documented operating procedures | Deployment, operations, demo, runbooks list | docs/ | Partial | Site runbooks (runbook pages still to be written) |

### 6. People controls

| Control | What CSPortal provides | State | CSP responsibility |
|---|---|---|---|
| 6.1 to 6.6 Screening, terms, awareness, discipline, termination | Not a product function. Removal of staff accounts and session revocation is immediate | CSP | HR and awareness programme |
| 6.8 Information security event reporting | Security log entries for failed sign-in, lock-out, permission denial, cross-origin and anti-forgery refusals | Provided | Reporting channel and triage |

### 7. Physical controls

All CSP (data centre, hosts, media). The product contributes nothing except the documented advice to keep the
master key apart from the data (docs/DEPLOYMENT.md).

### 8. Technological controls

| Control | What CSPortal provides | Where | State | CSP responsibility |
|---|---|---|---|---|
| 8.1 User endpoint devices | Not applicable to the product | | CSP | Endpoint policy for staff |
| 8.2 Privileged access rights | Super administrator limited to named staff; staff MFA mandatory outside demo mode | auth.py | Partial | Keep the group small; four-eyes planned |
| 8.3 Information access restriction | Customer-scoped accessor; permission checks; tested cross-customer isolation | db.py, tests | Provided | |
| 8.4 Access to source code | Repository access controlled on GitHub | repository | CSP | Repository permissions and branch protection |
| 8.5 Secure authentication | MFA (TOTP), lock-out, rate limits, equal timing, short sessions, `__Host-` cookies over TLS | auth.py, web/core.py | Provided | WebAuthn planned |
| 8.6 Capacity management | Quota meter, alerts, grid capacity overview, system health page | modules/capacity_alerts.py | Partial | Capacity planning of hosts and grid |
| 8.7 Protection against malware | Not a product function. No file uploads are accepted | | CSP | Host protection |
| 8.8 Technical vulnerabilities | Python dependencies pinned and scanned for known vulnerabilities on every push, pull request and weekly (build fails on a finding); Dependabot updates. **Base image, host and the grid are not scanned; no penetration test.** The scan has run clean locally; its first run in GitHub Actions is not yet confirmed | requirements.txt, .github/workflows/ci.yml | Partial | Patch the base image and host; scan the image |
| 8.9 Configuration management | Single reviewed configuration file; production mode refuses unsafe settings; scrubbed copy in diagnostic bundle | config.py | Provided | Keep config under change control |
| 8.10 Information deletion | Customer close action; deletion of the grid account is a separate provider step. Personal-data deletion is planned | modules/tenant_onboarding.py | Partial | Deletion schedule |
| 8.11 / 8.12 Masking and leakage prevention | Secrets never logged; S3 secret not stored; mail copy loses its link after delivery; no object data passes through | logs.py, services.py | Provided | |
| 8.13 Information backup | Consistent backup command; restore documented | db.py, docs/DEPLOYMENT.md | Provided | Schedule, off-site copy, restore tests |
| 8.14 Redundancy | None inside the product (single node) | | Planned | Standby host or virtualisation HA |
| 8.15 Logging | Application, access and audit logs; request ids; rotation; syslog forwarding; secret scrubbing | logs.py, audit.py | Provided | Central log store and retention |
| 8.16 Monitoring activities | Health endpoint, system page, job status, log viewer. No alert rules on log content | modules/system.py | Partial | Monitoring and alerting on the forwarded logs |
| 8.17 Clock synchronisation | Uses the host clock (all stamps in UTC) | | CSP | Time sync on the host |
| 8.18 Privileged utility programs | Command line tools need host access and the master key | __main__.py | CSP | Restrict host shell access |
| 8.19 Software installation | Single image; no plug-in loading from outside | Dockerfile | Provided | Image provenance |
| 8.20 to 8.22 Network security, services, segregation | Admin console on a separate private listener; refuses proxy headers; strict TLS to the grid; outbound limited to configured endpoints | web/core.py, config.py | Provided | Firewalls, segmentation, WAF |
| 8.23 Web filtering | Not applicable | | CSP | |
| 8.24 Use of cryptography | AES-256-GCM for stored secrets, scrypt, TLS 1.2 minimum, SHA-256 audit chain, random tokens from the OS | crypto.py | Provided | Key custody, rotation (rotation command planned) |
| 8.25 to 8.28 Secure development, requirements, architecture, coding | Threat model, security rules, parameterised queries only, output escaping by default, strict content security policy | docs/SECURITY.md, db.py, web/ui.py | Provided | |
| 8.29 Security testing | Automated tests for authorisation matrix, isolation, anti-forgery, lock-out, secret scrubbing. **No independent test yet** | tests/ | Partial | Commission a penetration test |
| 8.30 Outsourced development | Not applicable | | CSP | |
| 8.31 Separation of environments | Demo mode runs only on the simulator with its own data directory and key; production refuses simulator and unsafe settings | config.py | Provided | Separate test and production hosts |
| 8.32 Change management | Version control, tests, changelog with "not verified" statements, forward-only migrations | CHANGELOG.md, db.py | Partial | Change approval process for the CSP's own deployment |
| 8.33 / 8.34 Test information, audit testing | Demo data is invented; tests use temporary data directories | demo.py, tests/ | Provided | |

## SOC 2 Trust Services Criteria

Security (the common criteria, CC) is always in scope. Availability and Confidentiality are included here
because a storage service is judged on them. **Processing integrity** and **Privacy** are optional categories and
are not mapped yet; confirm with your auditor which categories your report will cover.

| Criterion | What CSPortal contributes | State | CSP responsibility |
|---|---|---|---|
| **CC1 Control environment** (1.1 to 1.5) | Documented roles and decision log (ADRs) | Partial | Governance, hiring, accountability |
| **CC2 Communication and information** (2.1 to 2.3) | Documentation set; customer-visible notices and status page; customer activity history | Partial | Internal and external communication, customer terms |
| **CC3 Risk assessment** (3.1 to 3.4) | Threat table in docs/SECURITY.md | Partial | Formal risk assessment and register |
| **CC4 Monitoring activities** (4.1, 4.2) | Audit verification, tests, system page, job state | Partial | Ongoing evaluation, deficiency handling |
| **CC5 Control activities** (5.1 to 5.3) | Controls built into the product; configuration rules | Partial | Policies and procedures |
| **CC6.1** Logical access software and architecture | Roles, scoped data access, permission checks, secure authentication | Provided | Access governance |
| **CC6.2** Provisioning and removal of users | Invitation flow; removal revokes sessions; all audited | Provided | Authorisation of new users |
| **CC6.3** Role-based access and least privilege | Per-route permissions; least-privilege grid identities for the portal | Provided | Periodic review |
| **CC6.4 / 6.5** Physical access, disposal | | CSP | Data centre and media disposal |
| **CC6.6** Boundary protection | Private admin listener; strict TLS; no inbound except the two surfaces | Provided | Firewalls and WAF |
| **CC6.7** Restricting transmission, movement, removal | TLS; no bulk data path through the portal; exports are logged | Provided | |
| **CC6.8** Preventing and detecting malicious software | Not applicable to the product | CSP | Host controls |
| **CC7.1** Detect configuration changes and vulnerabilities | Dependency scan in CI (Python packages); reconcile and conformance checks are planned/partial | Partial | Scan the image, host and grid |
| **CC7.2** Monitoring for anomalies | Security log events; log forwarding | Partial | Central monitoring and alerting |
| **CC7.3 / 7.4 / 7.5** Evaluate, respond to, recover from incidents | Diagnostic bundle, request ids, audit trail, backup and restore | Partial | Incident response plan and testing |
| **CC8.1** Change management | Version control, tests, changelog, forward-only migrations | Partial | Approval and deployment process |
| **CC9.1 / 9.2** Risk mitigation, vendors | Few dependencies, listed; documented shared responsibility | Partial | Business continuity, vendor management |
| **A1.1** Capacity | Quota and capacity views, alerts | Partial | Capacity monitoring of infrastructure |
| **A1.2** Environmental protections, backup, recovery infrastructure | Backup command; no redundancy in product | Partial | Facilities, redundancy |
| **A1.3** Recovery testing | Restore procedure documented; audit verification after restore | Partial | Run and record restore tests |
| **C1.1** Identify and maintain confidential information | Secrets encrypted; personal data minimised; customer data separated by scope | Provided | Classification and retention |
| **C1.2** Dispose of confidential information | Customer close; grid deletion by provider; secure deletion of personal data planned | Partial | Disposal procedure and evidence |

## Evidence the product can produce

| Evidence | How |
|---|---|
| Who changed what, when, from where | Admin console Audit log (filterable); customer Activity page with CSV download (customer view only) |
| Proof the audit log was not altered | `python -m csportal verify-audit`; Audit log page shows chain state |
| Access list for review | Admin console: customers and their users; staff users page |
| Configuration in force (secrets removed) | Diagnostic bundle, `config.json` |
| System version, modules, schema | Diagnostic bundle, `system.json` |
| Logs | Log files, syslog stream, log viewer |
| Statement integrity | Closed statements are immutable; adjustments are linked rows |
| Test results | `PYTHONPATH=. python -m unittest discover -s tests` |

## Work to close the gaps

| Gap | Planned work | Controls it helps |
|---|---|---|
| Container image scanning | Scan the built image (operating-system packages) in CI. Python dependency scan and bill of materials are done | ISO 8.8; SOC 2 CC7.1 |
| Audit retention | Retention job with signed chain checkpoints | ISO 5.33; SOC 2 CC4, C1.2 |
| Four-eyes and re-authentication | Approval workflow for delete, suspend all, key rotation | ISO 5.3, 8.2; SOC 2 CC6.3 |
| Key rotation | Master-key and grid-credential rotation commands | ISO 8.24 |
| Personal-data export and deletion | Admin action and customer request | ISO 5.34; SOC 2 C1.2 |
| Redundancy | Server database and replicas | ISO 8.14; SOC 2 A1.2 |
| Penetration test | Independent test and fixed findings | ISO 8.29; SOC 2 CC4, CC7 |
| Runbooks | Write the pages listed in docs/OPERATIONS.md | ISO 5.37; SOC 2 CC5 |
| Drift detection | Reconcile job comparing portal and grid | SOC 2 CC7.1 |

## Keeping this page true

Update the state of a row in the same commit that changes the control. When a gap above is closed, move it
out of the table and note it in [CHANGELOG.md](../../CHANGELOG.md).
