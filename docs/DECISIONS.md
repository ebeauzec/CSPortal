# Decisions

Architecture decision log. Status is **Accepted**, **Proposed** (recommendation made, owner has not
confirmed) or **Open** (owner's decision needed). Entries are never deleted; a changed decision gets
a new entry that supersedes the old one.

## ADR-001. Technology stack

**Status: Accepted (2026-11-19): Python 3.12, standard library plus one package (`cryptography`), server-rendered
pages with a small vendored script, SQLite.** Chosen because it keeps the dependency tree tiny, builds into one
image, matches the owner's other tools, and is easy to audit. The options considered are kept below.

The principles (simple, self-contained, secure; see [ARCHITECTURE.md](ARCHITECTURE.md)) favour a
stack that builds to one deployable unit with few dependencies.

| Option | For | Against |
|---|---|---|
| **Python backend (FastAPI or similar), server-rendered pages with a little vendored JavaScript, SQLite** | Same language and habits as the owner's other tools; small dependency set; easy to read and audit; one process | Needs a packaged runtime; typed client generation is less direct |
| **Go single binary, server-rendered pages, SQLite** | One static binary; strong standard library for TLS and HTTP; very few dependencies; good fit for secure and self-contained | New language for the owner's other projects |
| **Node/TypeScript backend with a React front end** | Rich UI libraries; typed OpenAPI clients | Large dependency tree, which cuts against simple, self-contained and supply-chain safety |

**Recommendation:** Go single binary, or Python if the owner prefers one language across projects.
Avoid a large front-end framework: server-rendered pages with small vendored scripts.

## ADR-002. Embedded database by default

**Status: Accepted (implemented).** One embedded database file (SQLite). A server database (PostgreSQL) is a later option
for large CSPs, behind the same data layer. Reason: self-contained, simple backup, no database server
to secure.

## ADR-003. Connector interface and generated client

**Status: Accepted.** Modules reach storage only through a `StorageBackend` interface. The StorageGRID
connector's client is generated from the grid's own published OpenAPI definition, per supported
release range. Reason: native, accurate use of the documented API; testable with a simulator.

## ADR-004. Identity model for customer sign-in

**Status: Proposed, and implemented as option A in 0.1.0; the owner has not confirmed it.** Recommendation below.

- **A. Portal-held identities.** Portal users live in the portal; the portal acts on the tenant
  through a least-privilege per-tenant service identity and applies its own roles. Simple for the
  customer, one sign-in, branded, MFA under the CSP's control. The portal service identity holds
  broad tenant rights, so the portal's authorisation must be exact.
- **B. Grid-held identities with pass-through.** The customer signs in with their StorageGRID tenant
  user; the portal forwards the user's own token. Rights are exactly the grid's, and the grid is the
  single source of truth. The customer sees grid-style accounts and passwords, MFA is limited to
  what the grid offers, and white-labelling is weaker.

**Recommendation:** A, with the service identity limited to a dedicated tenant group, and an option
for customers to bring their own identity provider (module `federation`). Confirm before building
`core-accounts`.

## ADR-005. Ownership, licence and attribution

**Status: Accepted.** The licence and ownership terms are the same as the owner's other product,
adapted in name only: all rights belong to Obi1 - FZCO ([LICENSE](../LICENSE), [LEGAL.md](../LEGAL.md)).

## ADR-006. No assistant attribution in the repository

**Status: Accepted.** No file, commit message, author field, trailer, issue, pull request or release
in the repository or on GitHub names or credits any AI assistant or tool as author, co-author or
contributor. Enforced by the hooks in `.githooks/` (commit-msg removes such trailers; pre-push and
a repository scan block anything that remains). Hooks are never bypassed.

## ADR-009. Referrer policy is same-origin

**Status: Accepted.** `no-referrer` makes browsers send `Origin: null` on form posts, which defeats the
origin check. `same-origin` keeps every URL (including invitation links) from leaving the site and lets the
origin check work. Found by testing in a real browser.

## ADR-007. Compliance scope

**Status: Accepted (2026-11-19).** "Fully compliant" means: ISO/IEC 27001:2022 and SOC 2 are the
security frameworks. The product is mapped to both in [compliance/CONTROL_MAP.md](compliance/CONTROL_MAP.md);
no certificate or report is claimed, because those belong to the CSP's organisation. The rest of the working
set in [COMPLIANCE.md](COMPLIANCE.md) stays: public-API-only use, data protection (GDPR-style), WCAG 2.2 AA.
Sector rules and regional residency are added when a CSP needs them.

## ADR-008. Documentation is maintained with the code

**Status: Accepted.** See [DOCUMENTATION_POLICY.md](DOCUMENTATION_POLICY.md).
