# Compliance

CSPortal is designed to be compliant by construction and to make the CSP's own compliance easier.
**No certification or attestation is claimed.** A certificate belongs to an operator and a
deployment, not to a code base. This page states what the product commits to and what it leaves to
the CSP.

> Which regulations and frameworks matter depends on the CSP's customers and jurisdictions. The
> security-framework scope is **ISO/IEC 27001 and SOC 2** (owner decision of 2026-11-19, see
> [DECISIONS.md](DECISIONS.md), ADR-007). The other items below are the working set.

## 1. Compliance with the StorageGRID API contract

- Only documented, public APIs are used (see [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md)).
- No non-public NetApp information is used or stored anywhere in the code, documentation, tests or
  commit messages: nothing from behind a support sign-in, no internal identifiers, no customer
  material. Only pages that open without sign-in on the public documentation sites are cited.
- NetApp and StorageGRID names appear for identification only. The customer-facing portal is branded
  by the CSP and does not present NetApp marks as the CSP's or as CSPortal's own (see
  [LEGAL.md](../LEGAL.md)). The CSP is responsible for its own agreements with NetApp about
  reselling and branding a StorageGRID service.
- Documented limits and semantics (quota, retention, consistency) are respected, not worked around.

## 2. Data protection and privacy

Targets (for example GDPR and comparable laws):
- **Data minimisation.** Only the personal data needed to run the service is kept: name, e-mail,
  role, sign-in and activity records. No object data and no object names are stored by the portal
  unless a module needs them and says so.
- **Purpose and access.** Personal data is used for operating the service only. CSP staff access to
  customer records is role-based and audited.
- **Rights.** The admin console supports export and deletion of a person's portal data.
- **Retention.** Retention periods are configurable per record type, with documented defaults.
- **Residency.** The portal runs where the CSP puts it; it makes no outside calls (no telemetry,
  no hosted fonts or scripts), so data does not leave the CSP's environment by itself.
- **Records.** A record of processing and a data-flow diagram are kept in this folder and updated
  with each module.

## 3. Security frameworks

The control set in [SECURITY.md](SECURITY.md) is mapped to ISO/IEC 27001:2022 Annex A and the
SOC 2 trust services criteria (security, availability, confidentiality) in
[compliance/CONTROL_MAP.md](compliance/CONTROL_MAP.md). The map shows, for each control, what the
product provides, its state (Provided, Partial, Planned or CSP), and what the CSP must do in its own
operation. It also lists the gaps that matter most. Processing integrity and privacy criteria are not
mapped yet.

## 4. Retention and immutability

StorageGRID S3 Object Lock supports regulated retention. The portal never weakens it: it cannot
shorten a locked retention, cannot remove a legal hold without the permission the grid requires,
and shows the effective retention in plain language. Whether a given configuration meets a specific
regulation (for example financial-records rules) is for the CSP and its customer to confirm.

## 5. Auditability

- Append-only, tamper-evident audit log of all changes and sign-ins (see [SECURITY.md](SECURITY.md)).
- Statements are immutable once closed; corrections are linked adjustments.
- Customers can export their own activity history.

## 6. Accessibility and usability

Customer portal and admin console target WCAG 2.2 level AA: keyboard operation, sensible focus order,
contrast, labels, no information by colour alone. Checked per module before release.

## 7. Software licence and supply chain

- Every dependency's licence is recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), reviewed
  on addition, and compatible with the proprietary [LICENSE](../LICENSE).
- Dependencies are pinned and few. No runtime downloads.

## 8. Ownership and attribution

Ownership and intellectual property follow [LICENSE](../LICENSE) and [LEGAL.md](../LEGAL.md): the
software is the sole property of Obi1 - FZCO. No file, commit or release lists any tool or
assistant as author, contributor or co-author.

## What the CSP still has to do

Run the service within its own policies; hold its own certifications; sign data-processing terms
with its customers; manage keys, backups and access to its infrastructure; confirm that regulated
retention settings match the customer's obligations; keep the StorageGRID grid itself patched and
configured to the CSP's compliance requirements.
