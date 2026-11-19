# Tenant capability parity

The aim of CSPortal is that a customer never needs the native StorageGRID Tenant Manager. This page
lists what a StorageGRID tenant can do and where each capability lives in the portal.

> **Verification rule.** The list below follows StorageGRID's public documentation (docs.netapp.com)
> as understood at the time of writing. Which capabilities exist, and through which API, differs
> between StorageGRID releases. Before a capability is built, its row is checked against the public
> documentation for the supported release range and the result is recorded in
> [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md). A row is never marked *Planned* on
> memory alone. Rows still to be checked are marked **verify**.

## Who decides

Every capability has two switches.
- **Allowed** (CSP): set per plan in the admin console. Some StorageGRID features can only be used
  when the grid administrator enables them on the tenant account (for example platform services,
  an own identity source, S3 Select, grid federation); the portal sets those tenant-account
  permissions when it creates or updates the tenant.
- **Done** (customer): the customer's own portal users act, according to their portal role.

Where StorageGRID has a grid-wide setting that tenants cannot change (for example ILM policy and
grid-wide Object Lock enablement), the portal shows the result as read-only information and the CSP
changes it in the Grid Manager.

## Parity map

Status: **R1** = Release 1, **R2** = Release 2, **R3** = Release 3, **CSP** = CSP only, never
exposed to customers. Module names are in [MODULES.md](MODULES.md).

**Build state (0.1.0).** All **R1** rows below are built and tested against the simulator, except where a row
says otherwise. None is verified on a real grid yet. The "bucket details: consistency level" row is shown
read-only; changing it is not built. Object Lock is chosen at bucket creation; retention rules are set by the
customer's applications through the S3 API. **R2** and **R3** rows are not built.

### Account and access

| Capability | Module | Status | Note |
|---|---|---|---|
| Dashboard: usage, quota, buckets, objects | `tenant-dashboard` | R1 | Portal-styled equivalent of the tenant dashboard. |
| Local users: create, edit, disable, delete, reset password | `tenant-access` | R1 | Tenant users on the grid; also portal users (see below). |
| Groups and permissions | `tenant-access` | R1 | Group permissions and the S3 group policy. |
| S3 access keys: create, view once, rotate, delete (own and for other users) | `s3-access` | R1 | Secret shown once; portal never stores it. |
| Temporary S3 credentials | `s3-access` | R3 | **verify** availability. |
| Own identity source (SAML, OIDC, Active Directory, OpenLDAP, Azure AD) | `federation` | R2 | Needs the tenant permission "use own identity source". **verify** list per release. |
| Tenant root user and its password | `tenant-onboarding` | R1 | Set at creation; portal then manages access by group. Root access is not used for daily work. |
| Swift users and containers | none | out | Swift is not offered unless a CSP asks; **verify** if still supported. |

### Storage (S3)

| Capability | Module | Status | Note |
|---|---|---|---|
| Bucket create, list, delete | `buckets` | R1 | Region or site where the CSP offers several. |
| Bucket details: size, objects, consistency level | `buckets` | R1 | Consistency level choices are limited by CSP plan. |
| Versioning | `buckets` | R1 | |
| Lifecycle rules | `buckets` | R1 | Delivered through the S3 API on the tenant's behalf. |
| S3 Object Lock (default retention, legal hold) | `buckets` | R1 | Needs grid-wide enablement by the CSP. |
| Bucket policy and ACL, public-access guard | `buckets` | R1 | |
| CORS | `buckets` | R2 | |
| Default encryption | `buckets` | R2 | **verify** |
| Last-access-time updates | `buckets` | R2 | **verify** |
| Cross-origin and website hosting settings | `buckets` | R3 | **verify** |
| Platform-service endpoints (replication, notifications, search integration) | `platform-services` | R2 | Needs the tenant permission "allow platform services". Destination allow-list set by the CSP. |
| CloudMirror replication | `platform-services` | R2 | |
| Event notifications | `platform-services` | R2 | |
| Search integration | `platform-services` | R3 | |
| Cross-grid replication (grid federation) | `platform-services` | R2 | Needs grid federation connection set up by the CSP. |
| Browse, upload, download and delete objects (S3 console) | `object-browser` | R2 | **verify** the native feature and the release it appeared in. The portal never proxies data in bulk; it gives time-limited links. |
| S3 Select | `buckets` | R3 | Needs the tenant permission "allow S3 Select". |

### Usage, billing and support (portal-native, added value)

| Capability | Module | Status | Note |
|---|---|---|---|
| Usage per bucket and tenant, trends | `usage-billing` | R1 | UC2. |
| Monthly statements and exports | `usage-billing` | R1 | UC2. |
| Quota meter, alerts, quota requests | `capacity-alerts` | R1 | UC4. |
| Service status and maintenance notices | `capacity-alerts` | R1 | UC4. |
| Activity history (who changed what) | `audit-reports` | R2 | Per customer. |
| Support requests | `support` | R2 | UC5. |

### CSP-only (never shown to a customer)

| Capability | Where |
|---|---|
| Grid, node, hardware and software management | StorageGRID Grid Manager |
| ILM policy and storage pools | StorageGRID Grid Manager (shown to customers as a storage class name) |
| Grid-wide Object Lock enablement, S3 and Swift endpoints and certificates | StorageGRID Grid Manager |
| Tenant account creation, quota and tenant-account permissions | CSPortal admin console `tenant-onboarding`, using the Grid Management API |
| Plans, rate cards, branding, module entitlement | CSPortal admin console |

## Portal users and grid users

A customer has two kinds of identity. They are kept deliberately simple:

- **Portal users** sign in to the CSP's portal and hold a portal role. They are the people.
- **Grid users and keys** are the tenant's own StorageGRID users and S3 access keys. They are the
  workloads and applications.

Which of the two models is used for sign-in (portal-held identities, or grid-held identities with
pass-through) is an open decision recorded in [DECISIONS.md](DECISIONS.md) (ADR-004).

## Keeping this page true

When a StorageGRID release changes a capability, or a module is built, the row and the status are
updated in the same commit (see [DOCUMENTATION_POLICY.md](DOCUMENTATION_POLICY.md)).
