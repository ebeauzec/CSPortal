# Use cases

These are the use cases a cloud service provider (CSP) running StorageGRID most often wants to
offer its external customers through a self-service portal. Each one names the actor, the goal,
what the customer sees and does in the **customer portal**, what the CSP controls in the
**admin console**, and the StorageGRID calls behind it.

The first four are the launch set (Release 1). Further candidates are in the backlog at the end.

**Design intent.** CSPortal white-labels the StorageGRID offering. The customer manages their own
tenant through the CSP's portal, to the maximum extent StorageGRID allows, instead of using the
native Tenant Manager. UC1 to UC4 are the most common journeys; the complete list of tenant
capabilities, and which module covers each, is in [TENANT_PARITY.md](TENANT_PARITY.md). Anything a
tenant can do in StorageGRID is in scope unless the CSP switches it off for a plan.

Terms: **CSP** is the service provider (the operator of CSPortal and the grid). **Customer** is
an organisation buying object storage from the CSP. **Tenant** is the StorageGRID tenant account
that holds a customer's buckets and users. **Portal user** is a person at the customer who signs
in to the customer portal.

---

## UC1. Tenant onboarding and access management

**Goal.** A new customer goes from signed contract to working S3 access without a ticket.

**Actors.** CSP administrator (approves and configures), customer administrator (first portal
user), customer users.

**Customer portal.**
- Accept the invitation, set up sign-in (local account with multi-factor authentication, or the
  customer's own identity provider where the CSP allows it).
- See the service they bought: storage class, quota, region or site, S3 endpoint URL.
- Invite and remove portal users; assign and change a role (administrator, operator, billing, read-only); cancel or
  resend an invitation; sign a person out everywhere; unlock an account.
- Create storage groups (read only or read and write, for all buckets or named buckets) and storage users in them.
- Create, view-once, rotate and revoke S3 access keys for themselves and for service accounts, with an optional expiry.
- All of these controls, with roles and audit actions, are in [CUSTOMER_CONTROLS.md](CUSTOMER_CONTROLS.md).

**Admin console.**
- Define the service catalogue: plans, quota, enabled modules, allowed regions, default policies.
- Create a customer from a plan. The console creates the StorageGRID tenant, sets the quota and
  the root user, and sends the invitation. Approval can be automatic or manual per plan.
- Suspend, resume and close a customer. Closing follows a documented hold period before deletion.
- Branding per CSP (name, logo, colours, support links, legal text).

**StorageGRID.** Grid Management API: tenant accounts (create, update quota, delete), S3 endpoint
and load balancer endpoint information. Tenant Management API: users, groups, S3 access keys,
identity federation.

**Done when.** A customer can sign in, create an access key and complete an S3 `PutObject`
against the correct endpoint, with the CSP having touched nothing by hand.

---

## UC2. Usage, metering and billing visibility

**Goal.** The customer sees what they use and what it costs; the CSP gets accurate, exportable
usage for invoicing.

**Actors.** Customer billing user, customer administrator, CSP finance and operations.

**Customer portal.**
- Current usage: stored bytes, object count, per bucket and in total, against the quota.
- Trends over a chosen period (day, month, 12 months) and a month-to-date cost estimate.
- Usage statement per month (download as CSV and PDF) that matches the CSP's invoice basis.

**Admin console.**
- Rate card per plan: price per GB-month, minimum commit, included volume, request and egress
  charges if the CSP bills them, currency, tax text.
- Metering schedule: how often usage is sampled, how the month is closed, how corrections are made.
- Per-customer usage and revenue overview; export for the CSP's billing system (CSV first,
  API or webhook later).
- Reconciliation view: the portal's figure next to the grid's own figure, with differences flagged.

**StorageGRID.** Grid Management API usage and quota data per tenant account; metrics from the
admin node for trends and for S3 request counts where available. Audit logs where request-level
billing needs them.

**Done when.** The monthly statement for a test tenant equals the figure read from the grid on the
same day, and a closed month cannot change without a recorded correction.

---

## UC3. Bucket lifecycle and data protection self-service

**Goal.** The customer creates and protects their own buckets safely, within limits the CSP sets.
This use case covers buckets; users, groups, keys and identity are UC1, and the full tenant feature
list is in [TENANT_PARITY.md](TENANT_PARITY.md).

**Actors.** Customer operator, customer administrator, CSP administrator (defines guard rails).

**Customer portal.**
- Create, list and delete buckets; see size and object count per bucket.
- Turn on versioning; set lifecycle rules (expire objects, expire old versions, abort incomplete
  uploads); set the default Object Lock retention (governance or compliance) where the CSP and the grid allow it.
- Bucket access: grant a group or storage user read, read-write or upload-only access to the whole bucket or one
  folder; require encrypted connections; a checked policy editor; a public-access guard that follows the plan.
- Cross-origin (CORS) rules for browser applications.
- Cross-grid or cross-region replication and event notifications, where the CSP offers them
  (StorageGRID platform services).
- A protection posture panel per bucket: versioning on or off, lock on or off, replication on or
  off, public or private, with a one-line recommendation for each gap.

**Admin console.**
- Per plan: which of these features are on, naming rules, maximum buckets, whether public buckets
  are allowed, minimum retention, allowed replication destinations.
- Fleet view of risky settings across customers (public buckets, no versioning on locked plans).

**StorageGRID.** Tenant Management API and the S3 API for buckets, versioning, lifecycle, policy
and Object Lock; Tenant Management API for platform services endpoints. Information lifecycle
management (ILM) stays a grid-wide, CSP-only setting and is shown to the customer as a storage
class, never edited by them.

**Done when.** A customer can create a versioned, lifecycle-managed, private bucket from the
portal and the portal shows its posture as complete.

---

## UC4. Capacity, quota and alerting

**Goal.** Nobody is surprised by a full quota, a failed bill or a service problem.

**Actors.** Customer administrator, customer operator, CSP operations.

**Customer portal.**
- Quota meter with thresholds the customer sets (for example 70, 85, 95 percent).
- Alerts by e-mail, webhook and in the portal when a threshold is crossed or when usage grows
  unusually fast.
- Request for more quota: a form that goes to the CSP for approval, or applies automatically up to
  a limit the plan allows. The request, decision and change are logged.
- Service status page: current state of the endpoint and region, planned maintenance, recent
  incidents, published by the CSP.

**Admin console.**
- Default thresholds and alert channels per plan.
- Approval queue for quota requests; auto-approve rules.
- Grid health and capacity overview for the CSP (this is for the CSP only, never shown to customers).
- Publish status messages and maintenance windows.

**StorageGRID.** Grid Management API (tenant usage and quota, grid health and alerts), metrics API
on the admin node.

**Done when.** A tenant crossing 85 percent produces one alert to the right people, the customer
can request more quota in the portal, and the CSP's decision shows in the customer's history.

---

## Backlog (candidates, not yet scheduled)

| Id | Use case | Note |
|---|---|---|
| UC5 | Support and tickets | Open and follow a request; link to the CSP's ticketing system by webhook or e-mail first. |
| UC6 | Audit and compliance reports | Per-customer activity log (who created which key or bucket), downloadable for the customer's auditors. |
| UC7 | Identity federation self-set-up | Customer configures its own SAML or OIDC provider for its tenant. |
| UC8 | Data migration help | Guided S3-to-S3 migration with endpoint and key checks. |
| UC9 | Multi-site and region choice | Customer picks a site per bucket where the CSP runs several grids. |
| UC10 | Reseller and sub-account model | A reseller manages its own customers under the CSP. |
| UC11 | Customer-visible SLA reporting | Availability figures per month against the contracted target. |
| UC12 | Cost forecasting and budgets | Budget alerts on projected month-end cost. |

Each use case is built as one or more modules (see [MODULES.md](MODULES.md)). A new use case adds a
module; it does not change the core.
