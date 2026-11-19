# StorageGRID integration

CSPortal uses StorageGRID **natively**: through its own documented APIs, as the product intends,
and nothing else. No screen scraping, no browser automation, no undocumented or private
endpoints, no direct access to nodes, databases or log files.

> **Verification rule.** Endpoint paths, API version numbers and field names below are indicative.
> Each is confirmed against the public StorageGRID documentation (docs.netapp.com) and against the
> OpenAPI definition that the target grid itself publishes before it is used in code. Confirmed
> items are marked **confirmed (release range)** in the table at the end. Nothing is built on
> memory alone.

## The three native interfaces

| Interface | Used for | Who authenticates |
|---|---|---|
| **Grid Management API** (REST, JSON, served by the admin nodes) | Tenant accounts (create, update quota and permissions, delete), grid-level usage per tenant, grid health and alerts, metrics queries, S3 endpoint and load-balancer information | One provisioning identity, held by the portal, least-privilege grid group |
| **Tenant Management API** (REST, JSON, same host family, tenant scope) | Everything inside a tenant: users, groups, S3 access keys, buckets and their settings, platform-service endpoints, identity source, tenant usage | Per-tenant identity (see ADR-004), least-privilege tenant group |
| **S3 API** (the S3 protocol on the grid's S3 endpoints) | Bucket configuration that StorageGRID exposes only as S3 operations (for example lifecycle, policy, CORS, Object Lock settings), and the customer's own data path | The customer's own S3 keys for the data path; a portal-held, scoped key for configuration calls on the customer's behalf |

Customers use the S3 endpoints directly for data. The portal is control plane only.

## Using the API natively

1. **Typed client from the grid's own OpenAPI definition.** Both management APIs publish an
   OpenAPI description on the grid. The connector's client is generated from that description for
   each supported release range, not hand-written from guesses, and is checked in with the release
   it came from.
2. **Version negotiation.** The connector asks the grid which API versions it supports, picks the
   newest one it was built and tested for, and records the grid's software release. A grid outside
   the supported range puts the connector in a clear *unsupported release* state; it does not try anyway.
3. **Feature detection, not release guessing.** Capabilities (for example Object Lock, platform
   services, grid federation, S3 console) are detected from the grid's reported configuration and
   the tenant's permissions, and the portal hides or explains what is not available.
4. **Documented authentication only.** The documented authorise call returns a short-lived bearer
   token; the connector refreshes it before expiry and never stores a password longer than needed.
   Single sign-on to the grid is not used by the portal itself.
5. **Native semantics preserved.** Quota, permission, consistency-level and retention values use
   StorageGRID's own meanings and limits. The portal validates against the grid's limits before
   sending and returns the grid's own error text (cleaned of secrets) with a stable portal error code.
6. **Idempotent, reconciled provisioning.** Every create or change is tied to a portal operation id.
   A reconcile job compares the portal's records with the grid and reports drift (for example a
   tenant changed in the Grid Manager) instead of silently overwriting it.
7. **Polite client.** Concurrency limits, back-off on throttling or errors, per-call timeouts, and a
   circuit breaker so a slow grid does not stall the portal.
8. **Strict TLS.** The grid certificate is verified against a CSP-supplied trust anchor.

## Capability to API map (indicative, to be confirmed)

| Portal capability | Native interface | Typical resource family | Status |
|---|---|---|---|
| Create, update, delete tenant; quota; tenant-account permissions | Grid Management API | tenant accounts | verify |
| Grid usage per tenant | Grid Management API | tenant account usage | verify |
| Grid health, alerts, capacity for CSP view | Grid Management API | health, alerts, metrics query | verify |
| Users, groups, group permissions | Tenant Management API | users, groups | verify |
| S3 access keys | Tenant Management API | S3 access keys | verify |
| Identity source (own identity provider) | Tenant Management API | identity source | verify |
| Bucket create, delete, list, consistency level, versioning | Tenant Management API | buckets (containers) | verify |
| Lifecycle, bucket policy, CORS, Object Lock configuration | S3 API | bucket sub-resources | verify |
| Platform-service endpoints | Tenant Management API | endpoints | verify |
| Tenant usage and quota | Tenant Management API | usage | verify |
| S3 endpoint URLs shown to the customer | Grid Management API | load-balancer endpoints | verify |

## Implementation (unreleased, after 0.1.0)

The connector is `csportal/backends/storagegrid.py`; the interface is `csportal/backends/base.py`.

- **Status: written, not yet verified on a real grid.** Calls follow the public documentation as understood
  at the time. Treat this as unproven until the steps below pass on your release.
- `CALLS` in the connector lists every management API call it makes. `python -m csportal conformance` (or
  System health, API conformance) fetches the OpenAPI description the grid itself publishes and reports each
  call as `ok` or `MISSING`. This is the authority on what exists on your release.
- Authentication: the documented authorise call returns a short-lived bearer token per scope (the grid, or one
  tenant); tokens are refreshed on expiry or a 401.
- Per tenant, the portal creates a dedicated group and a service user and keeps its credentials in encrypted
  storage (ADR-004, option A). Bucket settings that StorageGRID exposes only through the S3 API (versioning,
  lifecycle, bucket policy, CORS, Object Lock default retention) are read and written with that user's S3 key using
  Signature V4 (`csportal/backends/s3sign.py`, `s3xml.py`). The signer is tested against the worked example in the
  AWS Signature Version 4 documentation. An earlier version of the signer sent sub-resource queries such as
  `?versioning` without the `=` that Signature V4 requires, so it would very probably have been refused by a real S3
  endpoint; that is fixed and covered by a test. Settings calls that carry a body also send `Content-MD5`.
- **Bucket page reads** (one S3 call each): versioning, lifecycle, policy, CORS and, on locked buckets, Object Lock.
  A setting that cannot be read is reported on the page; it is never shown as empty. The bucket list does not make
  these calls (it shows "-" for versioning and access) so that a long list stays fast.
- **Lifecycle rules the portal cannot describe** (tags, transitions, date expiry) are kept as the original XML and
  written back unchanged when another rule changes.
- **Group policies** are written as S3 statements on the group (`/org/groups/{id}`, `PUT` to change). A group limited
  to buckets lists those buckets and their objects as resources and is not allowed `ListAllMyBuckets`.
- Client behaviour: timeouts, back-off on throttling and gateway errors for reads, a circuit breaker, TLS with
  verification always on, grid error text cleaned of secrets before display.
- **Connection settings** are entered in the admin console (Storage grid page) or the configuration file; see
  [ADMIN_CONSOLE.md](ADMIN_CONSOLE.md#3-the-storage-grid-connection-grid). Several admin nodes can be listed: the
  connector uses the primary and moves to the next node only when a node cannot be reached, and it signs in again
  on the new node. S3 gateway endpoints and their regions come from the same page and are what customers see; the
  first is used for bucket settings, and requests are signed for that endpoint's region.
- **Connection test:** the console checks each admin node and each S3 endpoint step by step (network, certificate,
  API version, sign-in, the two permissions the portal needs, S3 answer) before and after saving. It is tested here
  against a fake admin node that speaks real TLS; that is not a substitute for the verification plan below.
- Load balancer endpoints are entered by hand. The connector does not discover them from the grid.
- Customer controls built on these calls are listed in [CUSTOMER_CONTROLS.md](CUSTOMER_CONTROLS.md).
- Not covered yet: platform services, identity source, grid federation, default encryption, legal hold
  (see [TENANT_PARITY.md](TENANT_PARITY.md)).
- Possible fault, to settle on a real grid: `create_tenant` generates a password for the service user but does not
  set it, and stores the tenant root credentials as the working credential. If the grid does not accept the root
  credentials for the calls the portal makes, the service user needs a password set at creation.

### Test plan for a real grid

Run it on a non-production grid before real customers use the portal. Write the grid release and the result of each
step in [CHANGELOG.md](../CHANGELOG.md), then change the status in this page, the README and
[TENANT_PARITY.md](TENANT_PARITY.md). Use a throw-away tenant and bucket names that cannot clash with real data.

| # | Step | Expected result |
|---|---|---|
| 1 | Admin console > Storage grid > Test these settings | Every step ok for every admin node and endpoint |
| 2 | `python -m csportal conformance` | Every call `ok` (this now includes `PUT /org/groups/{id}`) |
| 3 | Create a tenant from the admin console | Account, quota, group `csportal-service` and user exist on the grid. **Open question:** the service user's credentials work for the calls in steps 5-12 (see the possible fault in Implementation) |
| 4 | Customer: invite a person, accept, sign in with MFA | Sign-in works; role change signs the person out |
| 5 | Create a bucket with versioning; list buckets | Bucket appears with the right region; versioning "enabled" on the bucket page |
| 6 | Add, change, remove a lifecycle rule; on the grid add a rule with a tag filter, then change another rule in the portal | The tag rule is unchanged on the grid |
| 7 | Create a group limited to one bucket, a storage user in it, an access key with a 30-day expiry | With an S3 client: put/get in that bucket works; listing or reading another bucket is refused; the grid shows the expiry |
| 8 | Change the group to read only | Put is now refused, get still works |
| 9 | Bucket access: grant a group read on one folder | The group reads inside the folder and is refused outside it; the portal shows the grant |
| 10 | Make the bucket public (plan allows), read an object without credentials, make it private | Anonymous read works, then fails |
| 11 | Require encrypted connections; try a plain-HTTP request if the gateway allows one | Refused. If the gateway serves only HTTPS, record that the rule has no visible effect |
| 12 | CORS: add a rule, send a browser-style preflight from an allowed origin | Allowed headers come back; a different origin gets none |
| 13 | Object Lock bucket: set default retention (governance), write an object | Object shows the retention; delete is refused |
| 14 | Paste a policy that names another bucket, another account, public write | Each is refused by the portal; nothing changes on the grid |
| 15 | Change the quota; suspend and resume | Grid and portal agree; suspended users cannot use keys |
| 16 | Compare the portal's usage figure with the grid's own for the same tenant | Same figure within the grid's reporting delay |
| 17 | Stop the primary admin node (or block it) | Portal moves to the next node; the bucket page still loads |

## Supported release range

To be set when the first connector is built. The policy: the portal supports the current StorageGRID
release and the previous two feature releases, and states the range in the README and the release
notes. A new grid release is tested against a simulated and a real grid before the range is widened.

## Testing without a grid

The connector interface has a simulated back end that implements the same documented calls and
error cases, used for development, automated tests and demonstrations. Anything proven only against
the simulator is recorded as *not verified on a real grid* in [CHANGELOG.md](../CHANGELOG.md) until it has run
against one.

## Sources

Only public documentation: the StorageGRID documentation on docs.netapp.com and the OpenAPI
definition served by the operator's own grid. See [COMPLIANCE.md](COMPLIANCE.md).
