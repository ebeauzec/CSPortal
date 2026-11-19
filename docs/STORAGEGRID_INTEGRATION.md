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

## Implementation (version 0.1.0)

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
  lifecycle, policy) are applied with that user's S3 key using Signature V4.
- Client behaviour: timeouts, back-off on throttling and gateway errors for reads, a circuit breaker, TLS with
  verification always on, grid error text cleaned of secrets before display.
- Not covered yet: platform services, identity source, grid federation, Object Lock retention rules,
  CORS, default encryption (see [TENANT_PARITY.md](TENANT_PARITY.md)).

### Verification plan (run on a non-production grid before use)

1. `conformance` reports every call `ok`.
2. Create a tenant from the admin console; confirm account, quota, group and service user on the grid.
3. As the customer: create a bucket with versioning, add a lifecycle rule, create a storage user and an
   access key; use the key with an S3 client to put and get an object.
4. Change the quota; confirm the grid and the portal agree. Suspend and resume.
5. Compare the portal's usage figure with the grid's own figure for the same tenant.
6. Record the grid release and the result in [CHANGELOG.md](../CHANGELOG.md) and update the status above.

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
