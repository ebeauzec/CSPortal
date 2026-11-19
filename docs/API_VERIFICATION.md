# StorageGRID API verification record

This page records what the connector's requests were compared with, what matched, what was wrong and fixed, and what is
still unconfirmed. It is a **paper check against published sources**. It is not a test against a real grid. The connector
stays marked unverified until the plan in [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md) passes on a real release.

Checked on 19 November 2026 against StorageGRID **11.9** documentation.

## Sources used

| Source | What it gave |
|---|---|
| NetApp StorageGRID 11.9 documentation, source files in the `NetAppDocs/storagegrid-119` repository (the pages on docs.netapp.com refuse automated requests, so the source of the same pages was read) | Authorize call, API versioning, operation groups, S3 operations and limits, lifecycle rules, tenant creation |
| NetApp's own Ansible collection `netapp.storagegrid` (`ansible-collections/netapp.storagegrid`) | Working request paths and bodies for accounts, containers, groups, users, S3 keys, health |
| The grid's own Swagger page | **Not available here.** It is the authority for exact fields. `python -m csportal conformance` compares every path with it on a real grid |

## Confirmed as matching

| Connector call | Evidence |
|---|---|
| `POST /api/v4/authorize`, token in `data`, sent as `Authorization: Bearer` | Docs (authorize, bearer token, 16-hour expiry); Ansible login module |
| `GET /api/versions` returns the supported major versions | Docs, "Determine which API versions are supported" |
| `/org/...` is served on the same host, restricted to tenant users | Docs, "Use the Grid Management API", top-level resources |
| `GET/POST /grid/accounts`, `GET/PUT/DELETE /grid/accounts/{id}`; body `name`, `capabilities`, `policy.{useAccountIdentitySource, allowPlatformServices, quotaObjectBytes}`, `password` | Ansible `na_sg_grid_account` |
| `GET /grid/health` | Ansible `na_sg_grid_info` |
| `GET /org/usage` | Ansible `na_sg_org_info` |
| `POST /org/containers` with `name`, `region`, `s3ObjectLock.enabled`; `DELETE /org/containers/{name}` | Ansible `na_sg_org_container` |
| `GET/POST /org/groups`, `PUT/DELETE /org/groups/{id}`; `displayName`, `uniqueName` (`group/..`), `policies.management`, `policies.s3` as a policy document; management keys `manageAllContainers`, `manageEndpoints`, `manageOwnS3Credentials`, `rootAccess` | Ansible `na_sg_org_group` |
| `GET/POST /org/users`, `DELETE /org/users/{id}`; `fullName`, `uniqueName` (`user/..`), `memberOf` (group ids), `disable` | Ansible `na_sg_org_user` |
| `GET/POST /org/users/{id}/s3-access-keys`, `DELETE .../s3-access-keys/{key}`; `expires` | Ansible `na_sg_org_user_s3_key`; docs (keys expire and are removed automatically) |
| S3 settings through the S3 API: versioning, lifecycle, policy, CORS, Object Lock, path-style, Signature V4 | Docs, "Operations on buckets" lists each operation as supported |

## Differences found and fixed

| # | What was wrong | Why it mattered | Fix |
|---|---|---|---|
| 1 | A new tenant was created with `capabilities: ["s3"]` only | NetApp's tooling adds `management` so the tenant can sign in to the tenant API. Without it the portal's tenant sign-in would very probably have been refused, and every customer page that reads the grid would fail | `["s3", "management"]` |
| 2 | A quota of 0 was sent as `0` | NetApp's tooling sends `null` for "no quota". `0` may be refused or read as a zero quota | `null` for 0, in create and in update |
| 3 | The grid sign-in sent `accountId: "0"` | The documented grid sign-in takes only user name and password; the tenant sign-in adds `accountId` | `accountId` only for tenants |
| 4 | Access keys were listed by an `accessKey` field and deleted by that value | The list returns an opaque `id` (what delete needs) and a masked `displayName`; the real key ID is not in the list | List by `id`, show the masked label, delete by `id`. The key ID is shown once at creation |
| 5 | `PATCH /org/users/{id}` | NetApp's tooling uses `PUT`. `PATCH` was not found in any source | `PUT` with the full user body |
| 6 | Group changes sent back the whole record, including read-only fields (`id`, `accountId`, `groupURN`, `federated`) | Read-only fields in a change can be refused | Only `displayName`, `uniqueName`, `policies` |
| 7 | Bucket list did not ask for the region | NetApp's tooling asks with `include=compliance,region`; without it every bucket would read as `us-east-1` | `include=compliance,region` |
| 8 | The bucket list read `s3ObjectLock` as true whenever the field existed | The field is `{"enabled": false}` for ordinary buckets, which is truthy | Reads `s3ObjectLock.enabled`. The bucket page also asks the bucket (S3 `?object-lock`) |
| 9 | Lists were read in one call | The grid pages its answers (NetApp's tooling passes `limit` and follows `marker`). A customer with more than one page of buckets, users or groups would silently lose the rest | Pages of 100 followed by `marker`; stops on a short, empty or repeating page |
| 10 | **Lifecycle rule "remove incomplete uploads after 7 days", ticked by default on every new bucket** | NetApp: StorageGRID supports Expiration actions only, not `AbortIncompleteMultipartUpload` or Transition. The grid would very probably refuse the lifecycle step and the portal would then roll the new bucket back. A rule that matches all objects with no Expiration action also tells the grid to keep every object forever | Removed everywhere: connector, guided bucket page, lifecycle form, demo data, customer guide |
| 11 | A key creation answer without the secret was accepted | The create response was not documented in any source found. A key whose secret nobody saw is useless | The answer is checked; if it lacks `accessKey` or `secretAccessKey` the key is deleted and an error is shown |

Tests: `tests/test_access.py`, class `ConnectorRequestShapes`, plus the paging check against the fake grid.

## Still unconfirmed

These were **not** found in any source available. They are most likely right, but they are not proved.

| Item | Where | How it closes |
|---|---|---|
| `GET /grid/alerts` and the alert fields (`name`, `severity`) | Grid overview | `conformance` and test step 1 |
| `GET /grid/accounts/{id}/usage` and its fields (`dataBytes`, `objectCount`, `buckets[]`) | Usage and billing | Test plan step 16 |
| The create-key answer fields `accessKey` and `secretAccessKey` | Key creation | Test plan step 7. The connector now refuses an answer without them |
| `marker` as the paging parameter on users, groups and buckets (confirmed for accounts only) | Long lists | Test with more than 100 users, groups or buckets. A grid that ignores `marker` still returns the first page only |
| Whether the bucket list returns `s3ObjectLock` | Bucket list | The bucket page asks the bucket directly, so the answer there is right either way |
| Page size 100 is accepted on every list | Long lists | Test plan step 5 |
| `Content-MD5` on settings calls | Bucket settings | Test plan steps 5 to 12 |

## A lead for the root-credential deviation

NetApp's Ansible collection sets a local tenant user's password with `POST /org/users/{uniqueName}/change-password`
and a body `{"password": ...}`. That is probably the documented way the roadmap item asks for: create the portal's service
user, give it a password with this call, and sign in as that user instead of the tenant root user. Not built, because it
changes the sign-in design and cannot be tested here. See [ROADMAP.md](ROADMAP.md).

## What this does not show

The connector has still not been run against a real grid. Everything above is a comparison of requests with documents.
Real grids can differ by release, by configuration (for example single sign-on) and by permissions. Run the
[test plan](STORAGEGRID_INTEGRATION.md#test-plan-for-a-real-grid) and `python -m csportal conformance` before any customer relies on it.
