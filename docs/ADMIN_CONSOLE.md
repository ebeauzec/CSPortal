# Admin console guide: settings and the storage grid connection

The admin console is the private surface for the CSP's staff. This page covers where every configuration
parameter lives, how to connect the portal to a StorageGRID system, and what the grid administrators must
prepare. For installing the portal see [DEPLOYMENT.md](DEPLOYMENT.md); for the API calls the connector makes
see [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md).

Who can do what: **operations** and **super administrator** can see these pages. Only a **super administrator**
can change anything (permission `settings.edit`). Every change is recorded in the audit log.

## 1. Where a setting comes from

Each value has one of three sources, lowest priority first:

1. **default**: built into the product.
2. **file**: the JSON configuration file (and the few environment variables: `CSPORTAL_MODE`,
   `CSPORTAL_DATA_DIR`, `CSPORTAL_LOG_LEVEL`, `CSPORTAL_CONFIG`).
3. **console**: saved in the admin console. Stored in the database. Wins over the file.

The **All settings** page (`/settings`) lists every parameter with its value, source and when a change takes
effect. "Use file value" removes a console value so the file value applies again.

| Takes effect | Meaning |
|---|---|
| Immediately | Applied to the running service as soon as you save. |
| After a restart | Saved now, applied when the service next starts. |
| Configuration file only | Changes how the service starts (addresses, ports, certificates, master key). Edit the file and restart. These are shown, not editable, in the console. |
| On the Storage grid page | Managed by the grid connection page, section 3. |

### Parameter reference

| Group | Parameter | Editable in console | Notes |
|---|---|---|---|
| General | `mode`, `data_dir` | no | `production` or `demo`; demo only runs on the simulator. |
| General | `public_url`, `admin_public_url` | yes, immediately | Used in invitation and reset links. `https://` only outside demo. |
| Network and TLS | `behind_proxy`, `customer_listen.*`, `admin_listen.*`, `admin_allow_proxy`, `tls.*`, `master_key_file` | no | Start-up settings. The master key itself is never shown. |
| Sessions | `session.idle_minutes` (5 to 720), `session.absolute_hours` (1 to 72) | yes, immediately | |
| Security | `security.customer_mfa_required` | yes, immediately | Turning it off weakens security: flagged and audited. |
| Security | `security.lockout_attempts` (3 to 50), `security.lockout_minutes`, `security.min_password_length` (8 to 128) | yes, immediately | |
| Security | `security.audit_retention_days` | yes | See [SECURITY.md](SECURITY.md) for how retention works. |
| Logging | `log.level` | yes, immediately | |
| Logging | `log.dir`, `log.max_mb`, `log.backups`, `log.json`, `log.syslog` | yes, after a restart | |
| Outgoing mail | `smtp.host`, `smtp.port`, `smtp.username`, `smtp.from`, `smtp.starttls` | yes, immediately | |
| Outgoing mail | mail password | write-only | Saved encrypted, or from the environment variable named by `smtp.password_env`. |
| Background jobs | `jobs.usage_sample_minutes`, `jobs.alert_check_minutes` | yes, after a restart | |
| Storage grid | `backend.type` | no | `simulator` (demo) or `storagegrid`. |
| Storage grid | admin nodes, endpoints, account, user, password, certificates | yes, see section 3 | |
| Branding | name, service name, colour, support address, legal text | yes, on the Branding page | |

Values are checked before they are saved (range, format, and the production rules in `config.validate`). A bad
value is refused with a message, never saved.

### Weaker than recommended

The All settings page lists any setting that is weaker than the recommended default (MFA not required, minimum
password under 12, lock-out above 10 attempts, idle sessions over 60 minutes, sessions over 12 hours). A change that
newly weakens security is flagged in the confirmation message and recorded in the audit log with the word
`WEAKENED`.

## 2. Secrets

Two secrets can be saved in the console: the **grid password** and the **mail password**.

- They are encrypted with the master key (AES-256-GCM, bound to their purpose) and stored in the database.
- They are **write-only**: no page, log, audit record, backup listing or diagnostic bundle shows them.
- A value saved in the console wins over the environment variable. Remove the saved value to fall back to the
  variable. The page always states which one is in use ("saved in the console (encrypted)", "environment
  variable CSPORTAL_GRID_PASSWORD" or "not set").
- If your policy is that secrets come only from a secret store, leave the console field empty and use the
  environment variable; the portal then never stores them.
- Rotating: enter the new password and save. The connection is rebuilt immediately and tested.

## 3. The storage grid connection (`/grid`)

This page holds everything about the connection to StorageGRID and everything the grid administrators need.

### 3.1 Fields

| Field | What to enter |
|---|---|
| **Admin nodes** | One per line: `name, address[:port]`. The address is a host name or IP address (IPv6 as `[addr]:port`). Default port 443. The **first line is the primary**; if it cannot be reached the portal moves to the next one and stays there until that one fails. Up to 8. |
| **Management API version** | For example `v4`. The test shows which versions the grid offers. |
| **Grid account ID** | `0` for the grid itself. The portal's provisioning user lives there. |
| **Grid user name** | A dedicated user in a least-privilege group. Never the root user. |
| **Grid password** | Write-only, see section 2. |
| **CA certificates** | PEM text of the CA certificate(s) that signed the admin node and gateway certificates, one after the other. Empty means the system trust store (and the file named in `backend.storagegrid.ca_file`, if any). Certificates only: a private key is refused. |
| **Portal source address** | The address the grid sees the portal connecting from. Information for the grid administrators' firewall rules. |
| **Request timeout** | 3 to 120 seconds. |
| **S3 gateway endpoints** | One per line: `name \| https://address[:port] \| region \| note`. Only the address is required. These are the addresses customers' applications use, and they are shown to customers. The first is also used by the portal to apply bucket settings. Use the load balancer endpoints, not individual storage nodes. Up to 16. |

Certificate checking is **always on**. There is no setting to turn it off, in the console or the file, and
production mode refuses `verify_tls: false`. A host name or IP that the certificate does not list is a failed
check, with a hint.

Loopback and link-local addresses (127.0.0.0/8, 169.254.0.0/16) are refused outside demo mode, which also
prevents the test button being used to probe cloud metadata services.

### 3.2 Test before saving

**Test these settings first** runs the checks below against the values in the form, without saving them. Use it
before every change to a working connection. After **Save and apply** the portal rebuilds its connection and runs the
same test, and the result is kept (it is also in the diagnostic bundle).

| Check | Passes when | If it fails |
|---|---|---|
| Network connection | A TCP connection opens to the node's port. | Check address, port, routing and the firewall. |
| Certificate check | TLS 1.2 or newer completes and the certificate is trusted and lists the address. Warns when it expires within 30 days. | The detail shows the certificate the server presented (subject, issuer, SHA-256) so the grid administrator can confirm it; the hint says whether to add a CA certificate or use another address. |
| Management API version | `/api/versions` lists the configured version. | Pick a version the grid offers, or the address is not an admin node. |
| Sign-in | The grid accepts account, user and password. Not repeated on every node. | Check credentials; the grid's own message is shown. |
| Read grid health | The user may read health. | Grant the group the metrics/health permission. |
| List tenant accounts | The user may list tenant accounts. | Grant the group the "Tenant accounts" permission. |
| Answers as an S3 service (each endpoint) | TLS verifies and the endpoint answers like S3 (HTTP 403 without credentials is expected). | Check that the address is the load balancer endpoint, and its certificate. |

The password is sent **only after** the certificate has been verified. If verification fails, the checker opens
one extra connection that does not verify, only to read and show the certificate the server presents; nothing is sent
on it.

In demo mode the test returns clearly marked simulated results and contacts nothing.

### 3.3 Sheet for the grid administrators

The lower part of the page, and the downloadable text file (`/grid/handover.txt`), give the grid administrators:

1. the connection details (admin nodes, API version, account, user, where the password comes from; never the password);
2. the permissions the portal's grid group needs (indicative, see below);
3. what the portal creates for each customer tenant;
4. the S3 endpoints given to customers;
5. the network rules: each flow, host and port, and that the grid never connects to the portal;
6. the certificates the portal trusts, with fingerprints and expiry;
7. the last connection test.

Permissions the portal's grid group needs (**indicative: confirm against the documentation for your StorageGRID
release**; the connector has not been verified on a real grid, see [STORAGEGRID_INTEGRATION.md](STORAGEGRID_INTEGRATION.md)):

| Permission | Why |
|---|---|
| Tenant accounts | Create, change and delete tenant accounts; set quotas and permissions. |
| Metrics query | Read usage and health figures. |
| Read-write access mode | The group must not be read-only. |
| Not needed | Root access, maintenance, ILM, other administrator permissions. Do not grant them. |

Per customer tenant the portal creates a group `csportal-service` (manage containers, manage endpoints, manage its own
S3 credentials; **no root access**) and a user `csportal-service` with one S3 key used only for bucket settings that
S3 alone can set. Their credentials are stored encrypted in the portal. If the grid administrator deletes them in the
tenant, the portal loses control of that tenant.

### 3.4 First connection: a worked sequence

1. Grid administrator: create the group and user (section 3.3), the load balancer endpoint(s) for S3, and send you the
   CA certificate(s).
2. Start the portal (see [DEPLOYMENT.md](DEPLOYMENT.md)). It starts even without grid details; customers see a clear
   "not set up yet" message until they are entered.
3. Open **Storage grid**. Enter admin nodes, account `0`, user, password, CA certificates and endpoints.
4. Press **Test these settings first**. Fix every failed row using its hint.
5. Press **Save and apply**. Check the result card.
6. Run the **API conformance check** on the System health page. Every call must be `ok`.
7. Download the sheet and give it to the grid administrators; ask them to confirm the permissions against their
   release's documentation.
8. Create a test customer and walk through [USE_CASES.md](USE_CASES.md) before real customers.

### 3.5 Changing the connection later

- **New admin node or changed address:** edit the list, test, save. In-flight customer requests are unaffected; the
  connection is rebuilt in place.
- **Certificate renewal:** add the new CA certificate before the old one expires (both may be listed), test, save,
  then remove the old one. The table on the page shows days left; the test warns under 30 days.
- **Password rotation:** enter the new password, test, save.
- **Something broke:** the page shows the last test and which admin node is in use. Download the diagnostic bundle: it
  contains `grid_connection.json` (settings without secrets, certificate fingerprints, last test result) for remote
  help.

## 4. Audit

| Action | When |
|---|---|
| `settings.update` | A group of settings was saved. Detail lists `key: old -> new` (never secrets) and any `WEAKENED` note. |
| `settings.reset` | A console value was removed. |
| `grid.settings.update` | The grid connection was saved: nodes, API version, account, user, endpoints, certificate fingerprints, timeout, and whether the password changed. |
| `grid.test` | A connection test was run. |
| `grid.handover.download` | The sheet was downloaded. |
