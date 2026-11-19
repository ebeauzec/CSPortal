# Operations

CSPortal is meant to run where nobody can easily look at it from outside: a CSP's private network,
sometimes a dark site. Operations design is therefore part of the product.

## Run and recover

- One process, one data directory, one configuration file (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- **Backup:** copy the data directory (consistent snapshot command provided by the admin console and
  the command line) and store the master key separately.
- **Restore:** put the data directory back and start with the same master key. The start-up check
  reports schema version, module versions and connector state.
- **Upgrade:** replace the image; migrations run at start-up; a pre-upgrade backup is taken
  automatically; a documented rollback restores it.

## Failure always leaves evidence (diagnostic bundle)

Every failure that a person may have to fix remotely leaves a complete, portable **debug bundle**:
one archive, created by one admin-console button or one command, that holds what is needed to find
the cause without access to the system.

The bundle contains: product and module versions; configuration with secrets removed; connector
state and the StorageGRID release range seen; the last N hours of structured logs; recent job
results and errors with the grid's own error text; schema and migration state; time, certificate and
reachability checks for each configured endpoint; the audit-log chain check result.

Rules: secrets and customer object data are never included (secret values cannot be printed by
construction, see [SECURITY.md](SECURITY.md)); the bundle is written even when most of the system is
down; it is a single file that can be sent by any channel; its contents are listed in a manifest the
operator can read before sending.

## Commands

```
python -m csportal serve          run both surfaces and the job runner
python -m csportal demo           demo mode (simulated storage, sample data)
python -m csportal genkey         new master key
python -m csportal init-admin     first administrator; prints a one-time set-password link
python -m csportal conformance    check connector calls against the grid's own API description
python -m csportal bundle         write the diagnostic bundle (csportal-diagnostics.zip)
python -m csportal backup         consistent database copy
python -m csportal verify-audit   check the audit hash chain (exit code 2 if broken)
```

## Logging

| Log | File (in `log.dir`, default `data/logs`) | Content |
|---|---|---|
| Application | `csportal.log` | JSON lines: time, level, logger, request id, message and fields. Loggers: `csportal`, `csportal.security` (sign-in and policy events), `csportal.job`, `csportal.backend` |
| Access | `access.log` | One line per request: method, path (invitation tokens removed), status, time in ms, address, surface |
| Audit | database table `audit` | Business changes with actor, target, address and request id; hash-chained; viewable and exportable |

- Level: `log.level` (`DEBUG`, `INFO`, `WARNING`, `ERROR`) or the environment variable `CSPORTAL_LOG_LEVEL`.
- Rotation: `log.max_mb` and `log.backups`. Forwarding: `log.syslog` (`host:port`, UDP). Text instead of JSON: `log.json = false`.
- Every request has an id (`X-Request-Id` response header). Error pages quote it, so a customer's report can be
  matched to one log line.
- Secrets never reach a log: a scrubber removes values after `password`, `token`, `secret`, `authorization`,
  `cookie`, `key` and similar names, and stored secrets have a type that cannot be printed.
- The admin console has a log viewer (filter by file, level and text) and records each time it is opened.

## Health and monitoring

- Health endpoint for each surface, and a system-health page in the admin console: database,
  connector (reachability, authentication, release), job runner (last run, lag), mail relay, disk,
  certificate expiry, clock drift.
- Optional metrics endpoint on the private interface for the CSP's own monitoring.
- No outside reporting.

## Runbooks

One page per task in `docs/runbooks/` (to be written with the first release): first start,
backup and restore, upgrade and rollback, rotate the master key, rotate grid service credentials,
add a grid, onboard a customer by hand, recover a stuck provisioning, widen the supported StorageGRID
release range.
