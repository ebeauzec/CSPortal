# Diagnose a failure and send what is needed

**Use it when** something fails and the person who will fix it cannot log in to your system.

**You need:** a staff user with `system.view`, or shell access.

## Steps

1. Note the time, the page or action, and the **reference** shown on any error page (a request id such as `r_...`).
2. Download the **diagnostic bundle**: System health, **Download diagnostic bundle**. Or on the host:
   ```
   docker compose exec csportal python -m csportal bundle --out /tmp/csportal-diagnostics.zip
   ```
3. Open `MANIFEST.txt` in the bundle. It lists every file. The bundle holds versions, configuration with secrets
   removed, job state, connector health, the grid connection (no password), audit chain result, backups, last drift
   result, waiting approvals, schema state and recent logs. It holds no passwords, keys or customer
   object data. Secrets are removed from every line before it is written.
4. Send the bundle and the notes from step 1 by any channel.

## Reading it yourself

| Symptom | Look at |
|---|---|
| A customer sees "Service problem" | `logs/csportal.log.txt`, search the reference; the line shows the grid's own error code and text |
| Grid unreachable | `backend_health.json` and `grid_connection.json`; Storage grid page, **Test these settings first** (certificates, names, each admin node) |
| Jobs failing | System health, Background jobs: the last error is kept; the same text is in the log under `csportal.job` |
| Sign-in problems | `csportal.security` lines: bad credentials, locks, refused origins |
| Audit chain problem | [AUDIT_RETENTION.md](AUDIT_RETENTION.md) |
| Portal and grid disagree | [DRIFT.md](DRIFT.md) |

## Check

The sender can open the zip and the manifest. Nothing in the files looks like a password or key (search for
`password`, `secret`, `token`: values must be `[REDACTED]`).

## Go back

Nothing was changed. Delete the zip from the host when it has been delivered.
