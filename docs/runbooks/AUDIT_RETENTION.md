# Audit log: retention, archives and integrity problems

**Use it when** you set up archive custody, answer an auditor, or the audit check reports a problem.

## How it works in one paragraph

Every audit record holds the hash of the one before it. Every hour the portal signs the newest record (a
**checkpoint**). Once a day, records older than `security.audit_retention_days` (default 2555, about seven years) are
written to `data/audit-archive/audit-<first>-<last>.jsonl` with a `.sha256` file, and removed from the database. A
signed **anchor** keeps the hash of the last removed record, so the rest still verifies. Details and limits are in
[SECURITY.md](../SECURITY.md#audit-log-integrity-and-retention).

## Archive custody (do this on a schedule)

1. Copy new files from `data/audit-archive/` to long-term storage that fits your retention policy (write once if you
   can). The portal never deletes archive files.
2. Check a file against its checksum:
   ```
   sha256sum -c audit-1-5000.jsonl.sha256
   ```
3. To answer a question about an old event, search the `.jsonl` files (one record per line, fields `ts`, `actor`,
   `action`, `target`, `detail`, `ip`, `request_id`).

## The check reports a problem

Run `python -m csportal verify-audit` or open Operations. Messages and meaning:

| Message | Meaning | First action |
|---|---|---|
| The chain is broken at record N | A record was changed or removed in the middle | Stop. Take a copy of the database and the logs now. Compare with the latest backup ([RESTORE.md](RESTORE.md) on another host): records before N should be identical. Treat as a security incident |
| Records up to N were expected (checkpoint) but are missing | The newest records were cut off | Same as above |
| Record N does not match checkpoint | The log was rebuilt | Same as above |
| Checkpoint ... has a bad signature, or the anchor has a bad signature | Someone wrote a checkpoint without the key, or the master key changed without `rotate-key` | If you changed the key by hand, put the old key back and rotate with [ROTATE_MASTER_KEY.md](ROTATE_MASTER_KEY.md). Otherwise treat as an incident |

Retention does nothing while the chain does not verify. The `audit-retention` job reports the reason.

## Change the retention period

All settings, Security, `security.audit_retention_days` (30 to 36500). Shortening it archives older records at the
next daily run. Agree the period with your compliance owner first.

## Check

`python -m csportal verify-audit` prints `intact`, with the number of records, checkpoints and the id up to which
records were archived.

## Go back

A removed record cannot be returned to the database. The archive file holds it.
