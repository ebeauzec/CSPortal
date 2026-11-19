# Restore from backup

**Use it when** the data is lost or damaged, when you move to a new host, and **once a quarter as a test** on a
different host. A backup that was never restored is not known to work.

**You need:** a backup file (`csportal-<time>.db`), the master key that was in force **when that backup was made**
(see the note on rotation), and the configuration file.

## Steps

1. Stop the service: `docker compose stop`.
2. Keep what is there: copy the current `csportal.db` (and any `csportal.db-wal` and `csportal.db-shm` beside it)
   to a safe place, even if it is damaged.
3. Check the backup before you use it. In the console (on a working copy): Operations, **Check** next to the file.
   Or with the SQLite shell on any host: `sqlite3 csportal-<time>.db "PRAGMA integrity_check;"` must print `ok`.
4. Put the backup in place as `/data/csportal.db`. Delete `csportal.db-wal` and `csportal.db-shm` from the data
   folder, because they belong to the old file.
5. Restore `/data/audit-archive/` from your long-term copy if it was lost. It is not part of the database file.
6. Start with the master key of that backup: `docker compose up -d`.

## Check

- `python -m csportal verify-audit` prints `intact` (a restore of an older file passes: checkpoints newer than the file
  are not in it).
- Sign in as staff and as a customer. System health shows the jobs starting again.
- Run [DRIFT.md](DRIFT.md). Changes made on the grid after the backup show up as differences. Fix them on purpose;
  do not align blindly.
- People who signed in after the backup must sign in again, and invitations sent after the backup are gone.

## The master key and rotation

Every secret in a backup is encrypted with the master key that was current when the copy was made. After
[ROTATE_MASTER_KEY.md](ROTATE_MASTER_KEY.md), older backups need the **old** key. Keep each old key until the last
backup made with it is no longer needed, in the same secret store, labelled with its dates.

## Go back

Put the files from step 2 back and start. For a quarterly test on another host, delete the test host's data when done.
